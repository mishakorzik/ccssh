"""
 Synchronous SSH client over the native ccssh transport.

 Supports password, publickey (ed25519 / ecdsa / rsa / mldsa44-ed25519),
 OpenSSH certificates, custom ports, exec channels, SFTP subsystem,
 local forwarding, manual/auto rekey, and strict/accept-new/off host-key
 policies.
"""
from __future__ import annotations
import base64
import hashlib
import os
import socket
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ccssh import algs
from ccssh import auth as A
from ccssh import channel as CH
from ccssh import chacha as _chacha_mod
from ccssh import chansock as _chansock_mod
from ccssh import crypto
from ccssh import forward as _forward_mod
from ccssh import gcm as _gcm_mod
from ccssh import hostkeys as HK
from ccssh import kex as K0
from ccssh import kex_ext as KX
from ccssh import sftp as SFTP
from ccssh.mldsa import KeyPair as MldsaKeyPair
from ccssh.sk import SkKey
from ccssh.transport import SyncTransport, CCSSHError
from ccssh import wire as W

VERSION = b"SSH-2.0-CC_1.0.0"
CIPHER_DEFAULT = algs.SUPPORTED_CIPHERS
MAC_DEFAULT = algs.SUPPORTED_MACS
HOSTKEY_DEFAULT = algs.SUPPORTED_HOSTKEYS


class AuthError(CCSSHError):
    pass


class HostKeyError(CCSSHError):
    pass


def _load_user_priv(key_path: str, passphrase: str | None):
    path = os.path.expanduser(key_path)
    if os.name == "posix":
        try:
            if os.stat(path).st_mode & 0o077:
                raise AuthError(f"key {path} is group/world-readable (chmod 600 it)")
        except AuthError:
            raise
        except OSError:
            pass  # missing file: let the open below report it
    with open(path, "rb") as f:
        # Bounded single read (no getsize/read TOCTOU: a file grown past
        # the cap between two syscalls must not OOM this process).
        data = f.read((1 << 20) + 1)
    if len(data) > (1 << 20):
        raise AuthError(f"key file {path} too large")
    try:
        return serialization.load_ssh_private_key(
            data, password=passphrase.encode() if passphrase else None)
    except Exception:
        pass
    # Fallback for ssh-mldsa44-ed25519 files unknown to this cryptography build.
    from ccssh.mldsa import load_openssh_private
    try:
        return load_openssh_private(path, passphrase.encode() if passphrase else None)
    except Exception:
        pass
    # Fallback for FIDO2 security-key files (sk-ssh-ed25519 / sk-ecdsa-sha2).
    from ccssh.sk import load_openssh_private as sk_load
    try:
        return sk_load(path, passphrase.encode() if passphrase else None)
    except Exception:
        pass
    # Re-raise the original error for anything else, typed as AuthError so
    # the login loop (passphrase prompts, next-identity fallback) sees it.
    try:
        return serialization.load_ssh_private_key(
            data, password=passphrase.encode() if passphrase else None)
    except AuthError:
        raise
    except Exception as e:
        raise AuthError(f"cannot load key {path}: {e}") from e


def _user_blob(priv, cert_path: str | None):
    """Returns (alg, key_blob). Certificates pass through opaquely from file."""
    if cert_path:
        with open(os.path.expanduser(cert_path), encoding="utf-8") as f:
            p = f.read().strip().split()
        if len(p) < 2:
            raise AuthError(f"bad certificate file {cert_path}")
        try:
            return p[0].encode(), base64.b64decode(p[1], validate=True)
        except Exception as e:
            raise AuthError(f"bad certificate file {cert_path}: {e}") from e
    if isinstance(priv, MldsaKeyPair):
        return b"ssh-mldsa44-ed25519", priv.public_blob()
    if isinstance(priv, SkKey):
        return priv.alg.encode(), priv.public_blob()
    if isinstance(priv, Ed25519PrivateKey):
        pub = priv.public_key().public_bytes_raw()
        return b"ssh-ed25519", W.enc_string(b"ssh-ed25519") + W.enc_string(pub)
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        cn = priv.curve.name
        alg = {"secp256r1": "ecdsa-sha2-nistp256", "secp384r1": "ecdsa-sha2-nistp384", "secp521r1": "ecdsa-sha2-nistp521"}[cn]
        curve_ssh = {"secp256r1": b"nistp256", "secp384r1": b"nistp384", "secp521r1": b"nistp521"}[cn]
        size = (priv.key_size + 7) // 8
        nums = priv.public_key().public_numbers()
        q = b"\x04" + nums.x.to_bytes(size, "big") + nums.y.to_bytes(size, "big")
        return alg.encode(), W.enc_string(alg.encode()) + W.enc_string(curve_ssh) + W.enc_string(q)
    if isinstance(priv, rsa.RSAPrivateKey):
        return b"ssh-rsa", None # blob is built from pub numbers below
    try:
        from cryptography.hazmat.primitives.asymmetric import dsa as _dsa_mod
        if isinstance(priv, _dsa_mod.DSAPrivateKey):
            nums = priv.public_key().public_numbers()
            p = nums.parameter_numbers.p
            blob = (W.enc_string(b"ssh-dss")
                    + W.enc_mpint(p)
                    + W.enc_mpint(nums.parameter_numbers.q)
                    + W.enc_mpint(nums.parameter_numbers.g)
                    + W.enc_mpint(nums.y))
            return b"ssh-dss", blob
    except AuthError:
        raise
    except Exception:
        pass
    raise AuthError(f"unsupported private key type {type(priv)}")


class ShellSession:
    """
     An open pty+shell channel (see CCSSHClient.open_shell).

     Single-reader model: exactly one thread may consume packets from the
     transport (ccssh.shell's pump, or your own recv loop in scripts).
     Sends are lock-guarded and honor the server's channel window.
     close() only SENDS close and reports the last exit status seen by the
     reader; the reader must keep draining until the peer's CLOSE arrives.
    """

    def __init__(self, client: "CCSSHClient", srv: int, window: int, maxpacket: int, chan: int | None = None):
        self._client = client
        self.srv = srv
        # Client-side channel id (incoming recipient). Older callers pass
        # only srv; then incoming checks accept srv (single-channel compat).
        self.chan = srv if chan is None else chan
        self._window = window
        # Honor the server's maxpacket but never exceed ours: a rogue
        # server announcing megabytes would make enc_data raise mid-send.
        self._maxpacket = max(1024, min(maxpacket, CH.MAXPKT))
        self._lock = threading.Lock()
        self._closed = False
        self.no_pty = False
        self.exit_status: int | None = None
        self.eof_received = False
        self.consumed = 0  # server->client bytes since last WINDOW_ADJUST

    @property
    def _t(self):
        t = self._client._t
        if t is None:
            raise CCSSHError("connection closed")
        return t

    def credit(self, delta: int) -> None:
        with self._lock:
            self._window = CH.check_window(self._window, delta)

    def add_consumed(self, n: int) -> None:
        """Reader-side: record received bytes (thread-safe)."""
        with self._lock:
            self.consumed += n

    def _ensure_window(self, need: int) -> None:
        # Credits arrive on the reader thread; wait for them briefly.
        deadline = time.monotonic() + self._client.timeout
        while True:
            with self._lock:
                if self._window >= need:
                    self._window -= need
                    return
            if time.monotonic() > deadline:
                raise CCSSHError("shell: send window exhausted, no adjust")
            time.sleep(0.01)

    def send(self, data: bytes) -> None:
        """Send stdin bytes, split to the server's maxpacket."""
        if not data:
            return
        t = self._t
        off = 0
        while off < len(data):
            chunk = data[off:off + self._maxpacket]
            self._ensure_window(len(chunk))
            t.send_packet(CH.enc_data(self.srv, chunk))
            off += len(chunk)

    def send_eof(self) -> None:
        try:
            self._t.send_packet(CH.enc_eof(self.srv))
        except Exception:
            pass

    def window_change(self, cols: int, rows: int) -> None:
        try:
            self._t.send_packet(CH.enc_window_change(self.srv, cols, rows))
        except Exception:
            pass

    def window_adjust(self) -> None:
        """Credit the server for consumed output (reader calls this)."""
        with self._lock:
            if self.consumed < CH.WINDOW_THRESHOLD:
                return
            delta = self.consumed
        try:
            self._t.send_packet(CH.enc_window_adjust(self.srv, delta))
        except Exception:
            return  # keep the credit: a later call retries a larger adjust
        with self._lock:
            self.consumed -= delta

    def close(self) -> int | None:
        """Send CLOSE (idempotent). Returns the last known exit status."""
        if not self._closed:
            self._closed = True
            try:
                self._t.send_packet(CH.enc_close(self.srv))
            except Exception:
                pass
        return self.exit_status

    def _peer_closed(self) -> None:
        """
         Peer sent CLOSE: drop the mux registration (pump calls this).

         Unregistering here (not in close()) keeps the queue alive while
         the reader still drains the goodbye; close() alone must not
         strand a blocked reader.
        """
        try:
            self._client._unreg(self.chan)
        except Exception:
            pass


class CCSSHClient:
    def __init__(self, *, timeout: float = 10.0, known_hosts: str | list[str] | None = None, host_policy: str = "strict", kex: list[str] | None = None, ciphers: list[str] | None = None, macs: list[str] | None = None, hostkeys: list[str] | None = None, rekey_bytes: int = 4 * 1024**3, rekey_interval: float = 3600.0, verbose: int = 0, ask_callback=None):
        if host_policy not in ("strict", "accept-new", "ask", "off"):
            raise ValueError(f"bad host_policy {host_policy!r} (must be strict|accept-new|ask|off)")
        self.timeout = timeout
        self.known_hosts = [os.path.expanduser(p) for p in known_hosts] if isinstance(known_hosts, list) else (os.path.expanduser(known_hosts) if known_hosts else None)
        self.host_policy = host_policy
        self.ask_callback = ask_callback
        self.kex_list = algs.normalize_list(algs.SUPPORTED_KEX, kex) or algs.default_kex()
        self.cipher_list = algs.normalize_list(algs.SUPPORTED_CIPHERS, ciphers) or CIPHER_DEFAULT
        self.mac_list = algs.normalize_list(algs.SUPPORTED_MACS, macs) or MAC_DEFAULT
        self.hostkey_list = algs.normalize_list(algs.SUPPORTED_HOSTKEYS, hostkeys) or HOSTKEY_DEFAULT
        self.rekey_bytes = rekey_bytes
        self.rekey_interval = rekey_interval
        self.verbose = verbose
        self._t: SyncTransport | None = None
        self._sid: bytes | None = None
        self._cipher = "none"
        self._kex = "none"
        self._mac = "none"
        self._strict = False
        self._chan_next = 1
        self._chan_lock = threading.Lock()
        self._open_chans: set[int] = set()  # channels needing mux queues
        self._fwds: list = []
        self._host_Ks: bytes | None = None
        self._host_alg = "unknown"
        self._mux = None  # ChannelMux once forwarding shares this connection

    def _log(self, level: int, msg: str) -> None:
        """OpenSSH-style debug output to stderr. level 1 (-v), 2+ (-vv)."""
        if self.verbose >= level:
            import sys as _sys
            print(f"debug{level}: {msg}", file=_sys.stderr)

    def _maybe_rekey(self) -> None:
        """
         Automatic rekey between operations (OpenSSH-style 4GB/60min limits).

         Skipped while the mux has live channels: rekey needs a quiet
         connection, and OpenSSH-transparent rekey-under-load is out of
         scope (same rule as manual rekey below).
        """
        t = self._t
        if t is None or self._sid is None:
            return
        if self._mux is not None and self._mux.busy():
            self._log(2, "rekey: deferred (mux has live channels)")
            return
        if (time.monotonic() - t.kex_at > self.rekey_interval
                or t.bytes_out + t.bytes_in > self.rekey_bytes):
            self.rekey()

    @staticmethod
    def _skip_unmatched_guess(t, peer: dict, our_kex: list[str], kex_name: str) -> None:
        """
         RFC 4253 section 7.1: if the peer sent first_follows with a wrong
         KEX guess, the packet after its KEXINIT is a decoy and must be
         discarded (otherwise we would parse it as the real KEX message).
         Servers never send this in practice; the guard only triggers then.
        """
        if not peer.get("first_follows"):
            return
        flags = {K0.KEX_STRICT_C, K0.KEX_STRICT_S, K0.EXT_INFO_C}
        guess = next((k for k in peer["kex"] if k in our_kex and k not in flags), None)
        if guess != kex_name:
            t.recv_packet() # discard the decoy

    def connect(self, hostname: str, *, port: int = 22, username: str, password: str | None = None, key_filename: str | None = None, cert_filename: str | None = None, passphrase: str | None = None, family: int = 0, sock: _chansock_mod.StreamSocket | None = None, kbdint_responder: A.KbdintResponder | None = None) -> "CCSSHClient":
        owned = sock is None  # dialled here (closable) vs jump-owned (hands off)
        # A previous connection's mux (if any) belongs to its transport:
        # never let a stale reader steal the new handshake.
        mux, self._mux = self._mux, None
        if mux is not None:
            try:
                mux.stop()
            except Exception:
                pass
        if sock is None:
            self._log(1, f"Connecting to {hostname} [{port}] (timeout={self.timeout}s)")
            infos = self._resolve(hostname, port, family)
            self._log(2, f"resolve {hostname}:{port} -> {len(infos)} addr(s): {', '.join(f'{af}:{sa}' for af, _st, _pr, _ca, sa in infos)}")
            last_err: OSError | None = None
            sock = None
            for af, st, proto, _canon, sa in infos:
                s: socket.socket | None = None
                try:
                    self._log(2, f"dialing {sa} ...")
                    s = socket.socket(af, st, proto)
                    s.settimeout(self.timeout)
                    s.connect(sa)
                except OSError as e:
                    self._log(2, f"dial {sa} failed: {e}")
                    last_err = e
                    if s is not None:
                        try:
                            s.close()
                        except Exception:
                            pass
                    continue
                self._log(1, f"connected to {sa}")
                sock = s
                break
            if sock is None:
                raise CCSSHError(f"connect {hostname}:{port}: {last_err}")
        else:
            self._log(1, f"using jump-tunnel socket to {hostname}:{port}")
        try:
            # TCP_NODELAY also on jump-owned sockets (best effort: a
            # ChannelSocket simply ignores unknown options).
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        t = SyncTransport(sock, VERSION, timeout=self.timeout)
        try:
            self._log(2, f"sending version {VERSION!r}")
            Vs = t.do_version()
            self._log(1, f"server version: {Vs!r}")
            Vc = VERSION
            self._log(2, f"KEX offer: kex={self.kex_list}")
            self._log(2, f"KEX offer: hostkey={self.hostkey_list} cipher={self.cipher_list} mac={self.mac_list}")
            our = K0.enc_kexinit(os.urandom(16), self.kex_list + [K0.KEX_STRICT_C, K0.EXT_INFO_C], self.hostkey_list, self.cipher_list, self.cipher_list, self.mac_list, self.mac_list, ["none"], ["none"])
            t.send_packet(our)  # still plaintext at this point
            peer_raw = t.recv_packet()
            peer = K0.dec_kexinit(peer_raw)
            self._log(2, f"peer KEX: kex={peer['kex']} hostkey={peer['hostkey']} cipher_c2s={peer['enc_c2s']} mac_c2s={peer['mac_c2s']}")
            kex_name = K0.negotiate(self.kex_list, peer["kex"])
            host_alg = K0.negotiate(self.hostkey_list, peer["hostkey"])
            cipher = K0.negotiate_symmetric(self.cipher_list, peer["enc_c2s"], peer["enc_s2c"], "cipher")
            mac = K0.negotiate_symmetric(self.mac_list, peer["mac_c2s"], peer["mac_s2c"], "mac")
            strict = K0.peer_wants_strict(peer["kex"], is_client=True)
            self._log(1, f"kex: {kex_name} hostkey: {host_alg} cipher: {cipher} mac: {mac} strict: {strict}")
            Ic, Is = K0.I_FOR_H(our), K0.I_FOR_H(peer["payload_full"])
            self._skip_unmatched_guess(t, peer, self.kex_list, kex_name)
            self._log(2, "running KEX ...")
            K_enc, Hh, Ks, hashfn = self._run_kex(t, kex_name, Vc, Vs, Ic, Is, host_alg)
            try:
                fp = HK.fingerprint(Ks)
            except Exception:
                fp = "<unparseable>"
            self._log(1, f"server host key: {host_alg} {fp} (policy={self.host_policy})")
            self._check_hostkey(hostname, port, Ks, host_alg)
            self._log(1, "host key verified")
            self._host_Ks = Ks
            self._host_alg = host_alg
            keys = self._derive(cipher, mac, K_enc, Hh, hashfn)
            t.activate(keys, cipher, mac, is_client=True)
            t.send_packet(bytes([K0.MSG_NEWKEYS]))  # old (plaintext) keys
            t._enc_on_send = True
            pkt = t.recv_packet()
            if not pkt or pkt[0] != K0.MSG_NEWKEYS:
                raise CCSSHError("expected NEWKEYS")
            t._enc_on_recv = True
            self._strict = K0.peer_wants_strict(peer["kex"], is_client=True)
            if self._strict:
                t.send_seq = 0
                t.recv_seq = 0
            self._t, self._sid, self._cipher, self._mac = t, Hh, cipher, mac
            self._kex = kex_name
            self._log(1, f"negotiated: kex={kex_name} cipher={cipher} mac={mac} strict={self._strict}")
            self._log(2, f"session id: {Hh.hex()[:32]}...")
            t.send_packet(A.enc_service_request())
            for _ in range(16): # EXT_INFO repeats are skipped, not fatal
                pkt = t.recv_packet()
                if pkt and pkt[0] == K0.MSG_EXT_INFO:
                    self._log(2, "got EXT_INFO from server")
                    continue
                break
            if not pkt or pkt[0] != A.MSG_SERVICE_ACCEPT:
                raise CCSSHError("no ssh-userauth service")
            self._log(2, "userauth service accepted")
            if key_filename or cert_filename:
                self._log(1, f"auth: publickey key={key_filename} cert={cert_filename}")
                self._auth_pubkey(username, key_filename, cert_filename, passphrase)
                self._log(1, "auth: publickey accepted")
            elif password is not None:
                self._log(1, "auth: password method")
                t.send_packet(A.enc_password_request(username, password))
                if (t.recv_packet() or b"\x00")[0] != A.MSG_USERAUTH_SUCCESS:
                    # Fall back to keyboard-interactive (RFC 4256) with the
                    # same secret: servers like serveo.net only offer that
                    # method. The original error is kept if it fails too.
                    self._log(1, "auth: password rejected, trying keyboard-interactive")
                    try:
                        self._auth_kbdint(username, lambda prompts: [password] * len(prompts))
                    except AuthError:
                        raise AuthError("password rejected") from None
                else:
                    self._log(1, "auth: password accepted")
            elif kbdint_responder is not None:
                self._auth_kbdint(username, kbdint_responder)
            else:
                raise AuthError("provide password or key_filename")
        except Exception:
            # An externally owned jump socket (sock=) stays open for the
            # caller to reuse; only a socket we dialled ourselves is closed.
            if owned:
                try:
                    t.sock.close()
                except Exception:
                    pass
            # Do not close an externally owned jump socket here; the caller
            # owns `sock=` (ProxyJump). We only drop our transport reference.
            self._t = None
            raise
        return self

    @staticmethod
    def _resolve(hostname: str, port: int, family: int) -> list:
        """getaddrinfo filtered by family (0 = any; -4/-6 map to AF_INET/6)."""
        try:
            infos = socket.getaddrinfo(hostname, port, family=family or socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        except OSError as e:
            raise CCSSHError(f"resolve {hostname}: {e}") from e
        if not infos:
            raise CCSSHError(f"no addresses for {hostname}")
        return infos

    def _run_kex(self, t: SyncTransport, name: str, Vc: bytes, Vs: bytes, Ic: bytes, Is: bytes, host_alg: str = "ssh-ed25519"):
        name = KX.KEX_ALIASES.get(name, name)
        hashfn = KX.kdf_hashfn(name)
        if name == "curve25519-sha256":
            c = K0.Curve25519Client()
            t.send_packet(c.init_msg())
            K_ecdh, Hh, Ks = c.finish(t.recv_packet(), Vc, Vs, Ic, Is, host_alg)
            return W.mpint_from_bytes(K_ecdh), Hh, Ks, hashfn
        if name == "mlkem768x25519-sha256":
            c = K0.MlkemHybridClient(Vc, Ic)
            t.send_packet(c.init_msg())
            Kr, Hh, Ks, _, _ = c.finish(t.recv_packet(), Vs, Is, host_alg)
            return W.enc_string(Kr), Hh, Ks, hashfn
        if name.startswith("ecdh-sha2-nistp"):
            c = KX.EcdhClient(name)
            t.send_packet(c.init_msg())
            Ke, Hh, Ks = c.finish(t.recv_packet(), Vc, Vs, Ic, Is, host_alg)
            return W.mpint_from_bytes(Ke), Hh, Ks, hashfn
        if name in KX.DH_GROUPS:
            c = KX.DhClient(name)
            t.send_packet(c.init_msg())
            Kr, Hh, Ks = c.finish(t.recv_packet(), Vc, Vs, Ic, Is, host_alg)
            return W.mpint_from_bytes(Kr), Hh, Ks, hashfn
        if name == "mlkem768nistp256-sha256":
            c = KX.MlkemP256Client(Vc, Ic)
            t.send_packet(c.init_msg())
            Kr, Hh, Ks = c.finish(t.recv_packet(), Vs, Is, host_alg)
            return W.enc_string(Kr), Hh, Ks, hashfn
        if name in ("diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1"):
            c = KX.GexClient(hashfn=hashlib.sha256 if name.endswith("sha256") else hashlib.sha1)
            t.send_packet(c.request_msg())
            t.send_packet(c.init_msg(t.recv_packet()))
            Kr, Hh, Ks = c.finish(t.recv_packet(), Vc, Vs, Ic, Is, host_alg)
            return W.mpint_from_bytes(Kr), Hh, Ks, hashfn
        if name == "sntrup761x25519-sha512":
            c = KX.SntrupClient(Vc, Ic)
            t.send_packet(c.init_msg())
            Kr, Hh, Ks, _, _ = c.finish(t.recv_packet(), Vs, Is, host_alg)
            return W.enc_string(Kr), Hh, Ks, hashfn
        raise CCSSHError(f"KEX {name} not wired to the transport")

    @staticmethod
    def _derive(cipher: str, mac: str, K_enc: bytes, Hh: bytes, hashfn, session_id: bytes | None = None) -> dict[str, bytes]:
        sid = Hh if session_id is None else session_id
        if cipher in crypto.CIPHER_SPECS or cipher in crypto.CBC_SPECS:
            return crypto.derive_keys(K_enc, Hh, sid, cipher, mac, hashfn)
        if cipher in ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com"):
            return _gcm_mod.derive_gcm_keys(K_enc, Hh, sid, cipher, hashfn)
        if cipher == "chacha20-poly1305@openssh.com":
            return _chacha_mod.derive_chacha_keys(K_enc, Hh, sid, hashfn)
        raise CCSSHError(f"key derivation for {cipher}")

    def _check_hostkey(self, host: str, port: int, Ks: bytes, alg: str) -> None:
        from ccssh.hostcheck import check_hostkey, HostKeyError as _HKE
        try:
            check_hostkey(host, port, Ks, alg, policy=self.host_policy, known_hosts=self.known_hosts, ask_callback=getattr(self, "ask_callback", None))
        except _HKE as e:
            raise HostKeyError(str(e)) from e

    def _auth_pubkey(self, username: str, key_path: str | None, cert_path: str | None, passphrase: str | None) -> None:
        if not self._t or self._sid is None:
            raise CCSSHError("call .connect() first")
        if not key_path:
            raise AuthError("cert without key_filename is unsupported")
        priv = _load_user_priv(key_path, passphrase)
        alg, blob = _user_blob(priv, cert_path)
        if blob is None: # RSA: build the blob from public numbers
            nums = priv.public_key().public_numbers()
            blob = W.enc_string(b"ssh-rsa") + W.enc_mpint(nums.e) + W.enc_mpint(nums.n)
            alg = b"rsa-sha2-256"
        self._log(1, f"auth: publickey probe {alg.decode(errors='replace')} key={key_path}")
        self._t.send_packet(A.enc_pubkey_probe(username, alg, blob))
        r = self._t.recv_packet()
        if r and r[0] == A.MSG_USERAUTH_SUCCESS:
            self._log(1, "auth: server accepted the key without signature")
            return
        if r and r[0] == A.MSG_USERAUTH_PK_OK:
            self._log(2, "auth: server PK_OK, sending signature")
        else:
            self._log(2, f"auth: probe answered {(r[0] if r else None)}, trying signed anyway")
        data = A.auth_sign_blob(self._sid, username, alg, blob)
        outer = HK.sign_userauth(priv, alg.decode(), data)
        self._t.send_packet(A.enc_pubkey_signed(username, alg, blob, outer))
        if (self._t.recv_packet() or b"\x00")[0] != A.MSG_USERAUTH_SUCCESS:
            self._log(1, f"auth: publickey key={key_path} rejected by server")
            raise AuthError("publickey rejected")
        self._log(1, f"auth: publickey key={key_path} accepted")
    def _auth_kbdint(self, username: str, responder: A.KbdintResponder) -> None:
        """Keyboard-interactive auth (RFC 4256): probe, answer each
        INFO_REQUEST via `responder`, stop at SUCCESS/FAILURE. Bounded
        rounds and prompt counts (rogue servers must not loop us)."""
        t = self._t
        if t is None or self._sid is None:
            raise CCSSHError("call .connect() first")
        self._log(1, "auth: keyboard-interactive method")
        t.send_packet(A.enc_kbdint_probe(username))
        for _ in range(A.MAX_KBDINT_ROUNDS):
            p = t.recv_packet() or b"\x00"
            m = p[0]
            if m == A.MSG_USERAUTH_SUCCESS:
                self._log(1, "auth: keyboard-interactive accepted")
                return
            if m == A.MSG_USERAUTH_FAILURE:
                raise AuthError("keyboard-interactive rejected")
            if m != A.MSG_USERAUTH_INFO_REQUEST:
                raise AuthError(f"keyboard-interactive: unexpected reply {m}")
            try:
                info = A.dec_info_request(p)
            except W.WireError as e:
                raise AuthError(f"keyboard-interactive: bad prompt: {e}") from e
            self._log(2, f"auth: kbdint {len(info['prompts'])} prompt(s): "
                          f"{[text for text, _echo in info['prompts']]}")
            try:
                answers = responder(info["prompts"])
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                raise AuthError(f"keyboard-interactive responder failed: {e}") from e
            if len(answers) != len(info["prompts"]):
                raise AuthError("keyboard-interactive responder gave wrong answer count")
            t.send_packet(A.enc_info_response([a.encode() for a in answers]))
        raise AuthError("keyboard-interactive rejected (too many rounds)")

    def _rx(self, chan: int, timeout: float | None = None) -> bytes:
        """Next inbound packet for a channel: via the mux when one is
        active (forwarding shares the connection), else a direct
        transport read (historical behavior, unchanged).

        `timeout` is honored only under a mux (mux.recv_chan); without
        one the transport-level read timeout bounds each read instead.
        Callers that need a hard deadline keep their own (see _top_up,
        _await_request, _make_closer).
        """
        mux = self._mux
        if mux is not None:
            return mux.recv_chan(chan, timeout)
        t = self._t
        if t is None:
            raise CCSSHError("connection closed")
        return t.recv_packet()

    def _expect(self, chan: int) -> None:
        """Prime request-reply correlation (call BEFORE sending a channel
        request; no-op without a mux). Prefer _send_request(), which makes
        the pair atomic across threads."""
        mux = self._mux
        if mux is not None:
            mux.expect_reply(chan)

    def _send_request(self, chan: int, payload: bytes) -> None:
        """expect_reply()+send as one atomic step.

        99/100 carry no channel id, so two threads doing expect(A)+send(A)
        and expect(B)+send(B) unlocked could cross-wire the replies. The
        mux request lock keeps each pair together.
        """
        mux = self._mux
        t = self._t
        if t is None:
            raise CCSSHError("connection closed")
        if mux is None:
            t.send_packet(payload)
            return
        with mux.request_lock:
            mux.expect_reply(chan)
            t.send_packet(payload)

    def _ensure_mux(self):
        """Start the channel multiplexer (first forwarder takes it)."""
        if self._mux is None:
            if self._t is None:
                raise CCSSHError("call .connect() first")
            from ccssh import mux as _mux_mod
            self._mux = _mux_mod.ChannelMux(self._t).start()
            with self._chan_lock:
                for chan in self._open_chans:
                    try:
                        self._mux.register(chan)
                    except Exception:
                        pass
            self._log(2, "channel multiplexer started (forwarding shares this connection)")
        return self._mux

    def _reg(self, chan: int) -> None:
        """Track an open channel and register its mux queue (if any)."""
        with self._chan_lock:
            self._open_chans.add(chan)
        if self._mux is not None:
            self._mux.register(chan)

    def _unreg(self, chan: int) -> None:
        """Forget a closed channel and drop its mux queue (if any)."""
        with self._chan_lock:
            self._open_chans.discard(chan)
        if self._mux is not None:
            try:
                self._mux.unregister(chan)
            except Exception:
                pass

    def exec_command(self, command: str, *, timeout: float | None = None,
                       max_bytes: int = 16 * 1024 * 1024, raw_bytes: bool = False):
        """Run one command. Returns (stdout, stderr, exit_status) as text,
        or as bytes with raw_bytes=True (binary-safe, like ssh pipes)."""
        if not self._t:
            raise CCSSHError("call .connect() first")
        self._maybe_rekey()
        t = self._t
        chan = self._alloc_chan()
        self._reg(chan)
        try:
            out_b, err_b, code = self._exec_inner(t, chan, command, max_bytes)
        finally:
            self._unreg(chan)
        if raw_bytes:
            return out_b, err_b, code
        return out_b.decode(errors="replace"), err_b.decode(errors="replace"), code

    def _exec_inner(self, t, chan: int, command: str, max_bytes: int) -> tuple[bytes, bytes, int]:
        self._log(2, f"exec: opening session channel {chan} for {command!r:.80}")
        t.send_packet(CH.enc_open_session(chan))
        while True:
            r = W.Reader(self._rx(chan))
            m0 = r.byte()
            if m0 == CH.MSG_CHANNEL_OPEN_CONFIRM:
                break
            if m0 == CH.MSG_CHANNEL_OPEN_FAILURE:
                raise CCSSHError("channel refused by server")
            continue  # WINDOW_ADJUST etc. before the channel exists
        if r.u32() != chan:
            raise CCSSHError("channel confirm for foreign channel")
        srv = r.u32()
        self._send_request(chan, CH.enc_exec(srv, command))
        while True:
            pkt = self._rx(chan) or b"\x00"
            if pkt[0] == CH.MSG_CHANNEL_SUCCESS:
                break
            if pkt[0] == CH.MSG_CHANNEL_FAILURE:
                raise CCSSHError("exec refused")
            continue  # WINDOW_ADJUST etc. before exec starts
        out_parts: list[bytes] = []
        err_parts: list[bytes] = []
        out_len = err_len = 0
        code = 0
        consumed = 0
        while True:
            p = self._rx(chan)
            m = p[0]
            rr = W.Reader(p)
            rr.byte()
            if m == CH.MSG_CHANNEL_DATA:
                if rr.u32() != chan:
                    continue
                chunk = rr.string()
                out_len += len(chunk)
                if out_len + err_len > max_bytes:
                    raise CCSSHError("exec output exceeds max_bytes")
                out_parts.append(chunk)
                consumed += len(chunk)
            elif m == CH.MSG_CHANNEL_EXTENDED_DATA:
                if rr.u32() != chan:
                    continue
                if rr.u32() != 1:  # RFC 4254: only type 1 (stderr) is defined
                    continue
                chunk = rr.string()
                err_len += len(chunk)
                if out_len + err_len > max_bytes:
                    raise CCSSHError("exec output exceeds max_bytes")
                err_parts.append(chunk)
                consumed += len(chunk)
            elif m == CH.MSG_WINDOW_ADJUST:
                continue  # our sends are small; the server window suffices
            elif m == CH.MSG_CHANNEL_REQUEST:
                if rr.u32() != chan:
                    continue
                if rr.string() == b"exit-status":
                    rr.bool()
                    code = rr.u32()
            elif m == 20:  # peer-initiated rekey needs idle channels
                raise CCSSHError("peer started rekey with an open channel: close channels and call rekey()")
            elif m == CH.MSG_CHANNEL_CLOSE:
                if rr.u32() != chan:
                    continue
                try:
                    t.send_packet(CH.enc_close(srv))
                except Exception:
                    pass
                break
            if consumed >= CH.WINDOW_THRESHOLD:
                try:
                    t.send_packet(CH.enc_window_adjust(srv, consumed))
                except Exception:
                    pass  # keep the credit; a later send retries it
                else:
                    consumed = 0
        out = b"".join(out_parts)
        err = b"".join(err_parts)
        self._log(2, f"exec: channel {chan}->{srv} done: stdout={len(out)}B stderr={len(err)}B exit={code}")
        return out, err, code

    def _alloc_chan(self) -> int:
        with self._chan_lock:
            if self._mux is not None:
                return self._mux.alloc_chan()
            n = self._chan_next
            self._chan_next = n + 1
            return n

    def _open_session(self) -> tuple:
        """
         Open a session channel. Returns (transport, client_chan, server_chan,
         server_window, server_maxpacket). Shared by exec/sftp/shell.
        """
        if not self._t:
            raise CCSSHError("call .connect() first")
        self._maybe_rekey()
        t = self._t
        chan = self._alloc_chan()
        self._reg(chan)
        try:
            t.send_packet(CH.enc_open_session(chan))
            while True:
                r = W.Reader(self._rx(chan))
                m0 = r.byte()
                if m0 == CH.MSG_CHANNEL_OPEN_CONFIRM:
                    break
                if m0 == CH.MSG_CHANNEL_OPEN_FAILURE:
                    raise CCSSHError("channel refused by server")
                continue  # WINDOW_ADJUST etc. before the channel exists
        except Exception:
            self._unreg(chan)
            raise
        r.u32()
        srv = r.u32()
        window = r.u32()
        maxpacket = r.u32()
        return t, chan, srv, window, maxpacket

    def _await_request(self, sess: "ShellSession | None", what: str) -> bool:
        """
         Wait for SUCCESS/FAILURE of a channel request. WINDOW_ADJUST packets
         credit the session flow; anything else is skipped. Returns True/False.
        """
        if self._t is None:
            raise CCSSHError("call .connect() first")
        if sess is None:
            raise CCSSHError("channel session is required")
        deadline = time.monotonic() + self.timeout
        while True:
            if time.monotonic() > deadline:
                raise CCSSHError(f"{what}: channel request timed out")
            pkt = self._rx(sess.chan) or b"\x00"
            m = pkt[0]
            if m == CH.MSG_CHANNEL_SUCCESS:
                return True
            if m == CH.MSG_CHANNEL_FAILURE:
                return False
            if m == CH.MSG_WINDOW_ADJUST:
                try:
                    rr = W.Reader(pkt)
                    rr.byte()
                    if rr.u32() != sess.chan:
                        continue
                    sess.credit(rr.u32())
                except ValueError as e:
                    raise CCSSHError(f"bad window adjust: {e}") from e
                except Exception:
                    pass
            elif m in (CH.MSG_CHANNEL_CLOSE, CH.MSG_CHANNEL_EOF):
                return False  # channel died instead of answering
            elif m == 20:  # peer-initiated rekey needs idle channels
                raise CCSSHError("peer started rekey with an open channel: close channels and call rekey()")
            continue

    def open_shell(self, *, term: str | None = None, cols: int = 80, rows: int = 24, pty: bool = True, command: str | None = None) -> "ShellSession":
        """
         Open a session channel with shell (RFC 4254 6.5), with pty
         (RFC 4254 6.2) unless pty=False (`ssh -T`).

         With command set, runs it on the pty channel instead of a shell
         (`ssh -t host command`). Returns a ShellSession for interactive
         use (see ccssh.shell). A refused pty is tolerated (shell continues
         without a terminal); a refused shell/exec raises CCSSHError.
         Like exec, no rekey is possible while the channel is open - call
         between sessions.
        """
        t, _chan, srv, window, maxpacket = self._open_session()
        sess = ShellSession(self, srv, window, maxpacket, chan=_chan)
        if pty:
            self._send_request(_chan, CH.enc_pty_req(srv, term or os.environ.get("TERM", "xterm"), cols, rows))
            if not self._await_request(sess, "pty-req"):
                sess.no_pty = True  # degraded but usable (no job control)
        else:
            sess.no_pty = True
        if command is not None:
            self._send_request(_chan, CH.enc_exec(srv, command))
            if not self._await_request(sess, "exec"):
                raise CCSSHError("exec refused by server")
        else:
            self._send_request(_chan, CH.enc_shell(srv))
            if not self._await_request(sess, "shell"):
                raise CCSSHError("shell refused by server")
        return sess

    def open_channel_socket(self, host: str, port: int, *, orig_host: str = "127.0.0.1", orig_port: int = 0) -> "_chansock_mod.ChannelSocket":
        """
         Open a direct-tcpip channel and wrap it as a socket (-J building
         block). On a mux-shared connection the tunnel rides the mux;
         otherwise it owns this connection's reads until closed: no
         exec/sftp/forward alongside on a mux-free jump connection.
        """
        if not self._t:
            raise CCSSHError("call .connect() first")
        self._maybe_rekey()
        t = self._t
        chan = self._alloc_chan()
        self._reg(chan)
        mux = self._mux
        try:
            t.send_packet(CH.enc_open_direct_tcpip(chan, host, port, orig_host, orig_port))
            while True:
                r = W.Reader(self._rx(chan))
                m0 = r.byte()
                if m0 == CH.MSG_CHANNEL_OPEN_CONFIRM:
                    break
                if m0 == CH.MSG_CHANNEL_OPEN_FAILURE:
                    raise CCSSHError("direct-tcpip refused by server")
                continue  # WINDOW_ADJUST etc. before the channel exists
        except Exception:
            self._unreg(chan)
            raise
        r.u32()
        srv = r.u32()
        window = r.u32()
        maxpacket = r.u32()
        return _chansock_mod.ChannelSocket(t, srv, window, maxpacket, timeout=self.timeout,
                                           mux=mux, chan=chan)

    def open_sftp(self):
        """Open SFTP over a subsystem channel. Returns an SFTPClient."""
        if not self._t:
            raise CCSSHError("call .connect() first")
        self._maybe_rekey()
        t = self._t
        chan = self._alloc_chan()
        self._reg(chan)
        try:
            t.send_packet(CH.enc_open_session(chan))
            while True:
                r = W.Reader(self._rx(chan))
                m0 = r.byte()
                if m0 == CH.MSG_CHANNEL_OPEN_CONFIRM:
                    break
                if m0 == CH.MSG_CHANNEL_OPEN_FAILURE:
                    raise CCSSHError("sftp: channel refused by server")
                continue
        except Exception:
            self._unreg(chan)
            raise
        if r.u32() != chan:
            self._unreg(chan)
            raise CCSSHError("sftp: confirm for foreign channel")
        srv = r.u32()
        srv_window = r.u32()
        srv_maxpacket = r.u32()
        flow = {"window": srv_window, "maxpacket": max(1024, min(srv_maxpacket, CH.MAXPKT))}
        cell: dict = {}
        self._send_request(chan, CH.enc_subsystem(srv))
        while True:
            pkt = self._rx(chan) or b"\x00"
            if pkt[0] == CH.MSG_CHANNEL_SUCCESS:
                break
            if pkt[0] == CH.MSG_CHANNEL_FAILURE:
                raise CCSSHError("sftp: subsystem refused")
            if pkt[0] == CH.MSG_WINDOW_ADJUST:
                try:
                    rr = W.Reader(pkt)
                    rr.byte()
                    rr.u32()
                    flow["window"] += rr.u32()
                except Exception:
                    pass
            continue

        def _top_up(need: int) -> None:
            """
             Top up the send window: consume packets, credit adjusts,
             stash SFTP data into the client buffer (never lose replies).
            """
            if self._t is None:
                raise CCSSHError("connection closed")
            deadline = time.monotonic() + self.timeout
            while flow["window"] < need:
                if time.monotonic() > deadline:
                    raise SFTP.SFTPError("sftp: send window exhausted, no adjust")
                p = self._rx(chan, timeout=max(0.01, deadline - time.monotonic()))
                m = p[0]
                rr = W.Reader(p)
                rr.byte()
                if m == CH.MSG_WINDOW_ADJUST:
                    if rr.u32() != chan:
                        continue
                    try:
                        flow["window"] = CH.check_window(flow["window"], rr.u32())
                    except ValueError as e:
                        raise SFTP.SFTPError(f"sftp: {e}") from e
                elif m == CH.MSG_CHANNEL_DATA:
                    if rr.u32() != chan:
                        continue
                    sc0 = cell.get("sc")
                    if sc0 is not None:
                        chunk = rr.string()
                        if len(sc0._buf) + len(chunk) > 2 * SFTP.SFTPClient.MAX_REPLY:
                            raise SFTP.SFTPError("sftp: reply too big")
                        sc0._buf += chunk
                elif m == CH.MSG_CHANNEL_CLOSE:
                    try:
                        if rr.u32() == chan:
                            raise SFTP.SFTPError("sftp: channel closed by server")
                    except SFTP.SFTPError:
                        raise
                    except Exception:
                        pass
                elif m == CH.MSG_CHANNEL_EOF:
                    # Sticky: after EOF no more DATA will come (anything still
                    # stashed is drained by _call); _recv turns it into a
                    # clean failure instead of hanging on the next read.
                    cell["eof"] = True
                    continue

        def _send(_srv: int, data: bytes) -> None:
            """
             One SFTP request per CHANNEL_DATA message (real servers reassemble
             the stream by the length prefix; splitting breaks framing).
             Our requests stay under ~33KB; server windows are megabytes.
            """
            if self._t is None:
                raise CCSSHError("connection closed")
            if flow["window"] < len(data):
                _top_up(len(data))
            self._t.send_packet(CH.enc_data(_srv, data))
            flow["window"] -= len(data)

        state = {"consumed": 0}

        def _recv() -> bytes:
            if self._t is None:
                raise CCSSHError("connection closed")
            while True:
                if cell.get("eof"):
                    raise SFTP.SFTPError("sftp: channel ended by server (EOF)")
                p = self._rx(chan)
                m = p[0]
                rr = W.Reader(p)
                rr.byte()
                if m == CH.MSG_CHANNEL_DATA:
                    if rr.u32() != chan:
                        continue
                    chunk = rr.string()
                    state["consumed"] += len(chunk)
                    if state["consumed"] >= CH.WINDOW_THRESHOLD:
                        if self._t is None:
                            raise CCSSHError("connection closed")
                        try:
                            self._t.send_packet(CH.enc_window_adjust(srv, state["consumed"]))
                        except Exception:
                            pass  # keep the credit AND the chunk; the next
                            # successful send retries a larger adjust
                        else:
                            state["consumed"] = 0
                    return chunk
                if m == CH.MSG_WINDOW_ADJUST:
                    if rr.u32() != chan:
                        continue
                    try:
                        flow["window"] = CH.check_window(flow["window"], rr.u32())
                    except ValueError as e:
                        raise SFTP.SFTPError(f"sftp: {e}") from e
                    continue
                if m == CH.MSG_CHANNEL_EOF:
                    if rr.u32() != chan:
                        continue
                    continue
                if m == CH.MSG_CHANNEL_CLOSE:
                    try:
                        if rr.u32() != chan:
                            continue
                    except Exception:
                        pass
                    raise SFTP.SFTPError("sftp: channel closed by server")
                if m == 20:
                    raise SFTP.SFTPError("peer started rekey during SFTP: close and rekey()")
                continue

        sc = SFTP.SFTPClient(_send, _recv, srv, maxpacket=srv_maxpacket)
        cell["sc"] = sc
        # INIT(3) -> VERSION (no request id on either side). The reply may
        # straddle CHANNEL_DATA messages, so accumulate like _call does.
        init = W.enc_u32(5) + bytes([SFTP.F_INIT]) + W.enc_u32(3)
        _send(srv, init)
        acc = b""
        deadline = time.monotonic() + self.timeout
        while True:
            if len(acc) >= 4:
                ln = int.from_bytes(acc[:4], "big")
                if ln > SFTP.SFTPClient.MAX_REPLY:
                    raise SFTP.SFTPError(f"sftp: reply too big ({ln} bytes)")
                if len(acc) >= 4 + ln:
                    break
            if len(acc) > SFTP.SFTPClient.MAX_REPLY + 4:
                raise SFTP.SFTPError("sftp: reply too big")
            if time.monotonic() > deadline:
                raise CCSSHError("sftp: version handshake timeout")
            acc += _recv()
        br = W.Reader(acc[4:4 + ln])
        if br.byte() != SFTP.F_VERSION or br.u32() > 3:
            raise CCSSHError("sftp: server did not offer version 3")
        sc._on_close = _make_closer(self, srv, chan)
        return sc

    def negotiated(self) -> dict[str, str]:
        return {"kex": self._kex, "cipher": self._cipher, "mac": self._mac, "strict": str(self._strict), "hostkey": getattr(self, "_host_alg", "unknown")}

    def _claim_forwarder(self, fwd):
        """
         Only one active forwarder per connection (kept as a deliberate
         v1 limit even though the mux could share more: two pumps would
         still split server-initiated opens ambiguously).
        """
        self._fwds = [f for f in self._fwds if not f.closed]
        if self._fwds:
            raise CCSSHError("only one active forwarder per connection")
        self._fwds.append(fwd)
        return fwd

    def forward_local(self, lport: int, rhost: str, rport: int, bind: str = "127.0.0.1"):
        """
         Local forwarding (-L) in a background daemon thread.

         Shares the connection with exec/sftp/shell through the channel
         multiplexer (ssh-like: no -N needed, though -N still works).
         Returns the LocalForwarder (.port, .close()).
        """
        if not self._t:
            raise CCSSHError("call .connect() first")
        mux = self._ensure_mux()
        self._log(1, f"forward: -L {bind}:{lport} -> {rhost}:{rport} (mux shared)")
        return self._claim_forwarder(
            _forward_mod.LocalForwarder(mux, lport, rhost, rport, bind=bind).start())

    def forward_remote(self, sport: int, rhost: str, rport: int, bind: str = "localhost"):
        """
         Remote forwarding (-R) in a background daemon thread: the server
         listens on (bind, sport) - sport 0 means auto-assign, the real
         port lands in .port - and each inbound connection is relayed to
         (rhost, rport) on our side. The default bind is "localhost" like
         OpenSSH (some servers match it literally). Shares the connection
         through the channel multiplexer (ssh-like). Returns RemoteForwarder
         (.port, .close()).
        """
        if not self._t:
            raise CCSSHError("call .connect() first")
        mux = self._ensure_mux()
        self._log(1, f"forward: -R {bind}:{sport} -> {rhost}:{rport} (mux shared)")
        return self._claim_forwarder(
            _forward_mod.RemoteForwarder(mux, sport, rhost, rport, bind=bind).start())

    def rekey(self) -> None:
        """
         Re-run KEX over the connection. session_id is kept, seq reset.

         Call only with no open channels (between exec calls, forwarders
         closed). Strict-kex and ext-info markers are NOT repeated
         (Terrapin rule); no EXT_INFO wait.
        """
        if not self._t or not self._sid:
            raise CCSSHError("call .connect() first")
        if self._mux is not None and self._mux.busy():
            raise CCSSHError("rekey with open channels/forwards is unsupported: "
                             "close channels and forwarders first")
        self._log(1, "rekey: starting ...")
        t = self._t
        mux = self._mux
        if mux is not None:
            # Park the mux reader: it must not be mid-read when the crypto
            # state below is swapped (old keys decrypt half a packet, new
            # keys the other half). No channels are open, so nothing else
            # reads or sends meanwhile.
            mux.pause()
        try:
            our = K0.enc_kexinit(os.urandom(16), self.kex_list, self.hostkey_list, self.cipher_list, self.cipher_list, self.mac_list, self.mac_list, ["none"], ["none"])
            t.send_packet(our)
            peer = K0.dec_kexinit(t.recv_packet())
            kex_name = K0.negotiate(self.kex_list, peer["kex"])
            cipher = K0.negotiate_symmetric(self.cipher_list, peer["enc_c2s"], peer["enc_s2c"], "cipher")
            mac = K0.negotiate_symmetric(self.mac_list, peer["mac_c2s"], peer["mac_s2c"], "mac")
            host_alg = K0.negotiate(self.hostkey_list, peer["hostkey"])
            Ic, Is = K0.I_FOR_H(our), K0.I_FOR_H(peer["payload_full"])
            self._skip_unmatched_guess(t, peer, self.kex_list, kex_name)
            K_enc, Hh2, Ks2, hashfn = self._run_kex(t, kex_name, VERSION, t.peer_version or VERSION, Ic, Is, host_alg)
            # The host key must not change across rekey (MITM during rekey).
            if self._host_Ks is not None and Ks2 != self._host_Ks:
                raise HostKeyError("host key changed during rekey (possible MitM!)")
            keys = self._derive(cipher, mac, K_enc, Hh2, hashfn, self._sid)
            from ccssh.transport import _encode_kind
            if _encode_kind(cipher) != _encode_kind(self._cipher) and self._cipher != "none":
                raise CCSSHError("rekey must not change the cipher kind "
                                 f"({self._cipher} -> {cipher})")
            t.stage_rekey(keys, cipher, mac, is_client=True)
            t.send_packet(bytes([K0.MSG_NEWKEYS]))  # old keys
            t.commit_rekey_send(reset_seq=self._strict)
            t._enc_on_send = True
            if (t.recv_packet() or b"\x00")[0] != K0.MSG_NEWKEYS:  # old keys
                raise CCSSHError("rekey: expected NEWKEYS")
            t.commit_rekey_recv(reset_seq=self._strict)
            t._enc_on_recv = True
            self._cipher, self._mac = cipher, mac
            self._kex = kex_name
            self._log(1, f"rekey: done kex={kex_name} cipher={cipher} mac={mac}")
        finally:
            if mux is not None:
                try:
                    mux.resume()
                except Exception:
                    pass

    def close(self) -> None:
        for f in list(self._fwds):
            try:
                f.close()
            except Exception:
                pass
            try:
                th = getattr(f, "_th", None)
                if th is not None:
                    th.join(timeout=2.0)
            except Exception:
                pass
        self._fwds = []
        try:
            if self._t:
                try:
                    self._t.send_packet(bytes([1]) + W.enc_u32(11) + W.enc_string(b"bye") + W.enc_string(b""))
                except Exception:
                    pass
                self._t.sock.close()
        except Exception:
            pass
        mux, self._mux = self._mux, None
        if mux is not None:
            try:
                mux.stop()
            except Exception:
                pass
        self._t = None

    def __enter__(self) -> "CCSSHClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()


def _make_closer(client: CCSSHClient, srv: int, chan: int):
    def _closer() -> None:
        try:
            if client._t is None:
                return
            try:
                client._t.send_packet(CH.enc_close(srv))
            except Exception:
                return
            deadline = time.monotonic() + client.timeout
            while True:
                if time.monotonic() > deadline:
                    break
                try:
                    if client._mux is not None:
                        p = client._rx(chan, timeout=max(0.01, deadline - time.monotonic()))
                    else:
                        p = client._t.recv_packet(keepalive=False)
                except Exception:
                    break
                if p and p[0] == CH.MSG_CHANNEL_CLOSE:
                    try:
                        rr = W.Reader(p)
                        rr.byte()
                        if rr.u32() != chan:
                            continue
                    except Exception:
                        pass
                    break
        finally:
            try:
                client._unreg(chan)
            except Exception:
                pass
    return _closer
