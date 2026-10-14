"""Async SSH client over asyncio. Same protocol core as the sync client."""
from __future__ import annotations
import asyncio
import hashlib
import os
import socket
import time

from ccssh import auth as A
from ccssh import algs
from ccssh import channel as CH
from ccssh import hostkeys as HK
from ccssh import kex as K0
from ccssh import kex_ext as KX
from ccssh.client import (
    VERSION,
    AuthError,
    HostKeyError,
    CIPHER_DEFAULT,
    MAC_DEFAULT,
    HOSTKEY_DEFAULT,
    _load_user_priv,
    _user_blob,
)
from ccssh.hostcheck import check_hostkey, HostKeyError as _HostCheckError
from ccssh.transport import AsyncTransport, CCSSHError
from ccssh import wire as W
from ccssh.client import CCSSHClient as _SyncClient


class AsyncCCSSHClient:
    """Async SSH client (no port/X11/agent forwarding; sync has the mux)."""

    def __init__(self, *, timeout: float = 10.0, host_policy: str = "strict", known_hosts: str | None = None, kex: list[str] | None = None, ciphers: list[str] | None = None, macs: list[str] | None = None, hostkeys: list[str] | None = None, rekey_bytes: int = 4 * 1024**3, rekey_interval: float = 3600.0, compression: bool | str | list[str] = False, compression_level: int = 6, use_agent: bool = True, agent_path: str | None = None):
        from ccssh import compress as _comp_mod
        _comp_mod.check_level(compression_level)
        self.timeout = timeout
        self.host_policy = host_policy
        self.known_hosts = os.path.expanduser(known_hosts) if known_hosts else None
        self.kex_list = algs.normalize_list(algs.SUPPORTED_KEX, kex) or algs.default_kex()
        self.cipher_list = algs.normalize_list(algs.SUPPORTED_CIPHERS, ciphers) or CIPHER_DEFAULT
        self.mac_list = algs.normalize_list(algs.SUPPORTED_MACS, macs) or MAC_DEFAULT
        self.hostkey_list = algs.normalize_list(algs.SUPPORTED_HOSTKEYS, hostkeys) or HOSTKEY_DEFAULT
        comp = algs.normalize_compression(compression)
        self.comp_list = comp if comp is not None else algs.default_compression(False)
        for _c in self.comp_list:
            _comp_mod.check_name(_c)
        if not self.comp_list:
            raise ValueError("compression list is empty")
        self.compression_level = compression_level
        self.use_agent = use_agent
        self.agent_path = os.path.expanduser(agent_path) if agent_path else None
        self.rekey_bytes = rekey_bytes
        self.rekey_interval = rekey_interval
        self._t: AsyncTransport | None = None
        self._sid: bytes | None = None
        self._cipher = "none"
        self._kex_name = "none"
        self._mac = "none"
        self._comp_c2s = "none"
        self._comp_s2c = "none"
        self._chan_next = 1
        self._strict = False
        self._host_Ks: bytes | None = None
        self._open_channels = 0
        # One channel operation at a time: concurrent readers would steal
        # each other's packets (same single-reader rule as the sync side
        # without a mux). Rekey takes the same lock.
        self._op_lock = asyncio.Lock()

    def negotiated(self) -> dict[str, str]:
        comp = self._comp_c2s if self._comp_c2s == self._comp_s2c else f"{self._comp_c2s}/{self._comp_s2c}"
        return {"kex": self._kex_name, "cipher": self._cipher, "mac": self._mac, "compression": comp, "strict": str(self._strict)}

    async def _maybe_rekey(self) -> None:
        t = self._t
        if t is None or self._sid is None:
            return
        if (time.monotonic() - t.kex_at > self.rekey_interval
                or t.bytes_out + t.bytes_in > self.rekey_bytes):
            await self.rekey()

    @staticmethod
    async def _skip_unmatched_guess(t, peer: dict, our_kex: list[str], kex_name: str) -> None:
        """RFC 4253 section 7.1 decoy discard (async twin of the sync guard)."""
        if not peer.get("first_follows"):
            return
        flags = {K0.KEX_STRICT_C, K0.KEX_STRICT_S, K0.EXT_INFO_C}
        guess = next((k for k in peer["kex"] if k in our_kex and k not in flags), None)
        if guess != kex_name:
            await t.recv_packet() # discard the decoy

    async def rekey(self) -> None:
        """Re-run KEX (sync semantics). Only with no open channels."""
        if self._t is None or self._sid is None:
            raise CCSSHError("call .connect() first")
        if self._open_channels:
            raise CCSSHError("rekey with open channels is unsupported: close channels first")
        async with self._op_lock:
            await self._rekey_inner()

    async def _rekey_inner(self) -> None:
        t = self._t
        assert t is not None
        our = K0.enc_kexinit(os.urandom(16), self.kex_list, self.hostkey_list, self.cipher_list, self.cipher_list, self.mac_list, self.mac_list, self.comp_list, self.comp_list)
        await t.send_packet(our)
        peer = K0.dec_kexinit(await t.recv_packet())
        kex_name = K0.negotiate(self.kex_list, peer["kex"])
        cipher = K0.negotiate_symmetric(self.cipher_list, peer["enc_c2s"], peer["enc_s2c"], "cipher")
        mac = K0.negotiate_symmetric(self.mac_list, peer["mac_c2s"], peer["mac_s2c"], "mac")
        comp_c2s = K0.negotiate(self.comp_list, peer["comp_c2s"])
        comp_s2c = K0.negotiate(self.comp_list, peer["comp_s2c"])
        if (comp_c2s, comp_s2c) != (self._comp_c2s, self._comp_s2c):
            raise CCSSHError(f"rekey must not change compression ({self._comp_c2s}/{self._comp_s2c} -> {comp_c2s}/{comp_s2c})")
        host_alg = K0.negotiate(self.hostkey_list, peer["hostkey"])
        Ic, Is = K0.I_FOR_H(our), K0.I_FOR_H(peer["payload_full"])
        await self._skip_unmatched_guess(t, peer, self.kex_list, kex_name)
        K_enc, Hh2, Ks2, hashfn = await self._kex(t, kex_name, VERSION, t.peer_version or VERSION, Ic, Is, host_alg)
        if self._host_Ks is not None and Ks2 != self._host_Ks:
            from ccssh.client import HostKeyError as _HKE2
            raise _HKE2("host key changed during rekey (possible MitM!)")
        keys = _SyncClient._derive(cipher, mac, K_enc, Hh2, hashfn, self._sid)
        from ccssh.transport import _encode_kind
        if _encode_kind(cipher) != _encode_kind(self._cipher) and self._cipher != "none":
            raise CCSSHError(f"rekey must not change the cipher kind ({self._cipher} -> {cipher})")
        t.stage_rekey(keys, cipher, mac, is_client=True)
        await t.send_packet(bytes([K0.MSG_NEWKEYS]))
        t.commit_rekey_send(reset_seq=self._strict)
        t._enc_on_send = True
        if (await t.recv_packet() or b"\x00")[0] != K0.MSG_NEWKEYS:
            raise CCSSHError("rekey: expected NEWKEYS")
        t.commit_rekey_recv(reset_seq=self._strict)
        t._enc_on_recv = True
        self._cipher, self._mac = cipher, mac
        self._kex_name = kex_name

    async def connect(self, hostname: str, *, port: int = 22, username: str, password: str | None = None, key_filename: str | None = None, cert_filename: str | None = None, passphrase: str | None = None, family: int = 0, kbdint_responder: A.KbdintResponder | None = None, use_agent: bool | None = None, agent_path: str | None = None) -> "AsyncCCSSHClient":
        reader, writer = await self._open(hostname, port, family)
        t = AsyncTransport(reader, writer, VERSION, timeout=self.timeout)
        Vs = await t.do_version()
        Vc = VERSION
        our = K0.enc_kexinit(os.urandom(16), self.kex_list + [K0.KEX_STRICT_C, K0.EXT_INFO_C], self.hostkey_list, self.cipher_list, self.cipher_list, self.mac_list, self.mac_list, self.comp_list, self.comp_list)
        await t.send_packet(our)
        peer = K0.dec_kexinit(await t.recv_packet())
        kex_name = K0.negotiate(self.kex_list, peer["kex"])
        host_alg = K0.negotiate(self.hostkey_list, peer["hostkey"])
        cipher = K0.negotiate_symmetric(self.cipher_list, peer["enc_c2s"], peer["enc_s2c"], "cipher")
        mac = K0.negotiate_symmetric(self.mac_list, peer["mac_c2s"], peer["mac_s2c"], "mac")
        comp_c2s = K0.negotiate(self.comp_list, peer["comp_c2s"])
        comp_s2c = K0.negotiate(self.comp_list, peer["comp_s2c"])
        Ic, Is = K0.I_FOR_H(our), K0.I_FOR_H(peer["payload_full"])
        await self._skip_unmatched_guess(t, peer, self.kex_list, kex_name)
        K_enc, Hh, Ks, hashfn = await self._kex(t, kex_name, Vc, Vs, Ic, Is, host_alg)
        try:
            check_hostkey(hostname, port, Ks, host_alg, policy=self.host_policy, known_hosts=self.known_hosts)
        except _HostCheckError as e:
            raise HostKeyError(str(e)) from e
        keys = _SyncClient._derive(cipher, mac, K_enc, Hh, hashfn)
        t.activate(keys, cipher, mac, is_client=True)
        t.set_compression(comp_c2s, comp_s2c, self.compression_level)
        await t.send_packet(bytes([K0.MSG_NEWKEYS]))
        t._enc_on_send = True
        if (await t.recv_packet() or b"\x00")[0] != K0.MSG_NEWKEYS:
            raise CCSSHError("expected NEWKEYS")
        t._enc_on_recv = True
        self._strict = K0.peer_wants_strict(peer["kex"], is_client=True)
        if self._strict:
            t.send_seq = 0
            t.recv_seq = 0
        self._t, self._sid = t, Hh
        self._cipher, self._mac = cipher, mac
        self._kex_name = kex_name
        self._comp_c2s, self._comp_s2c = comp_c2s, comp_s2c
        self._host_Ks = Ks
        await t.send_packet(A.enc_service_request())
        for _ in range(16): # EXT_INFO repeats are skipped, not fatal
            pkt = await t.recv_packet()
            if pkt and pkt[0] == K0.MSG_EXT_INFO:
                continue
            break
        if not pkt or pkt[0] != A.MSG_SERVICE_ACCEPT:
            raise CCSSHError("no ssh-userauth service")
        if key_filename or cert_filename:
            await self._auth_pubkey(username, key_filename, cert_filename, passphrase)
        else:
            _agent_ok = False
            _agent_err: Exception | None = None
            _want_agent = self.use_agent if use_agent is None else use_agent
            _agent_sock = agent_path if agent_path is not None else self.agent_path
            if _want_agent:
                try:
                    await self._auth_agent(username, _agent_sock)
                    _agent_ok = True
                except AuthError as e:
                    _agent_err = e
            if not _agent_ok:
                if password is not None:
                    await t.send_packet(A.enc_password_request(username, password))
                    if (await t.recv_packet() or b"\x00")[0] != A.MSG_USERAUTH_SUCCESS:
                        try:
                            await self._auth_kbdint(username, lambda prompts: [password] * len(prompts))
                        except AuthError:
                            raise AuthError("password rejected") from None
                elif kbdint_responder is not None:
                    await self._auth_kbdint(username, kbdint_responder)
                elif _agent_err is not None:
                    raise _agent_err
                else:
                    raise AuthError("provide password, key_filename or an agent key")
        t.enable_delayed_compression()
        return self

    async def _auth_agent(self, username: str, agent_path: str | None = None) -> None:
        """Agent publickey auth (sync twin; local socket is fast)."""
        from ccssh import agent as _AG
        from ccssh import hostkeys as _HK
        t = self._t
        if t is None or self._sid is None:
            raise CCSSHError("call .connect() first")
        try:
            ac = _AG.AgentClient(agent_path, timeout=self.timeout)
        except _AG.AgentError as e:
            raise AuthError(f"agent unavailable: {e}") from e
        try:
            identities = ac.list_identities()
        except _AG.AgentError as e:
            raise AuthError(f"agent failed: {e}") from e
        if not identities:
            raise AuthError("agent has no identities")
        last: Exception | None = None
        for blob, comment in identities:
            try:
                inner_alg, _ = _HK.parse_host_blob(blob)
            except Exception as e:
                last = e
                continue
            alg = b"rsa-sha2-256" if inner_alg == "ssh-rsa" else inner_alg.encode()
            await t.send_packet(A.enc_pubkey_probe(username, alg, blob))
            r = await t.recv_packet()
            if r and r[0] == A.MSG_USERAUTH_SUCCESS:
                return
            if r and r[0] != A.MSG_USERAUTH_PK_OK:
                pass  # try signed anyway (same rule as sync)
            assert self._sid is not None
            data = A.auth_sign_blob(self._sid, username, alg, blob)
            try:
                outer = ac.sign(blob, data, _AG.sign_flags_for_alg(alg.decode()))
            except _AG.AgentError as e:
                last = e
                continue
            await t.send_packet(A.enc_pubkey_signed(username, alg, blob, outer))
            if (await t.recv_packet() or b"\x00")[0] == A.MSG_USERAUTH_SUCCESS:
                return
            last = AuthError(f"agent key {comment or inner_alg} rejected")
        raise AuthError(f"agent keys rejected ({last})" if last else "agent keys rejected")

    async def _open(self, hostname: str, port: int, family: int):
        """
         Connect honoring the address family (asyncio.open_connection has
         no family knob, so dial manually and wrap the socket). DNS via
         the loop (never blocks it).
        """
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(hostname, port, family=family or 0, type=socket.SOCK_STREAM)
        except OSError as e:
            raise CCSSHError(f"resolve {hostname}: {e}") from e
        if not infos:
            raise CCSSHError(f"no addresses for {hostname}")
        last_err: OSError | None = None
        s: socket.socket | None = None
        for af, st, proto, _canon, sa in infos:
            s = None
            try:
                s = socket.socket(af, st, proto)
                s.setblocking(False)
                await asyncio.wait_for(loop.sock_connect(s, sa), self.timeout)
            except OSError as e:
                last_err = e
                if s is not None:
                    s.close()
                s = None
                continue
            break
        if s is None:
            raise CCSSHError(f"connect {hostname}:{port}: {last_err}")
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        return await asyncio.open_connection(sock=s)

    async def _kex(self, t: AsyncTransport, name: str, Vc: bytes, Vs: bytes, Ic: bytes, Is: bytes, host_alg: str = "ssh-ed25519"):
        name = KX.KEX_ALIASES.get(name, name)
        hashfn = KX.kdf_hashfn(name)
        if name == "curve25519-sha256":
            c = K0.Curve25519Client()
            await t.send_packet(c.init_msg())
            Ke, Hh, Ks = c.finish(await t.recv_packet(), Vc, Vs, Ic, Is, host_alg)
            return W.mpint_from_bytes(Ke), Hh, Ks, hashfn
        if name == "mlkem768x25519-sha256":
            c = K0.MlkemHybridClient(Vc, Ic)
            await t.send_packet(c.init_msg())
            Kr, Hh, Ks, _, _ = c.finish(await t.recv_packet(), Vs, Is, host_alg)
            return W.enc_string(Kr), Hh, Ks, hashfn
        if name.startswith("ecdh-sha2-nistp"):
            c = KX.EcdhClient(name)
            await t.send_packet(c.init_msg())
            Ke, Hh, Ks = c.finish(await t.recv_packet(), Vc, Vs, Ic, Is, host_alg)
            return W.mpint_from_bytes(Ke), Hh, Ks, hashfn
        if name in KX.DH_GROUPS:
            c = KX.DhClient(name)
            await t.send_packet(c.init_msg())
            Kr, Hh, Ks = c.finish(await t.recv_packet(), Vc, Vs, Ic, Is, host_alg)
            return W.mpint_from_bytes(Kr), Hh, Ks, hashfn
        if name == "mlkem768nistp256-sha256":
            c = KX.MlkemP256Client(Vc, Ic)
            await t.send_packet(c.init_msg())
            Kr, Hh, Ks = c.finish(await t.recv_packet(), Vs, Is, host_alg)
            return W.enc_string(Kr), Hh, Ks, hashfn
        if name in ("diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1"):
            c = KX.GexClient(hashfn=hashlib.sha256 if name.endswith("sha256") else hashlib.sha1)
            await t.send_packet(c.request_msg())
            await t.send_packet(c.init_msg(await t.recv_packet()))
            Kr, Hh, Ks = c.finish(await t.recv_packet(), Vc, Vs, Ic, Is, host_alg)
            return W.mpint_from_bytes(Kr), Hh, Ks, hashfn
        if name == "sntrup761x25519-sha512":
            c = KX.SntrupClient(Vc, Ic)
            await t.send_packet(c.init_msg())
            Kr, Hh, Ks, _, _ = c.finish(await t.recv_packet(), Vs, Is, host_alg)
            return W.enc_string(Kr), Hh, Ks, hashfn
        raise CCSSHError(name)

    async def _auth_pubkey(self, username: str, key_path: str | None, cert_path: str | None, passphrase: str | None) -> None:
        if not self._t or self._sid is None:
            raise CCSSHError("call .connect() first")
        if not key_path:
            raise AuthError("cert without key_filename is unsupported")
        priv = _load_user_priv(key_path, passphrase)
        alg, blob = _user_blob(priv, cert_path)
        if blob is None:
            nums = priv.public_key().public_numbers()
            blob = W.enc_string(b"ssh-rsa") + W.enc_mpint(nums.e) + W.enc_mpint(nums.n)
            alg = b"rsa-sha2-256"
        await self._t.send_packet(A.enc_pubkey_probe(username, alg, blob))
        if (await self._t.recv_packet() or b"\x00")[0] == A.MSG_USERAUTH_SUCCESS:
            return
        outer = HK.sign_userauth(priv, alg.decode(), A.auth_sign_blob(self._sid, username, alg, blob))
        await self._t.send_packet(A.enc_pubkey_signed(username, alg, blob, outer))
        if (await self._t.recv_packet() or b"\x00")[0] != A.MSG_USERAUTH_SUCCESS:
            raise AuthError("publickey rejected")

    async def _auth_kbdint(self, username: str, responder: A.KbdintResponder) -> None:
        """Keyboard-interactive auth (RFC 4256), async twin of the sync one."""
        t = self._t
        if t is None:
            raise CCSSHError("call .connect() first")
        await t.send_packet(A.enc_kbdint_probe(username))
        for _ in range(A.MAX_KBDINT_ROUNDS):
            p = await t.recv_packet() or b"\x00"
            m = p[0]
            if m == A.MSG_USERAUTH_SUCCESS:
                return
            if m == A.MSG_USERAUTH_FAILURE:
                raise AuthError("keyboard-interactive rejected")
            if m != A.MSG_USERAUTH_INFO_REQUEST:
                raise AuthError(f"keyboard-interactive: unexpected reply {m}")
            try:
                info = A.dec_info_request(p)
            except W.WireError as e:
                raise AuthError(f"keyboard-interactive: bad prompt: {e}") from e
            try:
                answers = responder(info["prompts"])
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                raise AuthError(f"keyboard-interactive responder failed: {e}") from e
            if len(answers) != len(info["prompts"]):
                raise AuthError("keyboard-interactive responder gave wrong answer count")
            await t.send_packet(A.enc_info_response([a.encode() for a in answers]))
        raise AuthError("keyboard-interactive rejected (too many rounds)")

    async def exec_command(self, command: str, *, timeout: float | None = None, max_bytes: int = 16 * 1024 * 1024, raw_bytes: bool = False):
        """One exec channel at a time (see _op_lock): concurrent readers
        would steal each other's packets on the shared transport."""
        if self._t is None:
            raise CCSSHError("call .connect() first")
        async with self._op_lock:
            out_b, err_b, code = await self._exec_inner(command, timeout=timeout, max_bytes=max_bytes)
        if raw_bytes:
            return out_b, err_b, code
        return out_b.decode(errors="replace"), err_b.decode(errors="replace"), code

    async def _exec_inner(self, command: str, *, timeout: float | None, max_bytes: int) -> tuple[str, str, int]:
        _ = timeout # accepted for sync parity; the transport timeout applies
        await self._maybe_rekey()
        t = self._t
        assert t is not None
        chan = self._chan_next
        self._chan_next += 1
        self._open_channels += 1
        try:
            await t.send_packet(CH.enc_open_session(chan))
            while True:
                r = W.Reader(await t.recv_packet())
                m0 = r.byte()
                if m0 == CH.MSG_CHANNEL_OPEN_CONFIRM:
                    break
                if m0 == CH.MSG_CHANNEL_OPEN_FAILURE:
                    raise CCSSHError("channel refused")
                continue
            if r.u32() != chan:
                raise CCSSHError("channel confirm for foreign channel")
            srv = r.u32()
            await t.send_packet(CH.enc_exec(srv, command))
            while True:
                pkt = await t.recv_packet() or b"\x00"
                if pkt[0] == CH.MSG_CHANNEL_SUCCESS:
                    break
                if pkt[0] == CH.MSG_CHANNEL_FAILURE:
                    raise CCSSHError("exec refused")
                continue
            out_parts: list[bytes] = []
            err_parts: list[bytes] = []
            out_len = err_len = 0
            code = 0
            consumed = 0
            while True:
                p = await t.recv_packet() or b"\x00"
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
                    if rr.u32() != 1:
                        continue
                    chunk = rr.string()
                    err_len += len(chunk)
                    if out_len + err_len > max_bytes:
                        raise CCSSHError("exec output exceeds max_bytes")
                    err_parts.append(chunk)
                    consumed += len(chunk)
                elif m == CH.MSG_CHANNEL_REQUEST:
                    if rr.u32() != chan:
                        continue
                    if rr.string() == b"exit-status":
                        rr.bool()
                        code = rr.u32()
                elif m == 20: # peer-initiated rekey needs idle channels
                    raise CCSSHError("peer started rekey with an open channel: close channels and call rekey()")
                elif m == CH.MSG_CHANNEL_CLOSE:
                    try:
                        rr2 = W.Reader(p)
                        rr2.byte()
                        if rr2.u32() != chan:
                            continue
                    except Exception:
                        pass
                    try:
                        await t.send_packet(CH.enc_close(srv))
                    except Exception:
                        pass
                    break
                if consumed >= CH.WINDOW_THRESHOLD:
                    try:
                        await t.send_packet(CH.enc_window_adjust(srv, consumed))
                    except Exception:
                        pass
                    else:
                        consumed = 0
            out = b"".join(out_parts)
            err = b"".join(err_parts)
            return out, err, code
        finally:
            self._open_channels -= 1

    async def close(self) -> None:
        try:
            if self._t:
                try:
                    await self._t.send_packet(bytes([1]) + W.enc_u32(11) + W.enc_string(b"bye") + W.enc_string(b""))
                except Exception:
                    pass
                try:
                    self._t.writer.close()
                    await asyncio.wait_for(self._t.writer.wait_closed(), 2.0)
                except Exception:
                    pass
        except Exception:
            pass
        self._t = None

    async def __aenter__(self) -> "AsyncCCSSHClient":
        return self

    async def __aexit__(self, *_) -> None:
        await self.close()
