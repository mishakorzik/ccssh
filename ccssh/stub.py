"""
 In-process SSH server stub for loopback tests. NOT production code.

 Speaks just enough of the protocol to exercise a real client over TCP:
 version exchange, KEXINIT (curve25519-sha256 / mlkem768x25519-sha256),
 NEWKEYS with aes128-ctr + hmac-sha2-256, strict-kex/ext-info, password and
 publickey auth (with strict signature checks, like a real sshd), session
 exec (canned replies), SFTP subsystem (confined temp dir), direct-tcpip
 forwarding relay, and rekey between operations. Never executes commands.
"""
from __future__ import annotations
import os
import socket
import stat as statmod
import tempfile
import threading

from ccssh import auth as A
from ccssh import channel as CH
from ccssh import crypto
from ccssh import kex as K
from ccssh import wire as W
from ccssh.transport import SyncTransport

try:
    from ccssh import __version__ as _VERSION
except Exception:
    _VERSION = "1.0.0"
SERVER_VERSION = ("SSH-2.0-CC_" + _VERSION).encode()
CIPHER = "aes128-ctr"
MAC = "hmac-sha2-256"


def _is_composite_host(host_priv) -> bool:
    return type(host_priv).__name__ == "KeyPair"


def _verify_user_sig(alg: bytes, blob: bytes, packet: bytes, to_verify: bytes) -> bool:
    """Strict userauth signature check, mirroring a real sshd."""
    from cryptography.exceptions import InvalidSignature
    r = W.Reader(packet)
    r.byte()
    r.string()
    r.string()
    r.string()
    r.bool()
    r.string()
    r.string()
    try:
        sig_field = r.string()
    except Exception:
        return False
    try:
        from ccssh import hostkeys as _HK
        return _HK.verify_host_signature(blob, alg.decode(), to_verify, sig_field)
    except (InvalidSignature, ValueError):
        return False


def _send_kexinit(t: SyncTransport, *, hostkeys: list[str] | None = None, initial: bool = True) -> bytes:
    kex = list(K.KEX_OFFER)
    if initial:
        kex += [K.KEX_STRICT_S]
    pkt = K.enc_kexinit(os.urandom(16), kex, hostkeys or K.HOSTKEY_OFFER, K.CIPHER_OFFER, K.CIPHER_OFFER, K.MAC_OFFER, K.MAC_OFFER, K.COMP_OFFER, K.COMP_OFFER)
    t.send_packet(pkt)
    return pkt


def _recv_kexinit(t: SyncTransport) -> dict:
    pkt = t.recv_packet()
    if not pkt or pkt[0] != K.MSG_KEXINIT:
        raise ValueError(f"expected KEXINIT, got msg={pkt[0] if pkt else None}")
    return K.dec_kexinit(pkt)


def _send_newkeys(t: SyncTransport) -> None:
    t.send_packet(bytes([K.MSG_NEWKEYS]))
    t._enc_on_send = True


def _recv_newkeys(t: SyncTransport) -> None:
    pkt = t.recv_packet()
    if not pkt or pkt[0] != K.MSG_NEWKEYS:
        raise ValueError("expected NEWKEYS")
    t._enc_on_recv = True


def _do_kex(t: SyncTransport, host_priv, Vc: bytes, Vs: bytes, peer_kex: dict, our_kex: bytes) -> tuple[bytes, bytes]:
    """Run one key exchange; returns (K_encoded, H). No key activation."""
    kex_name = K.negotiate(K.KEX_OFFER, peer_kex["kex"])
    Ic_H, Is_H = K.I_FOR_H(peer_kex["payload_full"]), K.I_FOR_H(our_kex)
    init_msg = t.recv_packet()
    if kex_name == "curve25519-sha256":
        srv = K.Curve25519ServerStub(host_priv)
        reply, K_ecdh, Hh = srv.reply(init_msg, Vc, Vs, Ic_H, Is_H)
        K_encoded = W.mpint_from_bytes(K_ecdh)
    else:
        srv = K.MlkemHybridServerStub(host_priv, Vs, Is_H)
        reply, K_raw, Hh = srv.reply(init_msg, Vc, Ic_H)
        K_encoded = W.enc_string(K_raw)
    t.send_packet(reply)
    return K_encoded, Hh


def run_once(sock: socket.socket, host_priv, *, password: str = "pw", timeout: float = 10.0, sftp_root: str | None = None, kbdint_password: str | None = None) -> None:
    t = SyncTransport(sock, SERVER_VERSION, timeout=timeout)
    Vs = SERVER_VERSION
    Vc = t.do_version()
    peer_kex = _recv_kexinit(t)
    hk_offer = (["ssh-mldsa44-ed25519"] if _is_composite_host(host_priv) else None)
    our_kex = _send_kexinit(t, hostkeys=hk_offer)
    K_encoded, Hh = _do_kex(t, host_priv, Vc, Vs, peer_kex, our_kex)
    session_id = Hh
    keys = crypto.derive_keys(K_encoded, Hh, session_id, CIPHER, MAC)
    t.activate(keys, CIPHER, MAC, is_client=False)
    strict = K.peer_wants_strict(peer_kex["kex"], is_client=False)
    _send_newkeys(t)
    _recv_newkeys(t)
    if strict:
        t.send_seq = 0
        t.recv_seq = 0
    if K.peer_wants_ext_info(peer_kex["kex"]):
        t.send_packet(K.enc_ext_info([(b"server-sig-algs", b"ssh-ed25519,ssh-mldsa44-ed25519,rsa-sha2-256,rsa-sha2-512," b"ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521")]))
    pkt = t.recv_packet()
    assert pkt[0] == A.MSG_SERVICE_REQUEST
    t.send_packet(bytes([A.MSG_SERVICE_ACCEPT]) + W.enc_string(b"ssh-userauth"))
    _auth_loop(t, Hh, password, kbdint_password if kbdint_password is not None else password)
    _connection_loop(t, Vc, Vs, host_priv, session_id, timeout, sftp_root)


def _auth_loop(t: SyncTransport, Hh: bytes, password: str, kbdint_password: str | None = None) -> None:
    if kbdint_password is None:
        kbdint_password = password
    authed = False
    while not authed:
        p = t.recv_packet()
        assert p[0] == A.MSG_USERAUTH_REQUEST
        d = A.dec_userauth_request(p)
        if d["method"] == "keyboard-interactive":
            # Minimal RFC 4256 server: a single non-echo password prompt.
            t.send_packet(bytes([A.MSG_USERAUTH_INFO_REQUEST])
                          + W.enc_string(b"")
                          + W.enc_string(b"")
                          + W.enc_string(b"")
                          + W.enc_u32(1)
                          + W.enc_string(b"Password:")
                          + W.enc_bool(False))
            p2 = t.recv_packet()
            try:
                answers = A.dec_info_response(p2)
            except Exception:
                answers = []
            if len(answers) == 1 and answers[0].decode(errors="replace") == kbdint_password:
                t.send_packet(bytes([A.MSG_USERAUTH_SUCCESS]))
                authed = True
            else:
                t.send_packet(bytes([A.MSG_USERAUTH_FAILURE]) + W.enc_namelist(["keyboard-interactive"]) + W.enc_bool(False))
        elif d["method"] == "password":
            r = W.Reader(p)
            r.byte()
            r.string()
            r.string()
            r.string()
            r.bool()
            pw = r.string().decode()
            if pw == password:
                t.send_packet(bytes([A.MSG_USERAUTH_SUCCESS]))
                authed = True
            else:
                t.send_packet(bytes([A.MSG_USERAUTH_FAILURE]) + W.enc_namelist(["password", "publickey"]) + W.enc_bool(False))
        elif d["method"] == "publickey":
            r = W.Reader(p)
            r.byte()
            r.string()
            r.string()
            r.string()
            has_sig = r.bool()
            alg = r.string()
            blob = r.string()
            if not has_sig:
                t.send_packet(bytes([A.MSG_USERAUTH_PK_OK])
                              + W.enc_string(alg)
                              + W.enc_string(blob))
            else:
                to_verify = A.auth_sign_blob(Hh, d["user"], alg, blob)
                if _verify_user_sig(alg, blob, p, to_verify):
                    t.send_packet(bytes([A.MSG_USERAUTH_SUCCESS]))
                    authed = True
                else:
                    t.send_packet(bytes([A.MSG_USERAUTH_FAILURE]) + W.enc_namelist(["password", "publickey"]) + W.enc_bool(False))
        else:
            t.send_packet(bytes([A.MSG_USERAUTH_FAILURE]) + W.enc_namelist(["password", "publickey"]) + W.enc_bool(False))


def _connection_loop(t: SyncTransport, Vc: bytes, Vs: bytes, host_priv, session_id: bytes, timeout: float, sftp_root: str | None) -> None:
    server_chan = 7
    send_lock = threading.Lock()
    fwd: dict[int, object] = {}
    shells: set[int] = set()  # recipient ids with an accepted shell (echo mode)
    rfwd: dict[tuple[str, int], socket.socket] = {}  # (bind, port) -> listener
    rchan_tcp: dict[int, object] = {}  # our channel id -> relayed TCP socket
    rchan_peer: dict[int, int] = {}  # our channel id -> client channel id
    rfwd_pending: dict[int, object] = {}  # our channel id -> TCP socket awaiting CONFIRM

    def _send_locked(payload: bytes) -> None:
        with send_lock:
            t.send_packet(payload)

    def _rchan_relay(ours: int, tcp) -> None:
        try:
            while True:
                data = tcp.recv(32768)
                if not data:
                    break
                peer = rchan_peer.get(ours)
                if peer is None:
                    break
                _send_locked(bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(peer) + W.enc_string(data))
        except Exception:
            pass
        finally:
            try:
                tcp.close()
            except Exception:
                pass
            peer = rchan_peer.pop(ours, None)
            rchan_tcp.pop(ours, None)
            rfwd_pending.pop(ours, None)
            if peer is not None:
                try:
                    _send_locked(bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(peer))
                except Exception:
                    pass

    def _rfwd_accept(key: tuple[str, int]) -> None:
        nonlocal server_chan
        while key in rfwd:
            ls = rfwd.get(key)
            if ls is None:
                return
            try:
                conn, addr = ls.accept()
            except Exception:
                return
            with send_lock:
                ours = server_chan
                server_chan += 1
                rfwd_pending[ours] = conn
                t.send_packet(bytes([CH.MSG_CHANNEL_OPEN]) + W.enc_string(b"forwarded-tcpip") + W.enc_u32(ours) + W.enc_u32(CH.WINDOW) + W.enc_u32(CH.MAXPKT) + W.enc_string(key[0].encode()) + W.enc_u32(key[1]) + W.enc_string(addr[0].encode()) + W.enc_u32(addr[1]))

    def _fwd_relay(cch: int, sch: int, tcp) -> None:
        try:
            while True:
                data = tcp.recv(32768)
                if not data:
                    break
                _send_locked(bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(cch) + W.enc_string(data))
        except Exception:
            pass
        finally:
            try:
                tcp.close()
            except Exception:
                pass
            fwd.pop(sch, None)
            try:
                _send_locked(bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(cch))
            except Exception:
                pass

    while True:
        try:
            p = t.recv_raw()
        except Exception:
            return
        m = p[0]
        if m in (2, 4): # IGNORE, DEBUG: skipped here (recv_raw has no service loop)
            continue
        if m == 1: # DISCONNECT
            return
        if m == 80: # GLOBAL_REQUEST: answered here (recv_raw, no auto-answer)
            try:
                r = W.Reader(p)
                r.byte()
                name, want = r.string(), r.bool()
            except Exception:
                continue
            if name == b"tcpip-forward" and want:
                try:
                    bind = r.string().decode() or "127.0.0.1"
                    sport = r.u32()
                    ls = socket.socket()
                    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    ls.bind((bind if bind != "localhost" else "127.0.0.1", sport))
                    ls.listen(16)
                    real = ls.getsockname()[1]
                    rfwd[(bind, real)] = ls
                    threading.Thread(target=_rfwd_accept, args=((bind, real),), daemon=True).start()
                    t.send_packet(bytes([81]) + W.enc_u32(real))
                except Exception:
                    try:
                        t.send_packet(bytes([82]))
                    except Exception:
                        pass
            elif name == b"cancel-tcpip-forward":
                try:
                    bind = r.string().decode() or "127.0.0.1"
                    sport = r.u32()
                    ls = rfwd.pop((bind, sport), None)
                    if ls is not None:
                        try:
                            ls.close()
                        except Exception:
                            pass
                    if want:
                        t.send_packet(bytes([81]))
                except Exception:
                    if want:
                        try:
                            t.send_packet(bytes([82]))
                        except Exception:
                            pass
            elif want:
                t.send_packet(bytes([82]) if name == b"hostkeys-00@openssh.com" else bytes([81]))
            continue
        if m == K.MSG_KEXINIT:
            peer2 = K.dec_kexinit(p)
            our2 = _send_kexinit(t, initial=False)
            Kenc2, _H2 = _do_kex(t, host_priv, Vc, Vs, peer2, our2)
            keys2 = crypto.derive_keys(Kenc2, _H2, session_id, CIPHER, MAC)
            t.stage_rekey(keys2, CIPHER, MAC, is_client=False)
            t.send_packet(bytes([K.MSG_NEWKEYS])) # old keys
            t.commit_rekey_send()
            t._enc_on_send = True
            t.recv_packet() # peer NEWKEYS (old keys)
            t.commit_rekey_recv()
            t._enc_on_recv = True
            t.send_seq = 0
            t.recv_seq = 0
            continue
        if m == CH.MSG_CHANNEL_DATA:
            r = W.Reader(p)
            r.byte()
            sch, data = r.u32(), r.string()
            tcp = fwd.get(sch)
            if tcp is not None:
                try:
                    tcp.sendall(data)
                except Exception:
                    pass
                continue
            tcp = rchan_tcp.get(sch)
            if tcp is not None:
                try:
                    tcp.sendall(data)
                except Exception:
                    pass
                continue
            if sch in shells:  # echo shell: mirror stdin back as stdout
                _send_locked(bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(sch) + W.enc_string(data))
            continue
        if m == CH.MSG_CHANNEL_EOF:
            r = W.Reader(p)
            r.byte()
            sch = r.u32()
            if sch in shells:
                shells.discard(sch)
                _send_locked(bytes([CH.MSG_CHANNEL_REQUEST])
                             + W.enc_u32(sch)
                             + W.enc_string(b"exit-status")
                             + W.enc_bool(False)
                             + W.enc_u32(0))
                _send_locked(bytes([CH.MSG_CHANNEL_EOF]) + W.enc_u32(sch))
                _send_locked(bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(sch))
                try:
                    p2 = t.recv_packet()
                except Exception:
                    return
                if p2 and p2[0] == 1:
                    return
            continue
        if m == CH.MSG_CHANNEL_CLOSE:
            r = W.Reader(p)
            r.byte()
            sch = r.u32()
            shells.discard(sch)
            tcp = fwd.pop(sch, None)
            if tcp is not None:
                try:
                    tcp.close()
                except Exception:
                    pass
                continue
            tcp = rchan_tcp.pop(sch, None)
            rfwd_pending.pop(sch, None)
            rchan_peer.pop(sch, None)
            if tcp is not None:
                try:
                    tcp.close()
                except Exception:
                    pass
                continue
            # Client-initiated close of a shell channel: acknowledge it.
            try:
                _send_locked(bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(sch))
            except Exception:
                pass
            continue
        if m == CH.MSG_CHANNEL_OPEN_CONFIRM:
            r = W.Reader(p)
            r.byte()
            ours = r.u32()
            peer = r.u32()
            tcp = rfwd_pending.pop(ours, None)
            if tcp is None:
                continue
            rchan_peer[ours] = peer
            rchan_tcp[ours] = tcp
            threading.Thread(target=_rchan_relay, args=(ours, tcp), daemon=True).start()
            continue
        if m == CH.MSG_CHANNEL_OPEN_FAILURE:
            r = W.Reader(p)
            r.byte()
            ours = r.u32()
            tcp = rfwd_pending.pop(ours, None)
            if tcp is not None:
                try:
                    tcp.close()
                except Exception:
                    pass
            continue
        if m == CH.MSG_CHANNEL_OPEN:
            r = W.Reader(p)
            r.byte()
            ctype = r.string()
            client_chan = r.u32()
            if ctype == b"direct-tcpip":
                r.u32()
                r.u32() # window, maxpacket
                host, port = r.string().decode(), r.u32()
                r.string()
                r.u32() # originator
                try:
                    tcp = socket.create_connection((host, port), timeout=timeout)
                except Exception:
                    t.send_packet(bytes([CH.MSG_CHANNEL_OPEN_FAILURE]) + W.enc_u32(client_chan) + W.enc_u32(2) + W.enc_string(b"connect failed") + W.enc_string(b""))
                    continue
                sch = server_chan
                server_chan += 1
                fwd[sch] = tcp
                t.send_packet(bytes([CH.MSG_CHANNEL_OPEN_CONFIRM]) + W.enc_u32(client_chan) + W.enc_u32(sch) + W.enc_u32(CH.WINDOW) + W.enc_u32(CH.MAXPKT))
                threading.Thread(target=_fwd_relay, args=(client_chan, sch, tcp), daemon=True).start()
                continue
            t.send_packet(bytes([CH.MSG_CHANNEL_OPEN_CONFIRM]) + W.enc_u32(client_chan) + W.enc_u32(server_chan) + W.enc_u32(CH.WINDOW) + W.enc_u32(CH.MAXPKT))
        elif m == CH.MSG_CHANNEL_REQUEST:
            r = W.Reader(p)
            r.byte()
            _ch = r.u32()
            name = r.string()
            _wr = r.bool()
            if name == b"subsystem" and r.string() == b"sftp":
                t.send_packet(bytes([CH.MSG_CHANNEL_SUCCESS]))
                serve_sftp(t, client_chan, sftp_root or tempfile.mkdtemp(prefix="ccssh-stub-"))
                continue
            if name == b"pty-req":
                # Consume TERM(cols/rows/wh/modes); accept everything test-side.
                r.string()
                r.u32()
                r.u32()
                r.u32()
                r.u32()
                r.string()
                t.send_packet(bytes([CH.MSG_CHANNEL_SUCCESS]))
                continue
            if name == b"env":
                r.string()
                r.string()
                t.send_packet(bytes([CH.MSG_CHANNEL_SUCCESS]))
                continue
            if name == b"window-change":
                for _ in range(4):
                    r.u32()
                if _wr: # we only reply when explicitly asked (ours sends False)
                    t.send_packet(bytes([CH.MSG_CHANNEL_SUCCESS]))
                continue
            if name == b"shell":
                t.send_packet(bytes([CH.MSG_CHANNEL_SUCCESS]))
                shells.add(_ch) # echo mode; EOF/CLOSE handled in the main loop
                continue
            if name == b"exec":
                cmd = r.string().decode()
                t.send_packet(bytes([CH.MSG_CHANNEL_SUCCESS]))
                if cmd.startswith("echo "):
                    body = (cmd[5:] + "\n").encode()
                elif cmd == "fail":
                    body = b"oops\n"
                else:
                    body = f"stub:{cmd}\n".encode()
                t.send_packet(bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(client_chan) + W.enc_string(body))
                code = 3 if cmd == "fail" else 0
                t.send_packet(bytes([CH.MSG_CHANNEL_REQUEST]) + W.enc_u32(client_chan) + W.enc_string(b"exit-status") + W.enc_bool(False) + W.enc_u32(code))
                t.send_packet(bytes([CH.MSG_CHANNEL_EOF]) + W.enc_u32(client_chan))
                t.send_packet(bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(client_chan))
                try:
                    p2 = t.recv_packet()
                except Exception:
                    return
                if p2 and p2[0] == 1:
                    return
                continue
            else:
                t.send_packet(bytes([CH.MSG_CHANNEL_FAILURE]))


"""
 SFTP subsystem server (test-only, confined to a temp dir).
"""

from ccssh.sftp import (
    F_INIT, F_VERSION, F_OPEN, F_CLOSE, F_READ, F_WRITE,
    F_OPENDIR, F_READDIR, F_REMOVE, F_MKDIR, F_REALPATH, F_STAT,
    F_HANDLE, F_DATA, F_NAME, F_ATTRS, F_STATUS,
    S_OK, S_EOF, S_NO_SUCH_FILE, S_FAILURE, S_OP_UNSUPPORTED,
    P_READ, P_WRITE, P_APPEND, P_CREAT, P_TRUNC, P_EXCL,
)


def _status(rid: int, code: int, msg: str = "", lang: bytes = b"en") -> bytes:
    body = (bytes([F_STATUS]) + W.enc_u32(rid) + W.enc_u32(code) + W.enc_string(msg.encode()) + W.enc_string(lang))
    return W.enc_u32(len(body)) + body


def _reply(rid: int, ftype: int, body: bytes) -> bytes:
    return W.enc_u32(1 + 4 + len(body)) + bytes([ftype]) + W.enc_u32(rid) + body


def _attrs_of(st: os.stat_result) -> bytes:
    return (W.enc_u32(0x01 | 0x04 | 0x08) + W.enc_u64(st.st_size) + W.enc_u32(statmod.S_IMODE(st.st_mode)) + W.enc_u32(int(st.st_atime)) + W.enc_u32(int(st.st_mtime)))


def serve_sftp(t, client_chan: int, root: str) -> None:
    """Serve SFTP on a channel. Returns on CHANNEL_CLOSE (after replying CLOSE)."""
    os.makedirs(root, exist_ok=True)
    handles: dict[bytes, object] = {}
    counter = 0

    def new_handle() -> bytes:
        nonlocal counter
        counter += 1
        return W.enc_u32(counter)[-4:] + os.urandom(4)

    def resolve(p: str) -> str:
        full = os.path.normpath(os.path.join(root, p.lstrip("/")))
        if full != root and not full.startswith(root + os.sep):
            raise PermissionError("escape")
        return full

    def send_sftp(payload: bytes) -> None:
        t.send_packet(bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(client_chan) + W.enc_string(payload))

    while True:
        p = t.recv_packet()
        m = p[0]
        r = W.Reader(p)
        r.byte()
        if m == K.MSG_KEXINIT:
            return # rekey requested: back to the main loop
        if m == CH.MSG_CHANNEL_CLOSE:
            r.u32() # client channel id (single-channel stub)
            t.send_packet(bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(client_chan))
            return
        if m != CH.MSG_CHANNEL_DATA:
            continue
        r.u32() # client channel id (single-channel stub)
        blob = r.string()
        br = W.Reader(blob)
        ln = br.u32()
        body = br.raw(ln)
        cr = W.Reader(body)
        ftype = cr.byte()
        if ftype == F_INIT: # INIT/VERSION carry no request id
            ver = cr.u32()
            send_sftp(W.enc_u32(5) + bytes([F_VERSION]) + W.enc_u32(min(ver, 3)))
            continue
        rid = cr.u32()
        rest = body[5:]
        try:
            out = handle_request(ftype, rid, rest, resolve, handles, new_handle)
        except PermissionError:
            out = _status(rid, S_FAILURE, "escape denied")
        except FileNotFoundError:
            out = _status(rid, S_NO_SUCH_FILE, "no such file")
        except IsADirectoryError:
            out = _status(rid, S_FAILURE, "is a directory")
        except Exception as e:
            out = _status(rid, S_FAILURE, str(e)[:200])
        if out is not None:
            send_sftp(out)


def handle_request(ftype: int, rid: int, rest: bytes, resolve, handles: dict, new_handle):
    r = W.Reader(rest)
    if ftype == F_REALPATH:
        p = resolve(r.string().decode())
        rel = os.path.relpath(p, _root_of(resolve))
        rel = "/" if rel == "." else "/" + rel
        attrs = W.enc_u32(0)
        return _reply(rid, F_NAME, W.enc_u32(1) + W.enc_string(rel.encode()) + W.enc_string(rel.encode()) + attrs)
    if ftype == F_STAT:
        st = os.stat(resolve(r.string().decode()))
        return _reply(rid, F_ATTRS, _attrs_of(st))
    if ftype == F_OPENDIR:
        full = resolve(r.string().decode())
        entries = sorted(os.listdir(full))
        h = new_handle()
        handles[h] = {"dir": full, "entries": entries, "i": 0}
        return _reply(rid, F_HANDLE, W.enc_string(h))
    if ftype == F_READDIR:
        h = r.string()
        stt = handles.get(h)
        if not isinstance(stt, dict) or "entries" not in stt:
            return _status(rid, S_FAILURE, "bad handle")
        if stt["i"] >= len(stt["entries"]):
            return _status(rid, S_EOF, "eof")
        chunk = stt["entries"][stt["i"]:stt["i"] + 32]
        stt["i"] += len(chunk)
        body = W.enc_u32(len(chunk))
        for name in chunk:
            fp = os.path.join(stt["dir"], name)
            try:
                at = _attrs_of(os.stat(fp))
            except OSError:
                at = W.enc_u32(0)
            body += W.enc_string(name.encode()) + W.enc_string(name.encode()) + at
        return _reply(rid, F_NAME, body)
    if ftype == F_OPEN:
        path, flags = r.string().decode(), r.u32()
        _attrs_skip(r)
        full = resolve(path)
        if flags & P_EXCL and os.path.exists(full):
            return _status(rid, S_FAILURE, "exists")
        mode = "r+b" if (flags & P_READ and flags & P_WRITE) else ("rb" if flags & P_READ else "w+b")
        if flags & P_APPEND:
            mode = "a+b"
        if flags & P_CREAT and not os.path.exists(full):
            open(full, "wb").close()
            if not (flags & P_WRITE):
                mode = "rb"
        if flags & P_TRUNC:
            open(full, "wb").close()
        fo = open(full, mode)
        h = new_handle()
        handles[h] = fo
        return _reply(rid, F_HANDLE, W.enc_string(h))
    if ftype == F_READ:
        h, off, ln = r.string(), r.u64(), r.u32()
        fo = handles.get(h)
        if fo is None or isinstance(fo, dict):
            return _status(rid, S_FAILURE, "bad handle")
        fo.seek(off)
        data = fo.read(min(ln, 32768))
        if not data:
            return _status(rid, S_EOF, "eof")
        return _reply(rid, F_DATA, W.enc_string(data))
    if ftype == F_WRITE:
        h, off, data = r.string(), r.u64(), r.string()
        fo = handles.get(h)
        if fo is None or isinstance(fo, dict):
            return _status(rid, S_FAILURE, "bad handle")
        fo.seek(off)
        fo.write(data)
        fo.flush()
        return _status(rid, S_OK, "")
    if ftype == F_CLOSE:
        h = r.string()
        fo = handles.pop(h, None)
        if fo is not None and not isinstance(fo, dict):
            fo.close()
        return _status(rid, S_OK, "")
    if ftype == F_REMOVE:
        os.unlink(resolve(r.string().decode()))
        return _status(rid, S_OK, "")
    if ftype == F_MKDIR:
        full = resolve(r.string().decode())
        _attrs_skip(r)
        os.mkdir(full)
        return _status(rid, S_OK, "")
    return _status(rid, S_OP_UNSUPPORTED, f"op {ftype}")


def _root_of(resolve) -> str:
    return resolve("/")


def _attrs_skip(r: W.Reader) -> None:
    fl = r.u32()
    if fl & 0x01:
        r.u64()
    if fl & 0x02:
        r.u32()
        r.u32()
    if fl & 0x04:
        r.u32()
    if fl & 0x08:
        r.u32()
        r.u32()
    if fl & 0x80000000:
        for _ in range(r.u32()):
            r.string()
            r.string()
