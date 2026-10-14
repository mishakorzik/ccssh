"""Dynamic (-D), agent (-A) and X11 (-X/-Y) forwarding: codecs, relays, CLI."""
from __future__ import annotations

import os
import socket
import struct
import threading

import pytest

from ccssh import agent as AG
from ccssh import channel as CH
from ccssh import socks as SK
from ccssh import wire as W
from ccssh import x11 as X11


# SOCKS codecs

def test_socks5_greeting_ok():
    reply, ok = SK.greeting_reply(bytes([5, 2, 0, 1]))
    assert ok and reply == b"\x05\x00"


def test_socks5_greeting_no_acceptable():
    reply, ok = SK.greeting_reply(bytes([5, 1, 2]))
    assert not ok and reply == b"\x05\xff"
    with pytest.raises(SK.SocksError):
        SK.greeting_reply(b"\x04\x01")  # SOCKS4-shaped
    with pytest.raises(SK.SocksError):
        SK.greeting_reply(bytes([5, 0]))


def test_socks5_requests():
    assert SK.parse_s5_request(bytes([5, 1, 0, 1, 127, 0, 0, 1, 0x1F, 0x90])) == ("127.0.0.1", 8080)
    dom = b"example.com"
    req = bytes([5, 1, 0, 3, len(dom)]) + dom + struct.pack(">H", 443)
    assert SK.parse_s5_request(req) == ("example.com", 443)
    v6 = bytes([5, 1, 0, 4]) + bytes(15) + bytes([1]) + struct.pack(">H", 22)
    host, port = SK.parse_s5_request(v6)
    assert port == 22 and ":" in host
    with pytest.raises(SK.SocksError):
        SK.parse_s5_request(bytes([5, 2, 0, 1, 1, 2, 3, 4, 0, 80]))  # BIND
    with pytest.raises(SK.SocksError):
        SK.parse_s5_request(bytes([5, 1, 0, 9, 1, 2, 3, 4, 0, 80]))  # bad atyp
    assert SK.s5_reply_ok()[1] == SK.S5_REP_OK
    assert SK.s5_reply_fail()[1] == SK.S5_REP_REFUSED


def test_socks4_requests():
    assert SK.parse_s4_request(b"\x04\x01\x1F\x90\x7F\x00\x00\x01user\x00") == ("127.0.0.1", 8080)
    dom = b"example.com\x00"
    req = b"\x04\x01\x01\xBB\x00\x00\x00\x01user\x00" + dom
    assert SK.parse_s4_request(req) == ("example.com", 443)
    assert SK.s4_reply_ok() == b"\x00\x5a\x00\x00\x00\x00\x00\x00"
    with pytest.raises(SK.SocksError):
        SK.parse_s4_request(b"\x04\x02\x1F\x90\x7F\x00\x00\x01u\x00")  # BIND


# channel codecs

def test_agent_channel_codecs():
    req = CH.enc_agent_req(7)
    r = W.Reader(req)
    assert r.byte() == 98 and r.u32() == 7
    assert r.string() == b"auth-agent-req@openssh.com" and r.bool() is True
    open_pkt = (bytes([90]) + W.enc_string(b"auth-agent@openssh.com")
                + W.enc_u32(3) + W.enc_u32(2 * 1024 * 1024) + W.enc_u32(32768))
    assert AG.dec_agent_open(open_pkt) == 3
    with pytest.raises(AG.AgentError):
        AG.dec_agent_open(bytes([90]) + W.enc_string(b"session") + W.enc_u32(1)
                          + W.enc_u32(2) + W.enc_u32(3))
    c = CH.enc_open_confirm(9, 4)
    r = W.Reader(c)
    assert r.byte() == 91 and (r.u32(), r.u32()) == (9, 4)
    f = CH.enc_open_failure(9)
    assert W.Reader(f).byte() == 92
    assert AG.sign_flags_for_alg("rsa-sha2-256") == 2
    assert AG.sign_flags_for_alg("rsa-sha2-512") == 4
    assert AG.sign_flags_for_alg("ssh-ed25519") == 0


def test_x11_codecs_and_display():
    assert X11.parse_display(":0") == ("", 0, 0)
    assert X11.parse_display("host:10.0") == ("host", 10, 0)
    assert X11.parse_display("localhost:3.1") == ("localhost", 3, 1)
    for bad in ("", "nope", ":9999", "h:-1", ":1.100"):
        with pytest.raises(X11.X11Error):
            X11.parse_display(bad)
    assert len(X11.gen_cookie()) == 16
    cookie = X11.gen_cookie()
    pkt = X11.enc_x11_req(5, cookie=cookie, screen=0)
    r = W.Reader(pkt)
    assert r.byte() == 98 and r.u32() == 5 and r.string() == b"x11-req"
    assert r.bool() is True and r.bool() is False
    assert r.string() == X11.AUTH_PROTO
    assert bytes.fromhex(r.string().decode()) == cookie
    assert r.u32() == 0
    with pytest.raises(X11.X11Error):
        X11.enc_x11_req(5, cookie=b"short")
    open_pkt = (bytes([90]) + W.enc_string(b"x11") + W.enc_u32(9)
                + W.enc_u32(1024) + W.enc_u32(1024)
                + W.enc_string(b"127.0.0.1") + W.enc_u32(6010))
    info = X11.dec_x11_open(open_pkt)
    assert info["sender"] == 9 and info["originator"] == b"127.0.0.1"
    with pytest.raises(X11.X11Error):
        X11.dec_x11_open(bytes([90]) + W.enc_string(b"session") + W.enc_u32(1)
                         + W.enc_u32(1) + W.enc_u32(1))


# mux typed inbound routing

def test_mux_inbound_routing_by_type():
    from ccssh.mux import ChannelMux

    class FakeT:
        timeout = 5.0

    mux = ChannelMux(FakeT())
    aq = mux.register_inbound(b"auth-agent@openssh.com")
    assert mux.register_inbound(b"auth-agent@openssh.com") is aq
    xq = mux.register_inbound(b"x11")
    agent_open = (bytes([90]) + W.enc_string(b"auth-agent@openssh.com")
                  + W.enc_u32(1) + W.enc_u32(2) + W.enc_u32(3))
    x11_open = (bytes([90]) + W.enc_string(b"x11") + W.enc_u32(2)
                + W.enc_u32(2) + W.enc_u32(3) + W.enc_string(b"h") + W.enc_u32(1))
    other_open = (bytes([90]) + W.enc_string(b"forwarded-tcpip") + W.enc_u32(3)
                  + W.enc_u32(2) + W.enc_u32(3) + W.enc_string(b"h") + W.enc_u32(1)
                  + W.enc_string(b"o") + W.enc_u32(2))
    mux._route(agent_open)
    mux._route(x11_open)
    mux._route(other_open)  # unregistered -> catch-all (legacy path)
    assert aq.get_nowait() == agent_open
    assert xq.get_nowait() == x11_open
    assert mux.catch_all().get_nowait() == other_open
    mux.unregister_inbound(b"x11")
    mux._route(x11_open)
    assert mux.catch_all().get_nowait() == x11_open


# fake agent + loopback helpers

def _ed25519_keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    blob = W.enc_string(b"ssh-ed25519") + W.enc_string(priv.public_key().public_bytes_raw())
    return priv, blob


class _FakeAgent(threading.Thread):
    """Minimal ssh-agent: identities + ed25519 signing over a unix socket."""

    def __init__(self, path, priv, blob, comment=b"test-key"):
        super().__init__(daemon=True)
        self.path = path
        self.priv = priv
        self.blob = blob
        self.comment = comment
        self._stop = threading.Event()

    def run(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass
        ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        ls.bind(self.path)
        ls.listen(8)
        ls.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = ls.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._serve(conn)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        try:
            ls.close()
        except Exception:
            pass

    def _serve(self, conn):
        conn.settimeout(5)
        while not self._stop.is_set():
            hdr = _readn(conn, 4)
            (ln,) = struct.unpack(">I", hdr)
            if ln == 0 or ln > 65536:
                return
            body = _readn(conn, ln)
            r = W.Reader(body)
            m = r.byte()
            if m == AG.REQ_IDENTITIES:
                out = (bytes([AG.IDENTITIES_ANSWER]) + W.enc_u32(1)
                       + W.enc_string(self.blob) + W.enc_string(self.comment))
            elif m == AG.SIGN_REQUEST:
                blob, data = r.string(), r.string()
                r.u32()  # flags (ed25519 ignores them)
                if blob != self.blob:
                    out = bytes([AG.AGENT_FAILURE])
                else:
                    sig = self.priv.sign(data)
                    nested = W.enc_string(b"ssh-ed25519") + W.enc_string(sig)
                    out = bytes([AG.SIGN_RESPONSE]) + W.enc_string(nested)
            else:
                out = bytes([AG.AGENT_FAILURE])
            conn.sendall(struct.pack(">I", len(out)) + out)

    def stop(self):
        self._stop.set()


def _readn(conn, n):
    out = b""
    while len(out) < n:
        chunk = conn.recv(n - len(out))
        if not chunk:
            raise ConnectionError("agent closed")
        out += chunk
    return out


def test_agent_client_against_fake(tmp_path):
    sock = str(tmp_path / "agent.sock")
    priv, blob = _ed25519_keypair()
    ag = _FakeAgent(sock, priv, blob)
    ag.start()
    try:
        for _ in range(100):
            if os.path.exists(sock):
                break
            import time as _t
            _t.sleep(0.02)
        c = AG.AgentClient(sock)
        ids = c.list_identities()
        assert len(ids) == 1 and ids[0][0] == blob
        sig = c.sign(blob, b"hello-agent", 0)
        r = W.Reader(sig)
        assert r.string() == b"ssh-ed25519" and len(r.string()) == 64
        with pytest.raises(AG.AgentError):
            c.sign(b"\x00\x00\x00\x03abc", b"data", 0)  # unknown key
    finally:
        ag.stop()
        ag.join(timeout=3)


def test_agent_client_errors():
    with pytest.raises(AG.AgentError):
        AG.AgentClient("/nonexistent-agent-sock-12345").list_identities()
    import unittest.mock as _mock
    with _mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SSH_AUTH_SOCK", None)
        assert AG.default_agent_path() is None
        with pytest.raises(AG.AgentError):
            AG.AgentClient(None)


def _loopback(password="pw", sftp_root=None, x11_echo=None, agent_probe=None, **client_kw):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh.stub import run_once
    from ccssh.client import CCSSHClient
    host_priv = Ed25519PrivateKey.generate()
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = ls.getsockname()[1]
    err = {}

    def srv():
        try:
            conn, _ = ls.accept()
            run_once(conn, host_priv, password=password, x11_echo=x11_echo,
                     agent_probe=agent_probe)
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()
    kw = dict(timeout=5, host_policy="off")
    kw.update(client_kw)
    c = CCSSHClient(**kw)
    c.connect("127.0.0.1", port=port, username="u", password=password)
    return c, th, err


def test_loopback_agent_auth(tmp_path):
    sock = str(tmp_path / "agent.sock")
    priv, blob = _ed25519_keypair()
    ag = _FakeAgent(sock, priv, blob)
    ag.start()
    try:
        from ccssh.client import CCSSHClient
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ccssh.stub import run_once
        host_priv = Ed25519PrivateKey.generate()
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        port = ls.getsockname()[1]
        err = {}

        def srv():
            try:
                conn, _ = ls.accept()
                run_once(conn, host_priv, password="__never__")
                conn.close()
            except Exception as e:
                err["e"] = e
            finally:
                ls.close()

        th = threading.Thread(target=srv, daemon=True)
        th.start()
        c = CCSSHClient(timeout=5, host_policy="off", agent_path=sock)
        # No password, no key file: the agent key alone must log us in
        # (the stub accepts any self-consistent signature, like a real sshd
        # with the key authorized).
        c.connect("127.0.0.1", port=port, username="u")
        try:
            assert c.exec_command("echo via-agent")[0] == "via-agent\n"
        finally:
            c.close()
            th.join(timeout=5)
        if "e" in err:
            raise err["e"]
    finally:
        ag.stop()
        ag.join(timeout=3)


def test_loopback_agent_unavailable_falls_back_to_password():
    c, th, err = _loopback(password="pw", agent_path="/nonexistent-agent-sock")
    try:
        assert c.exec_command("echo fallback")[0] == "fallback\n"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def _echo_server():
    import threading as _th
    echo = socket.socket()
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo.bind(("127.0.0.1", 0))
    echo.listen(8)
    port = echo.getsockname()[1]
    estop = _th.Event()

    def echo_loop():
        while not estop.is_set():
            try:
                conn, _ = echo.accept()
            except Exception:
                continue
            try:
                conn.settimeout(5)
                while True:
                    d = conn.recv(4096)
                    if not d:
                        break
                    conn.sendall(d)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    _th.Thread(target=echo_loop, daemon=True).start()

    def _close():
        estop.set()
        try:
            echo.close()
        except Exception:
            pass

    return port, _close


def test_loopback_dynamic_socks5():
    echo_port, echo_close = _echo_server()
    c, th, err = _loopback()
    try:
        fwd = c.forward_dynamic(0)
        try:
            s = socket.create_connection(("127.0.0.1", fwd.port), timeout=5)
            try:
                s.sendall(bytes([5, 1, 0]))  # greeting, no-auth
                assert s.recv(2) == b"\x05\x00"
                s.sendall(bytes([5, 1, 0, 1, 127, 0, 0, 1])
                          + struct.pack(">H", echo_port))
                assert s.recv(10)[1] == 0  # granted
                s.sendall(b"ping-dynamic")
                got = b""
                while len(got) < len(b"ping-dynamic"):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    got += chunk
                assert got == b"ping-dynamic"
            finally:
                s.close()
        finally:
            fwd.close()
    finally:
        c.close()
        echo_close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_loopback_dynamic_socks4_and_domain():
    echo_port, echo_close = _echo_server()
    c, th, err = _loopback()
    try:
        fwd = c.forward_dynamic(0)
        try:
            # SOCKS4 with IPv4
            s = socket.create_connection(("127.0.0.1", fwd.port), timeout=5)
            try:
                s.sendall(b"\x04\x01" + struct.pack(">H", echo_port)
                          + bytes([127, 0, 0, 1]) + b"u\x00")
                assert s.recv(8)[:2] == b"\x00\x5a"
                s.sendall(b"s4")
                assert s.recv(2) == b"s4"
            finally:
                s.close()
            # SOCKS5 with a domain name (localhost resolves server-side)
            s = socket.create_connection(("127.0.0.1", fwd.port), timeout=5)
            try:
                s.sendall(bytes([5, 1, 0]))
                assert s.recv(2) == b"\x05\x00"
                dom = b"localhost"
                s.sendall(bytes([5, 1, 0, 3, len(dom)]) + dom + struct.pack(">H", echo_port))
                assert s.recv(10)[1] == 0
                s.sendall(b"s5d")
                assert s.recv(3) == b"s5d"
            finally:
                s.close()
            # garbage version is refused (clean EOF or RST — both mean closed)
            s = socket.create_connection(("127.0.0.1", fwd.port), timeout=5)
            try:
                s.sendall(b"\x02\x01\x00")
                s.settimeout(2)
                try:
                    assert s.recv(8) == b""
                except ConnectionResetError:
                    pass
            finally:
                s.close()
        finally:
            fwd.close()
    finally:
        c.close()
        echo_close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_loopback_dynamic_and_local_share_slot():
    from ccssh.transport import CCSSHError
    c, th, err = _loopback()
    try:
        fwd = c.forward_dynamic(0)
        try:
            with pytest.raises(CCSSHError, match="one active forwarder"):
                c.forward_local(0, "127.0.0.1", 80)
        finally:
            fwd.close()
        assert c.exec_command("echo after")[0] == "after\n"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_loopback_x11_end_to_end(monkeypatch):
    # Fake X server (echo) on 127.0.0.1:60NN; stub opens an x11 channel
    # back and requires the identical echo (full relay through X11Forwarder).
    import threading as _th
    echo = socket.socket()
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    disp_num = None
    for cand in range(71, 100):
        try:
            echo.bind(("127.0.0.1", 6000 + cand))
            disp_num = cand
            break
        except OSError:
            continue
    assert disp_num is not None, "no free 60NN port for the fake X server"
    echo.listen(8)
    estop = _th.Event()

    def echo_loop():
        while not estop.is_set():
            try:
                conn, _ = echo.accept()
            except Exception:
                continue
            try:
                conn.settimeout(5)
                while True:
                    d = conn.recv(4096)
                    if not d:
                        break
                    conn.sendall(d)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    _th.Thread(target=echo_loop, daemon=True).start()
    monkeypatch.setenv("DISPLAY", f"127.0.0.1:{disp_num}")
    c, th, err = _loopback(password="pw", x11_echo=b"x11-payload-123")
    try:
        c.forward_x11()  # DISPLAY from the monkeypatched env
        out, _, code = c.exec_command("echo hi", x11=True)
        assert (out, code) == ("hi\n", 0)
    finally:
        c.close()
        estop.set()
        try:
            echo.close()
        except Exception:
            pass
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_loopback_agent_forwarding_end_to_end(tmp_path):
    sock = str(tmp_path / "agent.sock")
    priv, blob = _ed25519_keypair()
    ag = _FakeAgent(sock, priv, blob)
    ag.start()
    try:
        c, th, err = _loopback(password="pw",
                               agent_probe={"blob": blob, "data": b"probe-data"})
        try:
            c.forward_agent(sock)
            out, _, code = c.exec_command("echo hi", forward_agent=True)
            assert (out, code) == ("hi\n", 0)
        finally:
            c.close()
            th.join(timeout=5)
        if "e" in err:
            raise err["e"]
    finally:
        ag.stop()
        ag.join(timeout=3)


def test_cli_forward_flags(monkeypatch):
    from ccssh import cli as CLIMOD

    seen = {}

    class Fake:
        def __init__(self, **k):
            seen.update(k)

        def connect(self, *a, **k):
            return self

        def forward_dynamic(self, port, bind="127.0.0.1"):
            seen["D"] = (port, bind)
            return FakeFwd()

        def forward_agent(self, path=None):
            seen["A"] = path
            return FakeFwd()

        def forward_x11(self, display=None, trusted=False):
            seen["X"] = trusted
            return FakeFwd()

        def exec_command(self, cmd, **kw):
            seen["sess"] = kw
            return (b"", b"", 0)

        def close(self):
            pass

    class FakeFwd:
        port = 1080

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert CLIMOD.main(["-D", "1080", "-A", "-X", "u@h.example.com", "echo", "hi"]) == 0
    assert seen["D"] == (1080, "127.0.0.1")
    assert seen["A"] is None and seen["X"] is False
    assert seen["sess"].get("forward_agent") is True and seen["sess"].get("x11") is True
    seen.clear()
    assert CLIMOD.main(["-Y", "u@h.example.com", "echo", "hi"]) == 0
    assert seen["X"] is True and seen["sess"].get("x11_trusted") is True
    # -X then -Y: last wins (trusted); -Y then -X: untrusted
    seen.clear()
    assert CLIMOD.main(["-X", "-Y", "u@h.example.com", "echo", "hi"]) == 0
    assert seen["sess"].get("x11_trusted") is True
    seen.clear()
    assert CLIMOD.main(["-Y", "-X", "u@h.example.com", "echo", "hi"]) == 0
    assert seen["sess"].get("x11_trusted") is False


def test_cli_forward_exclusivity_and_options(monkeypatch):
    from ccssh import cli as CLIMOD

    class Fake:
        def __init__(self, **k):
            pass

        def connect(self, *a, **k):
            return self

        def open_shell(self, **kw):
            raise AssertionError("no shell expected here")

        def exec_command(self, cmd, **kw):
            return (b"", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert CLIMOD.main(["-L", "8080:127.0.0.1:80", "-D", "1080", "u@h"]) == 255
    assert CLIMOD.main(["-R", "8080:127.0.0.1:80", "-D", "1080", "u@h"]) == 255
    assert CLIMOD.main(["-o", "ForwardAgent=maybe", "u@h"]) == 255
    assert CLIMOD.main(["-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
                        "u@h", "echo", "hi"]) == 0
    with pytest.raises(CLIMOD.UsageError):
        CLIMOD._parse_D("notaport")
    with pytest.raises(CLIMOD.UsageError):
        CLIMOD._parse_D("0")
    assert CLIMOD.main(["-Q", "key"]) == 0


def test_async_agent_auth_loopback(tmp_path):
    import asyncio
    from ccssh import async_client as AC
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh.stub import run_once
    sock = str(tmp_path / "agent.sock")
    priv, blob = _ed25519_keypair()
    ag = _FakeAgent(sock, priv, blob)
    ag.start()
    try:
        host_priv = Ed25519PrivateKey.generate()
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        port = ls.getsockname()[1]
        err = {}

        def srv():
            try:
                conn, _ = ls.accept()
                run_once(conn, host_priv, password="__never__")
                conn.close()
            except Exception as e:
                err["e"] = e
            finally:
                ls.close()

        th = threading.Thread(target=srv, daemon=True)
        th.start()

        async def go():
            c = AC.AsyncCCSSHClient(timeout=5, host_policy="off", agent_path=sock)
            await c.connect("127.0.0.1", port=port, username="u")
            try:
                return await c.exec_command("echo async-agent")
            finally:
                await c.close()

        assert asyncio.run(go())[0] == "async-agent\n"
        th.join(timeout=5)
        if "e" in err:
            raise err["e"]
    finally:
        ag.stop()
        ag.join(timeout=3)


# live interop (self-contained sshd -D; skips cleanly without the binaries)

import shutil as _shutil
import subprocess as _subprocess
import tempfile as _tempfile
import time as _time

import pytest as _pytest

_sshd_bin = _shutil.which("sshd")
_needs_sshd = _pytest.mark.skipif(_sshd_bin is None, reason="no sshd binary")
_needs_agent_bin = _pytest.mark.skipif(
    _shutil.which("ssh-agent") is None or _shutil.which("ssh-add") is None,
    reason="no ssh-agent binaries")


@_pytest.fixture(scope="module")
def live_sshd_d():
    """Real sshd in foreground (-D) with agent forwarding pointed at tmp."""
    if _sshd_bin is None:
        _pytest.skip("no sshd binary")
    # NOTE: keep this prefix SHORT: sshd builds its agent socket as
    # <tmp>/<agentdir>/ssh-XXX/agent.sshd.PID and Unix sun_path caps at
    # 108 bytes (Termux $TMPDIR alone is 35). A long prefix makes the
    # server refuse agent forwarding with "path too long".
    tmp = _tempfile.mkdtemp(prefix="cxf-")
    proc = None
    try:
        host_keys = {}
        for kind, name in (("-t", "ed25519"), ("-t", "rsa")):
            path = os.path.join(tmp, f"ssh_host_{name}_key")
            _subprocess.run(["ssh-keygen", "-q", "-N", "", "-t", name, "-f", path],
                            check=True, capture_output=True)
            host_keys[name] = path
        user = os.path.join(tmp, "id_user")
        _subprocess.run(["ssh-keygen", "-q", "-N", "", "-t", "ed25519", "-f", user],
                        check=True, capture_output=True)
        auth = os.path.join(tmp, "authorized_keys")
        _shutil.copy(user + ".pub", auth)
        os.chmod(auth, 0o600)
        agent_dir = os.path.join(tmp, "ag")  # short: see sun_path note above
        os.makedirs(agent_dir, mode=0o700)
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        port = ls.getsockname()[1]
        ls.close()
        cfg = os.path.join(tmp, "sshd_config")
        with open(cfg, "w") as f:
            f.write(f"Port {port}\nListenAddress 127.0.0.1\n")
            for p in host_keys.values():
                f.write(f"HostKey {p}\n")
            f.write(f"PidFile {tmp}/sshd.pid\nAuthorizedKeysFile {auth}\n"
                    "PasswordAuthentication no\nPubkeyAuthentication yes\n"
                    "StrictModes no\nUseDNS no\nAllowAgentForwarding yes\n"
                    f"AgentSocketPath shared:{agent_dir}\n")
        proc = _subprocess.Popen([_sshd_bin, "-D", "-f", cfg, "-E", os.path.join(tmp, "log")],
                                 stdout=_subprocess.DEVNULL, stderr=_subprocess.DEVNULL)
        _time.sleep(1.0)
        if proc.poll() is not None:
            _pytest.skip("sshd refused to start here")
        from ccssh.client import CCSSHClient as _C
        probe = _C(timeout=5, host_policy="off")
        try:
            probe.connect("127.0.0.1", port=port, username="root",
                          key_filename=user, use_agent=False)
            probe.close()
        except Exception:
            proc.terminate()
            _pytest.skip("sshd unreachable here")
        yield {"port": port, "user": user, "tmp": tmp}
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    finally:
        _shutil.rmtree(tmp, ignore_errors=True)


@_needs_sshd
def test_live_dynamic_socks(live_sshd_d):
    """-D against real OpenSSH: tunnel back into sshd, read its banner."""
    from ccssh.client import CCSSHClient as _C
    c = _C(timeout=10, host_policy="off")
    c.connect("127.0.0.1", port=live_sshd_d["port"], username="root",
              key_filename=live_sshd_d["user"], use_agent=False)
    try:
        fwd = c.forward_dynamic(0)
        try:
            s = socket.create_connection(("127.0.0.1", fwd.port), timeout=5)
            try:
                s.sendall(bytes([5, 1, 0]))
                assert s.recv(2) == b"\x05\x00"
                s.sendall(bytes([5, 1, 0, 1, 127, 0, 0, 1])
                          + struct.pack(">H", live_sshd_d["port"]))
                assert s.recv(10)[1] == 0
                banner = s.recv(64)
                assert banner.startswith(b"SSH-2.0")
            finally:
                s.close()
        finally:
            fwd.close()
    finally:
        c.close()


@_needs_sshd
@_needs_agent_bin
def test_live_agent_auth_and_forward(live_sshd_d):
    """Agent login + -A relay against real OpenSSH (remote ssh-add -l)."""
    from ccssh.client import CCSSHClient as _C
    tmp = live_sshd_d["tmp"]
    sock = os.path.join(tmp, "agent.sock")
    ag = _subprocess.run(["ssh-agent", "-a", sock, "-s"], check=False,
                         capture_output=True, text=True)
    if ag.returncode != 0:
        _pytest.skip("ssh-agent cannot run here")
    pid = None
    for line in ag.stdout.splitlines():
        if line.startswith("SSH_AGENT_PID="):
            pid = line.split(";")[0].split("=", 1)[1]
    try:
        _subprocess.run(["ssh-add", live_sshd_d["user"]], check=True,
                        capture_output=True,
                        env={**os.environ, "SSH_AUTH_SOCK": sock})
        # authorized_keys already trusts live_sshd_d["user"].pub
        with open(live_sshd_d["user"] + ".pub") as f:
            pub = f.read()
        with open(os.path.join(tmp, "authorized_keys"), "a") as f:
            f.write(pub if pub.endswith("\n") else pub + "\n")
        c = _C(timeout=10, host_policy="off")
        c.connect("127.0.0.1", port=live_sshd_d["port"], username="root",
                  agent_path=sock)  # no key file, no password: agent only
        try:
            assert c.exec_command("echo agent-live")[0] == "agent-live\n"
            c.forward_agent(sock)
            out, _, code = c.exec_command("echo $SSH_AUTH_SOCK", forward_agent=True)
            assert code == 0 and out.strip(), repr(out)
            out2, err2, code2 = c.exec_command("ssh-add -l")
            assert code2 == 0 and "ED25519" in (out2 + err2), (out2, err2)
        finally:
            c.close()
    finally:
        if pid:
            _subprocess.run(["kill", pid], check=False)


@_needs_sshd
def test_live_x11_refusal_tolerated(live_sshd_d):
    """x11-req against stock sshd (usually refused: no xauth) never breaks login."""
    from ccssh.client import CCSSHClient as _C
    c = _C(timeout=10, host_policy="off")
    c.connect("127.0.0.1", port=live_sshd_d["port"], username="root",
              key_filename=live_sshd_d["user"], use_agent=False)
    try:
        out, _, code = c.exec_command("echo x11-live", x11=True)
        assert (out, code) == ("x11-live\n", 0)
    finally:
        c.close()
