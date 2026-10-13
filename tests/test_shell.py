"""Shell channel tests: pty/shell codecs, loopback echo-shell, CLI dispatch."""
from __future__ import annotations
import queue
import socket
import threading
import time
import types

import pytest

from ccssh import channel as CH
from ccssh import wire as W


def test_pty_req_codec():
    pkt = CH.enc_pty_req(7, "xterm-256color", 100, 40)
    r = W.Reader(pkt)
    assert r.byte() == CH.MSG_CHANNEL_REQUEST
    assert r.u32() == 7
    assert r.string() == b"pty-req"
    assert r.bool() is True
    assert r.string() == b"xterm-256color"
    assert (r.u32(), r.u32(), r.u32(), r.u32()) == (100, 40, 0, 0)
    assert r.string() == b"" # default modes: everything stays default


def test_shell_codec():
    pkt = CH.enc_shell(9)
    r = W.Reader(pkt)
    assert r.byte() == CH.MSG_CHANNEL_REQUEST
    assert r.u32() == 9
    assert r.string() == b"shell"
    assert r.bool() is True
    assert r.rest() == 0


def test_window_change_codec():
    pkt = CH.enc_window_change(9, 132, 50)
    r = W.Reader(pkt)
    assert r.byte() == CH.MSG_CHANNEL_REQUEST
    assert r.u32() == 9
    assert r.string() == b"window-change"
    assert r.bool() is False # never expect a reply
    assert (r.u32(), r.u32()) == (132, 50)


def test_eof_codec():
    pkt = CH.enc_eof(9)
    r = W.Reader(pkt)
    assert r.byte() == CH.MSG_CHANNEL_EOF
    assert r.u32() == 9


def _loopback_shell(command=None, **kw):
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
            run_once(conn, host_priv, password="pw")
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()
    c = CCSSHClient(timeout=5, host_policy="off")
    c.connect("127.0.0.1", port=port, username="u", password="pw")
    sess = c.open_shell(command=command, **kw)
    return c, sess, th, ls, err


def _drain_data(client, want: bytes, timeout: float = 5.0) -> bytes:
    """Read raw channel DATA until `want` appears (recipient-agnostic)."""
    from ccssh.transport import CCSSHError
    buf = b""
    deadline = time.monotonic() + timeout
    while want not in buf:
        if time.monotonic() > deadline:
            raise CCSSHError(f"shell echo timeout waiting for {want!r}")
        p = client._t.recv_packet()
        if not p or p[0] != CH.MSG_CHANNEL_DATA:
            continue
        rr = W.Reader(p)
        rr.byte()
        rr.u32() # recipient: stub echo uses its own id, real servers ours
        buf += rr.string()
    return buf


def _drain_close(client, timeout: float = 5.0) -> None:
    """
     Read until the server's CHANNEL_CLOSE so both sides shut down cleanly.

     Without this the client may close (RST) while the stub is still
     writing its goodbye, flaking the server thread with BrokenPipeError
     under load - a test artefact, not a product bug.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            p = client._t.recv_packet()
        except Exception:
            return
        if p and p[0] == CH.MSG_CHANNEL_CLOSE:
            return


def test_shell_echo_loopback():
    c, sess, th, ls, err = _loopback_shell(pty=False)
    try:
        sess.send(b"echo-me\n")
        assert b"echo-me" in _drain_data(c, b"echo-me")
    finally:
        sess.send_eof()
        _drain_close(c)
        sess.close()
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_pty_exec_loopback():
    c, sess, th, ls, err = _loopback_shell(command="echo pty-hi")
    try:
        assert b"pty-hi" in _drain_data(c, b"pty-hi")
        assert sess.exit_status is None or isinstance(sess.exit_status, int)
    finally:
        _drain_close(c)
        sess.close()
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_connect_family_ipv4_loopback():
    import socket as _sock
    c, sess, th, ls, err = _loopback_shell(pty=False)
    try:
        assert sess.srv > 0
    finally:
        sess.close()
        c.close()
        th.join(timeout=5)
    _ = _sock.AF_INET
    if "e" in err:
        raise err["e"]


def test_connect_family_mismatch_fails_fast():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh.stub import run_once
    from ccssh.client import CCSSHClient
    import socket as _sock
    from ccssh.transport import CCSSHError
    host_priv = Ed25519PrivateKey.generate()
    ls = _sock.socket(_sock.AF_INET)
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = ls.getsockname()[1]

    def srv():
        try:
            conn, _ = ls.accept()
            run_once(conn, host_priv, password="pw")
            conn.close()
        except Exception:
            pass
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()
    c = CCSSHClient(timeout=3, host_policy="off")
    with pytest.raises(CCSSHError):
        # No IPv6 loopback listener exists for this socket: fast failure,
        # not a hang.
        c.connect("127.0.0.1", port=port, username="u", password="pw", family=_sock.AF_INET6)
    c.close()
    th.join(timeout=5)


class _FakeTransport:
    def __init__(self):
        self.q: queue.Queue = queue.Queue()

    def recv_packet(self, **kw):
        return self.q.get(timeout=5)

    def send_packet(self, payload: bytes) -> None:
        pass


class _FakeSession:
    def __init__(self):
        self.srv = 1
        self.consumed = 0
        self.exit_status: int | None = None
        self.eof_received = False
        self.eof_sent = False
        self.closed = False

    def send(self, data: bytes) -> None:
        pass

    def send_eof(self) -> None:
        self.eof_sent = True

    def window_change(self, cols: int, rows: int) -> None:
        pass

    def window_adjust(self) -> None:
        pass

    def credit(self, delta: int) -> None:
        pass

    def close(self):
        self.closed = True
        return self.exit_status


def _data_packet(text: bytes) -> bytes:
    return bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(1) + W.enc_string(text)


def _close_packet() -> bytes:
    return bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(1)


def test_interactive_returns_when_server_closes_first(monkeypatch, capfd):
    """
     Ctrl+D case: remote bash exits -> CLOSE arrives while stdin is idle.
     Must return promptly, not hang on the stdin read (ex-Ctrl+C hang).
    """
    from ccssh.shell import run_interactive

    t, sess = _FakeTransport(), _FakeSession()
    client = types.SimpleNamespace(_t=t)
    t.q.put(_data_packet(b"hi"))
    t.q.put(_close_packet())
    sin, sout = socket.socketpair() # peer stays open: no stdin EOF ever
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(
        fileno=sin.fileno, isatty=lambda: False))
    try:
        t0 = time.monotonic()
        rc = run_interactive(client, sess)
        dt = time.monotonic() - t0
    finally:
        sin.close()
        sout.close()
    assert rc == 0
    assert dt < 8, f"hung {dt:.1f}s on stdin instead of exiting on CLOSE"
    assert sess.eof_sent is False # exit came from the server, not stdin
    assert sess.closed is True
    assert capfd.readouterr().out == "hi"


def test_interactive_stdin_eof_half_closes(monkeypatch):
    """
     Piped stdin ending: EOF is forwarded, queued output still drains,
     the remote exit status is returned. CLOSE is delivered only after the
     client forwarded EOF, so the half-close path is exercised deterministically.
    """
    from ccssh.shell import run_interactive

    t, sess = _FakeTransport(), _FakeSession()
    client = types.SimpleNamespace(_t=t)
    t.q.put(_data_packet(b"bye"))
    t.q.put(bytes([CH.MSG_CHANNEL_REQUEST]) + W.enc_u32(1) + W.enc_string(b"exit-status") + W.enc_bool(False) + W.enc_u32(3))
    t.q.put(bytes([CH.MSG_CHANNEL_EOF]) + W.enc_u32(1))
    sin, sout = socket.socketpair()
    sout.close() # immediate local EOF
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(
        fileno=sin.fileno, isatty=lambda: False))
    out: dict = {}
    th = threading.Thread(target=lambda: out.setdefault(
        "rc", run_interactive(client, sess)), daemon=True)
    try:
        th.start()
        deadline = time.monotonic() + 5.0
        while not sess.eof_sent and time.monotonic() < deadline:
            time.sleep(0.01)
        assert sess.eof_sent is True
        t.q.put(_close_packet())
        th.join(timeout=5)
        assert out.get("rc") == 3
        assert sess.eof_received is True
    finally:
        sin.close()
    assert not th.is_alive()


def test_jump_through_channel_socket():
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
            run_once(conn, host_priv, password="pw")
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()
    jump = CCSSHClient(timeout=5, host_policy="off")
    jump.connect("127.0.0.1", port=port, username="u", password="pw")
    try:
        tun = jump.open_channel_socket("127.0.0.1", port)
        tun.close()
    finally:
        jump.close()
    th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_cli_no_command_opens_shell(monkeypatch):
    from ccssh import cli as CLIMOD
    from ccssh.cli import main

    calls = {}

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, *a, **k):
            return self

        def negotiated(self):
            return {"cipher": "aes128-ctr"}

        def close(self):
            calls["closed"] = True

    def fake_shell(c, **kw):
        calls["shell"] = c
        calls["kw"] = kw
        return 3

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    monkeypatch.setattr("ccssh.shell.run_interactive", fake_shell)
    assert main(["u@h.example.com"]) == 3
    assert isinstance(calls["shell"], Fake) and calls.get("closed")
    assert calls["kw"].get("pty", True) is True


def test_cli_password_prompt(monkeypatch):
    from ccssh import cli as CLIMOD
    from ccssh.client import AuthError

    prompts = []

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, hostname, *, port, username, password, **kw):
            if password == "secret":
                return self
            raise AuthError("password rejected")

    def fake_getpass(text):
        prompts.append(text)
        return "secret"

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    monkeypatch.setattr("ccssh.cli.getpass.getpass", fake_getpass)
    # Transport is mocked: skip the real TCP preflight dial.
    monkeypatch.setattr(CLIMOD, "_preflight_tcp", lambda *a, **k: None)
    c = CLIMOD._connect_first_working({}, "10.0.0.10", port=2022, username="he1zen", password=None, identities=[], cert=None, verbose=0, prompt=True)
    assert isinstance(c, Fake)
    assert prompts == ["he1zen@10.0.0.10's password: "]


def test_encrypted_key_needs_passphrase(tmp_path):
    pytest.importorskip("bcrypt")  # OpenSSH PEM encryption needs it
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh.client import _load_user_priv
    from ccssh import cli as CLIMOD

    priv = Ed25519PrivateKey.generate()
    kf = tmp_path / "id_enc"
    kf.write_bytes(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.BestAvailableEncryption(b"pp")))
    kf.chmod(0o600)  # group/world-readable keys are refused before parsing
    try:
        _load_user_priv(str(kf), None)
        raised = None
    except Exception as e:
        raised = e
    assert raised is not None and CLIMOD._needs_passphrase(raised)
    assert _load_user_priv(str(kf), "pp") is not None
    kf.chmod(0o644)
    with pytest.raises(Exception, match="world-readable|group"):
        _load_user_priv(str(kf), "pp")
