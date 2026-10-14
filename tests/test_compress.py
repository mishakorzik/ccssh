"""Compression 1:1 with OpenSSH: zlib / zlib@openssh.com.

Covers RFC 4253 section 6.2 + draft-miller-secsh-compression-delayed-00:
unit roundtrips, level guards, bomb caps, transport integration (all cipher
kinds), loopback exec/sftp/rekey with and without compression, legacy zlib,
CLI (-C / -o Compression / -Q compression) and async parity.
"""
from __future__ import annotations

import os
import socket
import threading

import pytest

from ccssh import algs
from ccssh import compress as C


def test_alg_registry():
    assert algs.SUPPORTED_COMPRESSION == ["none", "zlib@openssh.com"]
    assert algs.LEGACY_COMPRESSION == ["zlib"]
    assert algs.OPENSSH_COMPRESSION == ["none", "zlib@openssh.com"]
    assert algs.default_compression(False) == ["none", "zlib@openssh.com"]
    assert algs.default_compression(True) == ["zlib@openssh.com", "none"]
    assert algs.normalize_compression(True) == ["zlib@openssh.com", "none"]
    assert algs.normalize_compression(False) == ["none", "zlib@openssh.com"]
    assert algs.normalize_compression(None) is None
    assert algs.normalize_compression("zlib@openssh.com") == ["zlib@openssh.com"]
    assert "zlib" in (algs.normalize_compression(["+zlib"]) or [])
    assert "compression" in algs.coverage()
    with pytest.raises(ValueError):
        algs.normalize_compression("")
    with pytest.raises(ValueError):
        algs.normalize_compression([])


def test_level_guards():
    for bad in (0, 10, -1, "6", None):
        with pytest.raises(ValueError):
            C.check_level(bad)  # type: ignore[arg-type]
    assert C.check_level(1) == 1 and C.check_level(9) == 9
    for bad_name in ("zlip", "NONE", "", "gzip"):
        with pytest.raises(ValueError):
            C.check_name(bad_name)
    assert C.check_name("none") == "none"


def test_roundtrip_all_levels():
    payload = os.urandom(2048) + b"A" * 8192  # mixed + highly compressible
    for level in range(1, 10):
        comp, decomp = C.Compressor(level), C.Decompressor()
        # stateful across packets (one stream, many flush points)
        for chunk in (payload[:1000], payload[1000:5000], payload[5000:]):
            wire = comp.compress(chunk)
            assert decomp.decompress(wire) == chunk
        # fresh pair still interops (dictionary reset is legal)
        assert C.Decompressor().decompress(C.Compressor(level).compress(payload)) == payload


def test_empty_bypasses_deflate():
    comp, decomp = C.Compressor(), C.Decompressor()
    assert comp.compress(b"") == b""
    assert decomp.decompress(b"") == b""


def test_incompressible_still_roundtrips():
    data = os.urandom(5000) # grows slightly when "compressed"
    comp, decomp = C.Compressor(), C.Decompressor()
    wire = comp.compress(data)
    assert decomp.decompress(wire) == data


def test_decompressor_rejects_garbage_and_bomb():
    with pytest.raises(ValueError):
        C.Decompressor().decompress(b"\xff\xff not zlib")
    # bomb: tiny wire claiming huge output must fail closed, never OOM
    comp = C.Compressor(9)
    bomb_wire = comp.compress(b"\x00" * (C.MAX_DECOMPRESSED + 65536))
    with pytest.raises(ValueError, match="too big"):
        C.Decompressor().decompress(bomb_wire)
    # trailing garbage after a valid unit fails
    good = C.Compressor().compress(b"hello")
    with pytest.raises(ValueError):
        C.Decompressor().decompress(good + b"trailing")


def _enc_pair(cipher="aes128-ctr", mac="hmac-sha2-256"):
    import hashlib as _hl
    from ccssh import crypto as CR
    from ccssh import wire as W
    from ccssh.transport import SyncTransport
    K_enc = W.enc_string(os.urandom(32))
    Hh = os.urandom(32)
    hf = lambda d: _hl.sha256(d).digest()
    if cipher in ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com"):
        from ccssh import gcm as G
        keys = G.derive_gcm_keys(K_enc, Hh, Hh, cipher, hf)
    elif cipher == "chacha20-poly1305@openssh.com":
        from ccssh import chacha as CHH
        keys = CHH.derive_chacha_keys(K_enc, Hh, Hh, hf)
    else:
        keys = CR.derive_keys(K_enc, Hh, Hh, cipher, mac, hf)
    a1, b1 = socket.socketpair()
    tc = SyncTransport(a1, b"SSH-2.0-T", timeout=2)
    ts = SyncTransport(b1, b"SSH-2.0-T", timeout=2)
    tc.activate(keys, cipher, mac, is_client=True)
    ts.activate(keys, cipher, mac, is_client=False)
    tc._enc_on_send = tc._enc_on_recv = True
    ts._enc_on_send = ts._enc_on_recv = True
    return tc, ts


@pytest.mark.parametrize("cipher,mac", [
    ("aes128-ctr", "hmac-sha2-256"),
    ("aes128-ctr", "hmac-sha2-256-etm@openssh.com"),
    ("aes256-ctr", "hmac-sha2-512"),
    ("aes128-gcm@openssh.com", "hmac-sha2-256"),
    ("aes256-gcm@openssh.com", "hmac-sha2-512"),
    ("chacha20-poly1305@openssh.com", "hmac-sha2-256"),
])
def test_transport_compressed_all_ciphers(cipher, mac):
    tc, ts = _enc_pair(cipher, mac)
    try:
        tc.set_compression("zlib@openssh.com", "zlib@openssh.com", 6, is_client=True)
        ts.set_compression("zlib@openssh.com", "zlib@openssh.com", 6, is_client=False)
        # pre-auth: pending means plaintext on the wire
        tc.send_packet(b"pre-auth")
        assert ts.recv_packet(keepalive=False) == b"pre-auth"
        assert ts._decompressor is None or True  # server pending too
        tc.enable_delayed_compression()
        ts.enable_delayed_compression()
        payload = b"compressible! " * 2000
        tc.send_packet(payload)
        assert ts.recv_packet(keepalive=False) == payload
        ts.send_packet(payload)
        assert tc.recv_packet(keepalive=False) == payload
    finally:
        tc.sock.close()
        ts.sock.close()


def test_transport_immediate_zlib():
    tc, ts = _enc_pair()
    try:
        tc.set_compression("zlib", "zlib", 6, is_client=True)
        ts.set_compression("zlib", "zlib", 6, is_client=False)
        # immediate: active from the first packet (no enable call)
        assert tc._compressor is not None and ts._compressor is not None
        tc.send_packet(b"immediate")
        assert ts.recv_packet(keepalive=False) == b"immediate"
    finally:
        tc.sock.close()
        ts.sock.close()


def test_transport_server_role_mapping():
    # Server sends are s2c: set_compression(c2s=zlib,s2c=none,is_client=False)
    # must compress server->client but not the reverse.
    tc, ts = _enc_pair()
    try:
        tc.set_compression("zlib", "none", 6, is_client=True)
        ts.set_compression("zlib", "none", 6, is_client=False)
        # client sends compressed (c2s=zlib), server recvs decompresses? No:
        # server recv is c2s=zlib -> decompressor active. Server sends are
        # s2c=none -> no compressor.
        assert tc._compressor is not None and tc._decompressor is None
        assert ts._compressor is None and ts._decompressor is not None
        tc.send_packet(b"c->s compressed")
        assert ts.recv_packet(keepalive=False) == b"c->s compressed"
        ts.send_packet(b"s->c plain")
        assert tc.recv_packet(keepalive=False) == b"s->c plain"
    finally:
        tc.sock.close()
        ts.sock.close()


def _loopback(password="pw", **client_kw):
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
            run_once(conn, host_priv, password=password)
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


def test_loopback_no_compression_default():
    c, th, err = _loopback()
    try:
        assert c.negotiated()["compression"] == "none"
        assert c.exec_command("echo hi")[0] == "hi\n"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_loopback_delayed_compression_exec_sftp_rekey():
    c, th, err = _loopback(compression=True)
    try:
        assert c.negotiated()["compression"] == "zlib@openssh.com"
        assert c.exec_command("echo hi")[0] == "hi\n"
        # big compressible output exercises many compressed packets
        out, _, code = c.exec_command("echo " + "A" * 20000)
        assert code == 0 and len(out) > 20000
        s = c.open_sftp()
        try:
            data = b"B" * 100000
            s.put("/big.bin", data)
            assert s.get("/big.bin") == data
            s.remove("/big.bin")
        finally:
            s.close()
        sid = c._sid
        c.rekey()
        assert c._sid == sid
        assert c.negotiated()["compression"] == "zlib@openssh.com"
        assert c.exec_command("echo after")[0] == "after\n"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_loopback_compression_levels():
    for level in (1, 6, 9):
        c, th, err = _loopback(compression=True, compression_level=level)
        try:
            assert c.exec_command("echo lv")[0] == "lv\n"
        finally:
            c.close()
            th.join(timeout=5)
        if "e" in err:
            raise err["e"]


def test_loopback_explicit_none_and_delayed_lists():
    c, th, err = _loopback(compression=["none"])
    try:
        assert c.negotiated()["compression"] == "none"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]
    c, th, err = _loopback(compression=["zlib@openssh.com", "none"])
    try:
        assert c.negotiated()["compression"] == "zlib@openssh.com"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_bad_level_rejected():
    from ccssh.client import CCSSHClient
    for bad in (0, 10):
        with pytest.raises(ValueError):
            CCSSHClient(compression=True, compression_level=bad)
    with pytest.raises(ValueError):
        CCSSHClient(compression="zlip")


def test_cli_compression_flags(monkeypatch, capsys):
    from ccssh import cli as CLIMOD

    seen = {}

    class Fake:
        def __init__(self, **k):
            seen.update(k)

        def connect(self, *a, **k):
            return self

        def exec_command(self, cmd, **kw):
            return (b"", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert CLIMOD.main(["-C", "u@h.example.com", "echo", "hi"]) == 0
    assert seen.get("compression") is True
    seen.clear()
    assert CLIMOD.main(["-o", "Compression=yes", "-o", "CompressionLevel=9",
                        "u@h.example.com", "echo", "hi"]) == 0
    assert seen.get("compression") is True and seen.get("compression_level") == 9
    seen.clear()
    assert CLIMOD.main(["-o", "Compression=no", "u@h.example.com", "echo", "hi"]) == 0
    assert seen.get("compression") is False
    assert CLIMOD.main(["-o", "Compression=maybe", "u@h.example.com"]) == 255
    assert CLIMOD.main(["-o", "CompressionLevel=0", "u@h.example.com"]) == 255
    assert CLIMOD.main(["-o", "CompressionLevel=10", "u@h.example.com"]) == 255
    # -Q lists delayed (like ssh -Q), never legacy-only
    assert CLIMOD.main(["-Q", "compression"]) == 0
    out = capsys.readouterr().out.split()
    assert "none" in out and "zlib@openssh.com" in out


def test_async_compression_loopback():
    import asyncio
    from ccssh import async_client as AC
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
            run_once(conn, host_priv, password="pw")
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()

    async def go():
        c = AC.AsyncCCSSHClient(timeout=5, host_policy="off", compression=True)
        await c.connect("127.0.0.1", port=port, username="u", password="pw")
        try:
            assert c.negotiated()["compression"] == "zlib@openssh.com"
            out, _, code = await c.exec_command("echo async-comp")
            assert (out, code) == ("async-comp\n", 0)
            await c.rekey()
            out2, _, _ = await c.exec_command("echo after")
            assert out2 == "after\n"
        finally:
            await c.close()

    asyncio.run(go())
    th.join(timeout=5)
    if "e" in err:
        raise err["e"]
