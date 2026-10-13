"""Core roundtrips: wire codecs, KDF/padding, AES-CTR stream, loopback exec."""
from __future__ import annotations
import os
import socket
import threading

from ccssh import wire as W


def test_wire_roundtrips():
    assert W.dec_byte(W.enc_bool(True), 0) == (1, 1)
    assert W.dec_bool(W.enc_bool(False), 0) == (False, 1)
    for v in (0, 1, 255, 2**32 - 1):
        assert W.dec_u32(W.enc_u32(v), 0) == (v, 4)
    for v in (0, 2**64 - 1):
        assert W.dec_u64(W.enc_u64(v), 0) == (v, 8)
    data = os.urandom(64)
    assert W.dec_string(W.enc_string(data), 0) == (data, 4 + len(data))
    names = ["curve25519-sha256", "aes128-ctr"]
    assert W.dec_namelist(W.enc_namelist(names), 0) == (names, 4 + len(",".join(names)))
    for v in (0, 1, 127, 128, 2**256 + 7):
        assert W.dec_mpint(W.enc_mpint(v), 0) == (v, 4 + len(W.enc_mpint(v)) - 4)
    r = W.Reader(W.enc_u32(9) + W.enc_string(b"hi"))
    assert r.u32() == 9 and r.string() == b"hi" and r.rest() == 0
    r.assert_end()


def test_kdf_and_padding():
    from ccssh import crypto as C
    hf = C.HASH_sha256
    K_enc = W.enc_string(b"K" * 32)
    H = b"H" * 32
    # RFC 4253 section 7.2: first block then chained expansion
    k1 = C.kdf(hf, K_enc, H, H, b"C", 32)
    assert len(k1) == 32
    k2 = C.kdf(hf, K_enc, H, H, b"C", 64)
    assert k2[:32] == k1 and len(k2) == 64
    # padding: (4 + 1 + len + pad) % 16 == 0 and pad>=4
    for n in (0, 1, 15, 16, 100, 1000):
        pad = C.pad_packet(1 + n, 16)
        assert pad >= 4 and (4 + 1 + n + pad) % 16 == 0
        blk = C.build_unencrypted_block(b"x" * n, 16)
        assert len(blk) == 4 + 1 + n + pad


def test_aes_ctr_stream_roundtrip():
    from ccssh import crypto as C
    keys = {
        "enc_c2s": os.urandom(16), "iv_c2s": os.urandom(16), "mac_c2s": os.urandom(32),
        "enc_s2c": os.urandom(16), "iv_s2c": os.urandom(16), "mac_s2c": os.urandom(32),
    }
    s = C.AesCtrHmacCtx("aes128-ctr", "hmac-sha2-256", keys["enc_c2s"], keys["iv_c2s"], keys["mac_c2s"])
    r = C.AesCtrHmacCtx("aes128-ctr", "hmac-sha2-256", keys["enc_c2s"], keys["iv_c2s"], keys["mac_c2s"])
    # fresh contexts with identical keys decrypt each other's stream
    pt = os.urandom(128)
    assert r.decrypt_stream(s.encrypt_stream(pt)) == pt
    assert s.mac_of(7, pt) == r.mac_of(7, pt)


def test_curve25519_math_loopback():
    from ccssh import kex as K
    c = K.Curve25519Client()
    assert len(c.qc) == 32
    msg = c.init_msg()
    assert msg[0] == K.MSG_KEX_ECDH_INIT


def test_mlkem_math_loopback():
    from ccssh import mlkem as M
    sess_c, sess_s, _keys = M.run_handshake()
    assert sess_c.K == sess_s.K and sess_c.H == sess_s.H == sess_c.session_id
    assert len(sess_c.K) == M.K_LEN


def _loopback_exec(password=None, key_setup=None, **client_kw):
    import tempfile
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
    kw = dict(timeout=5, host_policy="off")
    kw.update(client_kw)
    c = CCSSHClient(**kw)
    if key_setup is not None:
        key_path = key_setup()
        c.connect("127.0.0.1", port=port, username="u", key_filename=key_path)
    else:
        c.connect("127.0.0.1", port=port, username="u", password=password or "pw")
    try:
        out, err_out, code = c.exec_command("echo hi")
        assert (out, err_out, code) == ("hi\n", "", 0)
    finally:
        c.close()
    th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_loopback_exec_password_mlkem():
    _loopback_exec()


def test_loopback_exec_pubkey(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    def setup():
        # The stub accepts any self-consistent key; the client must load it
        # from disk with strict 0600 permissions.
        priv = Ed25519PrivateKey.generate()
        kf = tmp_path / "id_test"
        kf.write_bytes(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
        kf.chmod(0o600)
        return str(kf)

    _loopback_exec(key_setup=setup)
