"""Loopback + unit tests for the sync/async clients, crypto and CLI."""
from __future__ import annotations
import base64
import hashlib
import os
import socket
import threading
import time
import types

import pytest

from ccssh import algs
from ccssh import channel as CH
from ccssh import hostkeys as HK
from ccssh import kex_ext as KX
from ccssh.cli import build_parser, parse_destination, parse_o_options, main
from ccssh import wire as W
import ccssh.mlkem as H


def _loopback(password="pw", sftp_root=None, **client_kw):
    """Stub sshd on 127.0.0.1 + connected client. Returns (client, thread, err)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh.stub import run_once
    from ccssh.client import CCSSHClient as _C

    host_priv = Ed25519PrivateKey.generate()
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = ls.getsockname()[1]
    err = {}

    def srv():
        try:
            conn, _ = ls.accept()
            run_once(conn, host_priv, password=password,
                     sftp_root=sftp_root() if callable(sftp_root) else sftp_root)
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()
    kw = dict(timeout=5, host_policy="off")
    kw.update(client_kw)
    c = _C(**kw)
    c.connect("127.0.0.1", port=port, username="u", password=password)
    return c, th, err, host_priv


def test_coverage_honest():
    cov = algs.coverage()
    assert int(cov["kex"].split("/")[0]) >= 12
    assert int(cov["cipher"].split("/")[0]) >= 6
    assert "sntrup761x25519-sha512" in algs.SUPPORTED_KEX
    assert "ssh-dss" in algs.LEGACY_HOSTKEYS
    assert "ssh-dss" not in algs.SUPPORTED_HOSTKEYS
    # legacy is implemented but never offered by default
    assert "3des-cbc" in algs.LEGACY_CIPHERS
    assert "3des-cbc" not in algs.SUPPORTED_CIPHERS
    assert "hmac-md5" in algs.LEGACY_MACS
    assert "hmac-md5" not in algs.SUPPORTED_MACS
    assert "diffie-hellman-group1-sha1" in algs.LEGACY_KEX
    # every list is strongest-first
    assert algs.SUPPORTED_CIPHERS[0] == "aes256-gcm@openssh.com"
    assert algs.SUPPORTED_MACS[0] == "hmac-sha2-512-etm@openssh.com"


def test_normalize_list_plus_minus_caret():
    assert algs.normalize_list(algs.MAX_KEX, None) is None
    assert algs.normalize_list(algs.SUPPORTED_CIPHERS, ["+3des-cbc"])[-1] == "3des-cbc"
    assert "aes128-ctr" in algs.normalize_list(algs.SUPPORTED_CIPHERS, ["+3des-cbc"])
    assert "aes128-ctr" not in algs.normalize_list(algs.SUPPORTED_CIPHERS, ["-aes128-ctr"])
    assert algs.normalize_list(["a", "b"], ["^c"]) == ["c", "a", "b"]
    assert algs.normalize_list(algs.SUPPORTED_CIPHERS, ["aes128-ctr"]) == ["aes128-ctr"]
    assert algs.MAX_KEX[0] == "mlkem768x25519-sha256"
    assert algs.MAX_CIPHERS[0] == "aes256-gcm@openssh.com"
    assert algs.MAX_MACS[0] == "hmac-sha2-512-etm@openssh.com"
    assert algs.MAX_HOSTKEYS[0] == "ssh-mldsa44-ed25519"


def test_cipher_variants_roundtrip():
    from ccssh import crypto as C
    from ccssh import gcm as G
    from ccssh import chacha as CHACHA
    for cipher, klen in (("aes128-ctr", 16), ("aes192-ctr", 24), ("aes256-ctr", 32)):
        for mac in ("hmac-sha2-256", "hmac-sha2-256-etm@openssh.com"):
            ms = C.MAC_SPECS[mac]
            # same-key pair decrypts (fresh contexts share the key schedule input)
            key, iv, mk = os.urandom(klen), os.urandom(16), os.urandom(ms["key_len"])
            a = C.AesCtrHmacCtx(cipher, mac, key, iv, mk)
            b = C.AesCtrHmacCtx(cipher, mac, key, iv, mk)
            pt = os.urandom(48)
            assert b.decrypt_stream(a.encrypt_stream(pt)) == pt
            assert a.mac_of(12, pt) == b.mac_of(12, pt)
    for gcipher in ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com"):
        keys = G.derive_gcm_keys(W.enc_string(b"K" * 32), b"H" * 32, b"H" * 32, gcipher)
        c = G.AesGcmCtx(gcipher, keys["enc_c2s"], keys["iv_c2s"])
        d = G.AesGcmCtx(gcipher, keys["enc_c2s"], keys["iv_c2s"])
        pt = d.open(c.seal(b"payload"))
        assert pt[1:len(pt) - pt[0]] == b"payload"
    keys = CHACHA.derive_chacha_keys(W.enc_string(b"K" * 32), b"H" * 32, b"H" * 32)
    c1 = CHACHA.ChachaSshCtx(keys["enc_c2s"])
    c2 = CHACHA.ChachaSshCtx(keys["enc_c2s"])
    from ccssh.crypto import pad_len_aad
    import struct
    pad = pad_len_aad(5, 8)
    body = bytes([pad]) + b"hello" + os.urandom(pad)
    wire = c1.seal(7, struct.pack(">I", len(body)), body)
    plen, pblk = c2.open(7, wire)
    assert pblk[1:len(pblk) - pblk[0]] == b"hello"
    assert struct.unpack(">I", plen)[0] == len(body)
def test_ecdh_all_curves():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    host_priv = Ed25519PrivateKey.generate()
    for name in ("ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"):
        c = KX.EcdhClient(name)
        s = KX.EcdhServerStub(name, host_priv)
        reply, K_srv, H_srv = s.reply(c.init_msg(), b"Vc", b"Vs", b"Ic", b"Is")
        K_raw, Hh, _Ks = c.finish(reply, b"Vc", b"Vs", b"Ic", b"Is")
        assert K_raw == K_srv and Hh == H_srv


def test_dh14_math():
    from ccssh import kex_ext as KX2
    from ccssh.dh_groups import P14_2048
    assert P14_2048.bit_length() == 2048
    c = KX2.Dh14Client()
    assert c.p == P14_2048 and c.init_msg()[0] == 30


def test_dh_all_groups_math():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    host_priv = Ed25519PrivateKey.generate()
    for name in KX.DH_GROUPS:
        c = KX.DhClient(name)
        s = KX.DhServerStub(name, host_priv)
        reply, K_srv, H_srv = s.reply(c.init_msg(), b"Vc", b"Vs", b"Ic", b"Is")
        K_raw, Hh, _Ks = c.finish(reply, b"Vc", b"Vs", b"Ic", b"Is")
        assert K_raw == K_srv and Hh == H_srv


def test_gex_math_loopback():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    host_priv = Ed25519PrivateKey.generate()
    c = KX.GexClient()
    s = KX.GexServerStub(host_priv)
    init = c.init_msg(s.reply_request(c.request_msg()))
    reply, K_srv, H_srv = s.reply_init(init, b"Vc", b"Vs", b"Ic", b"Is")
    K_raw, Hh, _Ks = c.finish(reply, b"Vc", b"Vs", b"Ic", b"Is")
    assert K_raw == K_srv and Hh == H_srv


def test_sntrup_fake_backend_loopback():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import sntrup as SN
    be = SN.FakeBackend()
    host_priv = Ed25519PrivateKey.generate()
    st = SN.client_create(b"Vc", b"Ic", be)
    assert len(st.C_INIT) == SN.C_INIT_LEN
    s_reply, Ks, sig, sess_s = SN.server_process_init(
        host_priv=host_priv, V_C=b"Vc", V_S=b"Vs", I_C=b"Ic", I_S=b"Is",
        C_INIT=st.C_INIT, backend=be)
    assert len(s_reply) == SN.S_REPLY_LEN
    sess_c = SN.client_process_reply(st, V_S=b"Vs", I_S=b"Is", K_S=Ks, S_REPLY=s_reply, sig_inner=sig)
    assert sess_c.K == sess_s.K and sess_c.H == sess_s.H


def test_sntrup_framing_fake_backend():
    from ccssh import sntrup as SN
    import pytest
    be = SN.FakeBackend()
    st = SN.client_create(b"Vc", b"Ic", be)
    assert len(st.C_INIT) == 1158 + 32
    with pytest.raises(ValueError):
        SN.client_process_reply(st, V_S=b"Vs", I_S=b"Is", K_S=b"k", S_REPLY=b"short", sig_inner=b"s")


def test_kex_alias_libssh():
    from ccssh import kex as K
    assert KX.KEX_ALIASES.get("curve25519-sha256@libssh.org") == "curve25519-sha256"
    assert KX.KEX_ALIASES.get("sntrup761x25519-sha512@openssh.com") == "sntrup761x25519-sha512"
    assert K.negotiate(["curve25519-sha256"], ["curve25519-sha256"]) == "curve25519-sha256"


def test_mlkem_p256_math():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
    from ccssh import mlkem as M
    host_priv = Ed25519PrivateKey.generate()
    Ks = M.hostkey_blob_from_priv(host_priv)
    c = KX.MlkemP256Client(b"Vc", b"Ic")
    assert len(c.c_init) == 1184 + 65
    # manual server side: encap + ephemeral P-256 share + sign
    ek, x_pk_c = c.c_init[:1184], c.c_init[1184:]
    assert len(x_pk_c) == 65
    Kpq, ct = MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
    assert len(Kpq) == 32 and len(ct) == 1088
    sk_s = ec.generate_private_key(ec.SECP256R1())
    Qs = sk_s.public_key().public_numbers()
    size = 32
    Qs_raw = b"\x04" + Qs.x.to_bytes(size, "big") + Qs.y.to_bytes(size, "big")
    from ccssh.kex_ext import _point_decode
    Kec = sk_s.exchange(ec.ECDH(), _point_decode(ec.SECP256R1(), x_pk_c))
    K_raw = hashlib.sha256(Kpq + Kec).digest()
    S_reply = ct + Qs_raw
    import hashlib as _hl2
    Hh = _hl2.sha256(W.enc_string(b"Vc") + W.enc_string(b"Vs")
                     + W.enc_string(b"Ic") + W.enc_string(b"Is")
                     + W.enc_string(Ks) + W.enc_string(c.c_init)
                     + W.enc_string(S_reply) + W.enc_string(K_raw)).digest()
    sig = M.sign_exchange_hash(host_priv, Hh)
    reply = bytes([31]) + W.enc_string(Ks) + W.enc_string(S_reply) + W.enc_string(sig)
    K_out, H_out, Ks_out = c.finish(reply, b"Vs", b"Is")
    assert K_out == K_raw and H_out == Hh and Ks_out == Ks


def test_hostkeys_ecdsa_rsa_verify():
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    Hh = bytes(32)
    # ed25519 roundtrip
    priv = Ed25519PrivateKey.generate()
    blob = H.hostkey_blob_from_priv(priv)
    assert HK.verify_host_signature(blob, "ssh-ed25519", Hh, H.sign_exchange_hash(priv, Hh))
    assert not HK.verify_host_signature(blob, "ssh-ed25519", b"\x01" + Hh[1:], H.sign_exchange_hash(priv, Hh))
    # ecdsa + rsa via the userauth signer (same nested-wire codec family)
    for alg, maker in (("ecdsa-sha2-nistp256", lambda: ec.generate_private_key(ec.SECP256R1())),
                       ("ecdsa-sha2-nistp384", lambda: ec.generate_private_key(ec.SECP384R1())),
                       ("ecdsa-sha2-nistp521", lambda: ec.generate_private_key(ec.SECP521R1()))):
        p = maker()
        nums = p.public_key().public_numbers()
        size = (p.key_size + 7) // 8
        q = b"\x04" + nums.x.to_bytes(size, "big") + nums.y.to_bytes(size, "big")
        curve_ssh = {"ecdsa-sha2-nistp256": b"nistp256", "ecdsa-sha2-nistp384": b"nistp384", "ecdsa-sha2-nistp521": b"nistp521"}[alg]
        Ks = W.enc_string(alg.encode()) + W.enc_string(curve_ssh) + W.enc_string(q)
        nested = HK.sign_userauth(p, alg, Hh)
        assert HK.verify_host_signature(Ks, alg, Hh, nested)
        assert not HK.verify_host_signature(Ks, alg, Hh, nested[:-2] + b"\x00\x00")
    rp = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    rnums = rp.public_key().public_numbers()
    Ks = W.enc_string(b"ssh-rsa") + W.enc_mpint(rnums.e) + W.enc_mpint(rnums.n)
    nested = HK.sign_userauth(rp, "rsa-sha2-256", Hh)
    assert HK.verify_host_signature(Ks, "rsa-sha2-256", Hh, nested)
    assert not HK.verify_host_signature(Ks, "rsa-sha2-256", Hh + b"\x00", nested)


def test_rsa_sig_tied_to_negotiation():
    from cryptography.hazmat.primitives.asymmetric import rsa
    Hh = bytes(32)
    rp = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    rnums = rp.public_key().public_numbers()
    Ks = W.enc_string(b"ssh-rsa") + W.enc_mpint(rnums.e) + W.enc_mpint(rnums.n)
    sig256 = HK.sign_userauth(rp, "rsa-sha2-256", Hh)
    sig512 = HK.sign_userauth(rp, "rsa-sha2-512", Hh)
    assert HK.verify_host_signature(Ks, "rsa-sha2-256", Hh, sig256)
    assert HK.verify_host_signature(Ks, "rsa-sha2-512", Hh, sig512)
    # cross-wired negotiation fails closed
    assert not HK.verify_host_signature(Ks, "rsa-sha2-256", Hh, sig512)
    assert not HK.verify_host_signature(Ks, "rsa-sha2-512", Hh, sig256)


def test_check_secret_nonzero():
    import pytest
    H.check_secret_nonzero(os.urandom(32))
    with pytest.raises(ValueError):
        H.check_secret_nonzero(bytes(32))


def test_negotiate_symmetric_rejects_asymmetry():
    from ccssh import kex as K
    import pytest
    assert K.negotiate_symmetric(["a", "b"], ["a", "b"], ["a", "b"], "cipher") == "a"
    with pytest.raises(ValueError):
        K.negotiate_symmetric(["a", "b"], ["a"], ["b"], "cipher")


def test_dh_rejects_degenerate_peer_value():
    import pytest
    from ccssh import wire as W2
    for name in ("diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"):
        c = KX.DhClient(name)
        for bad in (0, 1, c.p - 1, c.p, c.p + 1):
            reply = bytes([31]) + W2.enc_string(b"ks") + W2.enc_mpint(bad) + W2.enc_string(b"sig")
            with pytest.raises(ValueError):
                c.finish(reply, b"Vc", b"Vs", b"Ic", b"Is")


def test_first_follows_decoy_skipped():
    from ccssh.client import CCSSHClient as _C

    class FakeT:
        def __init__(self):
            self.discarded = 0

        def recv_packet(self):
            self.discarded += 1
            return b"decoy"

    # peer guessed ecdh but we agreed on curve25519 -> decoy must be dropped
    _C._skip_unmatched_guess(FakeT(), {"first_follows": True, "kex": ["ecdh-sha2-nistp256", "curve25519-sha256"]}, ["curve25519-sha256", "ecdh-sha2-nistp256"], "curve25519-sha256")
    t = FakeT()
    _C._skip_unmatched_guess(t, {"first_follows": True, "kex": ["curve25519-sha256", "ecdh-sha2-nistp256"]}, ["curve25519-sha256", "ecdh-sha2-nistp256"], "curve25519-sha256")
    assert t.discarded == 0
    t2 = FakeT()
    _C._skip_unmatched_guess(t2, {"first_follows": False, "kex": ["curve25519-sha256"]}, ["curve25519-sha256"], "curve25519-sha256")
    assert t2.discarded == 0


def test_gcm_roundtrip_both_sizes():
    from ccssh import gcm as G
    from ccssh import wire as W2
    for cipher in ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com"]:
        keys = G.derive_gcm_keys(W2.enc_string(b"K" * 32), b"H" * 32, b"H" * 32, cipher)
        a = G.AesGcmCtx(cipher, keys["enc_c2s"], keys["iv_c2s"])
        b = G.AesGcmCtx(cipher, keys["enc_c2s"], keys["iv_c2s"])
        pt = b.open(a.seal(b"roundtrip"))
        assert pt[1:len(pt) - pt[0]] == b"roundtrip"


def test_chacha_roundtrip_and_poly1305():
    import struct
    import pytest
    from ccssh import chacha as C2
    from ccssh.crypto import pad_len_aad
    keys = C2.derive_chacha_keys(W.enc_string(b"K" * 32), b"H" * 32, b"H" * 32)
    a = C2.ChachaSshCtx(keys["enc_c2s"])
    b = C2.ChachaSshCtx(keys["enc_c2s"])
    pad = pad_len_aad(3, 8)
    body = bytes([pad]) + b"hey" + os.urandom(pad)
    plen = struct.pack(">I", len(body))
    wire = a.seal(11, plen, body)
    rplen, pblk = b.open(11, wire)
    assert rplen == plen and pblk == body
    # length decrypts statelessly; tags reject tampering and wrong seq
    assert b.decrypt_length(11, wire[:4]) == plen
    with pytest.raises(ValueError):
        b.open(12, wire)
    bad = bytearray(wire)
    bad[5] ^= 1
    with pytest.raises(ValueError):
        b.open(11, bytes(bad))
def _make_cert(host="db.internal", **kw):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import certs as CERT
    ca = Ed25519PrivateKey.generate()
    host_priv = Ed25519PrivateKey.generate()
    host_pub = host_priv.public_key().public_bytes_raw()
    blob = CERT.build_cert(keytype="ssh-ed25519-cert-v01@openssh.com", pub_fields=W.enc_string(host_pub), principals=host, ca_priv=ca, **kw)
    info = CERT.parse_cert(blob)
    ca_blob = info["sig_key"]
    return blob, ca_blob, info


def test_cert_verify_ok_and_tamper():
    from ccssh import certs as CERT
    blob, ca_blob, info = _make_cert()
    assert info["principals"] == ["db.internal"] and info["role"] == CERT.CERT_TYPE_HOST
    out = CERT.verify_cert(blob, expected_principal="db.internal", is_host=True, ca_blobs=[ca_blob])
    assert out["principals"] == ["db.internal"]
    bad = bytearray(blob)
    bad[-5] ^= 1
    try:
        CERT.verify_cert(bytes(bad), expected_principal="db.internal", is_host=True, ca_blobs=[ca_blob])
        raise AssertionError("tampered cert accepted")
    except CERT.CertError:
        pass


def test_cert_rejects_expired_principal_critical_untrusted():
    from ccssh import certs as CERT
    import pytest
    blob, ca_blob, _ = _make_cert()
    with pytest.raises(CERT.CertError):
        CERT.verify_cert(blob, expected_principal="other.internal", is_host=True,
                         ca_blobs=[ca_blob])
    with pytest.raises(CERT.CertError):
        CERT.verify_cert(blob, expected_principal="db.internal", is_host=False,
                         ca_blobs=[ca_blob])
    with pytest.raises(CERT.CertError):
        CERT.verify_cert(blob, expected_principal="db.internal", is_host=True,
                         ca_blobs=[])
    short, short_ca, _ = _make_cert(valid_after=100, valid_before=200)
    with pytest.raises(CERT.CertError):
        CERT.verify_cert(short, expected_principal="db.internal", is_host=True,
                         ca_blobs=[short_ca], now=300)
    inv, inv_ca, _ = _make_cert(valid_after=500, valid_before=100)
    with pytest.raises(CERT.CertError):
        CERT.verify_cert(inv, expected_principal="db.internal", is_host=True,
                         ca_blobs=[inv_ca], now=550)
    crit = W.enc_string(b"weird-opt@x") + W.enc_string(b"1")
    weird, weird_ca, _ = _make_cert(critical=crit)
    with pytest.raises(CERT.CertError):
        CERT.verify_cert(weird, expected_principal="db.internal", is_host=True,
                         ca_blobs=[weird_ca])
    must_touch = W.enc_string(b"verify-required") + W.enc_string(b"")
    touch, touch_ca, _ = _make_cert(critical=must_touch)
    with pytest.raises(CERT.CertError):
        CERT.verify_cert(touch, expected_principal="db.internal", is_host=True,
                         ca_blobs=[touch_ca])


def test_client_accepts_ca_cert_via_known_hosts(tmp_path):
    from ccssh.hostcheck import check_hostkey
    blob, ca_blob, _ = _make_cert()
    kh = tmp_path / "known_hosts"
    kh.write_text(f"@cert-authority * ssh-ed25519 {base64.b64encode(ca_blob).decode()}\n")
    check_hostkey("db.internal", 22, blob, "ssh-ed25519-cert-v01@openssh.com",
                  policy="strict", known_hosts=str(kh))


def test_hashed_known_hosts(tmp_path):
    import hashlib as _hl
    import hmac as _hm
    from ccssh.hostcheck import check_hostkey, HostKeyError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M2
    priv = Ed25519PrivateKey.generate()
    Ks = M2.hostkey_blob_from_priv(priv)
    salt = os.urandom(20)
    digest = _hm.new(salt, b"h.example.com", _hl.sha1).digest()
    hashed = f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()}"
    kh = tmp_path / "known_hosts"
    kh.write_text(f"{hashed} ssh-ed25519 {base64.b64encode(Ks).decode()}\n")
    check_hostkey("h.example.com", 22, Ks, "ssh-ed25519", policy="strict", known_hosts=str(kh))
    other = M2.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    try:
        check_hostkey("h.example.com", 22, other, "ssh-ed25519", policy="strict", known_hosts=str(kh))
        raise AssertionError("changed key accepted")
    except HostKeyError as e:
        assert "CHANGED" in str(e)


def test_revoked_key_rejected_everywhere(tmp_path):
    import pytest
    from ccssh.hostcheck import check_hostkey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M2
    Ks = M2.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    kh = tmp_path / "known_hosts"
    kh.write_text(f"@revoked h.example.com ssh-ed25519 {base64.b64encode(Ks).decode()}\n")
    for policy in ("strict", "accept-new"):
        with pytest.raises(Exception, match="[Rr]evoked|[Rr]EVOKED"):
            check_hostkey("h.example.com", 22, Ks, "ssh-ed25519",
                          policy=policy, known_hosts=str(kh))


def test_alg_mismatch_rejected(tmp_path):
    import pytest
    from ccssh.hostcheck import check_hostkey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M2
    Ks = M2.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    with pytest.raises(Exception, match="!= negotiated"):
        check_hostkey("h.example.com", 22, Ks, "ecdsa-sha2-nistp256", policy="strict", known_hosts=str(tmp_path / "nonexistent"))
    assert not HK.verify_host_signature(Ks, "ssh-ed25519", bytes(32), b"junk")


def test_sftp_roundtrip_loopback(tmp_path):
    sftp_root = str(tmp_path / "srv")
    c, th, err, _hp = _loopback(sftp_root=sftp_root)
    try:
        s = c.open_sftp()
        assert s.realpath("/").endswith("/")
        s.mkdir("/sub")
        data = b"x" * 100000  # > 3 chunks of 32768
        s.put("/sub/f.bin", data)
        assert s.stat("/sub/f.bin")["size"] == len(data)
        assert sorted(s.listdir("/sub")) == ["f.bin"]
        assert s.get("/sub/f.bin") == data
        s.remove("/sub/f.bin")
        assert s.listdir("/sub") == []
        s.close()
        out, _, code = c.exec_command("echo after-sftp")
        assert (out, code) == ("after-sftp\n", 0)
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_sftp_unknown_op_returns_op_unsupported():
    from ccssh.stub import handle_request
    from ccssh.sftp import F_STATUS, S_OP_UNSUPPORTED
    out = handle_request(250, 7, b"", lambda p: p, {}, lambda: b"h")
    r = W.Reader(out[4:])  # strip the u32 length prefix
    assert r.byte() == F_STATUS
    assert r.u32() == 7
    assert r.u32() == S_OP_UNSUPPORTED


def test_sftp_get_error_is_not_silent_eof(tmp_path):
    import pytest
    from ccssh.sftp import SFTPError
    c, th, err, _hp = _loopback(sftp_root=str(tmp_path / "srv"))
    try:
        s = c.open_sftp()
        with pytest.raises(SFTPError):
            s.get("/missing")
        s.close()
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_sftp_reply_size_capped():
    import pytest
    from ccssh.sftp import SFTPClient, SFTPError
    sc = SFTPClient(lambda srv, data: None,
                    lambda: b"\xff\xff\xff\xff", 1)
    with pytest.raises(SFTPError):
        sc._call(17, b"")


def test_sftp_get_max_bytes(tmp_path):
    import pytest
    from ccssh.sftp import SFTPError
    c, th, err, _hp = _loopback(sftp_root=str(tmp_path / "srv"))
    try:
        s = c.open_sftp()
        s.put("/big.bin", b"y" * 1000)
        with pytest.raises(SFTPError):
            s.get("/big.bin", max_bytes=10)
        s.remove("/big.bin")
        s.close()
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]
def _echo_server():
    """Background echo server: returns (port, stop_event, close_fn)."""
    import socket as _sock
    import threading as _th
    echo = _sock.socket()
    echo.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
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
                while True:
                    d = conn.recv(4096)
                    if not d:
                        break
                    conn.sendall(b"echo:" + d)
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

    return port, estop, _close


def test_mux_forward_and_exec_share_connection():
    """The 1:1 proof: -L forward AND exec on ONE connection, concurrently."""
    import socket as _sock
    import time as _time
    echo_port, _estop, _echo_close = _echo_server()
    c, th, err, _hp = _loopback()
    try:
        fwd = c.forward_local(0, "127.0.0.1", echo_port)
        try:
            _time.sleep(0.2)
            # exec runs WHILE the forward is active (old code forbade this)
            assert c.exec_command("echo one")[0] == "one\n"
            assert c.exec_command("echo two")[0] == "two\n"
            # ... and the forward still relays afterwards
            s = _sock.create_connection(("127.0.0.1", fwd.port), timeout=5)
            s.sendall(b"ping-mux")
            got = b""
            while len(got) < len(b"echo:ping-mux"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                got += chunk
            s.close()
            assert got == b"echo:ping-mux", got
        finally:
            fwd.close()
    finally:
        c.close()
        _echo_close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_mux_exec_after_forward_close():
    c, th, err, _hp = _loopback()
    try:
        fwd = c.forward_remote(0, "127.0.0.1", 22)
        fwd.close()  # mux survives the forwarder; exec works after
        assert c.exec_command("echo after")[0] == "after\n"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_mux_rekey_guards():
    import pytest as _pt
    from ccssh.transport import CCSSHError
    echo_port, _estop, _echo_close = _echo_server()
    c, th, err, _hp = _loopback()
    try:
        fwd = c.forward_local(0, "127.0.0.1", echo_port)
        try:
            c.rekey()  # mux idle (no open channels): allowed through catch-all
            assert c.exec_command("echo ok")[0] == "ok\n"
            c._mux.register(4242)  # simulate a live channel
            try:
                with _pt.raises(CCSSHError, match="close channels"):
                    c.rekey()
            finally:
                c._mux.unregister(4242)
            c.rekey()  # idle again: fine
        finally:
            fwd.close()
    finally:
        c.close()
        _echo_close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_forward_local_echo_loopback():
    import socket as _sock
    import threading as _th
    import time as _time
    from ccssh.client import CCSSHClient as _C

    echo = _sock.socket()
    echo.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    echo.bind(("127.0.0.1", 0))
    echo.listen(8)
    echo_port = echo.getsockname()[1]
    estop = _th.Event()

    def echo_loop():
        while not estop.is_set():
            try:
                conn, _ = echo.accept()
            except Exception:
                continue
            try:
                while True:
                    d = conn.recv(4096)
                    if not d:
                        break
                    conn.sendall(b"echo:" + d)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    _th.Thread(target=echo_loop, daemon=True).start()
    c, th, err, _hp = _loopback()
    try:
        fwd = c.forward_local(0, "127.0.0.1", echo_port)
        try:
            _time.sleep(0.2)
            s = _sock.create_connection(("127.0.0.1", fwd.port), timeout=5)
            s.sendall(b"ping-fwd")
            got = b""
            while len(got) < len(b"echo:ping-fwd"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                got += chunk
            s.close()
            assert got == b"echo:ping-fwd", got
        finally:
            fwd.close()
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


def test_remote_forward_echo_loopback():
    import socket as _sock
    import threading as _th
    import time as _time
    from ccssh.client import CCSSHClient as _C

    echo = _sock.socket()
    echo.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    echo.bind(("127.0.0.1", 0))
    echo.listen(8)
    echo_port = echo.getsockname()[1]
    estop = _th.Event()

    def echo_loop():
        while not estop.is_set():
            try:
                conn, _ = echo.accept()
            except Exception:
                continue
            try:
                while True:
                    d = conn.recv(4096)
                    if not d:
                        break
                    conn.sendall(b"echo:" + d)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    _th.Thread(target=echo_loop, daemon=True).start()
    c, th, err, _hp = _loopback()
    try:
        fwd = c.forward_remote(0, "127.0.0.1", echo_port)
        try:
            assert fwd.port != 0  # server auto-assigned and reported it
            _time.sleep(0.3)
            s = _sock.create_connection(("127.0.0.1", fwd.port), timeout=5)
            s.sendall(b"ping-r")
            got = b""
            while len(got) < len(b"echo:ping-r"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                got += chunk
            s.close()
            assert got == b"echo:ping-r", got
            try:
                c.forward_local(0, "127.0.0.1", echo_port)
                raise AssertionError("second forwarder on one connection allowed")
            except Exception as e:
                assert "one active forwarder" in str(e)
        finally:
            fwd.close()
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


def test_strict_extinfo_rekey_loopback():
    """strict-kex (seq reset), EXT_INFO consumed, rekey rotates keys, session_id kept."""
    c, th, err, _hp = _loopback()
    try:
        assert c._strict is True  # stub advertises kex-strict-s
        sid_before = c._sid
        out1, _, code1 = c.exec_command("echo one")
        assert (out1, code1) == ("one\n", 0)
        c.rekey()
        assert c._sid == sid_before  # session_id is kept
        assert c._t is not None and c._t.send_seq < 8  # seq numbers were reset
        out2, _, code2 = c.exec_command("echo two")
        assert (out2, code2) == ("two\n", 0)
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_auto_rekey_loopback():
    c, th, err, _hp = _loopback(rekey_bytes=64, rekey_interval=3600.0)
    try:
        sid_before = c._sid
        assert c.exec_command("echo one")[0] == "one\n"
        # traffic exceeded rekey_bytes: the next op rekeys transparently
        assert c.exec_command("echo two")[0] == "two\n"
        assert c._sid == sid_before
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_non_etm_oversize_packet_rejected():
    import struct
    import pytest
    from ccssh.transport import SyncTransport, CCSSHError
    from ccssh.crypto import build_unencrypted_block
    a, b = socket.socketpair()
    try:
        t = SyncTransport(a, b"SSH-2.0-T", timeout=2)
        b.sendall(struct.pack(">I", 40000))
        with pytest.raises(CCSSHError):
            t._read_one()
    finally:
        a.close()
        b.close()
    a, b = socket.socketpair()
    try:
        t = SyncTransport(a, b"SSH-2.0-T", timeout=2)
        good = build_unencrypted_block(b"hi", 8)
        bad = bytes([250]) + good[5:]  # pad longer than the packet itself
        b.sendall(struct.pack(">I", len(bad) - 4) + bad[4:])
        with pytest.raises(CCSSHError):
            t._read_one()
    finally:
        a.close()
        b.close()


def test_steady_state_keepalive_recovers():
    import threading as _th
    import time as _time
    from ccssh.transport import SyncTransport
    from ccssh.crypto import build_unencrypted_block
    a, b = socket.socketpair()
    t = SyncTransport(a, b"SSH-2.0-T", timeout=0.2)
    t._enc_on_recv = True  # steady state: keepalives allowed

    def peer():
        _time.sleep(0.35)
        try:
            # message 50 (not a service type: 2/4/80 are skipped/answered)
            b.sendall(build_unencrypted_block(b"\x32data", 8))
        except Exception:
            pass

    th = _th.Thread(target=peer, daemon=True)
    th.start()
    try:
        assert t.recv_packet() == b"\x32data"
    finally:
        a.close()
        b.close()
        th.join(timeout=2)


def test_handshake_timeout_still_fatal():
    import pytest
    from ccssh.transport import SyncTransport, CCSSHTimeoutError
    a, b = socket.socketpair()
    t = SyncTransport(a, b"SSH-2.0-T", timeout=0.2)
    try:
        # pre-NEWKEYS reads never keepalive: a stall stays fatal
        with pytest.raises(CCSSHTimeoutError):
            t.recv_packet()
        with pytest.raises(CCSSHTimeoutError):
            t.recv_packet(keepalive=True)
    finally:
        a.close()
        b.close()


def test_async_loopback_exec():
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
        c = AC.AsyncCCSSHClient(timeout=5, host_policy="off")
        await c.connect("127.0.0.1", port=port, username="u", password="pw")
        try:
            return await c.exec_command("echo async-hi")
        finally:
            await c.close()

    out, err_out, code = asyncio.run(go())
    th.join(timeout=5)
    assert (out, err_out, code) == ("async-hi\n", "", 0)
    if "e" in err:
        raise err["e"]


def test_async_keepalive_recovers():
    import asyncio
    import time as _time
    from ccssh.transport import AsyncTransport
    from ccssh.crypto import build_unencrypted_block

    async def go():
        a, b = socket.socketpair()
        reader, writer = await asyncio.open_connection(sock=a)
        t = AsyncTransport(reader, writer, b"SSH-2.0-T", timeout=0.2)
        t._enc_on_recv = True

        def peer():
            _time.sleep(0.35)
            try:
                # message 50 (not a service type: 2/4/80 are skipped/answered)
                b.sendall(build_unencrypted_block(b"\x32data", 8))
            except Exception:
                pass

        th = threading.Thread(target=peer, daemon=True)
        th.start()
        try:
            assert await t.recv_packet() == b"\x32data"
        finally:
            a.close()
            b.close()
            th.join(timeout=2)

    asyncio.run(go())


def test_mldsa_hybrid_primitives():
    from ccssh import mldsa as ML
    import pytest
    kp = ML.KeyPair.generate()
    assert len(kp.public_blob()) > 0
    mp1, ep = ML.parse_pub_blob(kp.public_blob())
    assert len(mp1) == ML.MLDSA_PK_LEN and len(ep) == 32
    sig = kp.sign_nested(b"msg")
    assert ML.verify_nested(kp.public_blob(), b"msg", sig)
    assert not ML.verify_nested(kp.public_blob(), b"msg!", sig)
    k2 = ML.KeyPair.from_seeds(bytes([17]) * 32, bytes([34]) * 32)
    assert k2.seeds() == bytes([17]) * 32 + bytes([34]) * 32
    assert ML.KeyPair.from_seeds(bytes([17]) * 32, bytes([34]) * 32).public_blob() \
        == k2.public_blob()
    assert kp.public_line("c").split()[0] == "ssh-mldsa44-ed25519"
    with pytest.raises(Exception):
        ML.KeyPair.from_seeds(b"short", b"short")


def test_mldsa_loopback_host_and_user(tmp_path):
    from ccssh import mldsa as ML
    from ccssh.stub import run_once
    from ccssh.client import CCSSHClient as _C
    host_kp = ML.KeyPair.generate()
    user_kp = ML.KeyPair.generate()
    kf = tmp_path / "id_mldsa"
    ML.save_openssh_private(str(kf), user_kp, "cmt")
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = ls.getsockname()[1]
    err = {}

    def srv():
        try:
            conn, _ = ls.accept()
            run_once(conn, host_kp, password="pw")
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()
    c = _C(timeout=5, host_policy="off")
    c.connect("127.0.0.1", port=port, username="u", key_filename=str(kf))
    try:
        assert c.negotiated()["hostkey"] == "ssh-mldsa44-ed25519"
        assert c.exec_command("echo mldsa")[0] == "mldsa\n"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_mldsa_save_is_0600_atomic(tmp_path):
    import stat
    from ccssh import mldsa as ML
    kp = ML.KeyPair.generate()
    kf = tmp_path / "id_mldsa"
    ML.save_openssh_private(str(kf), kp, "c")
    assert stat.S_IMODE(os.stat(kf).st_mode) == 0o600
    back = ML.load_openssh_private(str(kf))
    assert back.public_blob() == kp.public_blob()
def test_kbdint_codec_roundtrip():
    from ccssh import auth as A
    probe = A.enc_kbdint_probe("user")
    assert probe[0] == A.MSG_USERAUTH_REQUEST
    assert b"keyboard-interactive" in probe
    req = (bytes([A.MSG_USERAUTH_INFO_REQUEST]) + W.enc_string(b"n")
           + W.enc_string(b"instr") + W.enc_string(b"en") + W.enc_u32(2)
           + W.enc_string(b"Password:") + W.enc_bool(False)
           + W.enc_string(b"Token:") + W.enc_bool(True))
    info = A.dec_info_request(req)
    assert info["name"] == "n" and info["instruction"] == "instr"
    assert info["prompts"] == [("Password:", False), ("Token:", True)]
    resp = A.enc_info_response([b"a", b"b"])
    assert A.dec_info_response(resp) == [b"a", b"b"]
    fail = bytes([A.MSG_USERAUTH_FAILURE]) + W.enc_namelist(["publickey"]) + W.enc_bool(False)
    assert A.dec_failure(fail) == {"methods": ["publickey"], "partial": False}
    import pytest as _pt
    with _pt.raises(W.WireError):
        A.dec_info_request(bytes([A.MSG_USERAUTH_INFO_REQUEST]) + W.enc_string(b"")
                           + W.enc_string(b"") + W.enc_string(b"") + W.enc_u32(17))
    with _pt.raises(ValueError):
        A.enc_info_response([b"x"] * 17)
    with _pt.raises(W.WireError):
        A.dec_info_response(bytes([A.MSG_USERAUTH_INFO_RESPONSE]) + W.enc_u32(99))


def _kbdint_loopback(password, kbdint_password, client_password):
    """Stub whose password and keyboard-interactive secrets differ."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh.stub import run_once
    from ccssh.client import CCSSHClient as _C
    host_priv = Ed25519PrivateKey.generate()
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = ls.getsockname()[1]
    err = {}

    def srv():
        try:
            conn, _ = ls.accept()
            run_once(conn, host_priv, password=password, kbdint_password=kbdint_password)
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()
    c = _C(timeout=5, host_policy="off")
    c.connect("127.0.0.1", port=port, username="u", password=client_password)
    return c, th, err


def test_kbdint_fallback_loopback():
    # password method rejects, keyboard-interactive accepts the same secret
    c, th, err = _kbdint_loopback("__never__", "pw", "pw")
    try:
        assert c.exec_command("echo kbd")[0] == "kbd\n"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_kbdint_wrong_secret_rejected():
    import pytest as _pt
    from ccssh.client import AuthError
    try:
        _kbdint_loopback("__never__", "pw", "bad")
        raise AssertionError("bad secret accepted")
    except AuthError as e:
        assert "password rejected" in str(e)


def test_kbdint_round_cap_and_count():
    import pytest as _pt
    from ccssh.client import CCSSHClient as _C

    class FakeT:
        def __init__(self, script):
            self.script = list(script)
            self.sent = []

        def send_packet(self, payload):
            self.sent.append(payload)

        def recv_packet(self, **kw):
            if not self.script:
                raise AssertionError("client read past the script")
            return self.script.pop(0)

    def _prompt(n=1):
        return (bytes([60]) + W.enc_string(b"") + W.enc_string(b"") + W.enc_string(b"")
                + W.enc_u32(n)
                + b"".join(W.enc_string(b"P:") + W.enc_bool(False) for _ in range(n)))

    # endless prompter: client must give up after the round cap
    c = _C(timeout=5, host_policy="off")
    c._t, c._sid = FakeT([_prompt()] * 10), bytes(32)
    with _pt.raises(Exception, match="too many rounds"):
        c._auth_kbdint("u", lambda prompts: ["x"] * len(prompts))
    assert len(c._t.sent) == 1 + 5  # probe + capped responses
    # responder answering the wrong count aborts loudly
    c2 = _C(timeout=5, host_policy="off")
    c2._t, c2._sid = FakeT([_prompt()]), bytes(32)
    with _pt.raises(Exception, match="wrong answer count"):
        c2._auth_kbdint("u", lambda prompts: [])
    # zero-prompt request answered with zero responses succeeds
    ok = bytes([52])
    c3 = _C(timeout=5, host_policy="off")
    c3._t, c3._sid = FakeT([_prompt(0), ok]), bytes(32)
    c3._auth_kbdint("u", lambda prompts: [])
    assert c3._t.sent[1] == bytes([61]) + W.enc_u32(0)


def test_kbdint_async_loopback():
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
            run_once(conn, host_priv, password="__never__", kbdint_password="pw")
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()

    async def go():
        c = AC.AsyncCCSSHClient(timeout=5, host_policy="off")
        await c.connect("127.0.0.1", port=port, username="u", password="pw")
        try:
            return await c.exec_command("echo akbd")
        finally:
            await c.close()

    assert asyncio.run(go())[0] == "akbd\n"
    th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_kbdint_responder_api_no_password():
    # keyboard-interactive as the only method: no key, no password stored.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh.stub import run_once
    from ccssh.client import CCSSHClient as _C
    host_priv = Ed25519PrivateKey.generate()
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    port = ls.getsockname()[1]
    err = {}

    def srv():
        try:
            conn, _ = ls.accept()
            run_once(conn, host_priv, password="__never__", kbdint_password="pw")
            conn.close()
        except Exception as e:
            err["e"] = e
        finally:
            ls.close()

    th = threading.Thread(target=srv, daemon=True)
    th.start()
    c = _C(timeout=5, host_policy="off")
    seen = []
    c.connect("127.0.0.1", port=port, username="u",
              kbdint_responder=lambda prompts: (seen.append(prompts), ["pw"])[1])
    try:
        assert seen and seen[0][0][0] == "Password:"
        assert c.exec_command("echo kr")[0] == "kr\n"
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_cli_kbdint_first_needs_no_prompt(monkeypatch):
    from ccssh import cli as CLIMOD

    prompts = []

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, *a, **k):
            return self

        def exec_command(self, cmd, **kw):
            return (b"", b"", 0)

        def close(self):
            pass

    def fake_getpass(text):
        prompts.append(text)
        return "secret"

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    monkeypatch.setattr("ccssh.cli.getpass.getpass", fake_getpass)
    monkeypatch.setattr(CLIMOD, "_preflight_tcp", lambda *a, **k: None)
    assert main(["u@h.example.com", "echo", "hi"]) == 0
    assert prompts == []  # kbdint-first succeeded: nothing was ever asked


def test_exec_raw_bytes_loopback():
    # Binary fidelity: raw_bytes returns bytes untouched by text decoding.
    c, th, err, _hp = _loopback()
    try:
        out, err_out, code = c.exec_command("echo raw", raw_bytes=True)
        assert isinstance(out, bytes) and isinstance(err_out, bytes)
        assert (out, code) == (b"raw\n", 0)
    finally:
        c.close()
        th.join(timeout=5)
    if "e" in err:
        raise err["e"]


def test_cli_parsing_and_version(capsys):
    p = build_parser()
    a = p.parse_args(["-p", "2222", "-l", "u", "-i", "k1", "-i", "k2",
                      "-c", "aes256-ctr",
                      "-o", "KexAlgorithms=curve25519-sha256", "h.example.com", "uname", "-a"])
    assert a.port == 2222 and a.identity == ["k1", "k2"] and a.command == ["uname", "-a"]
    assert a.cipher_spec == "aes256-ctr"
    assert parse_destination("u@h", None) == ("h", "u")
    assert parse_o_options(["Ciphers=aes128-ctr"]) == {"ciphers": "aes128-ctr"}
    assert main(["-V"]) == 0
    out = capsys.readouterr()
    assert "ccssh" in out.err and out.out == ""  # ssh prints -V to stderr


def test_cli_exec_mocked(monkeypatch, capsys):
    from ccssh import cli as CLIMOD

    seen = {}

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, *a, **k):
            return self

        def negotiated(self):
            return {"cipher": "aes128-ctr"}

        def exec_command(self, cmd, **kw):
            seen["run"] = {"command": cmd}
            assert cmd == "echo hi"
            return (b"hi\n", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert main(["u@h.example.com", "echo", "hi"]) == 0
    assert seen["run"].get("command") == "echo hi"
    assert main(["-t", "-T", "u@h.example.com", "echo", "hi"]) == 0  # last -T wins: plain exec


def test_cli_c_m_flags_like_ssh(monkeypatch):
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
    assert main(["-c", "aes256-ctr", "-m", "hmac-sha2-512",
                 "u@h.example.com", "echo", "hi"]) == 0
    assert seen["ciphers"] == ["aes256-ctr"]
    assert seen["macs"] == ["hmac-sha2-512"]
    assert seen["kex"] == algs.SUPPORTED_KEX  # untouched default offer
    assert seen["hostkeys"] == algs.SUPPORTED_HOSTKEYS  # untouched default


def test_cli_o_wins_over_c_m(monkeypatch):
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
    assert main(["-c", "aes128-ctr", "-o", "Ciphers=aes256-ctr",
                 "-o", "HostKeyAlgorithms=+ssh-dss",
                 "u@h.example.com", "echo", "hi"]) == 0
    assert seen["ciphers"] == ["aes256-ctr"]  # -o wins over -c
    assert seen["hostkeys"][-1] == "ssh-dss"  # relative append works


def test_cli_query_like_ssh(capsys):
    assert main(["-Q", "cipher"]) == 0
    out = capsys.readouterr().out.split()
    assert "aes256-ctr" in out and "3des-cbc" not in out
    assert main(["-Q", "kex"]) == 0
    assert "curve25519-sha256" in capsys.readouterr().out
    assert main(["-Q", "bogus"]) == 255
    assert main(["-Q", "help"]) == 0
    assert "cipher-auth" in capsys.readouterr().out.split()
    assert main(["-Q", "cipher-auth"]) == 0
    assert "chacha20-poly1305@openssh.com" in capsys.readouterr().out.split()
    assert main(["-Q", "protocol-version"]) == 0
    assert capsys.readouterr().out.split() == ["2"]


def test_split_argv_ssh_order():
    from ccssh.cli import split_argv
    opts, dest, cmd = split_argv(["-p", "2022", "u@h"])
    assert dest == "u@h" and cmd == [] and "-p" in opts and "2022" in opts
    opts, dest, cmd = split_argv(["u@h", "-p", "2022"])
    assert dest == "u@h" and cmd == [] and "2022" in opts
    opts, dest, cmd = split_argv(["u@h", "echo", "-p", "x"])
    assert dest == "u@h" and cmd == ["echo", "-p", "x"]


def test_cli_options_after_destination(monkeypatch):
    from ccssh import cli as CLIMOD

    seen = {}

    class Fake:
        def __init__(self, **k):
            pass

        def connect(self, host, *, port, **kw):
            seen["port"] = port
            return self

        def exec_command(self, cmd, **kw):
            seen["cmd"] = cmd
            return (b"", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert main(["u@h.example.com", "-p", "2022", "echo", "hi"]) == 0
    assert seen["port"] == 2022 and seen["cmd"] == "echo hi"


def test_cli_family_and_tty_flags(monkeypatch):
    import socket as _sock
    from ccssh import cli as CLIMOD

    seen = {}

    class Fake:
        def __init__(self, **k):
            pass

        def connect(self, *a, **k):
            seen.update(k)
            return self

        def exec_command(self, cmd, **kw):
            return (b"", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert main(["-4", "u@h.example.com", "echo", "hi"]) == 0
    assert seen.get("family") == _sock.AF_INET
    assert main(["-t", "-T", "u@h.example.com", "echo", "hi"]) == 0  # last -T wins: plain exec


def test_parse_L_ipv6_and_brackets():
    import pytest as _pt
    from ccssh.cli import _parse_L
    assert _parse_L("8080:127.0.0.1:80") == (8080, "127.0.0.1", 80, "127.0.0.1")
    assert _parse_L("0.0.0.0:8080:h:80") == (8080, "h", 80, "0.0.0.0")
    assert _parse_L("8080:::1:80") == (8080, "::1", 80, "127.0.0.1")
    assert _parse_L("8080:[::1]:80") == (8080, "::1", 80, "127.0.0.1")
    assert _parse_L("[::1]:8080:[2001:db8::1]:80") == (8080, "2001:db8::1", 80, "::1")
    # -R default bind is "localhost" like OpenSSH (explicit wins)
    assert _parse_L("80:localhost:3000", default_bind="localhost")[3] == "localhost"
    assert _parse_L("0.0.0.0:80:h:80", default_bind="localhost") == (80, "h", 80, "0.0.0.0")
    from ccssh.cli import UsageError
    with _pt.raises(UsageError):
        _parse_L("nope")
    with _pt.raises(UsageError):
        _parse_L("a:b:c")


def test_parse_destination_brackets():
    assert parse_destination("u@[::1]", None) == ("::1", "u")
    assert parse_destination("[::1]", "u") == ("::1", "u")
    assert parse_destination("u@h", "other") == ("h", "u")


def test_cli_unknown_option_is_255(capsys):
    assert main(["-Z", "u@h.example.com"]) == 255
    assert "unrecognized arguments" in capsys.readouterr().err
    assert main(["--frobnicate", "u@h.example.com"]) == 255


def test_cli_unknown_dash_o_is_255(capsys):
    assert main(["-o", "Frobnicate=yes", "u@h.example.com"]) == 255
    assert "Bad configuration option" in capsys.readouterr().err


def test_cli_permission_denied_split(capsys, monkeypatch):
    from ccssh import cli as CLIMOD
    from ccssh.client import AuthError

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, *a, **k):
            raise AuthError("password rejected")

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert main(["u@h.example.com", "echo", "hi"]) == 255
    err = capsys.readouterr().err
    assert "Permission denied" in err
    assert "ccssh: connect: password rejected" not in err


def test_cli_jump_chain(monkeypatch):
    from ccssh import cli as CLIMOD
    from ccssh.cli import parse_jump_chain

    assert parse_jump_chain("a,b", "u") == [("a", "u", 22), ("b", "u", 22)]
    assert parse_jump_chain("x@a:2022,y@b", "u") == [("a", "x", 2022), ("b", "y", 22)]

    order = []

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, host, *, port, username, sock=None, **kw):
            order.append((host, port, username, sock is not None))
            return self

        def open_channel_socket(self, host, port):
            class _D:
                def close(self):
                    pass
            return _D()

        def exec_command(self, cmd, **kw):
            return (b"", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert main(["-J", "j1,j2@jhop:2022", "u@target", "echo", "hi"]) == 0
    # chained left to right; each hop after the first rides the previous
    assert order[0][:3] == ("j1", 22, "u") and order[0][3] is False
    assert order[1][:3] == ("jhop", 2022, "j2") and order[1][3] is True
    assert order[2][:3] == ("target", 22, "u") and order[2][3] is True


def test_cli_N_with_command_is_255(capsys):
    assert main(["-N", "u@h.example.com", "echo", "hi"]) == 255
    assert "cannot execute command with -N" in capsys.readouterr().err


def test_cli_V_goes_to_stderr(capsys):
    assert main(["-V"]) == 0
    out = capsys.readouterr()
    assert "ccssh" in out.err and out.out == ""


def test_cli_bad_timeout_is_255(capsys):
    assert main(["-o", "ConnectTimeout=nope", "u@h.example.com"]) == 255
    assert main(["--timeout", "-5", "u@h.example.com"]) == 255


def test_parse_destination_without_user_env(monkeypatch):
    # Termux often has no $USER: fall back instead of "bad destination".
    from ccssh import cli as CLIMOD
    for var in ("USER", "LOGNAME", "USERNAME"):
        monkeypatch.delenv(var, raising=False)
    host, user = CLIMOD.parse_destination("serveo.net", None)
    assert host == "serveo.net" and user  # resolved via getpwuid fallback
    assert CLIMOD.parse_destination("u@serveo.net", None) == ("serveo.net", "u")


def test_cli_broken_pipe_is_141(monkeypatch):
    from ccssh import cli as CLIMOD
    import sys as _sys

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, *a, **k):
            return self

        def exec_command(self, cmd, **kw):
            assert kw.get("raw_bytes") is True  # CLI takes binary output
            return (b"hi\n", b"", 0)

        def close(self):
            pass

    import io as _io
    buf = _io.BytesIO()

    class _Stdout:
        buffer = buf

        def flush(self):
            pass

    class _BreakingBuffer:
        def write(self, _text):
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self):
            pass

    class _BreakingStdout:
        buffer = _BreakingBuffer()

        def flush(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    monkeypatch.setattr(_sys, "stdout", _Stdout())
    monkeypatch.setattr(_sys, "stderr", _Stdout())
    assert main(["u@h.example.com", "echo", "hi"]) == 0
    assert buf.getvalue() == b"hi\n"
    monkeypatch.setattr(_sys, "stdout", _BreakingStdout())
    assert main(["u@h.example.com", "echo", "hi"]) == 141


def test_parse_jump():
    from ccssh.cli import parse_jump
    import pytest as _pt
    assert parse_jump("juser@jumphost", "u") == ("jumphost", "juser", 22)
    assert parse_jump("jumphost:2022", "u") == ("jumphost", "u", 2022)
    # comma chains are real ProxyJump hops now (see below)
    assert parse_jump("juser@jumphost", "u") == ("jumphost", "juser", 22)


def test_cli_jump_flow(monkeypatch):
    from ccssh import cli as CLIMOD

    seen = {}

    class Fake:
        def __init__(self, **k):
            pass

        def connect(self, host, *, port, username, sock=None, **kw):
            seen[host] = (port, username, sock)
            return self

        def open_channel_socket(self, host, port):
            class _D:
                def close(self):
                    pass
            seen["tunnel"] = (host, port)
            return _D()

        def exec_command(self, cmd, **kw):
            return (b"", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert main(["-J", "j@jump", "u@target", "echo", "hi"]) == 0
    assert seen["jump"][0] == 22
    assert seen["tunnel"] == ("target", 22)
    assert seen["target"][2] is not None  # target dialled through the tunnel


def test_cli_default_identities_from_home(monkeypatch, tmp_path):
    from ccssh import cli as CLIMOD
    dotssh = tmp_path / ".ssh"
    dotssh.mkdir()
    (dotssh / "id_ed25519").write_bytes(b"k")
    (dotssh / "id_rsa").write_bytes(b"k")
    monkeypatch.setenv("HOME", str(tmp_path))
    got = CLIMOD.default_identities()
    assert got[0].endswith("id_rsa") and got[1].endswith("id_ed25519")
    assert all(p.startswith(str(tmp_path)) for p in got)


def test_cli_uses_default_keys_without_i(monkeypatch):
    from ccssh import cli as CLIMOD

    seen = {}

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, host, *, port, username, password=None,
                    key_filename=None, sock=None, **kw):
            seen["key_filename"] = key_filename
            return self

        def exec_command(self, cmd, **kw):
            return (b"", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    monkeypatch.setattr(CLIMOD, "default_identities", lambda: ["k1", "k2"])
    assert main(["u@h.example.com", "echo", "hi"]) == 0
    assert seen["key_filename"] == "k1"  # first default key tried, no -i given
    # ssh-like: -R works with a shell session too (mux shares the connection).
    from ccssh import cli as CLIMOD

    seen = {}

    class FakeFwd:
        port = 2022
        closed = False

        def close(self):
            self.closed = True

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, *a, **k):
            return self

        def negotiated(self):
            return {"cipher": "aes128-ctr"}

        def forward_remote(self, sport, rhost, rport, bind="127.0.0.1"):
            seen["R"] = (sport, rhost, rport, bind)
            return FakeFwd()

        def exec_command(self, cmd, **kw):
            seen["cmd"] = cmd
            return (b"", b"", 0)

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert main(["-R", "2022:127.0.0.1:22", "u@h.example.com", "echo", "hi"]) == 0
    assert seen["R"] == (2022, "127.0.0.1", 22, "localhost")  # ssh-like -R default bind
    assert seen["cmd"] == "echo hi"


def test_cli_L_parsing_and_forward_guards():
    assert main(["-L", "8080:127.0.0.1:80", "-R", "2022:127.0.0.1:22",
                 "-N", "u@h.example.com"]) == 255  # both directions at once




