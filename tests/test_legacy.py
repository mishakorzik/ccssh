"""
 Legacy primitives: disabled by default, explicit opt-in, math verified.

 Nothing legacy is ever negotiated unless named explicitly.
"""
from __future__ import annotations
import hashlib
import hmac as pyhmac
import os

from ccssh import algs


def test_legacy_disabled_by_default():
    for leg in (algs.LEGACY_KEX + algs.LEGACY_CIPHERS + algs.LEGACY_MACS + algs.LEGACY_HOSTKEYS):
        assert leg not in (algs.SUPPORTED_KEX + algs.SUPPORTED_CIPHERS + algs.SUPPORTED_MACS + algs.SUPPORTED_HOSTKEYS), leg
    # ... but every one of them is importable/constructible on demand
    assert "ssh-rsa" in algs.LEGACY_HOSTKEYS
    assert "ssh-dss" in algs.LEGACY_HOSTKEYS


def _cbc_pair(cipher):
    from ccssh import crypto as C
    specs = C.CBC_SPECS[cipher]
    key = os.urandom(specs["key_len"])
    iv = os.urandom(specs["iv_len"])
    mack = os.urandom(20)
    s = C.CbcHmacCtx(cipher, "hmac-sha1", key, iv, mack)
    r = C.CbcHmacCtx(cipher, "hmac-sha1", key, iv, mack)
    return s, r


def test_cbc_aes_variants():
    for cipher in ("aes128-cbc", "aes192-cbc", "aes256-cbc"):
        s, r = _cbc_pair(cipher)
        pt = os.urandom(64)  # block-multiple, like the transport sends
        ct = s.encrypt_stream(pt)
        assert r.decrypt_stream(ct) == pt
        assert s.mac_of(3, pt) == r.mac_of(3, pt)


def test_cbc_3des():
    s, r = _cbc_pair("3des-cbc")
    pt = os.urandom(24)
    assert r.decrypt_stream(s.encrypt_stream(pt)) == pt


def test_legacy_macs():
    from ccssh import crypto as C
    from cryptography.hazmat.primitives import hashes, hmac as _h
    for mac, hcls, out in (("hmac-sha1-96", hashes.SHA1, 12),
                           ("hmac-md5", hashes.MD5, 16),
                           ("hmac-md5-96", hashes.MD5, 12)):
        key = os.urandom(C.MAC_SPECS[mac]["key_len"])
        m = C.SshMac(mac, key)
        data = os.urandom(48)
        h = _h.HMAC(key, hcls())
        import struct
        h.update(struct.pack(">I", 9) + data)
        assert m.mac_of(9, data) == h.finalize()[:out]


def test_cbc_bitflip_fails_mac():
    import hmac as _pyhmac
    s, r = _cbc_pair("aes128-cbc")
    pt = os.urandom(32)
    ct = bytearray(s.encrypt_stream(pt))
    mac = s.mac_of(1, pt)
    ct[5] ^= 1
    assert not _pyhmac.compare_digest(r.mac_of(1, r.decrypt_stream(bytes(ct))), mac)


def test_group1_math():
    from ccssh import kex_ext as KX
    c = KX.DhClient("diffie-hellman-group1-sha1")
    assert c.p.bit_length() == 1024
    init = c.init_msg()
    from ccssh import wire as W
    assert W.Reader(init).byte() == 30
    # degenerate peer values are rejected without any network
    import pytest
    for bad in (0, 1, c.p - 1, c.p):
        with pytest.raises(ValueError):
            c.finish(bytes([31]) + W.enc_string(b"k") + W.enc_mpint(bad) + W.enc_string(b"s"), b"Vc", b"Vs", b"Ic", b"Is")


def test_gex_sha1_math():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import kex_ext as KX
    host_priv = Ed25519PrivateKey.generate()
    c = KX.GexClient(hashfn=hashlib.sha1)
    s = KX.GexServerStub(host_priv, hashfn=hashlib.sha1)
    group = s.reply_request(c.request_msg())
    init = c.init_msg(group)
    reply, K_srv, H_srv = s.reply_init(init, b"Vc", b"Vs", b"Ic", b"Is")
    K_raw, Hh, _Ks = c.finish(reply, b"Vc", b"Vs", b"Ic", b"Is")
    assert K_raw == K_srv and Hh == H_srv
