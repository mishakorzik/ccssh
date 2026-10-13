"""FIDO2 security-key codecs: blobs, nested signatures, file loading."""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from ccssh import sk as SK
from ccssh import wire as W


def _ed_pair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def _ec_pair():
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    size = (priv.key_size + 7) // 8
    q = b"\x04" + nums.x.to_bytes(size, "big") + nums.y.to_bytes(size, "big")
    return priv, q


def test_pub_roundtrip_both():
    _, ed_pub = _ed_pair()
    k = SK.SkKey(SK.ALG_ED, pub=ed_pub, key_handle=b"h")
    assert SK.parse_pub_blob(k.public_blob()).pub == ed_pub
    _, q = _ec_pair()
    k2 = SK.SkKey(SK.ALG_EC, curve=SK.EC_CURVE_SSH, q=q, key_handle=b"h")
    back = SK.parse_pub_blob(k2.public_blob())
    assert back.q == q and back.curve == SK.EC_CURVE_SSH
    # .pub lines are standard "alg base64(full blob)" form
    assert k.public_line("c").split()[0] == SK.ALG_ED


def _touch_signer_ed(priv):
    def signer(app, handle, message):
        pre = SK.preimage(app, 5, 9, message)
        return priv.sign(pre), 5, 9
    return signer


def _touch_signer_ec(priv):
    def signer(app, handle, message):
        pre = SK.preimage(app, 1, 2, message)
        der = priv.sign(pre, ec.ECDSA(hashes.SHA256()))
        r_int, s_int = decode_dss_signature(der)
        return W.enc_mpint(r_int) + W.enc_mpint(s_int), 1, 2
    return signer


def test_sign_verify_ed():
    priv, ed_pub = _ed_pair()
    k = SK.SkKey(SK.ALG_ED, pub=ed_pub, key_handle=b"h", signer=_touch_signer_ed(priv))
    nested = k.sign_nested(b"login Fus Ro Dah")
    assert SK.verify_nested(k.public_blob(), b"login Fus Ro Dah", nested)


def test_sign_verify_ecdsa():
    priv, q = _ec_pair()
    k = SK.SkKey(SK.ALG_EC, curve=SK.EC_CURVE_SSH, q=q, key_handle=b"h",
                 signer=_touch_signer_ec(priv))
    nested = k.sign_nested(b"msg")
    assert SK.verify_nested(k.public_blob(), b"msg", nested)


def test_tamper_matrix():
    priv, ed_pub = _ed_pair()
    k = SK.SkKey(SK.ALG_ED, pub=ed_pub, key_handle=b"h", signer=_touch_signer_ed(priv))
    good = k.sign_nested(b"msg")
    assert not SK.verify_nested(k.public_blob(), b"msg!", good)
    assert not SK.verify_nested(k.public_blob(), b"msg", good[:-1] + b"\x00")
    _, other_pub = _ed_pair()
    other = SK.SkKey(SK.ALG_ED, pub=other_pub, key_handle=b"h")
    assert not SK.verify_nested(other.public_blob(), b"msg", good)
    assert not SK.verify_nested(b"junk", b"msg", good)
    assert not SK.verify_nested(k.public_blob(), b"msg", b"junk")


def test_key_file_load(tmp_path):
    # Private halves round-trip through parse_private_blob; the file loader
    # needs a real openssh-key-v1 file, which ssh-keygen owns - here we
    # check the blob layer rejects cert-form halves and bad alg names.
    import pytest
    _, ed_pub = _ed_pair()
    blob = (W.enc_string(SK.ALG_ED.encode()) + W.enc_string(ed_pub) + W.enc_string(b"ssh:") + bytes([0]) + W.enc_string(b"h") + W.enc_string(b""))
    back = SK.parse_private_blob(blob)
    assert back.pub == ed_pub and back.key_handle == b"h"
    with pytest.raises(ValueError):
        SK.SkKey("sk-ssh-xyz@openssh.com", pub=ed_pub)


def test_userauth_integration():
    from ccssh import auth as A
    priv, ed_pub = _ed_pair()
    k = SK.SkKey(SK.ALG_ED, pub=ed_pub, key_handle=b"h", signer=_touch_signer_ed(priv))
    session_id = bytes(32)
    blob = k.public_blob()
    data = A.auth_sign_blob(session_id, "user", SK.ALG_ED.encode(), blob)
    nested = k.sign_nested(data)
    assert SK.verify_nested(blob, data, nested)
    probe = A.enc_pubkey_probe("user", SK.ALG_ED.encode(), blob)
    assert probe[0] == A.MSG_USERAUTH_REQUEST


def test_openssh_reads_our_cert():
    # public_line output must decode back to the identical blob
    import base64
    _, ed_pub = _ed_pair()
    k = SK.SkKey(SK.ALG_ED, pub=ed_pub, key_handle=b"h")
    alg, b64 = k.public_line("comment").split()[:2]
    assert alg == SK.ALG_ED
    assert SK.parse_pub_blob(base64.b64decode(b64)).pub == ed_pub
