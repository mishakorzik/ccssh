"""
 Host keys and userauth signatures: ssh-ed25519, ssh-mldsa44-ed25519,
 ecdsa-sha2-nistp*, rsa-sha2-256/512, ssh-dss (legacy: disabled by default,
 explicit opt-in only), plus *-cert variants.

 Certificate blobs are parsed structurally here; CA trust (authorities,
 principals, validity) lives in certs.py / hostcheck.py.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from ccssh import mlkem
from ccssh import wire as W
from ccssh.mldsa import KeyPair as MldsaKeyPair
from ccssh.sk import SkKey

EC_HASH = {"ecdsa-sha2-nistp256": hashes.SHA256, "ecdsa-sha2-nistp384": hashes.SHA384, "ecdsa-sha2-nistp521": hashes.SHA512}
EC_CURVE = {"ecdsa-sha2-nistp256": ec.SECP256R1(), "ecdsa-sha2-nistp384": ec.SECP384R1(), "ecdsa-sha2-nistp521": ec.SECP521R1()}
EC_SIZE = {"ecdsa-sha2-nistp256": 32, "ecdsa-sha2-nistp384": 48, "ecdsa-sha2-nistp521": 66}


def fingerprint(blob: bytes) -> str:
    """OpenSSH-style key fingerprint: ``SHA256:<base64-without-padding>``."""
    import base64 as _b64
    import hashlib as _hl
    digest = _hl.sha256(blob).digest()
    return "SHA256:" + _b64.b64encode(digest).decode().rstrip("=")


def parse_host_blob(blob: bytes) -> tuple[str, dict]:
    r = W.Reader(blob)
    alg = r.string().decode()
    if alg == "ssh-ed25519":
        pub = r.string()
        if len(pub) != 32 or r.rest():
            raise ValueError("bad ed25519 key length")
        return alg, {"pub": pub}
    if alg in EC_CURVE:
        curve_name = r.string().decode()  # e.g. "nistp256"
        q = r.string()
        exp = {"ecdsa-sha2-nistp256": "nistp256", "ecdsa-sha2-nistp384": "nistp384", "ecdsa-sha2-nistp521": "nistp521"}[alg]
        if curve_name != exp:
            raise ValueError(f"curve mismatch: {alg} carries {curve_name!r}")
        if r.rest():
            raise ValueError("trailing bytes in ecdsa host key")
        return alg, {"curve_name": curve_name, "q": q}
    if alg == "ssh-rsa":
        e, n = r.mpint(), r.mpint()
        if r.rest():
            raise ValueError("trailing bytes in ssh-rsa host key")
        return alg, {"e": e, "n": n}
    if alg == "ssh-dss":
        # Legacy algorithm (1024-bit DSA, removed from OpenSSH 10.x): parsed
        # and verified when explicitly forced, never offered by default.
        p, q, g, y = r.mpint(), r.mpint(), r.mpint(), r.mpint()
        if r.rest():
            raise ValueError("trailing bytes in ssh-dss host key")
        return alg, {"p": p, "q": q, "g": g, "y": y}
    if alg in ("ssh-mldsa44-ed25519",):
        from ccssh import mldsa as _ML
        pub = r.string()
        if len(pub) != _ML.PK_LEN or r.rest():
            raise ValueError("bad mldsa pub length")
        return alg, {"pub": pub}
    if alg.endswith("-cert-v01@openssh.com") or alg.endswith("-cert"):
        return alg, {"cert_blob": blob}  # opaque; see certs.py / cert_inner_plain
    raise ValueError(f"unknown host key {alg!r}")


def _ec_pubkey(alg: str, q: bytes):
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    curve = EC_CURVE[alg]
    return EllipticCurvePublicKey.from_encoded_point(curve, q)


def _dss_pubkey(p: int, q: int, g: int, y: int):
    from cryptography.hazmat.primitives.asymmetric import dsa as _dsa
    nums = _dsa.DSAPublicNumbers(y, _dsa.DSAParameterNumbers(p, q, g))
    return nums.public_key()


def cert_inner_plain(Ks: bytes) -> tuple[str, bytes]:
    """
     Extract (inner_alg, plain_pub_blob) from a certificate blob.

     CA trust is NOT checked here; see certs.py.
    """
    from ccssh import certs as CERT
    c = CERT.parse_cert(Ks)
    kt = c["keytype"]
    # ssh-keygen writes "ssh-ed25519-cert-v01@openssh.com" or bare "-cert" (mldsa)
    if kt.endswith("-cert-v01@openssh.com"):
        base = kt[:-len("-cert-v01@openssh.com")]
    elif kt.endswith("-cert"):
        base = kt[:-len("-cert")]
    else:
        raise ValueError(f"not a certificate type {kt!r}")
    pub = c["pub"]
    if base == "ssh-ed25519":
        blob = W.enc_string(b"ssh-ed25519") + W.enc_string(pub["pub"])
    elif base == "ssh-mldsa44-ed25519":
        blob = W.enc_string(b"ssh-mldsa44-ed25519") + W.enc_string(pub["pub"])
    elif base in EC_CURVE:
        curve_ssh = {"ecdsa-sha2-nistp256": b"nistp256", "ecdsa-sha2-nistp384": b"nistp384", "ecdsa-sha2-nistp521": b"nistp521"}[base]
        blob = W.enc_string(base.encode()) + W.enc_string(curve_ssh) + W.enc_string(pub["q"])
    elif base == "ssh-rsa":
        blob = W.enc_string(b"ssh-rsa") + W.enc_mpint(pub["e"]) + W.enc_mpint(pub["n"])
    elif base == "ssh-dss":
        blob = (W.enc_string(b"ssh-dss") + W.enc_mpint(pub["p"]) + W.enc_mpint(pub["q"]) + W.enc_mpint(pub["g"]) + W.enc_mpint(pub["y"]))
    else:
        raise ValueError(f"unsupported certificate inner key {base!r}")
    return base, blob


def verify_host_signature(Ks: bytes, host_alg: str, Hh: bytes, sig_outer: bytes) -> bool:
    """
     Verify a KEX signature. ``host_alg`` is the negotiated algorithm.

     For certificates the KEX signature is checked against the INNER key;
     CA trust is verified separately by hostcheck/certs. Never raises.
    """
    try:
        r = W.Reader(sig_outer)
        sig_alg = r.string().decode()
        sig_blob = r.string()
    except Exception:
        return False
    try:
        alg, parts = parse_host_blob(Ks)
    except Exception:
        return False
    if alg.endswith("-cert-v01@openssh.com") or alg.endswith("-cert"):
        try:
            alg, Ks = cert_inner_plain(Ks)
            parts = parse_host_blob(Ks)[1]
        except Exception:
            return False
    try:
        if alg == "ssh-ed25519":
            if sig_alg != "ssh-ed25519":
                return False
            return mlkem.verify_exchange_hash(parts["pub"], Hh, W.enc_string(b"ssh-ed25519") + W.enc_string(sig_blob))
        if alg in EC_CURVE:
            if sig_alg != alg:
                return False
            try:
                rr = W.Reader(sig_blob)
                r_int, s_int = rr.mpint(), rr.mpint()
                rr.assert_end()
            except Exception:
                return False
            der = encode_dss_signature(r_int, s_int)
            _ec_pubkey(alg, parts["q"]).verify(der, Hh, ec.ECDSA(EC_HASH[alg]()))
            return True
        if alg == "ssh-rsa":
            if host_alg in ("rsa-sha2-256", "rsa-sha2-512"):
                if sig_alg != host_alg:
                    return False
            elif sig_alg not in ("rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"):
                return False
            h = hashes.SHA256() if sig_alg == "rsa-sha2-256" else (hashes.SHA512() if sig_alg == "rsa-sha2-512" else hashes.SHA1())
            pub = rsa.RSAPublicNumbers(parts["e"], parts["n"]).public_key()
            # SSH omits leading zeroes of s - pad back to modulus length.
            # Longer-than-modulus signatures are rejected (no silent truncation).
            k = (pub.key_size + 7) // 8
            if len(sig_blob) > k:
                return False
            sig = sig_blob.rjust(k, b"\x00")
            pub.verify(sig, Hh, padding.PKCS1v15(), h)
            return True
        if alg == "ssh-mldsa44-ed25519":
            if sig_alg != "ssh-mldsa44-ed25519":
                return False
            from ccssh import mldsa as _ML
            blob = W.enc_string(b"ssh-mldsa44-ed25519") + W.enc_string(parts["pub"])
            return _ML.verify_nested(blob, Hh, sig_outer)
        if alg == "ssh-dss":
            # Legacy: 1024-bit DSA with SHA-1. Verified only when forced.
            if sig_alg != "ssh-dss":
                return False
            if len(sig_blob) != 40:
                return False
            r_int = int.from_bytes(sig_blob[:20], "big")
            s_int = int.from_bytes(sig_blob[20:], "big")
            der = encode_dss_signature(r_int, s_int)
            try:
                _dss_pubkey(parts["p"], parts["q"], parts["g"], parts["y"]).verify(der, Hh, hashes.SHA1())
            except Exception:
                return False
            return True
    except Exception:
        return False
    return False


def sign_userauth(priv, alg: str, data: bytes) -> bytes:
    """
     Sign a userauth blob. Returns the nested buffer as sshkey_sign does:
     string(alg) + string(sigblob). The caller wraps it into the signature
     string field. Raises ValueError for unsupported key types.
    """
    if isinstance(priv, MldsaKeyPair):
        if alg != "ssh-mldsa44-ed25519":
            raise ValueError(f"mldsa key with alg {alg}")
        return priv.sign_nested(data)
    if isinstance(priv, SkKey):
        if alg != priv.alg:
            raise ValueError(f"sk key with alg {alg}")
        return priv.sign_nested(data)
    if isinstance(priv, Ed25519PrivateKey):
        sig = priv.sign(data)
        if len(sig) != 64:
            raise ValueError("bad ed25519 signature length")
        return W.enc_string(b"ssh-ed25519") + W.enc_string(sig)
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        try:
            hash_cls = EC_HASH[alg]
        except KeyError:
            raise ValueError(f"unsupported EC user key {alg}") from None
        der = priv.sign(data, ec.ECDSA(hash_cls()))
        r_int, s_int = decode_dss_signature(der)
        return W.enc_string(alg.encode()) + W.enc_string(W.enc_mpint(r_int) + W.enc_mpint(s_int))
    if isinstance(priv, rsa.RSAPrivateKey):
        sigtype = "rsa-sha2-256" if alg in ("rsa-sha2-256", "ssh-rsa") else "rsa-sha2-512"
        h = hashes.SHA256() if sigtype == "rsa-sha2-256" else hashes.SHA512()
        sig = priv.sign(data, padding.PKCS1v15(), h)
        k = (priv.key_size + 7) // 8
        if len(sig) < k:
            sig = sig.rjust(k, b"\x00")
        return W.enc_string(sigtype.encode()) + W.enc_string(sig)
    try:
        from cryptography.hazmat.primitives.asymmetric import dsa as _dsa_mod
        _dsa_types = (_dsa_mod.DSAPrivateKey,)
    except Exception:
        _dsa_types = ()
    if _dsa_types and isinstance(priv, _dsa_types):
        # Legacy user key: raw 40-byte r||s (RFC 4253 section 6.6), SHA-1.
        if alg != "ssh-dss":
            raise ValueError(f"dss key with alg {alg}")
        der = priv.sign(data, hashes.SHA1())
        r_int, s_int = decode_dss_signature(der)
        raw = r_int.to_bytes(20, "big") + s_int.to_bytes(20, "big")
        if len(raw) != 40:
            raise ValueError("bad dss signature length")
        return W.enc_string(b"ssh-dss") + W.enc_string(raw)
    raise ValueError(f"unsupported private key type {type(priv)}")
