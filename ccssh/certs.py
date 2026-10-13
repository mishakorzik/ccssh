"""
 OpenSSH certificates (draft-miller-ssh-cert, *-cert-v01@openssh.com,
 ssh-mldsa44-ed25519-cert).

 Implemented: parsing, CA signatures (ed25519/mldsa/ecdsa/rsa), validity
 periods, principals, critical options (unknown ones REJECT the cert),
 @cert-authority lines from known_hosts.
 Not implemented: verify-required touch checks (such certs are rejected),
 source-address enforcement (a server-side concern for user certs).
"""
from __future__ import annotations
import base64
import fnmatch
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ccssh import hostkeys as HK
from ccssh import mldsa as ML
from ccssh import wire as W

CERT_TYPE_USER = 1
CERT_TYPE_HOST = 2

# Known user critical options (draft section 2.3). Unknown ones REJECT the cert.
KNOWN_CRITICAL = {"force-command", "source-address", "verify-required"}


class CertError(ValueError):
    pass


def _parse_section(raw: bytes) -> dict[str, bytes]:
    """A critical-options/extensions section: sequence of {string key, string value}."""
    r = W.Reader(raw)
    out: dict[str, bytes] = {}
    while r.rest():
        k = r.string().decode()
        v = r.string()
        out[k] = v
    return out


def parse_cert(blob: bytes) -> dict:
    """
     Parse and structurally validate a certificate blob.

     Raises CertError (never bare WireError/UnicodeDecodeError) so callers
     get one clean failure type for attacker-controlled input.
    """
    try:
        return _parse_cert_inner(blob)
    except CertError:
        raise
    except Exception as e:
        raise CertError(f"malformed certificate: {e}") from e


def _parse_cert_inner(blob: bytes) -> dict:
    r = W.Reader(blob)
    keytype = r.string().decode()
    if not (keytype.endswith("-cert-v01@openssh.com") or keytype.endswith("-cert")):
        raise CertError(f"not a certificate type {keytype!r}")
    nonce = r.string()
    pub: dict = {}
    if keytype.startswith("ssh-ed25519"):
        pub = {"pub": r.string()}
        if len(pub["pub"]) != 32:
            raise CertError("bad ed25519 pub length")
    elif keytype.startswith("ssh-mldsa44-ed25519"):
        pub = {"pub": r.string()}
        if len(pub["pub"]) != ML.PK_LEN:
            raise CertError("bad mldsa pub length")
    elif keytype.startswith("ecdsa-sha2-"):
        pub = {"curve": r.string().decode(), "q": r.string()}
    elif keytype.startswith("ssh-rsa"):
        pub = {"e": r.mpint(), "n": r.mpint()}
    else:
        raise CertError(f"unsupported certificate type {keytype!r}")
    serial = r.u64()
    role = r.u32()
    key_id = r.string()
    """
     Principals is a string CONTAINING cstrings (see sshkey_certify_custom
     in OpenSSH sshkey.c), NOT comma-joined text as the draft suggests.
    """
    principals_raw = r.string()
    principals: list[str] = []
    if principals_raw:
        pr = W.Reader(principals_raw)
        while pr.rest():
            principals.append(pr.string().decode())
    valid_after = r.u64()
    valid_before = r.u64()
    crit_raw = r.string()
    ext_raw = r.string()
    _reserved = r.string()
    if _reserved:
        raise CertError("certificate reserved field must be empty")
    sig_key = r.string()
    sig_off = r.tell() # the signature covers everything up to this point
    signature = r.string()
    if r.rest():
        raise CertError("trailing bytes in certificate")
    return {"keytype": keytype,
            "nonce": nonce,
            "pub": pub,
            "serial": serial,
            "role": role,
            "key_id": key_id,
            "principals": principals,
            "valid_after": valid_after,
            "valid_before": valid_before,
            "critical": _parse_section(crit_raw),
            "extensions": _parse_section(ext_raw),
            "sig_key": sig_key,
            "signature": signature,
            "signed_data": blob[:sig_off]}


def _ca_verify_signed(signed: bytes, sig_key_blob: bytes, signature: bytes) -> bool:
    """Verify a CA signature according to the CA key type. Never raises."""
    r = W.Reader(sig_key_blob)
    try:
        ca_type = r.string().decode()
    except Exception:
        return False
    if ca_type in ("ssh-ed25519",):
        rr = W.Reader(signature)
        try:
            alg, sig_raw = rr.string(), rr.string()
        except Exception:
            return False
        if alg != b"ssh-ed25519":
            return False
        r2 = W.Reader(sig_key_blob)
        r2.string()
        pub = r2.string()
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig_raw, signed)
            return True
        except Exception:
            return False
    if ca_type in ("ssh-mldsa44-ed25519",):
        try:
            inner = W.Reader(sig_key_blob)
            inner.string()
            ca_pub = inner.string()
            if len(ca_pub) != ML.PK_LEN:
                return False
            ca_blob = W.enc_string(b"ssh-mldsa44-ed25519") + W.enc_string(ca_pub)
            return ML.verify_nested(ca_blob, signed, signature)
        except Exception:
            return False
    # ECDSA/RSA CAs: signature has the same nested shape as hostkeys.
    rr = W.Reader(signature)
    try:
        outer_alg = rr.string().decode()
    except Exception:
        return False
    host_alg = outer_alg if ca_type == "ssh-rsa" else ca_type
    return HK.verify_host_signature(sig_key_blob, host_alg, signed, signature)


def verify_cert(blob: bytes, *, expected_principal: str, is_host: bool, ca_blobs: list[bytes], now: int | None = None) -> dict:
    """Full verification. Returns the parsed cert or raises CertError."""
    c = parse_cert(blob)
    want_role = CERT_TYPE_HOST if is_host else CERT_TYPE_USER
    if c["role"] != want_role:
        raise CertError(f"role {c['role']}, expected {want_role}")
    if c["valid_after"] > c["valid_before"]:
        raise CertError("certificate has inverted validity interval")
    t = now if now is not None else int(time.time())
    if not (c["valid_after"] <= t <= c["valid_before"]):
        raise CertError("certificate outside validity period")
    if expected_principal not in c["principals"]:
        raise CertError(f"principal {expected_principal!r} not in {c['principals']}")
    unknown_crit = set(c["critical"]) - KNOWN_CRITICAL
    if unknown_crit:
        raise CertError(f"unknown critical options (REJECT): {sorted(unknown_crit)}")
    if "verify-required" in c["critical"]:
        raise CertError("verify-required needs a security-key touch, unsupported")
    if c["sig_key"] not in ca_blobs:
        raise CertError("certificate CA not trusted (@cert-authority)")
    if not _ca_verify_signed(c["signed_data"], c["sig_key"], c["signature"]):
        raise CertError("CA signature mismatch")
    return c


def load_ca_keys(known_hosts, host: str, port: int = 22) -> list[bytes]:
    """
     CA blobs from @cert-authority lines matching host (fnmatch *?).

     Accepts one path or many (mirrors hostcheck's UserKnownHostsFile
     lists). Malformed lines are skipped, never fatal: a broken local
     file must not crash host verification (it just yields no CAs, then
     strict fails closed). Non-22 ports also match [host]:port patterns
     like OpenSSH. Hashed |1| patterns match like plain ones.
    """
    from ccssh import hostcheck as _HC
    paths = [known_hosts] if isinstance(known_hosts, str) else list(known_hosts or [])
    out: list[bytes] = []
    for kh in paths:
        if kh == "/dev/null" or os.path.basename(os.path.expanduser(kh)).lower() == "none":
            continue
        try:
            if os.path.getsize(os.path.expanduser(kh)) > _HC.MAX_KNOWN_HOSTS_SIZE:
                continue
            with open(os.path.expanduser(kh), encoding="utf-8") as f:
                lines = f.readlines()
            if len(lines) > _HC.MAX_KNOWN_HOSTS_LINES:
                continue
        except OSError:
            continue
        cands = [host] if port == 22 else [host, f"[{host}]:{port}"]
        for ln in lines:
            ln = ln.strip()
            if not ln.startswith("@cert-authority"):
                continue
            parts = ln.split()
            if len(parts) < 4:
                continue
            patterns, b64 = parts[1], parts[3] # [2] is the key-type column (informational)
            try:
                blob = base64.b64decode(b64, validate=True)
            except Exception:
                continue
            matched = False
            for c in cands:
                for pat in patterns.split(","):
                    if _match_host_ci(pat.strip(), c, host, port):
                        matched = True
                        break
                if matched:
                    break
            if matched:
                out.append(blob)
    return out


def _match_host_ci(pat: str, cand: str, host: str, port: int) -> bool:
    """
      Host pattern match: hashed |1| entries via hostcheck, plain/glob
      entries case-insensitively (DNS names are case-insensitive).
    """
    from ccssh import hostcheck as _HC
    if pat.startswith("|1|"):
        return _HC._match_host(pat, host, port)
    return fnmatch.fnmatchcase(cand.lower(), pat.lower())


def build_cert(*, keytype: str, pub_fields: bytes, serial: int = 1, role: int = CERT_TYPE_HOST, key_id: bytes = b"test", principals: str | list[str] = "host.example.com", valid_after: int = 0, valid_before: int = 0xFFFFFFFFFFFFFFFF, critical: bytes = b"", extensions: bytes = b"", ca_priv=None, nonce: bytes | None = None) -> bytes:
    """Assemble and CA-sign a certificate (for tests). pub_fields pre-encoded."""
    nonce = os.urandom(32) if nonce is None else nonce
    if isinstance(principals, str):
        principals = [principals]
    princ_blob = b"".join(W.enc_string(p.encode()) for p in principals)
    body = (W.enc_string(keytype.encode())
            + W.enc_string(nonce)
            + pub_fields
            + W.enc_u64(serial)
            + W.enc_u32(role)
            + W.enc_string(key_id)
            + W.enc_string(princ_blob)
            + W.enc_u64(valid_after)
            + W.enc_u64(valid_before)
            + W.enc_string(critical)
            + W.enc_string(extensions)
            + W.enc_string(b""))
    if isinstance(ca_priv, Ed25519PrivateKey):
        ca_pub = ca_priv.public_key().public_bytes_raw()
        sig_key = W.enc_string(b"ssh-ed25519") + W.enc_string(ca_pub)
        sig_key_field = W.enc_string(sig_key)
        sig_raw = ca_priv.sign(body + sig_key_field)
        sig = W.enc_string(b"ssh-ed25519") + W.enc_string(sig_raw)
    elif type(ca_priv).__name__ == "KeyPair":
        sig_key = ca_priv.public_blob()
        sig_key_field = W.enc_string(sig_key)
        sig = ca_priv.sign_nested(body + sig_key_field)
    else:
        raise CertError("build_cert supports Ed25519 and mldsa CA keys")
    return body + sig_key_field + W.enc_string(sig)
