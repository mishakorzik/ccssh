"""
 FIDO2 security-key user authentication (sk-ssh-ed25519, sk-ecdsa-sha2-nistp256).

 Formats follow OpenSSH PROTOCOL.u2f exactly (fetched 2026-10-11, v1.26):

  pub blob:  string(alg) + key fields + string(application, usually "ssh:")
  priv half: string(alg) + key fields + string(application)
             + byte(flags) + string(key_handle) + string(reserved)
  preimage:  SHA256(application) + byte(flags) + u32(counter)
             + ext(empty) + SHA256(message)
  wire sig:  string(alg) + string(sig) + byte(flags) + u32(counter),
             where ecdsa sig = mpint(r) + mpint(s) (RFC 5656) and ed25519
             sig is raw 64 B.

 The touch itself cannot happen in software: signing needs a FIDO2 token.
 SkKey therefore carries an injectable `signer(application, key_handle,
 message) -> (sig_raw, flags, counter)`; without one, sign_nested raises
 a clear error instead of failing obscurely server-side. Parsing,
 verification and userauth assembly are fully testable without hardware.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ccssh import wire as W

ALG_ED = "sk-ssh-ed25519@openssh.com"
ALG_EC = "sk-ecdsa-sha2-nistp256@openssh.com"
ALGS = (ALG_ED, ALG_EC)
DEFAULT_APPLICATION = b"ssh:"
EC_CURVE_SSH = b"nistp256"


def preimage(application: bytes, flags: int, counter: int, message: bytes) -> bytes:
    """
     The exact bytes a security key signs (PROTOCOL.u2f, no extensions).
    """
    if not 0 <= flags <= 255:
        raise ValueError("flags must be one byte")
    if not 0 <= counter < 2**32:
        raise ValueError("counter must fit uint32")
    return (hashlib.sha256(application).digest()
            + bytes([flags])
            + counter.to_bytes(4, "big")
            + hashlib.sha256(message).digest())


class SkKey:
    """
     A security key: public parts + key handle + optional signer callback.

     `signer(application, key_handle, message)` returns (sig_raw, flags,
     counter); hardware builds the preimage itself. Pass None when no
     token is attached - signing then raises instead of misbehaving.
    """

    def __init__(self, alg: str, application: bytes = DEFAULT_APPLICATION, flags: int = 0, key_handle: bytes = b"", pub: bytes = b"", curve: bytes = b"", q: bytes = b"", signer=None):
        if alg not in ALGS:
            raise ValueError(f"not a sk key type: {alg!r}")
        if not 0 <= flags <= 255:
            raise ValueError("flags must be one byte")
        self.alg = alg
        self.application = application
        self.flags = flags
        self.key_handle = key_handle
        self.signer = signer
        if alg == ALG_ED:
            if len(pub) != 32:
                raise ValueError("sk ed25519 pub must be 32 bytes")
            self.pub = pub
            self.curve, self.q = b"", b""
        else:
            if curve != EC_CURVE_SSH or not q:
                raise ValueError("sk ecdsa needs nistp256 + point")
            self.pub, self.curve, self.q = b"", curve, q

    def public_blob(self) -> bytes:
        if self.alg == ALG_ED:
            return W.enc_string(self.alg.encode()) + W.enc_string(self.pub) + W.enc_string(self.application)
        return W.enc_string(self.alg.encode()) + W.enc_string(self.curve) + W.enc_string(self.q) + W.enc_string(self.application)

    def public_line(self, comment: str = "") -> str:
        # OpenSSH .pub format: "alg base64(full_blob_with_alg) [comment]".
        inner = self.public_blob()
        suffix = f" {comment}" if comment else ""
        return f"{self.alg} {base64.b64encode(inner).decode()}{suffix}"

    def sign_nested(self, message: bytes) -> bytes:
        """
         Wire signature buffer: string(alg) + string(sig) + byte(flags) +
         u32(counter). Verifies its own output against the public key so
         a broken middleware fails here, not as a server rejection.
        """
        if self.signer is None:
            raise ValueError("no security-key signer configured (FIDO2 touch required)")
        sig_raw, flags, counter = self.signer(self.application, self.key_handle, message)
        if self.alg == ALG_ED:
            if len(sig_raw) != 64:
                raise ValueError("sk ed25519 signature must be 64 bytes")
        else:
            r = W.Reader(sig_raw)
            r.mpint()
            r.mpint()
            if r.rest():
                raise ValueError("sk ecdsa signature must be mpint(r)+mpint(s)")
        if not 0 <= flags <= 255 or not 0 <= counter < 2**32:
            raise ValueError("signer returned bad flags/counter")
        out = (W.enc_string(self.alg.encode()) + W.enc_string(sig_raw)
               + bytes([flags]) + counter.to_bytes(4, "big"))
        if not verify_nested(self.public_blob(), message, out):
            raise ValueError("signer output does not verify")
        return out


def parse_pub_blob(blob: bytes) -> SkKey:
    r = W.Reader(blob)
    alg = r.string().decode()
    if alg == ALG_ED:
        pub, app = r.string(), r.string()
        if r.rest():
            raise ValueError("trailing bytes in sk pub blob")
        return SkKey(alg, application=app, pub=pub)
    if alg == ALG_EC:
        curve, q, app = r.string(), r.string(), r.string()
        if r.rest():
            raise ValueError("trailing bytes in sk pub blob")
        return SkKey(alg, application=app, curve=curve, q=q)
    raise ValueError(f"not a sk public key: {alg!r}")


def parse_private_blob(blob: bytes, *, strict: bool = True) -> SkKey:
    """
     Private half: pub fields + application + flags + key_handle + reserved.
     Cert-form halves are refused: pass the plain key file with --cert.
     strict=False tolerates the openssh-key-v1 block padding that follows
     the half inside key files (used by the file loader only).
    """
    r = W.Reader(blob)
    alg = r.string().decode()
    if alg in ALGS:
        pub_part = r.string() if alg == ALG_ED else None
        if alg == ALG_EC:
            curve, q = r.string(), r.string()
        else:
            curve, q = b"", b""
        app = r.string()
        flags = r.byte()
        handle = r.string()
        r.string()  # reserved
        if strict and r.rest():
            raise ValueError("trailing bytes in sk private half")
        kw = {"pub": pub_part} if alg == ALG_ED else {"curve": curve, "q": q}
        return SkKey(alg, application=app, flags=flags, key_handle=handle, **kw)
    raise ValueError(f"not a sk private key: {alg!r}")


def verify_nested(pub_blob: bytes, message: bytes, sig_nested: bytes) -> bool:
    """
     Verify an sk wire signature. Returns True/False, never raises.
    """
    try:
        r = W.Reader(sig_nested)
        sig_alg = r.string().decode()
        sig_raw = r.string()
        flags = r.byte()
        counter = r.u32()
        if r.rest():
            return False
        key = parse_pub_blob(pub_blob)
        if key.alg != sig_alg:
            return False
        pre = preimage(key.application, flags, counter, message)
        if key.alg == ALG_ED:
            if len(sig_raw) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(key.pub).verify(sig_raw, pre)
            return True
        rr = W.Reader(sig_raw)
        der = encode_dss_signature(rr.mpint(), rr.mpint())
        if rr.rest():
            return False
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), key.q).verify(der, pre, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def load_openssh_private(path: str, passphrase: bytes | None = None) -> SkKey:
    """
     Load an sk openssh-key-v1 file (unencrypted only, like the mldsa
     loader: encrypted keys raise a clear error).
    """
    with open(os.path.expanduser(path), "rb") as f:
        pem = f.read().decode()
    b64 = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise ValueError(f"bad sk key file {path}: {e}") from e
    if not raw.startswith(b"openssh-key-v1\x00"):
        raise ValueError("not an openssh-key-v1 file")
    r = W.Reader(raw[15:])
    if r.string() != b"none":
        # Encrypted sk keys are unsupported (passphrase or not): callers
        # passing one unconditionally get the same clear error.
        raise ValueError("encrypted sk keys are unsupported: decrypt with ssh-keygen first")
    r.string()
    r.string()
    if r.u32() != 1:
        raise ValueError("expected exactly 1 key")
    r.string()  # public blob
    priv = r.string()
    pr = W.Reader(priv)
    if pr.u32() != pr.u32():
        raise ValueError("checkint mismatch (wrong passphrase?)")
    return parse_private_blob(priv[pr.tell():], strict=False)
