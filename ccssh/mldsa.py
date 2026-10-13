"""
 ssh-mldsa44-ed25519 composite signatures (OpenSSH 10.6).

 Format reverse-engineered from OpenSSH 10.6 (ssh-mldsa-eddsa.c,
 draft-miller-sshm-mldsa44-ed25519-composite-sigs-00, LAMPS composite-18):

  M' = "CompositeAlgorithmSignatures2025"
     + "COMPSIG-MLDSA44-Ed25519-SHA512"
     + u8(0) + SHA512(message)
  sig = ML-DSA-44(M', context=LABEL) [2420] || Ed25519(M') [64]
  PK  = mldsa_pub [1312] || ed_pub [32]
  SK seeds = mldsa_seed [32] || ed_seed [32]  (openssh-key-v1 private field)

 Wire:
  pubkey blob = string("ssh-mldsa44-ed25519") + string(PK)
  sig field   = string( string("ssh-mldsa44-ed25519") + string(sig) )

 Validated byte-for-byte against real ssh-keygen(10.6) keys and a live
 sshd(10.6)→client signature capture.
"""
from __future__ import annotations
import base64
import hashlib
import os

from ccssh import wire as W

ALG = b"ssh-mldsa44-ed25519"
ALG_CERT = b"ssh-mldsa44-ed25519-cert"
PREFIX = b"CompositeAlgorithmSignatures2025"
LABEL = b"COMPSIG-MLDSA44-Ed25519-SHA512"

MLDSA_PK_LEN = 1312
ED_PK_LEN = 32
PK_LEN = MLDSA_PK_LEN + ED_PK_LEN
MLDSA_SIG_LEN = 2420
ED_SIG_LEN = 64
SIG_LEN = MLDSA_SIG_LEN + ED_SIG_LEN
SEED_LEN = 64  # mldsa_seed32 || ed_seed32


def _require_backend():
    try:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey, MLDSA44PublicKey
    except ImportError as e:
        raise ImportError("cryptography without ML-DSA support") from e
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    return MLDSA44PrivateKey, MLDSA44PublicKey, Ed25519PrivateKey, Ed25519PublicKey


def m_prime(message: bytes, context: bytes = b"") -> bytes:
    if len(context) > 255:
        raise ValueError("context too long")
    return PREFIX + LABEL + bytes([len(context)]) + context + hashlib.sha512(message).digest()


class KeyPair:
    """In-memory composite keypair."""

    def __init__(self, mldsa_priv, ed_priv):
        self.mldsa_priv = mldsa_priv
        self.ed_priv = ed_priv

    @classmethod
    def generate(cls) -> "KeyPair":
        MLDSA44PrivateKey, _, Ed25519PrivateKey, _ = _require_backend()
        return cls(MLDSA44PrivateKey.generate(), Ed25519PrivateKey.generate())

    @classmethod
    def from_seeds(cls, mldsa_seed: bytes, ed_seed: bytes) -> "KeyPair":
        MLDSA44PrivateKey, _, Ed25519PrivateKey, _ = _require_backend()
        if len(mldsa_seed) != 32 or len(ed_seed) != 32:
            raise ValueError("seeds must be 32 bytes each")
        return cls(MLDSA44PrivateKey.from_seed_bytes(mldsa_seed), Ed25519PrivateKey.from_private_bytes(ed_seed))

    def public_blob(self) -> bytes:
        """Full SSH public key blob."""
        _require_backend() # fail fast without ML-DSA support
        mp = self.mldsa_priv.public_key().public_bytes_raw()
        ep = self.ed_priv.public_key().public_bytes_raw()
        return W.enc_string(ALG) + W.enc_string(mp + ep)

    def public_line(self, comment: str = "") -> str:
        body = self.public_blob()
        r = W.Reader(body)
        r.string()
        pk = r.string()
        suffix = f" {comment}" if comment else ""
        return f"ssh-mldsa44-ed25519 {base64.b64encode(pk).decode()}{suffix}"

    def sign_nested(self, message: bytes) -> bytes:
        """sshkey_sign output: string(alg) + string(sig)."""
        _require_backend() # fail fast without ML-DSA support
        mp = m_prime(message)
        s1 = self.mldsa_priv.sign(mp, context=LABEL)
        s2 = self.ed_priv.sign(mp)
        if len(s1) != MLDSA_SIG_LEN or len(s2) != ED_SIG_LEN:
            raise ValueError("bad composite signature part lengths")
        return W.enc_string(ALG) + W.enc_string(s1 + s2)

    def seeds(self) -> bytes:
        """mldsa_seed32 || ed_seed32 (openssh-key-v1 private field layout)."""
        return self.mldsa_priv.private_bytes_raw() + self.ed_priv.private_bytes_raw()


def parse_pub_blob(blob: bytes) -> tuple[bytes, bytes]:
    """Split public key blob -> (mldsa_pub, ed_pub)."""
    r = W.Reader(blob)
    alg = r.string()
    if alg not in (ALG, ALG_CERT):
        raise ValueError(f"not an mldsa key: {alg!r}")
    pk = r.string()
    if len(pk) != PK_LEN or r.rest():
        raise ValueError("bad mldsa pub length")
    return pk[:MLDSA_PK_LEN], pk[MLDSA_PK_LEN:]


def verify_nested(pub_blob: bytes, message: bytes, sig_nested: bytes) -> bool:
    """Verify sshkey_sign-style nested signature. Never raises."""
    try:
        _, MLDSA44PublicKey, _, Ed25519PublicKey = _require_backend()
        r = W.Reader(sig_nested)
        if r.string() not in (ALG, ALG_CERT):
            return False
        sig = r.string()
        if len(sig) != SIG_LEN or r.rest():
            return False
        mp1, ep = parse_pub_blob(pub_blob)
        mp = m_prime(message)
        MLDSA44PublicKey.from_public_bytes(mp1).verify(sig[:MLDSA_SIG_LEN], mp, context=LABEL)
        Ed25519PublicKey.from_public_bytes(ep).verify(sig[MLDSA_SIG_LEN:], mp)
        return True
    except Exception:
        return False


def load_openssh_private(path: str, passphrase: bytes | None = None) -> KeyPair:
    """Load ssh-keygen(10.6+) mldsa44-ed25519 openssh-key-v1 file."""
    with open(os.path.expanduser(path), "rb") as f:
        pem = f.read().decode()
    if passphrase is not None:
        raise ValueError("encrypted mldsa keys: use ssh-agent or decrypt first (TODO)")
    b64 = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
    raw = base64.b64decode(b64)
    if not raw.startswith(b"openssh-key-v1\x00"):
        raise ValueError("not an openssh-key-v1 file")
    r = W.Reader(raw[15:])
    if r.string() != b"none":
        raise ValueError("encrypted key (TODO passphrase support)")
    r.string()
    r.string()
    if r.u32() != 1:
        raise ValueError("expected exactly 1 key")
    r.string()  # public blob
    priv = r.string()
    pr = W.Reader(priv)
    if pr.u32() != pr.u32():
        raise ValueError("checkint mismatch (wrong passphrase?)")
    if pr.string() != ALG:
        raise ValueError("not an mldsa44-ed25519 key")
    pr.string()  # public part inside private section
    seeds = pr.string()
    if len(seeds) != SEED_LEN:
        raise ValueError("bad seed length")
    return KeyPair.from_seeds(seeds[:32], seeds[32:])


def save_openssh_private(path: str, kp: KeyPair, comment: str = "") -> None:
    """Write unencrypted openssh-key-v1 file (inverse of load_openssh_private)."""
    check = int.from_bytes(os.urandom(4), "big") or 1
    pub_blob = kp.public_blob()
    # pub blob inside private section = the 1344B pk string (NOT the full blob)
    r = W.Reader(pub_blob)
    r.string()
    pk = r.string()
    priv_sec = (W.enc_u32(check)
                + W.enc_u32(check)
                + W.enc_string(ALG)
                + W.enc_string(pk)
                + W.enc_string(kp.seeds())
                + W.enc_string(comment.encode()))
    padlen = (-len(priv_sec)) % 8
    priv_sec += bytes(range(1, padlen + 1))
    raw = (b"openssh-key-v1\x00"
           + W.enc_string(b"none")
           + W.enc_string(b"none")
           + W.enc_string(b"")
           + W.enc_u32(1)
           + W.enc_string(pub_blob)
           + W.enc_string(priv_sec))
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    b64 = base64.b64encode(raw).decode()
    pem += "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70)) + "\n"
    pem += "-----END OPENSSH PRIVATE KEY-----\n"
    fd = os.open(os.path.expanduser(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except Exception:
        pass
    with os.fdopen(fd, "w") as f:
        f.write(pem)


# Backwards-compatible helper.
def available() -> bool:
    try:
        _require_backend()
        return True
    except Exception:
        return False
