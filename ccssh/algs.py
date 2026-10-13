"""
 Algorithm registry: what ccssh supports vs OpenSSH (from local `ssh -Q`).

  Honest numbers only: an algorithm counts as supported after loopback AND
  live-interop tests against a real sshd go green. Weak primitives live in
  LEGACY (implemented, never offered unless named explicitly).
  (FIDO2 login additionally needs a
 hardware token at runtime - see ccssh.sk; all of its software side is
 implemented and tested.)
"""
from __future__ import annotations

import threading

# Full OpenSSH 10.6 algorithm set (`ssh -Q`), sorted strongest-first
# (NOT ssh order): PQ hybrids, then 256-bit ECDH/AEAD, down to 1024-bit
# group1-sha1 / 3DES / MD5 / ssh-dss-era primitives.
OPENSSH_KEX = [
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768nistp256-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp521",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
]
OPENSSH_CIPHERS = [
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc",
    "3des-cbc",
]
OPENSSH_MACS = [
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
    "umac-128@openssh.com",
    "hmac-sha1",
    "umac-64@openssh.com",
    "hmac-sha1-96",
    "hmac-md5",
    "hmac-md5-96",
]
OPENSSH_KEYS = [
    "ssh-mldsa44-ed25519",
    "ssh-mldsa44-ed25519-cert",
    "ssh-ed25519",
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ssh-rsa",
    "ssh-rsa-cert-v01@openssh.com",
]

"""
 Actually implemented and covered by loopback + live tests.
 Order in every list below is strongest-first: negotiation follows our
 preference, so the first common algorithm is the strongest both sides
 support. Tiers: SUPPORTED (offered by default), MAX (strict top tier
 for explicit API use), LEGACY (implemented but never offered unless
 named explicitly - weak, for old servers only).
"""
SUPPORTED_KEX = [
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768nistp256-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp521",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1"
]
SUPPORTED_CIPHERS = [
    "aes256-gcm@openssh.com",
    "aes256-ctr",
    "chacha20-poly1305@openssh.com",
    "aes192-ctr",
    "aes128-gcm@openssh.com",
    "aes128-ctr"
]
SUPPORTED_MACS = [
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
    "hmac-sha1"
]
SUPPORTED_HOSTKEYS = [
    "ssh-mldsa44-ed25519",
    "ssh-ed25519",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp256",
    "rsa-sha2-512",
    "rsa-sha2-256"
]
# Certificate host keys carry full CA verification (see certs.py), not opaque trust.

LEGACY_KEX = [
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1"
]
LEGACY_CIPHERS = [
    "aes256-cbc",
    "aes192-cbc",
    "aes128-cbc",
    "3des-cbc"
]
LEGACY_MACS = [
    "hmac-sha1-96-etm@openssh.com",
    "hmac-sha1-96",
    "hmac-md5-etm@openssh.com",
    "hmac-md5",
    "hmac-md5-96-etm@openssh.com",
    "hmac-md5-96",
    "umac-128-etm@openssh.com",
    "umac-128@openssh.com",
    "umac-64-etm@openssh.com",
    "umac-64@openssh.com"
]
LEGACY_HOSTKEYS = [
    "ssh-rsa",
    # 1024-bit DSA with SHA-1, removed from OpenSSH 10.x entirely
    # ("Bad key types"): implemented for old-box recovery, never offered
    # unless named explicitly - like every other legacy primitive.
    "ssh-dss",
]

"""
 Strength-ordered strict top tier: only the strongest primitives
 (PQ hybrids, 256-bit ciphers/MACs). Pass one of these lists explicitly
 (API) to offer nothing weaker; negotiation still intersects with the
 server offer, so it fails closed when the server lacks top-tier
 algorithms instead of silently downgrading.
"""
MAX_KEX = [
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768nistp256-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group18-sha512"
]
MAX_CIPHERS = [
    "aes256-gcm@openssh.com",
    "aes256-ctr",
    "chacha20-poly1305@openssh.com"
]
MAX_MACS = [
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com"
]
MAX_HOSTKEYS = [
    "ssh-mldsa44-ed25519",
    "ssh-ed25519",
    "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp256",
    "rsa-sha2-512",
    "rsa-sha2-256"
]


def normalize_list(base: list[str], value: list[str] | None) -> list[str] | None:
    """
     Resolve an algorithm list against built-in defaults (OpenSSH rules).

     ``None`` passes through (caller falls back to its default). A plain
     list replaces the defaults. Entries starting with ``+``/``-``/``^``
     are relative to the defaults (append / remove / prepend), exactly
     like ssh_config(5). There is no ``max`` keyword (not in OpenSSH).
    """
    if value is None:
        return None
    vals = [v.strip() for v in value]
    vals = [v for v in vals if v]
    if any(v[0] in "+-^" for v in vals):
        out = list(base)
        for v in vals:
            if len(v) == 1:  # lone +/-/^ is meaningless: fail, don't ignore
                raise ValueError(f"bad algorithm item {v!r}")
            if v.startswith("+"):
                if v[1:] not in out:
                    out.append(v[1:])
            elif v.startswith("-"):
                out = [x for x in out if x != v[1:]]
            elif v.startswith("^"):
                out = [v[1:]] + [x for x in out if x != v[1:]]
            elif v not in out:
                out.append(v)
        if not out:
            raise ValueError("algorithm list is empty after +/-/^ expansion")
        return out
    return list(vals)


def expand_alg_option(base: list[str], spec: str) -> list[str]:
    """
     Resolve one `-o` algorithm option string (OpenSSH-style).

     A plain comma list replaces the defaults; entries starting with
     ``+``/``-``/``^`` are relative to them (append / remove / prepend,
     like ssh_config). There is no ``max`` keyword (not in OpenSSH).
    """
    vals = [v.strip() for v in spec.split(",")]
    vals = [v for v in vals if v]
    out = normalize_list(base, vals)
    if not out:
        raise ValueError("algorithm option is empty")
    return out

_sntrup_ok: bool | None = None
_SNTRUP_LOCK = threading.Lock()


def sntrup_available() -> bool:
    """
     Whether sntrup761 can actually run here (liboqs present). Cached;
     safe to call often, never raises.
    """
    global _sntrup_ok
    if _sntrup_ok is None:
        with _SNTRUP_LOCK:
            if _sntrup_ok is None:
                try:
                    from ccssh import sntrup as SN
                    SN.load_backend()
                    _sntrup_ok = True
                except Exception:
                    _sntrup_ok = False
    return _sntrup_ok


def default_kex() -> list[str]:
    """
     Default KEX offer: everything supported that can run here. sntrup761
     is included only with a working liboqs, so default users never hit
     BackendMissing; explicit selection still errors clearly without one.
    """
    if sntrup_available():
        return list(SUPPORTED_KEX)
    return [k for k in SUPPORTED_KEX if "sntrup761" not in k]


def coverage() -> dict[str, str]:
    return {
        "kex": f"{len(SUPPORTED_KEX)}/{len(OPENSSH_KEX)} live (sntrup761 needs liboqs)",
        "cipher": f"{len(SUPPORTED_CIPHERS)}/{len(OPENSSH_CIPHERS)} live",
        "mac": f"{len(SUPPORTED_MACS)}/{len(OPENSSH_MACS)} live (+AEAD implicit)",
        "hostkey": f"{len(SUPPORTED_HOSTKEYS)}/{len(OPENSSH_KEYS)} live (certs with CA verify)",
    }
