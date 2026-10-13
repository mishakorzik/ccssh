"""
 Extra key exchange methods: ecdsa-sha2-nistp*, diffie-hellman-group*-sha*,
 diffie-hellman-group-exchange-sha256, mlkem768nistp256-sha256, sntrup761
 framing.

 Exchange-hash formulas follow RFC 5656 (ECDH), RFC 4253 section 8 (DH/GEX),
 and the hybrid drafts (mlkem+p256, sntrup+x25519). ServerStub classes are
 test-only peers.
"""
from __future__ import annotations
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import ec

from ccssh import hostkeys
from ccssh import mlkem
from ccssh import wire as W
from ccssh.dh_groups import P1_1024, P14_2048, P16_4096, P18_8192, G as DH_G
from ccssh.kex import MSG_KEX_ECDH_INIT, MSG_KEX_ECDH_REPLY

CURVES = {
    "ecdh-sha2-nistp256": (ec.SECP256R1(), hashlib.sha256),
    "ecdh-sha2-nistp384": (ec.SECP384R1(), hashlib.sha384),
    "ecdh-sha2-nistp521": (ec.SECP521R1(), hashlib.sha512),
}
DH_GROUPS = {
    "diffie-hellman-group14-sha256": (P14_2048, hashlib.sha256),
    "diffie-hellman-group14-sha1": (P14_2048, hashlib.sha1),
    "diffie-hellman-group16-sha512": (P16_4096, hashlib.sha512),
    "diffie-hellman-group18-sha512": (P18_8192, hashlib.sha512),
    "diffie-hellman-group1-sha1": (P1_1024, hashlib.sha1),
}

P14 = P14_2048 # short alias, used by tests

# curve25519-sha256@libssh.org is wire-identical to curve25519-sha256.
KEX_ALIASES = {
    "curve25519-sha256@libssh.org": "curve25519-sha256",
    "sntrup761x25519-sha512@openssh.com": "sntrup761x25519-sha512"
}

KEX_HASH = {
    "curve25519-sha256": hashlib.sha256,
    "curve25519-sha256@libssh.org": hashlib.sha256,
    "mlkem768x25519-sha256": hashlib.sha256,
    "mlkem768nistp256-sha256": hashlib.sha256,
    "ecdh-sha2-nistp256": hashlib.sha256,
    "ecdh-sha2-nistp384": hashlib.sha384,
    "ecdh-sha2-nistp521": hashlib.sha512,
    "diffie-hellman-group14-sha256": hashlib.sha256,
    "diffie-hellman-group14-sha1": hashlib.sha1,
    "diffie-hellman-group16-sha512": hashlib.sha512,
    "diffie-hellman-group18-sha512": hashlib.sha512,
    "diffie-hellman-group1-sha1": hashlib.sha1,
    "diffie-hellman-group-exchange-sha256": hashlib.sha256,
    "diffie-hellman-group-exchange-sha1": hashlib.sha1,
    "sntrup761x25519-sha512": hashlib.sha512,
}


def kdf_hashfn(kex_name: str):
    """KDF hash for a KEX method (always the KEX hash, never cipher/MAC-derived)."""
    h = KEX_HASH.get(KEX_ALIASES.get(kex_name, kex_name), hashlib.sha256)
    return lambda d: h(d).digest()


def _point_encode(pub) -> bytes:
    nums = pub.public_numbers()
    size = (pub.curve.key_size + 7) // 8
    return b"\x04" + nums.x.to_bytes(size, "big") + nums.y.to_bytes(size, "big")


def _point_decode(curve, data: bytes):
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    return EllipticCurvePublicKey.from_encoded_point(curve, data)


class EcdhClient:
    def __init__(self, name: str):
        curve, self.hash = CURVES[name]
        self.name = name
        self.curve = curve
        self.sk = ec.generate_private_key(curve)
        self.qc = _point_encode(self.sk.public_key())

    def init_msg(self) -> bytes:
        return bytes([MSG_KEX_ECDH_INIT]) + W.enc_string(self.qc)

    def finish(self, reply: bytes, Vc: bytes, Vs: bytes, Ic: bytes, Is: bytes, host_alg: str = "ssh-ed25519"):
        r = W.Reader(reply)
        if r.byte() != MSG_KEX_ECDH_REPLY:
            raise W.WireError("expected SSH_MSG_KEX_ECDH_REPLY")
        Ks, Qs, sig = r.string(), r.string(), r.string()
        r.assert_end()
        peer = _point_decode(self.curve, Qs)
        K_ecdh = self.sk.exchange(ec.ECDH(), peer) # x-coordinate octet string
        mlkem.check_secret_nonzero(K_ecdh, "ECDH")
        Hh = self.hash(W.enc_string(Vc) + W.enc_string(Vs) + W.enc_string(Ic) + W.enc_string(Is) + W.enc_string(Ks) + W.enc_string(self.qc) + W.enc_string(Qs) + W.mpint_from_bytes(K_ecdh)).digest()
        if not hostkeys.verify_host_signature(Ks, host_alg, Hh, sig):
            raise ValueError("host signature mismatch (ecdh)")
        return K_ecdh, Hh, Ks


class EcdhServerStub:
    def __init__(self, name: str, host_priv):
        curve, self.hash = CURVES[name]
        self.name, self.curve, self.host_priv = name, curve, host_priv
        self.sk = ec.generate_private_key(curve)
        self.qs = _point_encode(self.sk.public_key())

    def reply(self, init_msg: bytes, Vc: bytes, Vs: bytes, Ic: bytes, Is: bytes):
        r = W.Reader(init_msg)
        if r.byte() != MSG_KEX_ECDH_INIT:
            raise W.WireError("expected SSH_MSG_KEX_ECDH_INIT")
        Qc = r.string()
        K_ecdh = self.sk.exchange(ec.ECDH(), _point_decode(self.curve, Qc))
        Ks = mlkem.hostkey_blob_from_priv(self.host_priv)
        Hh = self.hash(W.enc_string(Vc) + W.enc_string(Vs) + W.enc_string(Ic) + W.enc_string(Is) + W.enc_string(Ks) + W.enc_string(Qc) + W.enc_string(self.qs) + W.mpint_from_bytes(K_ecdh)).digest()
        sig = mlkem.sign_exchange_hash(self.host_priv, Hh)
        msg = bytes([MSG_KEX_ECDH_REPLY]) + W.enc_string(Ks) + W.enc_string(self.qs) + W.enc_string(sig)
        return msg, K_ecdh, Hh


def _is_probable_prime(n: int, rounds: int | None = None) -> bool:
    """
     Miller-Rabin with trial division (for validating GEX groups from
     a possibly hostile server - never trust a composite modulus).

     The stock RFC 3526 groups skip the test (exact match); unknown
     moduli get size-scaled rounds (a full 8-round test of an 8192-bit
     unknown group would stall every handshake by ~15s).
    """
    if n in (P14_2048, P16_4096, P18_8192):
        return True
    if rounds is None:
        bits = n.bit_length()
        rounds = 12 if bits <= 2048 else (6 if bits <= 4096 else 3)
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small:
        if n % p == 0:
            return n == p
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    import random as _random
    rng = _random.SystemRandom()
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_dh_secret(p: int) -> int:
    """
     Private exponent sized to the group: 256 bits minimum (fast even
     for 8192-bit groups), scaling up toward RFC 3526 guidance.
    """
    nbytes = max(32, min(64, (p.bit_length() + 7) // 8))
    return int.from_bytes(os.urandom(nbytes), "big") | 1


def _check_dh_peer(value: int, p: int, what: str = "peer DH public value") -> None:
    if not 2 <= value <= p - 2:
        raise ValueError(f"{what} out of range")
    if pow(value, (p - 1) // 2, p) != 1:
        raise ValueError(f"{what} not in subgroup")


class DhClient:
    """Generic MODP DH: e=g^x, H=HASH(Vc||Vs||Ic||Is||Ks||e||f||K)."""

    def __init__(self, name: str):
        p, hf = DH_GROUPS[name]
        self.name, self.p, self.hash = name, p, hf
        self.x = _gen_dh_secret(p)
        self.e = pow(DH_G, self.x, self.p)

    def init_msg(self) -> bytes:
        return bytes([30]) + W.enc_mpint(self.e) # SSH_MSG_KEXDH_INIT

    def finish(self, reply: bytes, Vc: bytes, Vs: bytes, Ic: bytes, Is: bytes, host_alg: str = "ssh-ed25519"):
        r = W.Reader(reply)
        if r.byte() != 31:
            raise W.WireError("expected SSH_MSG_KEXDH_REPLY")
        Ks, f, sig = r.string(), r.mpint(), r.string()
        r.assert_end()
        _check_dh_peer(f, self.p)
        K_int = pow(f, self.x, self.p)
        K_raw = K_int.to_bytes((K_int.bit_length() + 7) // 8 or 1, "big")
        Hh = self.hash(W.enc_string(Vc) + W.enc_string(Vs) + W.enc_string(Ic) + W.enc_string(Is) + W.enc_string(Ks) + W.enc_mpint(self.e) + W.enc_mpint(f) + W.mpint_from_bytes(K_raw)).digest()
        if not hostkeys.verify_host_signature(Ks, host_alg, Hh, sig):
            raise ValueError(f"host signature mismatch ({self.name})")
        return K_raw, Hh, Ks


class DhServerStub:
    def __init__(self, name: str, host_priv):
        p, hf = DH_GROUPS[name]
        self.name, self.p, self.hash, self.host_priv = name, p, hf, host_priv
        self.y = _gen_dh_secret(p)
        self.f = pow(DH_G, self.y, self.p)

    def reply(self, init_msg: bytes, Vc: bytes, Vs: bytes, Ic: bytes, Is: bytes):
        r = W.Reader(init_msg)
        if r.byte() != 30:
            raise W.WireError("expected SSH_MSG_KEXDH_INIT")
        e = r.mpint()
        r.assert_end()
        _check_dh_peer(e, self.p)
        K_int = pow(e, self.y, self.p)
        K_raw = K_int.to_bytes((K_int.bit_length() + 7) // 8 or 1, "big")
        Ks = mlkem.hostkey_blob_from_priv(self.host_priv)
        Hh = self.hash(W.enc_string(Vc) + W.enc_string(Vs) + W.enc_string(Ic) + W.enc_string(Is) + W.enc_string(Ks) + W.enc_mpint(e) + W.enc_mpint(self.f) + W.mpint_from_bytes(K_raw)).digest()
        sig = mlkem.sign_exchange_hash(self.host_priv, Hh)
        msg = bytes([31]) + W.enc_string(Ks) + W.enc_mpint(self.f) + W.enc_string(sig)
        return msg, K_raw, Hh


class Dh14Client(DhClient):
    def __init__(self):
        super().__init__("diffie-hellman-group14-sha256")


class Dh14ServerStub(DhServerStub):
    def __init__(self, host_priv):
        super().__init__("diffie-hellman-group14-sha256", host_priv)


class MlkemP256Client:
    """mlkem768nistp256-sha256: ek||Qc_p256 -> ct||Qs_p256, K=SHA256(Kpq||x)."""

    def __init__(self, Vc: bytes, Ic: bytes):
        st = mlkem.client_create(Vc, Ic)
        self._st = st
        self._ec = ec.generate_private_key(ec.SECP256R1())
        self.qc = _point_encode(self._ec.public_key())
        self.c_init = st.mlkem_ek + self.qc # 1184+65=1249

    def init_msg(self) -> bytes:
        return bytes([30]) + W.enc_string(self.c_init)

    def finish(self, reply: bytes, Vs: bytes, Is: bytes, host_alg: str = "ssh-ed25519"):
        r = W.Reader(reply)
        if r.byte() != 31:
            raise W.WireError("expected SSH_MSG_KEX_HYBRID_REPLY")
        Ks, S_reply, sig = r.string(), r.string(), r.string()
        r.assert_end()
        if len(S_reply) != 1088 + 65:
            raise ValueError(f"bad hybrid reply length {len(S_reply)}")
        ct, Qs = S_reply[:1088], S_reply[1088:]
        Kpq = self._st.mlkem_sk.decapsulate(ct)
        Kec = self._ec.exchange(ec.ECDH(), _point_decode(ec.SECP256R1(), Qs))
        mlkem.check_secret_nonzero(Kec, "ECDH")
        K_raw = hashlib.sha256(Kpq + Kec).digest()
        Hh = hashlib.sha256(W.enc_string(self._st.V_C) + W.enc_string(Vs) + W.enc_string(self._st.I_C) + W.enc_string(Is) + W.enc_string(Ks) + W.enc_string(self.c_init) + W.enc_string(S_reply) + W.enc_string(K_raw)).digest()
        if not hostkeys.verify_host_signature(Ks, host_alg, Hh, sig):
            raise ValueError("host signature mismatch (mlkem+p256)")
        return K_raw, Hh, Ks


# diffie-hellman-group-exchange-sha256 (RFC 4253 section 8)
GEX_MIN, GEX_N, GEX_MAX = 2048, 3072, 8192
GEX_GROUPS = [(P14_2048, 2048), (P16_4096, 4096), (P18_8192, 8192)]


class GexClient:
    """
     Two round trips: REQUEST(min/n/max) -> GROUP(p, g) -> INIT(e) ->
     REPLY(Ks, f, sig). H binds the range as uint32 trio, p/g/e/f/K as
     mpints (RFC 4253 section 8, exactly - live-verified against OpenSSH).
    """

    def __init__(self, min_bits: int = GEX_MIN, n_bits: int = GEX_N, max_bits: int = GEX_MAX, hashfn=None):
        if not 1024 <= min_bits <= n_bits <= max_bits <= 8192:
            raise ValueError("bad GEX range (max 8192 to bound CPU)")
        self.min, self.n, self.max = min_bits, n_bits, max_bits
        self.hash = hashfn or hashlib.sha256
        self.x = None
        self.p = 0
        self.g = DH_G
        self.e = 0

    def request_msg(self) -> bytes:
        return bytes([34]) + W.enc_u32(self.min) + W.enc_u32(self.n) + W.enc_u32(self.max)

    def init_msg(self, group: bytes) -> bytes:
        r = W.Reader(group)
        if r.byte() != 31:
            raise W.WireError("expected SSH_MSG_KEX_DH_GEX_GROUP")
        p, g = r.mpint(), r.mpint()
        r.assert_end()
        if not 2 <= g <= p - 2:
            raise ValueError("server group generator out of range")
        if not self.min <= p.bit_length() <= self.max:
            raise ValueError("server group outside requested range")
        # A rogue server offering a smooth/composite modulus would expose
        # the private exponent: demand (probable) primality first.
        if not _is_probable_prime(p):
            raise ValueError("server group modulus is not prime")
        self.p = p
        self.g = g
        self.x = _gen_dh_secret(p)
        self.e = pow(g, self.x, p)
        return bytes([32]) + W.enc_mpint(self.e)

    def finish(self, reply: bytes, Vc: bytes, Vs: bytes, Ic: bytes, Is: bytes, host_alg: str = "ssh-ed25519"):
        r = W.Reader(reply)
        if r.byte() != 33:
            raise W.WireError("expected SSH_MSG_KEX_DH_GEX_REPLY")
        Ks, f, sig = r.string(), r.mpint(), r.string()
        r.assert_end()
        if self.p == 0 or self.x is None:
            raise ValueError("GEX group not negotiated (call init_msg first)")
        _check_dh_peer(f, self.p)
        K_int = pow(f, self.x, self.p)
        K_raw = K_int.to_bytes((K_int.bit_length() + 7) // 8 or 1, "big")
        Hh = self.hash(W.enc_string(Vc) + W.enc_string(Vs) + W.enc_string(Ic) + W.enc_string(Is) + W.enc_string(Ks) + W.enc_u32(self.min) + W.enc_u32(self.n) + W.enc_u32(self.max) + W.enc_mpint(self.p) + W.enc_mpint(self.g) + W.enc_mpint(self.e) + W.enc_mpint(f) + W.mpint_from_bytes(K_raw)).digest()
        if not hostkeys.verify_host_signature(Ks, host_alg, Hh, sig):
            raise ValueError("host signature mismatch (gex)")
        return K_raw, Hh, Ks


class GexServerStub:
    """
     Test-only loopback peer: serves the largest known group in range.
    """

    def __init__(self, host_priv, hashfn=None):
        self.hash = hashfn or hashlib.sha256
        self.host_priv = host_priv
        self.mn = self.n = self.mx = 0
        self.p = 0
        self.y = 0
        self.f = 0

    def reply_request(self, req: bytes) -> bytes:
        r = W.Reader(req)
        if r.byte() != 34:
            raise W.WireError("expected SSH_MSG_KEX_DH_GEX_REQUEST")
        self.mn, self.n, self.mx = r.u32(), r.u32(), r.u32()
        r.assert_end()
        if not 1024 <= self.mn <= self.n <= self.mx <= 8192:
            raise ValueError("bad GEX range")
        pick = [(p, b) for p, b in GEX_GROUPS if self.mn <= b <= self.mx]
        if not pick:
            raise ValueError("no group in range")
        self.p, _ = pick[-1]
        self.y = _gen_dh_secret(self.p)
        self.f = pow(DH_G, self.y, self.p)
        return bytes([31]) + W.enc_mpint(self.p) + W.enc_mpint(DH_G)

    def reply_init(self, init: bytes, Vc: bytes, Vs: bytes, Ic: bytes, Is: bytes):
        r = W.Reader(init)
        if r.byte() != 32:
            raise W.WireError("expected SSH_MSG_KEX_DH_GEX_INIT")
        e = r.mpint()
        r.assert_end()
        _check_dh_peer(e, self.p)
        K_int = pow(e, self.y, self.p)
        K_raw = K_int.to_bytes((K_int.bit_length() + 7) // 8 or 1, "big")
        Ks = mlkem.hostkey_blob_from_priv(self.host_priv)
        Hh = self.hash(W.enc_string(Vc) + W.enc_string(Vs) + W.enc_string(Ic) + W.enc_string(Is) + W.enc_string(Ks) + W.enc_u32(self.mn) + W.enc_u32(self.n) + W.enc_u32(self.mx) + W.enc_mpint(self.p) + W.enc_mpint(DH_G) + W.enc_mpint(e) + W.enc_mpint(self.f) + W.mpint_from_bytes(K_raw)).digest()
        sig = mlkem.sign_exchange_hash(self.host_priv, Hh)
        msg = bytes([33]) + W.enc_string(Ks) + W.enc_mpint(self.f) + W.enc_string(sig)
        return msg, K_raw, Hh


class SntrupClient:
    """
     sntrup761x25519-sha512 (and the @openssh.com alias): ek||Qc -> ct||Qs,
     K=SHA512(Kpq||Kecdh). Needs a liboqs backend at runtime; tests pass
     FakeBackend explicitly, otherwise load_backend() raises BackendMissing.
    """

    def __init__(self, Vc: bytes, Ic: bytes, backend=None):
        from ccssh import sntrup as SN
        self._st = SN.client_create(Vc, Ic, backend)

    def init_msg(self) -> bytes:
        return bytes([MSG_KEX_ECDH_INIT]) + W.enc_string(self._st.C_INIT)

    def finish(self, reply: bytes, Vs: bytes, Is: bytes,
               host_alg: str = "ssh-ed25519"):
        from ccssh import sntrup as SN
        r = W.Reader(reply)
        if r.byte() != MSG_KEX_ECDH_REPLY:
            raise W.WireError("expected SSH_MSG_KEX_HYBRID_REPLY")
        Ks, S_reply, sig = r.string(), r.string(), r.string()
        r.assert_end()
        sess = SN.client_process_reply(self._st, V_S=Vs, I_S=Is, K_S=Ks, S_REPLY=S_reply, sig_inner=sig, host_alg=host_alg)
        return sess.K, sess.H, Ks, sess.K_pq, sess.K_ecdh


class SntrupServerStub:
    """
     Test-only loopback peer (never production).
    """

    def __init__(self, host_priv, Vs: bytes, Is: bytes, backend=None):
        from ccssh import sntrup as SN
        be = backend if backend is not None else SN.FakeBackend()
        self._be = be
        self.host_priv = host_priv
        self.Vs = Vs
        self.Is_H = Is

    def reply(self, init_msg: bytes, Vc: bytes, Ic_H: bytes):
        from ccssh import sntrup as SN
        r = W.Reader(init_msg)
        if r.byte() != MSG_KEX_ECDH_INIT:
            raise W.WireError("expected SSH_MSG_KEX_HYBRID_INIT")
        C_init = r.string()
        S_reply, Ks, sig, sess = SN.server_process_init(host_priv=self.host_priv, V_C=Vc, V_S=self.Vs, I_C=Ic_H, I_S=self.Is_H, C_INIT=C_init, backend=self._be)
        msg = bytes([MSG_KEX_ECDH_REPLY]) + W.enc_string(Ks) + W.enc_string(S_reply) + W.enc_string(sig)
        return msg, sess.K, sess.H
