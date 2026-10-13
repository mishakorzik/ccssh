"""
 sntrup761x25519-sha512 hybrid KEX with a pluggable backend.

 NTRU Prime is not in `cryptography`, and pqcrypto does not build on this
 platform, so the primitive comes from optional liboqs (`pip install oqs`
 plus system liboqs). Framing/negotiation are ours and are tested with the
 fake backend below. Without a backend, sntrup is excluded from offers and
 forcing it raises a clear error (see load_backend).
 Sizes: ek 1158 B, ct 1039 B, C_INIT 1190 B, S_REPLY 1071 B, K = SHA512,
 string-encoded like the mlkem hybrid.
"""
from __future__ import annotations
import hashlib
import os
import threading

SNTRUP_EK_LEN = 1158
SNTRUP_CT_LEN = 1039
SNTRUP_SS_LEN = 32
X_PUB_LEN = 32
C_INIT_LEN = SNTRUP_EK_LEN + X_PUB_LEN
S_REPLY_LEN = SNTRUP_CT_LEN + X_PUB_LEN


class BackendMissing(Exception):
    pass


_liboqs = None
_LIBOQS_LOCK = threading.Lock()


def _load_liboqs():
    """
     liboqs shared library via ctypes (no Python dependency). Cached;
     raises BackendMissing with install hints when absent.
    """
    global _liboqs
    if _liboqs is not None:
        return _liboqs
    with _LIBOQS_LOCK:
        if _liboqs is not None:
            return _liboqs
        return _load_liboqs_locked()


def _load_liboqs_locked():
    global _liboqs
    import ctypes
    import ctypes.util
    cands = []
    try:
        found = ctypes.util.find_library("oqs")
        if found:
            cands.append(found)
    except Exception:
        pass
    cands.append("liboqs.so") # loader default paths (covers Termux $PREFIX/lib)
    last: Exception | None = None
    for cand in cands:
        try:
            lib = ctypes.CDLL(cand)
            lib.OQS_KEM_new.argtypes = [ctypes.c_char_p]
            lib.OQS_KEM_new.restype = ctypes.c_void_p
            lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]
            lib.OQS_KEM_free.restype = None
            lib.OQS_KEM_keypair.argtypes = [ctypes.c_void_p] * 3
            lib.OQS_KEM_keypair.restype = ctypes.c_int
            lib.OQS_KEM_encaps.argtypes = [ctypes.c_void_p] * 4
            lib.OQS_KEM_encaps.restype = ctypes.c_int
            lib.OQS_KEM_decaps.argtypes = [ctypes.c_void_p] * 4
            lib.OQS_KEM_decaps.restype = ctypes.c_int
            kem_probe = lib.OQS_KEM_new(b"sntrup761")
            if not kem_probe:
                raise BackendMissing("liboqs has no sntrup761 support")
            lib.OQS_KEM_free(kem_probe) # probe only: must not leak the context
            _liboqs = lib
            return lib
        except BackendMissing:
            raise
        except Exception as e:
            last = e
    raise BackendMissing(
        "sntrup761 needs liboqs (open-quantum-safe/liboqs) installed where "
        f"the loader finds it; last error: {last}. Without it, ccssh "
        "negotiates mlkem/curve instead.") from last


def _kem_lengths(lib):
    """
     Read sntrup761 size parameters from the OQS_KEM struct itself instead
     of hardcoding the secret-key length. Layout (stable since 0.8):
     char* name, char* version, u8 level, bool cca, then size_t
     public/secret/ciphertext/shared-secret lengths.
    """
    import ctypes

    class Kem(ctypes.Structure):
        _fields_ = [("method_name", ctypes.c_void_p),
                    ("alg_version", ctypes.c_void_p),
                    ("claimed_nist_level", ctypes.c_uint8),
                    ("ind_cca", ctypes.c_bool),
                    ("length_public_key", ctypes.c_size_t),
                    ("length_secret_key", ctypes.c_size_t),
                    ("length_ciphertext", ctypes.c_size_t),
                    ("length_shared_secret", ctypes.c_size_t)]

    kem = lib.OQS_KEM_new(b"sntrup761")
    if not kem:
        raise BackendMissing("liboqs has no sntrup761 support")
    try:
        k = Kem.from_address(kem)
        out = (k.length_public_key, k.length_secret_key,
               k.length_ciphertext, k.length_shared_secret)
    finally:
        lib.OQS_KEM_free(kem)
    if out[0] != SNTRUP_EK_LEN or out[2] != SNTRUP_CT_LEN or out[3] != SNTRUP_SS_LEN:
        raise BackendMissing(f"unexpected sntrup761 parameters {out}")
    return out


class LibOQSBackend:
    """
     Real sntrup761 via the liboqs C API. Each operation opens and frees
     its own KEM context (a handshake does a handful - negligible cost).
    """

    def __init__(self):
        lib = _load_liboqs()
        _ek, sk_len, _ct, _ss = _kem_lengths(lib)
        self._lib = lib
        self._sk_len = sk_len

    def _new(self):
        kem = self._lib.OQS_KEM_new(b"sntrup761")
        if not kem:
            raise BackendMissing("liboqs lost sntrup761 support")
        return kem

    def generate(self):
        import ctypes
        lib = self._lib
        kem = self._new()
        try:
            ek = ctypes.create_string_buffer(SNTRUP_EK_LEN)
            sk = ctypes.create_string_buffer(self._sk_len)
            if lib.OQS_KEM_keypair(kem, ek, sk) != 0:
                raise BackendMissing("sntrup761 keypair failed")
            return bytes(ek), bytes(sk)
        finally:
            lib.OQS_KEM_free(kem)

    def encap(self, ek: bytes):
        import ctypes
        if len(ek) != SNTRUP_EK_LEN:
            raise ValueError(f"sntrup ek must be {SNTRUP_EK_LEN} bytes")
        lib = self._lib
        kem = self._new()
        try:
            ct = ctypes.create_string_buffer(SNTRUP_CT_LEN)
            ss = ctypes.create_string_buffer(SNTRUP_SS_LEN)
            if lib.OQS_KEM_encaps(kem, ct, ss, ek) != 0:
                raise BackendMissing("sntrup761 encaps failed")
            return bytes(ct), bytes(ss)
        finally:
            lib.OQS_KEM_free(kem)

    def decap(self, sk: bytes, ct: bytes):
        import ctypes
        if len(ct) != SNTRUP_CT_LEN:
            raise ValueError(f"sntrup ct must be {SNTRUP_CT_LEN} bytes")
        if len(sk) != self._sk_len:
            raise ValueError("sntrup sk has wrong length")
        lib = self._lib
        kem = self._new()
        try:
            ss = ctypes.create_string_buffer(SNTRUP_SS_LEN)
            if lib.OQS_KEM_decaps(kem, ss, ct, sk) != 0:
                # Real KEMs never fail decaps (implicit rejection inside).
                ss = bytes(os.urandom(SNTRUP_SS_LEN))
            return bytes(ss)
        finally:
            lib.OQS_KEM_free(kem)


def load_backend():
    """
     Production backend (liboqs) or BackendMissing with install hints.
    """
    be = LibOQSBackend() # probe+reuse: raises BackendMissing when unusable
    return be


class FakeBackend:
    """Stateful fake for framing tests (NOT crypto): remembers ct->ss."""

    def __init__(self):
        self._ct_to_ss: dict[bytes, bytes] = {}

    def generate(self):
        ek, sk = os.urandom(SNTRUP_EK_LEN), os.urandom(32)
        return ek, sk

    def encap(self, ek: bytes):
        _ = ek # fake ignores its input; remembers ct->ss instead
        ct, ss = os.urandom(SNTRUP_CT_LEN), os.urandom(SNTRUP_SS_LEN)
        self._ct_to_ss[ct] = ss
        return ct, ss

    def decap(self, sk: bytes, ct: bytes):
        _ = sk  # fake ignores its input; looks up ct->ss instead
        ss = self._ct_to_ss.get(ct)
        if ss is None:  # implicit rejection, like real KEMs
            ss = os.urandom(SNTRUP_SS_LEN)
        return ss


def combine(Kpq: bytes, Kecdh: bytes) -> bytes:
    if len(Kpq) != 32 or len(Kecdh) != 32:
        raise ValueError("K_PQ and K_ECDH must be 32 bytes each")
    return hashlib.sha512(Kpq + Kecdh).digest()


# hybrid handshake (same shape as mlkem768x25519-sha256, SHA-512)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from ccssh import mlkem as _MLKEM
from ccssh import wire as _W


class ClientState:
    """Ephemeral client state between C_INIT and S_REPLY."""

    def __init__(self, backend, kem_sk: bytes, x_sk, Vc: bytes, Ic: bytes, C_INIT: bytes):
        self.backend = backend
        self.kem_sk = kem_sk
        self.x_sk = x_sk
        self.V_C = Vc
        self.I_C = Ic
        self.C_INIT = C_INIT


class Session:
    """Agreed session (mirrors mlkem.Session field names)."""

    def __init__(self, role, K_pq, K_ecdh, K, H, session_id,
                 V_C, V_S, I_C, I_S, K_S, C_INIT, S_REPLY):
        self.role = role
        self.K_pq = K_pq
        self.K_ecdh = K_ecdh
        self.K = K
        self.H = H
        self.session_id = session_id
        self.V_C = V_C
        self.V_S = V_S
        self.I_C = I_C
        self.I_S = I_S
        self.K_S = K_S
        self.C_INIT = C_INIT
        self.S_REPLY = S_REPLY


def compute_exchange_hash(V_C, V_S, I_C, I_S, K_S, C_INIT, S_REPLY, K_raw) -> bytes:
    if len(C_INIT) != C_INIT_LEN:
        raise ValueError(f"C_INIT must be {C_INIT_LEN} bytes, got {len(C_INIT)}")
    if len(S_REPLY) != S_REPLY_LEN:
        raise ValueError(f"S_REPLY must be {S_REPLY_LEN} bytes, got {len(S_REPLY)}")
    if len(K_raw) != 64:
        raise ValueError(f"K must be 64 bytes, got {len(K_raw)}")
    h = hashlib.sha512()
    for part in (V_C, V_S, I_C, I_S, K_S, C_INIT, S_REPLY, K_raw):
        h.update(_W.enc_string(part))
    return h.digest()


def client_create(V_C: bytes, I_C: bytes, backend=None) -> ClientState:
    be = backend if backend is not None else load_backend()
    ek, sk = be.generate()
    if len(ek) != SNTRUP_EK_LEN:
        raise ValueError(f"sntrup ek must be {SNTRUP_EK_LEN} bytes")
    x_sk = X25519PrivateKey.generate()
    C_INIT = ek + x_sk.public_key().public_bytes_raw()
    if len(C_INIT) != C_INIT_LEN:
        raise ValueError(f"C_INIT must be {C_INIT_LEN} bytes")
    return ClientState(be, sk, x_sk, V_C, I_C, C_INIT)


def client_process_reply(st: ClientState, *, V_S: bytes, I_S: bytes, K_S: bytes, S_REPLY: bytes, sig_inner: bytes, host_alg: str = "ssh-ed25519") -> Session:
    if len(S_REPLY) != S_REPLY_LEN:
        raise ValueError(f"S_REPLY must be {S_REPLY_LEN} bytes")
    ct, x_pk_s = S_REPLY[:SNTRUP_CT_LEN], S_REPLY[SNTRUP_CT_LEN:]
    K_pq = st.backend.decap(st.kem_sk, ct)
    _MLKEM.reject_low_order_x25519(x_pk_s)
    K_ecdh = st.x_sk.exchange(X25519PublicKey.from_public_bytes(x_pk_s))
    _MLKEM.check_secret_nonzero(K_ecdh)
    K_raw = combine(K_pq, K_ecdh)
    H = compute_exchange_hash(st.V_C, V_S, st.I_C, I_S, K_S, st.C_INIT, S_REPLY, K_raw)
    if host_alg == "ssh-ed25519":
        host_pub = _MLKEM.parse_hostkey_blob(K_S)
        ok = _MLKEM.verify_exchange_hash(host_pub, H, sig_inner)
    else:
        from ccssh import hostkeys as _HK # lazy: avoids an import cycle
        ok = _HK.verify_host_signature(K_S, host_alg, H, sig_inner)
    if not ok:
        raise ValueError("exchange hash signature mismatch (MitM/damage?)")
    return Session("client", K_pq, K_ecdh, K_raw, H, H, st.V_C, V_S, st.I_C, I_S, K_S, st.C_INIT, S_REPLY)


def server_process_init(*, host_priv, V_C: bytes, V_S: bytes, I_C: bytes, I_S: bytes, C_INIT: bytes, backend=None):
    be = backend if backend is not None else load_backend()
    if len(C_INIT) != C_INIT_LEN:
        raise ValueError(f"C_INIT must be {C_INIT_LEN} bytes")
    ek, x_pk_c = C_INIT[:SNTRUP_EK_LEN], C_INIT[SNTRUP_EK_LEN:]
    ct, K_pq = be.encap(ek)
    x_sk_s = X25519PrivateKey.generate()
    x_pk_s = x_sk_s.public_key().public_bytes_raw()
    _MLKEM.reject_low_order_x25519(x_pk_c)
    K_ecdh = x_sk_s.exchange(X25519PublicKey.from_public_bytes(x_pk_c))
    _MLKEM.check_secret_nonzero(K_ecdh)
    K_raw = combine(K_pq, K_ecdh)
    S_REPLY = ct + x_pk_s
    Ks = _MLKEM.hostkey_blob_from_priv(host_priv)
    H = compute_exchange_hash(V_C, V_S, I_C, I_S, Ks, C_INIT, S_REPLY, K_raw)
    sig = _MLKEM.sign_exchange_hash(host_priv, H)
    return S_REPLY, Ks, sig, Session("server", K_pq, K_ecdh, K_raw, H, H, V_C, V_S, I_C, I_S, Ks, C_INIT, S_REPLY)
