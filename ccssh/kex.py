"""
 Key exchange negotiation plus curve25519-sha256 and mlkem768x25519-sha256.

 Primitives come from `cryptography`; the hybrid math lives in ccssh.mlkem.
 ServerStub classes are test-only loopback peers (never production).
"""
from __future__ import annotations
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from ccssh import hostkeys
from ccssh import mlkem
from ccssh import wire as W

MSG_KEXINIT = 20
MSG_NEWKEYS = 21
MSG_EXT_INFO = 7
MSG_KEX_ECDH_INIT = 30
MSG_KEX_ECDH_REPLY = 31
# The hybrid KEX reuses message numbers 30/31 (HYBRID_INIT/REPLY).

# Terrapin defense (strict-kex) + extensions (ext-info). Clients send -c, servers -s.
KEX_STRICT_C = "kex-strict-c-v00@openssh.com"
KEX_STRICT_S = "kex-strict-s-v00@openssh.com"
EXT_INFO_C = "ext-info-c"

# Client offer for the loopback stub (priority order).
KEX_OFFER = ["mlkem768x25519-sha256", "curve25519-sha256"]
HOSTKEY_OFFER = ["ssh-ed25519"]
CIPHER_OFFER = ["aes128-ctr"]
MAC_OFFER = ["hmac-sha2-256"]
COMP_OFFER = ["none"]
LANG_OFFER: list[str] = []


def enc_ext_info(exts: list[tuple[bytes, bytes]]) -> bytes:
    out = bytes([MSG_EXT_INFO]) + W.enc_u32(len(exts))
    for n, v in exts:
        out += W.enc_string(n) + W.enc_string(v)
    return out


def negotiate(client: list[str], server: list[str]) -> str:
    flags = {KEX_STRICT_C, KEX_STRICT_S, EXT_INFO_C}
    for c in client:
        if c in flags:
            continue
        if c in server:
            return c
    raise ValueError(f"no common algorithm: client {client} vs server {server}")


def negotiate_symmetric(ours: list[str], peer_c2s: list[str], peer_s2c: list[str], what: str) -> str:
    """
     Negotiate one algorithm for both directions (OpenSSH behavior).

     RFC 4253 permits asymmetry, but OpenSSH always uses the same cipher/MAC
     both ways and so do our key schedules - accepting anything else would
     derive the wrong receive keys. Fail closed instead.
    """
    c2s = negotiate(ours, peer_c2s)
    s2c = negotiate(ours, peer_s2c)
    if c2s != s2c:
        raise ValueError(f"asymmetric {what}: c2s={c2s} s2c={s2c}")
    return c2s


def peer_wants_strict(peer_kex: list[str], *, is_client: bool) -> bool:
    """Whether the peer advertises strict-kex (clients need -s, servers -c)."""
    want = KEX_STRICT_S if is_client else KEX_STRICT_C
    return want in peer_kex


def peer_wants_ext_info(peer_kex: list[str]) -> bool:
    return EXT_INFO_C in peer_kex


def enc_kexinit(cookie: bytes, kex: list[str], hostkey: list[str], enc_c2s: list[str], enc_s2c: list[str], mac_c2s: list[str], mac_s2c: list[str], comp_c2s: list[str], comp_s2c: list[str], first_follows: bool = False) -> bytes:
    """Full KEXINIT packet payload, message number included."""
    if len(cookie) != 16:
        raise ValueError("cookie must be 16 bytes")
    out = bytes([MSG_KEXINIT]) + cookie
    out += W.enc_namelist(kex) + W.enc_namelist(hostkey)
    out += W.enc_namelist(enc_c2s) + W.enc_namelist(enc_s2c)
    out += W.enc_namelist(mac_c2s) + W.enc_namelist(mac_s2c)
    out += W.enc_namelist(comp_c2s) + W.enc_namelist(comp_s2c)
    out += W.enc_namelist(LANG_OFFER) + W.enc_namelist(LANG_OFFER)
    out += W.enc_bool(first_follows) + W.enc_u32(0)
    return out


def dec_kexinit(payload: bytes) -> dict:
    r = W.Reader(payload)
    if r.byte() != MSG_KEXINIT:
        raise W.WireError("expected SSH_MSG_KEXINIT")
    cookie = r.raw(16)
    out = {
        "cookie": cookie,
        "kex": r.namelist(), "hostkey": r.namelist(),
        "enc_c2s": r.namelist(), "enc_s2c": r.namelist(),
        "mac_c2s": r.namelist(), "mac_s2c": r.namelist(),
        "comp_c2s": r.namelist(), "comp_s2c": r.namelist(),
        "lang_c2s": r.namelist(), "lang_s2c": r.namelist(),
        "first_follows": r.bool(), "_reserved": r.u32(),
        "payload_full": payload,
    }
    if out["_reserved"] != 0:
        raise W.WireError("KEXINIT reserved must be zero")
    r.assert_end()
    return out


"""
 I_C/I_S for H is the whole SSH_MSG_KEXINIT content INCLUDING the
 message-number byte (how OpenSSH/Dropbear/PuTTY hash it; verified live
 against OpenSSH: without the first byte the server signature fails).
"""
I_FOR_H = lambda full_payload: full_payload


# curve25519-sha256
# Low-order set lives in mlkem (imported by every hybrid path); keep the
# historic names here so existing callers keep working.
_LOW_ORDER_X25519 = mlkem.X25519_LOW_ORDER


def _reject_low_order_x25519(q: bytes) -> None:
    mlkem.reject_low_order_x25519(q)


class Curve25519Client:
    def __init__(self):
        self.sk = X25519PrivateKey.generate()
        self.qc = self.sk.public_key().public_bytes_raw()

    def init_msg(self) -> bytes:
        return bytes([MSG_KEX_ECDH_INIT]) + W.enc_string(self.qc)

    def finish(self, reply: bytes, Vc: bytes, Vs: bytes, Ic_H: bytes, Is_H: bytes, host_alg: str = "ssh-ed25519") -> tuple[bytes, bytes, bytes]:
        """Returns (K_raw, H, K_S). Raises ValueError on bad length/signature."""
        r = W.Reader(reply)
        if r.byte() != MSG_KEX_ECDH_REPLY:
            raise W.WireError("expected SSH_MSG_KEX_ECDH_REPLY")
        Ks = r.string()
        Qs = r.string()
        sig = r.string()
        r.assert_end()
        if len(Qs) != 32 or len(self.qc) != 32:
            raise ValueError("Qc/Qs must be 32 bytes")
        _reject_low_order_x25519(Qs)
        K_ecdh = self.sk.exchange(X25519PublicKey.from_public_bytes(Qs))
        mlkem.check_secret_nonzero(K_ecdh)
        K_mpint = W.mpint_from_bytes(K_ecdh)
        Hh = hashlib.sha256(W.enc_string(Vc) + W.enc_string(Vs) + W.enc_string(Ic_H) + W.enc_string(Is_H) + W.enc_string(Ks) + W.enc_string(self.qc) + W.enc_string(Qs) + K_mpint).digest()
        if not hostkeys.verify_host_signature(Ks, host_alg, Hh, sig):
            raise ValueError("host signature mismatch (curve25519)")
        return K_ecdh, Hh, Ks


class Curve25519ServerStub:
    """Test-only loopback peer (never production)."""

    def __init__(self, host_priv):
        self.host_priv = host_priv
        self.sk = X25519PrivateKey.generate()
        self.qs = self.sk.public_key().public_bytes_raw()

    def reply(self, init_msg: bytes, Vc: bytes, Vs: bytes, Ic_H: bytes, Is_H: bytes) -> tuple[bytes, bytes, bytes]:
        r = W.Reader(init_msg)
        if r.byte() != MSG_KEX_ECDH_INIT:
            raise W.WireError("expected SSH_MSG_KEX_ECDH_INIT")
        Qc = r.string()
        K_ecdh = self.sk.exchange(X25519PublicKey.from_public_bytes(Qc))
        Ks = mlkem.hostkey_blob_from_priv(self.host_priv)
        K_mpint = W.mpint_from_bytes(K_ecdh)
        Hh = hashlib.sha256(W.enc_string(Vc) + W.enc_string(Vs) + W.enc_string(Ic_H) + W.enc_string(Is_H) + W.enc_string(Ks) + W.enc_string(Qc) + W.enc_string(self.qs) + K_mpint).digest()
        sig = mlkem.sign_exchange_hash(self.host_priv, Hh)
        msg = bytes([MSG_KEX_ECDH_REPLY]) + W.enc_string(Ks) + W.enc_string(self.qs) + W.enc_string(sig)
        return msg, K_ecdh, Hh


# mlkem768x25519-sha256 (wrapper over ccssh.mlkem)
class MlkemHybridClient:
    def __init__(self, Vc: bytes, Ic_H: bytes):
        st = mlkem.client_create(Vc, Ic_H)
        self._st = st

    @property
    def c_init(self) -> bytes:
        return self._st.C_INIT

    def init_msg(self) -> bytes:
        return bytes([MSG_KEX_ECDH_INIT]) + W.enc_string(self.c_init)

    def finish(self, reply: bytes, Vs: bytes, Is_H: bytes, host_alg: str = "ssh-ed25519") -> tuple[bytes, bytes, bytes, bytes, bytes]:
        """(K_raw for H/KDF, H, K_S, K_pq, K_ecdh)."""
        r = W.Reader(reply)
        if r.byte() != MSG_KEX_ECDH_REPLY:
            raise W.WireError("expected SSH_MSG_KEX_ECDH_REPLY")
        Ks = r.string()
        S_reply = r.string()
        sig = r.string()
        r.assert_end()
        sess = mlkem.client_process_reply(self._st, V_S=Vs, I_S=Is_H, K_S=Ks, S_REPLY=S_reply, sig_inner=sig, host_alg=host_alg)
        return sess.K, sess.H, Ks, sess.K_pq, sess.K_ecdh


class MlkemHybridServerStub:
    def __init__(self, host_priv, Vs: bytes, Is_H: bytes):
        self.host_priv = host_priv
        self.Vs = Vs
        self.Is_H = Is_H

    def reply(self, init_msg: bytes, Vc: bytes, Ic_H: bytes) -> tuple[bytes, bytes, bytes]:
        r = W.Reader(init_msg)
        if r.byte() != MSG_KEX_ECDH_INIT:
            raise W.WireError("expected SSH_MSG_KEX_ECDH_INIT")
        C_init = r.string()
        S_reply, Ks, sig, sess = mlkem.server_process_init( host_priv=self.host_priv, V_C=Vc, V_S=self.Vs, I_C=Ic_H, I_S=self.Is_H, C_INIT=C_init)
        msg = bytes([MSG_KEX_ECDH_REPLY]) + W.enc_string(Ks) + W.enc_string(S_reply) + W.enc_string(sig)
        return msg, sess.K, sess.H
