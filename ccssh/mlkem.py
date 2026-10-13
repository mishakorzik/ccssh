"""
 Hybrid post-quantum key exchange mlkem768x25519-sha256.

 Matches OpenSSH >= 9.9 / 10.0 (IETF draft-kampanakis-curdle-ssh-pq-ke,
 OpenSSH kexmlkem768x25519.c):

  client -> server: SSH_MSG_KEX_HYBRID_INIT (30)
    C_INIT = ek_pq (1184 B) || ephemeral_pub_x25519 (32 B) = 1216 B
  server -> client: SSH_MSG_KEX_HYBRID_REPLY (31)
    K_S (host key blob), S_REPLY = ct_pq (1088 B) || ephemeral_pub_x25519_s
    (32 B) = 1120 B, signature over H with the host key

  K_PQ   = ML-KEM-768 shared secret, 32 B
  K_ECDH = X25519 shared secret, 32 B
  K      = SHA256(K_PQ || K_ECDH), 32 B

  H = SHA256(string(V_C) || string(V_S) || string(I_C) || string(I_S)
             || string(K_S) || string(C_INIT) || string(S_REPLY) || string(K))

 Note: K is encoded as an SSH string (uint32 BE length + raw bytes), NOT as
 an mpint. The same encoding feeds both H and the RFC 4253 section 7.2 KDF.

 Pure in-memory library without I/O; tests drive both sides in one process.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from ccssh import wire as W
from ccssh.mldsa import KeyPair as MldsaKeyPair

# sizes in bytes, matching OpenSSH
MLKEM768_EK_LEN = 1184
MLKEM768_CT_LEN = 1088
MLKEM768_SS_LEN = 32
X25519_PUB_LEN = 32
X25519_SS_LEN = 32
C_INIT_LEN = MLKEM768_EK_LEN + X25519_PUB_LEN # 1216
S_REPLY_LEN = MLKEM768_CT_LEN + X25519_PUB_LEN # 1120
K_LEN = 32 # SHA256 digest

HOSTKEY_ALG = b"ssh-ed25519"

ssh_string = W.enc_string


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def generate_hostkey(seed: bytes | None = None) -> Ed25519PrivateKey:
    """Generate an Ed25519 host key (32-byte seed for determinism, else random)."""
    if seed is not None:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return Ed25519PrivateKey.from_private_bytes(seed)
    return Ed25519PrivateKey.generate()


def hostkey_blob_from_pubkey(pub_raw: bytes) -> bytes:
    """K_S blob: string('ssh-ed25519') + string(pub 32B) = 51 B."""
    if len(pub_raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return ssh_string(HOSTKEY_ALG) + ssh_string(pub_raw)


def hostkey_blob_from_priv(priv: Ed25519PrivateKey | MldsaKeyPair) -> bytes:
    if isinstance(priv, MldsaKeyPair):
        return priv.public_blob()
    pub_raw = priv.public_key().public_bytes_raw()
    return hostkey_blob_from_pubkey(pub_raw)


def parse_hostkey_blob(blob: bytes) -> bytes:
    """Extract the 32-byte raw key from an ssh-ed25519 K_S blob."""
    alg, off = W.dec_string(blob, 0)
    pub, off2 = W.dec_string(blob, off)
    if alg != HOSTKEY_ALG:
        raise ValueError(f"unknown host key alg: {alg!r}")
    if len(pub) != 32 or off2 != len(blob):
        raise ValueError("malformed K_S blob")
    return pub


def sign_exchange_hash(host_priv: Ed25519PrivateKey | MldsaKeyPair, H: bytes) -> bytes:
    """
     Sign H. Returns the inner signature blob: string(alg) + string(sig).

     On the wire it is additionally wrapped in string(); the library and
     tests pass the inner form around, which is what verify parses.
    """
    if isinstance(host_priv, MldsaKeyPair):
        return host_priv.sign_nested(H)
    sig_raw = host_priv.sign(H) # 64 B
    return ssh_string(HOSTKEY_ALG) + ssh_string(sig_raw)


def verify_exchange_hash(host_pub_raw: bytes, H: bytes, sig_inner: bytes) -> bool:
    """Verify a host signature over H. Returns True/False, never raises."""
    try:
        alg, off = W.dec_string(sig_inner, 0)
        sig_raw, off2 = W.dec_string(sig_inner, off)
        if alg != HOSTKEY_ALG or len(sig_raw) != 64 or off2 != len(sig_inner):
            return False
        Ed25519PublicKey.from_public_bytes(host_pub_raw).verify(sig_raw, H)
        return True
    except (ValueError, InvalidSignature):
        return False


# core KEX
def check_secret_nonzero(secret: bytes, what: str = "X25519") -> None:
    """
     Reject an all-zero shared secret: a low-order (contributory-failure)
     peer point. Some backends return zeros instead of raising.
    """
    if secret == bytes(len(secret)):
        raise ValueError(f"{what} shared secret is zero")


def combine_shared(K_pq: bytes, K_ecdh: bytes) -> bytes:
    """
    K = SHA256(K_PQ || K_ECDH). Both inputs are 32 bytes.
    """
    if len(K_pq) != MLKEM768_SS_LEN or len(K_ecdh) != X25519_SS_LEN:
        raise ValueError("K_PQ and K_ECDH must be 32 bytes each")
    return sha256(K_pq, K_ecdh)


def compute_exchange_hash(V_C: bytes, V_S: bytes, I_C: bytes, I_S: bytes, K_S: bytes, C_INIT: bytes, S_REPLY: bytes, K_raw: bytes) -> bytes:
    """Exchange hash exactly like OpenSSH: every field as ssh_string."""
    if len(C_INIT) != C_INIT_LEN:
        raise ValueError(f"C_INIT must be {C_INIT_LEN} bytes, got {len(C_INIT)}")
    if len(S_REPLY) != S_REPLY_LEN:
        raise ValueError(f"S_REPLY must be {S_REPLY_LEN} bytes, got {len(S_REPLY)}")
    if len(K_raw) != K_LEN:
        raise ValueError(f"K must be {K_LEN} bytes")
    return sha256(
        ssh_string(V_C),
        ssh_string(V_S),
        ssh_string(I_C),
        ssh_string(I_S),
        ssh_string(K_S),
        ssh_string(C_INIT),
        ssh_string(S_REPLY),
        ssh_string(K_raw),
    )


def derive_key(K_raw: bytes, H: bytes, session_id: bytes, letter: bytes, out_len: int) -> bytes:
    """
     RFC 4253 section 7.2 KDF with K passed as a string (hybrid profile).

     K1 = HASH(K || H || X || session_id)
     K2 = HASH(K || H || K1)
     K3 = HASH(K || H || K1 || K2) ...
    """
    if len(letter) != 1 or len(K_raw) != K_LEN:
        raise ValueError("letter must be 1 byte and K must be 32 bytes")
    K_enc = ssh_string(K_raw)
    out = sha256(K_enc, H, letter, session_id)
    while len(out) < out_len:
        out += sha256(K_enc, H, out)
    return out[:out_len]


def derive_session_keys(K_raw: bytes, H: bytes, session_id: bytes, *, cipher: str = "aes256-ctr", mac: str = "hmac-sha2-256", hashfn=None) -> dict[str, bytes]:
    """
     Standard six RFC 4253 keys sized per cipher/MAC (not a flat 32B).

     ``hashfn`` must be the KEX hash (no implicit default: SHA-256 would be
     wrong for SHA-512 KEX methods).
    """
    from ccssh import crypto as _C
    if hashfn is None:
        raise ValueError("derive_session_keys requires the KEX hash")
    try:
        cs = _C.CIPHER_SPECS[cipher]
    except KeyError:
        try:
            cs = _C.CBC_SPECS[cipher]
        except KeyError as e:
            raise ValueError(f"unsupported cipher {cipher}") from e
    try:
        ms = _C.MAC_SPECS[mac]
    except KeyError as e:
        raise ValueError(f"unsupported mac {mac}") from e
    letters = (("iv_c2s", "A", cs["iv_len"]), ("iv_s2c", "B", cs["iv_len"]),
               ("enc_c2s", "C", cs["key_len"]), ("enc_s2c", "D", cs["key_len"]),
               ("mac_c2s", "E", ms["key_len"]), ("mac_s2c", "F", ms["key_len"]))
    return {k: derive_key(K_raw, H, session_id, c.encode(), n) for k, c, n in letters}


#: X25519 low-order points (RFC 8731 §3.1): never accept as a peer share.
X25519_LOW_ORDER = frozenset({
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880"),
    bytes.fromhex("4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7"),
    bytes.fromhex("d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    bytes.fromhex("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    bytes.fromhex("dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
})


def reject_low_order_x25519(q: bytes) -> None:
    if q in X25519_LOW_ORDER:
        raise ValueError("low-order X25519 peer key rejected")


@dataclass
class ClientState:
    V_C: bytes
    I_C: bytes
    mlkem_sk: MLKEM768PrivateKey
    mlkem_ek: bytes  # 1184
    x_sk: X25519PrivateKey
    x_pk_raw: bytes  # 32
    C_INIT: bytes  # 1216


@dataclass
class Session:
    role: str  # "client" | "server"
    K_pq: bytes
    K_ecdh: bytes
    K: bytes  # 32, SHA256(K_PQ||K_ECDH)
    H: bytes  # 32, exchange hash
    session_id: bytes  # H of the first exchange
    V_C: bytes
    V_S: bytes
    I_C: bytes
    I_S: bytes
    K_S: bytes
    C_INIT: bytes
    S_REPLY: bytes

    def derive(self, letter: str, nbytes: int = 32) -> bytes:
        return derive_key(self.K, self.H, self.session_id, letter.encode(), nbytes)


def client_create(V_C: bytes, I_C: bytes, *, mlkem_seed: bytes | None = None, x_seed: bytes | None = None) -> ClientState:
    """Client step 1: generate ephemeral ML-KEM + ephemeral X25519, build C_INIT."""
    if mlkem_seed is not None:
        if len(mlkem_seed) != 64:
            raise ValueError("mlkem_seed must be 64 bytes (private_bytes_raw)")
        mlkem_sk = MLKEM768PrivateKey.from_seed_bytes(mlkem_seed)
    else:
        mlkem_sk = MLKEM768PrivateKey.generate()
    mlkem_ek = mlkem_sk.public_key().public_bytes_raw()
    if len(mlkem_ek) != MLKEM768_EK_LEN:
        raise ValueError("bad ML-KEM-768 ek length")

    if x_seed is not None:
        if len(x_seed) != 32:
            raise ValueError("x_seed must be 32 bytes")
        x_sk = X25519PrivateKey.from_private_bytes(x_seed)
    else:
        x_sk = X25519PrivateKey.generate()
    x_pk_raw = x_sk.public_key().public_bytes_raw()

    c_init = mlkem_ek + x_pk_raw
    if len(c_init) != C_INIT_LEN:
        raise ValueError("bad C_INIT length")
    return ClientState(V_C, I_C, mlkem_sk, mlkem_ek, x_sk, x_pk_raw, c_init)


def server_process_init(*, host_priv: Ed25519PrivateKey | MldsaKeyPair, V_C: bytes, V_S: bytes, I_C: bytes, I_S: bytes, C_INIT: bytes, x_seed: bytes | None = None) -> tuple[bytes, bytes, bytes, Session]:
    """Server step 2. Returns (S_REPLY, K_S, sig_inner, server_session)."""
    if len(C_INIT) != C_INIT_LEN:
        raise ValueError(f"C_INIT must be {C_INIT_LEN} bytes")
    ek = C_INIT[:MLKEM768_EK_LEN]
    x_pk_c_raw = C_INIT[MLKEM768_EK_LEN:]

    if x_seed is not None:
        x_sk_s = X25519PrivateKey.from_private_bytes(x_seed)
    else:
        x_sk_s = X25519PrivateKey.generate()
    x_pk_s_raw = x_sk_s.public_key().public_bytes_raw()

    """
     ML-KEM encapsulation to the client's ek: (ss 32B, ct 1088B).
     Decapsulation failures never raise (implicit rejection per FIPS 203).
    """
    peer_ek = MLKEM768PublicKey.from_public_bytes(ek)
    K_pq, ct = peer_ek.encapsulate()
    if len(K_pq) != 32 or len(ct) != MLKEM768_CT_LEN:
        raise ValueError("bad ML-KEM-768 encapsulate output")

    reject_low_order_x25519(x_pk_c_raw)
    K_ecdh = x_sk_s.exchange(X25519PublicKey.from_public_bytes(x_pk_c_raw))
    check_secret_nonzero(K_ecdh)
    K_raw = combine_shared(K_pq, K_ecdh)

    s_reply = ct + x_pk_s_raw
    k_s = hostkey_blob_from_priv(host_priv)
    H = compute_exchange_hash(V_C, V_S, I_C, I_S, k_s, C_INIT, s_reply, K_raw)
    sig = sign_exchange_hash(host_priv, H)

    sess = Session("server", K_pq, K_ecdh, K_raw, H, H, V_C, V_S, I_C, I_S, k_s, C_INIT, s_reply)
    return s_reply, k_s, sig, sess


def client_process_reply(st: ClientState, *, V_S: bytes, I_S: bytes, K_S: bytes, S_REPLY: bytes, sig_inner: bytes, host_alg: str = "ssh-ed25519") -> Session:
    """Client step 3: decapsulate + ECDH + H + verify. Raises ValueError on bad signature."""
    if len(S_REPLY) != S_REPLY_LEN:
        raise ValueError(f"S_REPLY must be {S_REPLY_LEN} bytes")
    ct = S_REPLY[:MLKEM768_CT_LEN]
    x_pk_s_raw = S_REPLY[MLKEM768_CT_LEN:]

    K_pq = st.mlkem_sk.decapsulate(ct)
    reject_low_order_x25519(x_pk_s_raw)
    K_ecdh = st.x_sk.exchange(X25519PublicKey.from_public_bytes(x_pk_s_raw))
    check_secret_nonzero(K_ecdh)
    K_raw = combine_shared(K_pq, K_ecdh)

    H = compute_exchange_hash(st.V_C, V_S, st.I_C, I_S, K_S, st.C_INIT, S_REPLY, K_raw)

    if host_alg == "ssh-ed25519":
        host_pub = parse_hostkey_blob(K_S)
        ok = verify_exchange_hash(host_pub, H, sig_inner)
    else:
        from ccssh import hostkeys as _HK # lazy: avoids an import cycle
        ok = _HK.verify_host_signature(K_S, host_alg, H, sig_inner)
    if not ok:
        raise ValueError("exchange hash signature mismatch (MitM/damage?)")
    return Session("client", K_pq, K_ecdh, K_raw, H, H, st.V_C, V_S, st.I_C, I_S, K_S, st.C_INIT, S_REPLY)


def run_handshake(*, V_C: bytes = b"SSH-2.0-OpenSSH_10.0", V_S: bytes = b"SSH-2.0-OpenSSH_10.0", I_C: bytes | None = None, I_S: bytes | None = None, host_priv: Ed25519PrivateKey | MldsaKeyPair | None = None, mlkem_seed: bytes | None = None, client_x_seed: bytes | None = None, server_x_seed: bytes | None = None) -> tuple[Session, Session, dict]:
    """
     Full client<->server handshake in one process. For tests.

     I_C/I_S are random stand-ins, not full KEXINIT payloads: this proves
     the KEM/ECDH math and framing agree, not the wire encoding of H
     (covered live against OpenSSH).

     Returns (client_session, server_session, wire) with
     wire = {C_INIT, S_REPLY, K_S, sig}.
    """
    I_C = os.urandom(32) if I_C is None else I_C
    I_S = os.urandom(32) if I_S is None else I_S
    host_priv = generate_hostkey() if host_priv is None else host_priv

    cl = client_create(V_C, I_C, mlkem_seed=mlkem_seed, x_seed=client_x_seed)
    s_reply, k_s, sig, serv = server_process_init(
        host_priv=host_priv, V_C=V_C, V_S=V_S, I_C=I_C, I_S=I_S,
        C_INIT=cl.C_INIT, x_seed=server_x_seed,
    )
    cli = client_process_reply(cl, V_S=V_S, I_S=I_S, K_S=k_s, S_REPLY=s_reply, sig_inner=sig)
    wire = {"C_INIT": cl.C_INIT, "S_REPLY": s_reply, "K_S": k_s, "sig": sig}
    return cli, serv, wire
