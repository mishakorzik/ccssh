"""
 Symmetric packet protection: AES-CTR + HMAC, key derivation, framing helpers.

 Primitives come from `cryptography`; all protocol framing is ours.
 Covers RFC 4253 section 6 (binary packet protocol) and section 7.2 (KDF),
 plus OpenSSH *-etm modes (length sent in the clear, see packet.c).
"""
from __future__ import annotations
import hashlib
import os
import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def HASH_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def kdf(hash_fn, K_encoded: bytes, H: bytes, session_id: bytes, letter: bytes, out_len: int) -> bytes:
    """
     RFC 4253 section 7.2 key expansion.

     K1 = HASH(K || H || X || session_id), Kn+1 = HASH(K || H || K1 || .. || Kn).
     ``hash_fn`` must be the *key exchange* hash (e.g. SHA-256 for
     curve25519-sha256), never derived from the cipher/MAC choice.
    """
    if len(letter) != 1:
        raise ValueError("letter must be a single byte")
    if not 0 < out_len <= 1024:
        raise ValueError("kdf out_len out of range")
    out = hash_fn(K_encoded + H + letter + session_id)
    while len(out) < out_len:
        out += hash_fn(K_encoded + H + out)
    return out[:out_len]


CIPHER_SPECS = {
    "aes128-ctr": {"key_len": 16, "iv_len": 16, "block": 16},
    "aes192-ctr": {"key_len": 24, "iv_len": 16, "block": 16},
    "aes256-ctr": {"key_len": 32, "iv_len": 16, "block": 16},
}
"""
 Legacy chained-IV CBC (RFC 4253 section 6): disabled by default, see
 algs.LEGACY_CIPHERS. Same framing as CTR; only the crypt operation differs.
"""
CBC_SPECS = {
    "aes128-cbc": {"prim": "aes", "key_len": 16, "iv_len": 16, "block": 16},
    "aes192-cbc": {"prim": "aes", "key_len": 24, "iv_len": 16, "block": 16},
    "aes256-cbc": {"prim": "aes", "key_len": 32, "iv_len": 16, "block": 16},
    "3des-cbc": {"prim": "3des", "key_len": 24, "iv_len": 8, "block": 8},
}
MAC_SPECS = {
    "hmac-sha2-256": {"key_len": 32, "out_len": 32, "etm": False},
    "hmac-sha2-512": {"key_len": 64, "out_len": 64, "etm": False},
    "hmac-sha1": {"key_len": 20, "out_len": 20, "etm": False},
    "hmac-sha2-256-etm@openssh.com": {"key_len": 32, "out_len": 32, "etm": True},
    "hmac-sha2-512-etm@openssh.com": {"key_len": 64, "out_len": 64, "etm": True},
    "hmac-sha1-etm@openssh.com": {"key_len": 20, "out_len": 20, "etm": True},
    "hmac-sha1-96": {"key_len": 20, "out_len": 12, "etm": False},
    "hmac-sha1-96-etm@openssh.com": {"key_len": 20, "out_len": 12, "etm": True},
    "hmac-md5": {"key_len": 16, "out_len": 16, "etm": False},
    "hmac-md5-etm@openssh.com": {"key_len": 16, "out_len": 16, "etm": True},
    "hmac-md5-96": {"key_len": 16, "out_len": 12, "etm": False},
    "hmac-md5-96-etm@openssh.com": {"key_len": 16, "out_len": 12, "etm": True},
    "umac-64@openssh.com": {"key_len": 16, "out_len": 8, "etm": False},
    "umac-128@openssh.com": {"key_len": 16, "out_len": 16, "etm": False},
    "umac-64-etm@openssh.com": {"key_len": 16, "out_len": 8, "etm": True},
    "umac-128-etm@openssh.com": {"key_len": 16, "out_len": 16, "etm": True},
}
_HASH_BY_MAC = {
    "hmac-sha2-256": hashlib.sha256,
    "hmac-sha2-256-etm@openssh.com": hashlib.sha256,
    "hmac-sha2-512": hashlib.sha512,
    "hmac-sha2-512-etm@openssh.com": hashlib.sha512,
    "hmac-sha1": hashlib.sha1,
    "hmac-sha1-etm@openssh.com": hashlib.sha1,
    "hmac-sha1-96": hashlib.sha1,
    "hmac-sha1-96-etm@openssh.com": hashlib.sha1,
    "hmac-md5": hashlib.md5,
    "hmac-md5-etm@openssh.com": hashlib.md5,
    "hmac-md5-96": hashlib.md5,
    "hmac-md5-96-etm@openssh.com": hashlib.md5,
}


def _kdf_hash(cipher: str, mac: str, hashfn):
    """
     Resolve the KDF hash: explicit KEX hash wins, else MAC-implied (legacy).

     Production callers always pass the KEX hash (RFC 4253 section 7.2);
     the fallback exists for the test stub and ad-hoc callers, which only
     use SHA-256 KEX methods there.
    """
    if hashfn is not None:
        return hashfn
    digestmod = _HASH_BY_MAC.get(mac, hashlib.sha256)
    return lambda d: digestmod(d).digest()


def derive_keys(K_encoded: bytes, H: bytes, session_id: bytes, cipher: str, mac: str, hashfn=None) -> dict[str, bytes]:
    """Derive the six direction keys (A..F). Prefer passing the KEX hash."""
    try:
        cs = CIPHER_SPECS[cipher]
    except KeyError:
        try:
            cs = CBC_SPECS[cipher]
        except KeyError as e:
            raise ValueError(f"unsupported cipher {cipher}") from e
    try:
        ms = MAC_SPECS[mac]
    except KeyError as e:
        raise ValueError(f"unsupported mac {mac}") from e
    hf = _kdf_hash(cipher, mac, hashfn)
    return {
        "iv_c2s": kdf(hf, K_encoded, H, session_id, b"A", cs["iv_len"]),
        "iv_s2c": kdf(hf, K_encoded, H, session_id, b"B", cs["iv_len"]),
        "enc_c2s": kdf(hf, K_encoded, H, session_id, b"C", cs["key_len"]),
        "enc_s2c": kdf(hf, K_encoded, H, session_id, b"D", cs["key_len"]),
        "mac_c2s": kdf(hf, K_encoded, H, session_id, b"E", ms["key_len"]),
        "mac_s2c": kdf(hf, K_encoded, H, session_id, b"F", ms["key_len"]),
    }


try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError: # older cryptography: pre-move location (warns, still works)
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

_HASH_CLASSES = {
    "hmac-sha2-256": hashes.SHA256,
    "hmac-sha2-256-etm@openssh.com": hashes.SHA256,
    "hmac-sha2-512": hashes.SHA512,
    "hmac-sha2-512-etm@openssh.com": hashes.SHA512,
    "hmac-sha1": hashes.SHA1,
    "hmac-sha1-etm@openssh.com": hashes.SHA1,
    "hmac-sha1-96": hashes.SHA1,
    "hmac-sha1-96-etm@openssh.com": hashes.SHA1,
    "hmac-md5": hashes.MD5,
    "hmac-md5-etm@openssh.com": hashes.MD5,
    "hmac-md5-96": hashes.MD5,
    "hmac-md5-96-etm@openssh.com": hashes.MD5,
}


class SshMac:
    """
     Packet MAC shared by the CTR and CBC direction contexts: HMAC-*
     (plain and -etm, full and -96 truncated) or UMAC-64/128
     (draft-miller-secsh-umac-01, seq as uint64 nonce).
    """

    def __init__(self, mac: str, mac_key: bytes):
        try:
            ms = MAC_SPECS[mac]
        except KeyError as e:
            raise ValueError(f"unsupported mac: {mac}") from e
        if len(mac_key) != ms["key_len"]:
            raise ValueError(f"bad mac key length for {mac}")
        self.mac, self.mac_len, self.etm = mac, ms["out_len"], ms["etm"]
        self._mac_key = mac_key
        self._umac = None
        self._hcls = None
        if mac.startswith("umac-"):
            from ccssh import umac as _umac_mod
            self._umac = _umac_mod.UMacCtx(mac_key, ms["out_len"])
        else:
            try:
                self._hcls = _HASH_CLASSES[mac]
            except KeyError as e:
                raise ValueError(f"unsupported mac: {mac}") from e

    def mac_of(self, seq: int, data: bytes) -> bytes:
        if not 0 <= seq < 2**32:
            raise ValueError("sequence number out of range")
        if self._umac is not None:
            return self._umac.tag(seq, data)
        h = hmac.HMAC(self._mac_key, self._hcls())
        h.update(struct.pack(">I", seq) + data)
        return h.finalize()[:self.mac_len]


class AesCtrHmacCtx:
    """
     One direction of AES-CTR + MAC. Stateful CTR via a held encryptor.

     ``etm`` switches the MAC input from plaintext to ciphertext; the caller
     (transport) owns framing for both cases.
    """

    def __init__(self, cipher: str, mac: str, enc_key: bytes, iv: bytes, mac_key: bytes):
        try:
            cs = CIPHER_SPECS[cipher]
        except KeyError as e:
            raise ValueError(f"unsupported cipher/mac: {cipher}/{mac}") from e
        if len(enc_key) != cs["key_len"] or len(iv) != cs["iv_len"]:
            raise ValueError(f"bad enc/iv lengths for {cipher}")
        self.cipher, self.mac = cipher, mac
        self._mac = SshMac(mac, mac_key)
        self.etm = self._mac.etm
        self.mac_len = self._mac.mac_len
        self.block_size = cs["block"]
        enc = Cipher(algorithms.AES(enc_key), modes.CTR(iv)).encryptor()
        dec = Cipher(algorithms.AES(enc_key), modes.CTR(iv)).decryptor()
        self._enc, self._dec = enc, dec

    def mac_of(self, seq: int, data: bytes) -> bytes:
        return self._mac.mac_of(seq, data)

    def encrypt_stream(self, data: bytes) -> bytes:
        return self._enc.update(data)

    def decrypt_stream(self, data: bytes) -> bytes:
        return self._dec.update(data)


class CbcHmacCtx:
    """
     One direction of chained-IV CBC + MAC (legacy: aes*-cbc, 3des-cbc).

     SSH CBC chains the IV across packets (RFC 4253 section 6), so the
     encryptor/decryptor are held like the CTR ones. Disabled by default
     (see algs.LEGACY_CIPHERS); force explicitly to interoperate.
    """

    def __init__(self, cipher: str, mac: str, enc_key: bytes, iv: bytes, mac_key: bytes):
        try:
            cs = CBC_SPECS[cipher]
        except KeyError as e:
            raise ValueError(f"unsupported cipher/mac: {cipher}/{mac}") from e
        if len(enc_key) != cs["key_len"] or len(iv) != cs["iv_len"]:
            raise ValueError(f"bad enc/iv lengths for {cipher}")
        self.cipher, self.mac = cipher, mac
        self._mac = SshMac(mac, mac_key)
        self.etm = self._mac.etm
        self.mac_len = self._mac.mac_len
        self.block_size = cs["block"]
        if cs["prim"] == "3des":
            enc = Cipher(TripleDES(enc_key), modes.CBC(iv)).encryptor()
            dec = Cipher(TripleDES(enc_key), modes.CBC(iv)).decryptor()
        else:
            enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
            dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        self._enc, self._dec = enc, dec

    def mac_of(self, seq: int, data: bytes) -> bytes:
        return self._mac.mac_of(seq, data)

    def encrypt_stream(self, data: bytes) -> bytes:
        if len(data) % self.block_size != 0:
            raise ValueError("CBC encrypt length must be a block multiple")
        return self._enc.update(data)

    def decrypt_stream(self, data: bytes) -> bytes:
        if len(data) % self.block_size != 0:
            raise ValueError("CBC decrypt length must be a block multiple")
        return self._dec.update(data)


def pad_packet(payload_len_plus1: int, block_size: int) -> int:
    """
     Padding length so that (4 + 1 + payload + pad) is a block multiple.

     ``payload_len_plus1`` is 1 (padding-length byte) + len(payload).
     For ciphers where packet_length itself is encrypted (CBC/CTR/non-ETM,
     and plaintext before NEWKEYS). Minimum padding is 4 bytes.
    """
    pad = block_size - ((4 + payload_len_plus1) % block_size)
    if pad < 4:
        pad += block_size
    if pad > 255:
        raise ValueError("padding exceeds 255 bytes")
    return pad


def pad_len_aad(payload_len: int, block_size: int) -> int:
    """
     Padding length so that (1 + payload + pad) is a block multiple.

     For modes where packet_length travels unencrypted (ETM, AES-GCM with
     block 16, chacha20-poly1305 with block 8). OpenSSH drops packets with
     wrong alignment ("padding error").
    """
    pad = block_size - ((1 + payload_len) % block_size)
    if pad < 4:
        pad += block_size
    if pad > 255:
        raise ValueError("padding exceeds 255 bytes")
    return pad


def build_unencrypted_block(payload: bytes, block_size: int) -> bytes:
    """Assemble packet_length || padding_length || payload || padding."""
    # SSH packet_length (payload+padding+1) must fit MAX_PACKET=35000;
    # SFTP data responses legitimately carry ~32KB + framing overhead,
    # so cap the final packet length, not the raw payload.
    pad_len = pad_packet(1 + len(payload), block_size)
    pkt_len = 1 + len(payload) + pad_len
    if pkt_len > 35000:
        raise ValueError(f"packet too large (packet_length={pkt_len})")
    return struct.pack(">I", pkt_len) + bytes([pad_len]) + payload + os.urandom(pad_len)


def build_aad_block(payload: bytes, block_size: int) -> tuple[bytes, bytes]:
    """
     Assemble (length_field, body) for length-in-clear modes.

     Returns the 4-byte big-endian packet_length and the
     padding_length || payload || padding body.
    """
    pad_len = pad_len_aad(len(payload), block_size)
    body = bytes([pad_len]) + payload + os.urandom(pad_len)
    if len(body) > 35000:
        raise ValueError(f"packet too large (packet_length={len(body)})")
    return struct.pack(">I", len(body)), body
