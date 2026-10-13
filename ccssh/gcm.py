"""
 AES-GCM for SSH, RFC 5647. Live-verified against OpenSSH.

 Layout: PT = padding_length || payload || padding (multiple of 16),
 AAD = packet_length (4 bytes, sent in the clear),
 nonce12 = fixed4 (from KDF) || counter8BE, where the counter STARTS at the
 KDF-derived value (proven by offline brute force against a live sshd;
 starting at zero fails interop).
 Wire: packet_length || CT || AT(16). Keys from KDF letters C/D, IV from A/B.
"""
from __future__ import annotations
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ccssh.crypto import kdf, HASH_sha256, pad_len_aad

GCM_SPECS = {
    "aes128-gcm@openssh.com": {"key_len": 16},
    "aes256-gcm@openssh.com": {"key_len": 32},
}
IV_LEN = 12
TAG_LEN = 16


def derive_gcm_keys(K_encoded: bytes, H: bytes, session_id: bytes, cipher: str, hashfn=None) -> dict[str, bytes]:
    # Production callers must pass the KEX hash; the SHA-256 fallback exists
    # only for unit tests / legacy callers (RFC 5647: KDF hash comes from KEX).
    if hashfn is None:
        hashfn = HASH_sha256
    try:
        kl = GCM_SPECS[cipher]["key_len"]
    except KeyError as e:
        raise ValueError(f"unsupported gcm cipher {cipher}") from e
    hf = hashfn
    return {
        "iv_c2s": kdf(hf, K_encoded, H, session_id, b"A", IV_LEN),
        "iv_s2c": kdf(hf, K_encoded, H, session_id, b"B", IV_LEN),
        "enc_c2s": kdf(hf, K_encoded, H, session_id, b"C", kl),
        "enc_s2c": kdf(hf, K_encoded, H, session_id, b"D", kl),
    }


class AesGcmCtx:
    """One direction. Never share an instance between directions or resets."""

    def __init__(self, cipher: str, enc_key: bytes, iv12: bytes):
        try:
            want = GCM_SPECS[cipher]["key_len"]
        except KeyError as e:
            raise ValueError(f"unsupported gcm cipher {cipher}") from e
        if len(enc_key) != want or len(iv12) != IV_LEN:
            raise ValueError("lengths must be: key 16/32, iv 12")
        self.fixed = iv12[:4]
        self._aead = AESGCM(enc_key)
        self._counter = int.from_bytes(iv12[4:], "big")

    def _nonce(self) -> bytes:
        if self._counter >= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("GCM nonce exhausted: rekey required")
        n = self.fixed + struct.pack(">Q", self._counter)
        self._counter = (self._counter + 1) & 0xFFFFFFFFFFFFFFFF
        return n

    def seal(self, payload: bytes) -> bytes:
        pad = pad_len_aad(len(payload), 16)
        pt = bytes([pad]) + payload + os.urandom(pad)
        aad = struct.pack(">I", 1 + len(payload) + pad)
        ct_at = self._aead.encrypt(self._nonce(), pt, aad)
        return aad + ct_at # packet_length in the clear + CT + AT

    def open(self, wire: bytes) -> bytes:
        """
         Returns the raw PT (padding_length || payload || padding); the
         transport strips padding. Raises InvalidTag/ValueError.
        """
        if len(wire) < 4 + 1 + TAG_LEN:
            raise ValueError("wire packet too short")
        aad, ct_at = wire[:4], wire[4:]
        (pl,) = struct.unpack(">I", aad)
        if pl < 16 or pl > 35000 or pl % 16 != 0 or len(ct_at) != pl + TAG_LEN:
            raise ValueError(f"bad packet_length {pl}")
        pt = self._aead.decrypt(self._nonce(), ct_at, aad) # raises InvalidTag
        if pt[0] < 4 or 1 + pt[0] > pl:
            raise ValueError("bad padding")
        return pt
