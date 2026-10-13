"""
 chacha20-poly1305@openssh.com (IETF draft-ietf-sshm-chacha20-poly1305).

 Bernstein's original ChaCha20 (8-byte nonce, 64-bit counter) combined with
 Poly1305 into the SSH AEAD. Layout (K_1 = first 32 key bytes for payload and
 the Poly1305 one-time key, K_2 = second 32 for the length field):

  enc_length  = packet_length XOR ChaCha(K_2, counter=0, nonce=seq)[:4]
  enc_payload = payload       XOR ChaCha(K_1, counter=1.., nonce=seq)
  poly_key    = ChaCha(K_1, counter=0, nonce=seq)[:32]
  tag         = Poly1305(poly_key, enc_length || enc_payload)

 The raw ChaCha block function is OpenSSL's (via `cryptography`), which is
 byte-identical to the original for these parameters: original state words
 x12=ctr_lo, x13=ctr_hi, x14/x15=nonce map onto OpenSSL's IV layout of
 LE32(counter) || LE32(counter_hi) || nonce8. Verified against the
 independent pure-Python reference and the draft section 8 test vector,
 plus live sessions against OpenSSH.
"""
from __future__ import annotations
import hmac as pyhmac
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.poly1305 import Poly1305

from ccssh.crypto import kdf, HASH_sha256


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor inputs must have equal length")
    out = bytearray(len(a))
    mv_a, mv_b = memoryview(a), memoryview(b)
    for i in range(len(a)):
        out[i] = mv_a[i] ^ mv_b[i]
    return bytes(out)


def keystream(key32: bytes, counter0: int, nonce8: bytes, nbytes: int) -> bytes:
    """
     ChaCha keystream for consecutive block counters starting at counter0.

     A single OpenSSL call covers the whole span (the counter advances
     internally), so this is fast even for tens of kilobytes.
    """
    if len(key32) != 32 or len(nonce8) != 8:
        raise ValueError("key must be 32 bytes, nonce 8 bytes")
    if not 0 <= counter0 < 2**64:
        raise ValueError("counter out of 64-bit range")
    iv = struct.pack("<I", counter0 & 0xFFFFFFFF) + struct.pack("<I", counter0 >> 32) + nonce8
    enc = Cipher(algorithms.ChaCha20(key32, iv), mode=None).encryptor()
    return enc.update(b"\x00" * nbytes) + enc.finalize()


def chacha_block(key32: bytes, counter: int, nonce8: bytes) -> bytes:
    """One 64-byte keystream block (convenience wrapper over keystream)."""
    return keystream(key32, counter, nonce8, 64)


class ChachaSshCtx:
    """One direction. Takes the 64-byte KDF key material (K_1 || K_2)."""

    def __init__(self, key64: bytes):
        if len(key64) != 64:
            raise ValueError("key material must be 64 bytes")
        self.k1, self.k2 = key64[:32], key64[32:]

    def seal(self, seq: int, packet_len: bytes, payload_block: bytes) -> bytes:
        """
         packet_len: 4 cleartext length bytes; payload_block holds
         padding_length || payload || padding. Returns the full wire packet.
        """
        if not 0 <= seq < 2**32:
            raise ValueError("chacha sequence exhausted: rekey required")
        nonce = struct.pack(">Q", seq)
        enc_len = _xor(packet_len, keystream(self.k2, 0, nonce, 4))
        enc_pay = _xor(payload_block, keystream(self.k1, 1, nonce, len(payload_block)))
        polykey = keystream(self.k1, 0, nonce, 32)
        tag = Poly1305(polykey)
        tag.update(enc_len + enc_pay)
        return enc_len + enc_pay + tag.finalize()

    def open(self, seq: int, wire: bytes) -> tuple[bytes, bytes]:
        """Returns (packet_len, payload_block). Raises on bad MAC."""
        if not 0 <= seq < 2**32:
            raise ValueError("chacha sequence exhausted: rekey required")
        if len(wire) < 4 + 1 + 16:
            raise ValueError("wire packet too short")
        nonce = struct.pack(">Q", seq)
        enc_len, rest = wire[:4], wire[4:]
        enc_pay, tag_recv = rest[:-16], rest[-16:]
        polykey = keystream(self.k1, 0, nonce, 32)
        tag = Poly1305(polykey)
        tag.update(enc_len + enc_pay)
        if not pyhmac.compare_digest(tag.finalize(), tag_recv):
            raise ValueError("Poly1305 mismatch")
        packet_len = _xor(enc_len, keystream(self.k2, 0, nonce, 4))
        payload_block = _xor(enc_pay, keystream(self.k1, 1, nonce, len(enc_pay)))
        return packet_len, payload_block

    def decrypt_length(self, seq: int, enc_len: bytes) -> bytes:
        """Decrypt the 4 length bytes without touching payload state (stateless)."""
        if not 0 <= seq < 2**32:
            raise ValueError("chacha sequence exhausted: rekey required")
        return _xor(enc_len, keystream(self.k2, 0, struct.pack(">Q", seq), 4))


def derive_chacha_keys(K_encoded: bytes, H: bytes, session_id: bytes, hashfn=None) -> dict[str, bytes]:
    # Production callers must pass the KEX hash; fallback kept for tests.
    if hashfn is None:
        hashfn = HASH_sha256
    hf = hashfn
    return {
        "enc_c2s": kdf(hf, K_encoded, H, session_id, b"C", 64),
        "enc_s2c": kdf(hf, K_encoded, H, session_id, b"D", 64),
    }
