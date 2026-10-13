"""
 UMAC message authentication (RFC 4418) + SSH wire mapping
 (draft-miller-secsh-umac-01: mac = UMAC(key, seq-as-uint64, packet)).

 Pure Python over AES-128-ECB from `cryptography` (correctness-first;
 SSH packets are small). Verified against every RFC Appendix test
 vector (32/64/96-bit tags plus all intermediate keys and L1/L2/L3
 outputs) AND live against OpenSSH (umac-64/128, plain and -etm).
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCKLEN = 16
KEYLEN = 16

P36 = 2**36 - 5
P64 = 2**64 - 59
P128 = 2**128 - 159
M64 = (1 << 64) - 1


def _enc(key: bytes, block: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def _enc_with(cipher: Cipher, block: bytes) -> bytes:
    e = cipher.encryptor()
    return e.update(block) + e.finalize()


def _kdf_with(cipher: Cipher, index: int, numbytes: int) -> bytes:
    out = b""
    n = (numbytes + BLOCKLEN - 1) // BLOCKLEN
    for i in range(1, n + 1):
        out += _enc_with(cipher, index.to_bytes(BLOCKLEN - 8, "big") + i.to_bytes(8, "big"))
    return out[:numbytes]


def _uhash_with_keys(l1key: bytes, l2key: bytes, l3k1: bytes, l3k2: bytes,
                     msg: bytes, taglen: int) -> bytes:
    """UHASH with pre-derived L1/L2/L3 subkeys (same math as uhash)."""
    iters = taglen // 4
    out = b""
    for i in range(iters):
        k1i = l1key[i * 16:i * 16 + 1024]
        k2i = l2key[i * 24:(i + 1) * 24]
        k3a = l3k1[i * 64:(i + 1) * 64]
        k3b = l3k2[i * 4:(i + 1) * 4]
        a = _l1(k1i, msg)
        b = b"\x00" * 8 + a if len(msg) <= 1024 else _l2(k2i, a)
        out += _l3(k3a, k3b, b)
    return out


def _pdf_with(pdf_cipher: Cipher, nonce: bytes, taglen: int) -> bytes:
    if taglen not in (4, 8, 12, 16):
        raise ValueError("taglen must be 4/8/12/16")
    if not 1 <= len(nonce) <= BLOCKLEN:
        raise ValueError("nonce must be 1..16 bytes")
    index = 0
    if taglen in (4, 8):
        index = int.from_bytes(nonce, "big") % (BLOCKLEN // taglen)
        nonce = bytes(a ^ b for a, b in zip(nonce, index.to_bytes(len(nonce), "big")))
    nonce = nonce + b"\x00" * (BLOCKLEN - len(nonce))
    # pdf encrypts with KDF(key, 0): derive the pad key once per context.
    t = _enc_with(pdf_cipher, nonce)
    if taglen in (4, 8):
        return t[index * taglen:(index + 1) * taglen]
    return t[:taglen]


def _u32(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _u64(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _pack32(n: int) -> bytes:
    return (n & 0xFFFFFFFF).to_bytes(4, "big")


def _pack64(n: int) -> bytes:
    return (n & M64).to_bytes(8, "big")


def _pack128(n: int) -> bytes:
    return (n & ((1 << 128) - 1)).to_bytes(16, "big")


def _endian_swap(s: bytes) -> bytes:
    return b"".join(s[i:i + 4][::-1] for i in range(0, len(s), 4))


def kdf(key: bytes, index: int, numbytes: int) -> bytes:
    # Test/reference path (RFC vectors): production tags go through
    # UMacCtx with precomputed subkeys below.
    out = b""
    n = (numbytes + BLOCKLEN - 1) // BLOCKLEN
    for i in range(1, n + 1):
        out += _enc(key, index.to_bytes(BLOCKLEN - 8, "big") + i.to_bytes(8, "big"))
    return out[:numbytes]


def pdf(key: bytes, nonce: bytes, taglen: int) -> bytes:
    if taglen not in (4, 8, 12, 16):
        raise ValueError("taglen must be 4/8/12/16")
    if not 1 <= len(nonce) <= BLOCKLEN:
        raise ValueError("nonce must be 1..16 bytes")
    index = 0
    if taglen in (4, 8):
        index = int.from_bytes(nonce, "big") % (BLOCKLEN // taglen)
        nonce = bytes(a ^ b for a, b in zip(nonce, index.to_bytes(len(nonce), "big")))
    nonce = nonce + b"\x00" * (BLOCKLEN - len(nonce))
    t = _enc(kdf(key, 0, KEYLEN), nonce)
    if taglen in (4, 8):
        return t[index * taglen:(index + 1) * taglen]
    return t[:taglen]


def _nh(key: bytes, msg: bytes) -> bytes:
    """
     NH over a 32-byte-multiple message with a 1024-byte key prefix.
    """
    t = len(msg) // 4
    y = 0
    m32 = 0xFFFFFFFF
    for i in range(0, t, 8):
        for j in range(4):
            a = (_u32(msg[4 * (i + j):4 * (i + j) + 4])
                 + _u32(key[4 * (i + j):4 * (i + j) + 4])) & m32
            b = (_u32(msg[4 * (i + 4 + j):4 * (i + 4 + j) + 4])
                 + _u32(key[4 * (i + 4 + j):4 * (i + 4 + j) + 4])) & m32
            y += a * b
    return _pack64(y & M64)


def _l1(key: bytes, msg: bytes) -> bytes:
    t = max((len(msg) * 8 + 8191) // 8192, 1)
    out = b""
    for i in range(t - 1):
        chunk = _endian_swap(msg[i * 1024:(i + 1) * 1024])
        out += _pack64((_u64(_nh(key, chunk)) + 1024 * 8) & M64)
    last = msg[(t - 1) * 1024:]
    bitlen = len(last) * 8
    pad = (-len(last)) % 32
    if not last:
        pad = 32  # zeropad() targets a *positive* multiple: empty -> 32 zeros
    last += b"\x00" * pad
    out += _pack64((_u64(_nh(key, _endian_swap(last))) + bitlen) & M64)
    return out


def _poly(wordbits: int, maxwordrange: int, k: int, msg: bytes) -> int:
    wb = wordbits // 8
    p = P64 if wordbits == 64 else P128
    offset = 2**wordbits - p
    marker = p - 1
    n = len(msg) // wb
    y = 1
    for i in range(n):
        m = int.from_bytes(msg[i * wb:(i + 1) * wb], "big")
        if m >= maxwordrange:
            y = (k * y + marker) % p
            y = (k * y + (m - offset)) % p
        else:
            y = (k * y + m) % p
    return y


def _l2(key: bytes, msg: bytes) -> bytes:
    mask64 = 0x01FFFFFF01FFFFFF
    mask128 = 0x01FFFFFF01FFFFFF01FFFFFF01FFFFFF
    k64 = _u64(key[:8]) & mask64
    k128 = int.from_bytes(key[8:24], "big") & mask128
    if len(msg) <= 2**17:
        y = _poly(64, 2**64 - 2**32, k64, msg)
    else:
        m1, m2 = msg[:2**17], msg[2**17:]
        m2 = m2 + b"\x80"
        m2 += b"\x00" * ((-len(m2)) % 16)
        y = _poly(64, 2**64 - 2**32, k64, m1)
        y = _poly(128, 2**128 - 2**96, k128, y.to_bytes(16, "big") + m2)
    return _pack128(y)


def _l3(k1: bytes, k2: bytes, msg: bytes) -> bytes:
    y = 0
    for i in range(8):
        m = int.from_bytes(msg[2 * i:2 * i + 2], "big")
        k = int.from_bytes(k1[8 * i:8 * i + 8], "big") % P36
        y += m * k
    y %= P36
    y %= 2**32
    return bytes(a ^ b for a, b in zip(_pack32(y), k2))


def uhash(key: bytes, msg: bytes, taglen: int) -> bytes:
    if taglen not in (4, 8, 12, 16):
        raise ValueError("taglen must be 4/8/12/16")
    iters = taglen // 4
    l1key = kdf(key, 1, 1024 + (iters - 1) * 16)
    l2key = kdf(key, 2, iters * 24)
    l3k1 = kdf(key, 3, iters * 64)
    l3k2 = kdf(key, 4, iters * 4)
    out = b""
    for i in range(iters):
        k1i = l1key[i * 16:i * 16 + 1024]
        k2i = l2key[i * 24:(i + 1) * 24]
        k3a = l3k1[i * 64:(i + 1) * 64]
        k3b = l3k2[i * 4:(i + 1) * 4]
        a = _l1(k1i, msg)
        b = b"\x00" * 8 + a if len(msg) <= 1024 else _l2(k2i, a)
        out += _l3(k3a, k3b, b)
    return out


def umac(key: bytes, msg: bytes, nonce: bytes, taglen: int) -> bytes:
    # Test/reference path: production tags go through UMacCtx.
    if len(key) != KEYLEN:
        raise ValueError("UMAC key must be 16 bytes")
    hashed = uhash(key, msg, taglen)
    pad = pdf(key, nonce, taglen)
    return bytes(a ^ b for a, b in zip(hashed, pad))


class UMacCtx:
    """
     SSH UMAC (draft-miller-secsh-umac-01): the packet sequence number,
     encoded as uint64, is the nonce. One direction per instance.

     The L1/L2/L3 subkeys depend only on the connection key, so they are
     derived once here instead of on every packet (dozens of AES ops per
     tag before). The AES key schedules are cached as Cipher objects.
    """

    def __init__(self, key: bytes, out_len: int):
        if len(key) != KEYLEN or out_len not in (8, 16):
            raise ValueError("UMAC needs a 16-byte key and 8/16-byte tags")
        self._key = key
        self._out_len = out_len
        iters = out_len // 4
        kdf_cipher = Cipher(algorithms.AES(key), modes.ECB())
        self._l1key = _kdf_with(kdf_cipher, 1, 1024 + (iters - 1) * 16)
        self._l2key = _kdf_with(kdf_cipher, 2, iters * 24)
        self._l3k1 = _kdf_with(kdf_cipher, 3, iters * 64)
        self._l3k2 = _kdf_with(kdf_cipher, 4, iters * 4)
        pdf_key = _kdf_with(kdf_cipher, 0, KEYLEN)
        self._pdf_cipher = Cipher(algorithms.AES(pdf_key), modes.ECB())

    def tag(self, seq: int, data: bytes) -> bytes:
        hashed = _uhash_with_keys(self._l1key, self._l2key, self._l3k1,
                                  self._l3k2, data, self._out_len)
        pad = _pdf_with(self._pdf_cipher,
                        struct.pack(">Q", seq & 0xFFFFFFFFFFFFFFFF),
                        self._out_len)
        return bytes(a ^ b for a, b in zip(hashed, pad))
