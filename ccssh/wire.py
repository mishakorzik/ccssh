"""
 SSH wire encoding, RFC 4251 section 5: byte/boolean/uint32/uint64/string/mpint/namelist.

 Dependency-free. Byte-for-byte compatible with OpenSSH on the wire.
"""
from __future__ import annotations
import struct


class WireError(ValueError):
    pass


def dec_byte(buf: bytes, off: int = 0) -> tuple[int, int]:
    if off + 1 > len(buf):
        raise WireError("buffer too short for byte")
    return buf[off], off + 1


def enc_bool(v: bool) -> bytes:
    return b"\x01" if v else b"\x00"


def dec_bool(buf: bytes, off: int = 0) -> tuple[bool, int]:
    b, off2 = dec_byte(buf, off)
    if b not in (0, 1):
        raise WireError("boolean must be 0 or 1")
    return bool(b), off2


def enc_u32(v: int) -> bytes:
    if not 0 <= v < 2**32:
        raise WireError("uint32 out of range")
    return struct.pack(">I", v)


def dec_u32(buf: bytes, off: int = 0) -> tuple[int, int]:
    if off + 4 > len(buf):
        raise WireError("buffer too short for uint32")
    return struct.unpack_from(">I", buf, off)[0], off + 4


def enc_u64(v: int) -> bytes:
    if not 0 <= v < 2**64:
        raise WireError("uint64 out of range")
    return struct.pack(">Q", v)


def dec_u64(buf: bytes, off: int = 0) -> tuple[int, int]:
    if off + 8 > len(buf):
        raise WireError("buffer too short for uint64")
    return struct.unpack_from(">Q", buf, off)[0], off + 8


def enc_string(data: bytes) -> bytes:
    return enc_u32(len(data)) + data


def dec_string(buf: bytes, off: int = 0) -> tuple[bytes, int]:
    ln, off2 = dec_u32(buf, off)
    end = off2 + ln
    if end > len(buf):
        raise WireError(f"string declares len={ln}, only {len(buf) - off2} left")
    return buf[off2:end], end


def enc_namelist(names: list[str]) -> bytes:
    for n in names:
        if not n or "," in n:
            raise WireError(f"bad namelist entry {n!r}")
        try:
            n.encode("ascii")
        except UnicodeEncodeError as e:
            raise WireError(f"namelist must be ascii: {n!r}") from e
    try:
        return enc_string(",".join(names).encode("ascii"))
    except UnicodeEncodeError as e:
        raise WireError(f"namelist must be ascii: {e}") from e


def dec_namelist(buf: bytes, off: int = 0) -> tuple[list[str], int]:
    raw, off2 = dec_string(buf, off)
    if not raw:
        return [], off2
    if len(raw) > 32768 or raw.count(b",") > 512:
        raise WireError("namelist too large")
    # Lenient like OpenSSH: empty items (trailing/double commas) are kept
    # and simply never match anything in negotiation.
    try:
        return raw.decode("ascii").split(","), off2
    except UnicodeDecodeError as e:
        raise WireError(f"namelist must be ascii: {e}") from e


def enc_mpint(value: int) -> bytes:
    """mpint per RFC 4251: uint32 length + minimal big-endian two's complement."""
    if value == 0:
        return enc_u32(0)
    if value < 0:
        # Negative values never occur on the wire, but encode them correctly.
        nbytes = (value.bit_length() + 8) // 8
        raw = value.to_bytes(nbytes, "big", signed=True)
    else:
        nbytes = (value.bit_length() + 7) // 8
        raw = value.to_bytes(nbytes, "big", signed=False)
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return enc_u32(len(raw)) + raw


def dec_mpint(buf: bytes, off: int = 0) -> tuple[int, int]:
    raw, off2 = dec_string(buf, off)
    if not raw:
        return 0, off2
    # RFC 4251 section 5: zero is the empty string; a lone 0x00 byte is
    # non-minimal and must be rejected.
    if len(raw) == 1 and raw[0] == 0:
        raise WireError("non-minimal mpint encoding of zero")
    # Minimal two's complement: no redundant leading 0x00 (when the next
    # byte's high bit is clear) or 0xFF (when it is set) bytes.
    if len(raw) > 1 and raw[0] == 0x00 and not (raw[1] & 0x80):
        raise WireError("non-minimal mpint: redundant leading zero")
    if len(raw) > 1 and raw[0] == 0xFF and (raw[1] & 0x80):
        raise WireError("non-minimal mpint: redundant leading 0xFF")
    return int.from_bytes(raw, "big", signed=True), off2


def mpint_from_bytes(b: bytes) -> bytes:
    """
     Encode a raw big-endian shared secret as an mpint field.

     Adds a 0x00 prefix when the top bit is set and strips redundant
     leading zeroes (keeping one if needed for the sign bit).
    """
    if not b:
        return enc_u32(0)
    if b[0] & 0x80:
        b = b"\x00" + b
    # Strip redundant leading zeroes in one pass (no quadratic slicing).
    i = 0
    while len(b) - i > 1 and b[i] == 0 and not (b[i + 1] & 0x80):
        i += 1
    if i:
        b = b[i:]
    return enc_u32(len(b)) + b


class Reader:
    """Sequential cursor reader over a payload buffer."""

    def __init__(self, buf: bytes):
        self._b = buf
        self._o = 0

    def rest(self) -> int:
        return len(self._b) - self._o

    def tell(self) -> int:
        return self._o

    def byte(self) -> int:
        v, self._o = dec_byte(self._b, self._o)
        return v

    def bool(self) -> bool:
        v, self._o = dec_bool(self._b, self._o)
        return v

    def u32(self) -> int:
        v, self._o = dec_u32(self._b, self._o)
        return v

    def u64(self) -> int:
        v, self._o = dec_u64(self._b, self._o)
        return v

    def string(self) -> bytes:
        v, self._o = dec_string(self._b, self._o)
        return v

    def namelist(self) -> list[str]:
        v, self._o = dec_namelist(self._b, self._o)
        return v

    def mpint(self) -> int:
        v, self._o = dec_mpint(self._b, self._o)
        return v

    def raw(self, n: int) -> bytes:
        if n < 0 or self._o + n > len(self._b):
            raise WireError("raw read out of bounds")
        v = self._b[self._o:self._o + n]
        self._o += n
        return v

    def assert_end(self) -> None:
        """Reject trailing garbage after a fixed-layout message."""
        if self.rest() != 0:
            raise WireError(f"trailing bytes in message ({self.rest()} left)")
