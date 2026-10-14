"""
 SSH packet compression: zlib (RFC 4253 section 6.2) and
 zlib@openssh.com (delayed, draft-miller-secsh-compression-delayed-00).

 Wire behavior is 1:1 with OpenSSH (see compress.c / packet.c):

 * only the payload is compressed (packet_length / padding / MAC never are);
 * encryption happens after compression, decryption before decompression;
 * one stateful zlib stream per direction, shared across packets;
 * each packet ends with Z_PARTIAL_FLUSH (Python: flush(Z_PARTIAL_FLUSH)),
   so every packet decompresses independently but in order;
 * empty payloads bypass deflate entirely (OpenSSH early return);
 * "zlib" starts right after NEWKEYS (pre-auth, legacy);
 * "zlib@openssh.com" starts only after USERAUTH_SUCCESS (delayed);
 * the context is re-initialized after every key exchange (RFC 4253:
   "initialized after each key exchange"), staying enabled across rekeys
   once delayed compression is active.

 Levels 1-9, default 6 (like `CompressionLevel` in ssh_config).
 Decompression is bomb-capped: a single packet must never expand past
 MAX_DECOMPRESSED (fail closed, never OOM).
"""
from __future__ import annotations

import zlib

DEFAULT_LEVEL = 6
MIN_LEVEL = 1
MAX_LEVEL = 9
# Wire cap for one decompressed payload. The SSH packet_length ceiling is
# 35000 on the wire (compressed); 1 MiB allows ~30x expansion for highly
# compressible data (e.g. zeros) while stopping zlib bombs.
MAX_DECOMPRESSED = 1024 * 1024

NONE = "none"
ZLIB = "zlib"
DELAYED = "zlib@openssh.com"
ALL_KNOWN = (NONE, DELAYED, ZLIB)


def check_level(level: int) -> int:
    """Validate a CompressionLevel (OpenSSH: fatal on bad level)."""
    if not isinstance(level, int) or not MIN_LEVEL <= level <= MAX_LEVEL:
        raise ValueError(f"bad compression level {level!r} (must be 1..9)")
    return level


def is_none(name: str) -> bool:
    return name == NONE


def is_delayed(name: str) -> bool:
    return name == DELAYED


def is_immediate(name: str) -> bool:
    return name == ZLIB


def check_name(name: str) -> str:
    if name not in ALL_KNOWN:
        raise ValueError(f"unsupported compression {name!r} (expected one of {list(ALL_KNOWN)})")
    return name


class Compressor:
    """One direction (client->server): stateful deflate with partial flush."""

    def __init__(self, level: int = DEFAULT_LEVEL):
        self.level = check_level(level)
        self._comp = zlib.compressobj(self.level)

    def compress(self, payload: bytes) -> bytes:
        if not payload:
            return payload  # OpenSSH: empty input bypasses deflate
        try:
            return self._comp.compress(payload) + self._comp.flush(zlib.Z_PARTIAL_FLUSH)
        except zlib.error as e:
            raise ValueError(f"compression failed: {e}") from e

    def reset(self) -> None:
        """Re-initialize after a key exchange (fresh dictionary)."""
        self._comp = zlib.compressobj(self.level)


class Decompressor:
    """One direction (server->client): stateful inflate with bomb cap."""

    def __init__(self):
        self._decomp = zlib.decompressobj()

    def decompress(self, data: bytes) -> bytes:
        if not data:
            return data
        try:
            out = self._decomp.decompress(data)
        except zlib.error as e:
            raise ValueError(f"decompression failed: {e}") from e
        # Trailing garbage after a flush unit means a hostile peer.
        if getattr(self._decomp, "unconsumed_tail", b""):
            raise ValueError("decompression failed: trailing garbage")
        if getattr(self._decomp, "unused_data", b""):
            raise ValueError("decompression failed: trailing garbage")
        if len(out) > MAX_DECOMPRESSED:
            raise ValueError(f"decompressed payload too big ({len(out)} bytes)")
        return out

    def reset(self) -> None:
        self._decomp = zlib.decompressobj()
