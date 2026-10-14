"""
 SOCKS handshake for dynamic forwarding (`ssh -D`).

 The forwarder listens locally and speaks SOCKS to local applications;
 every granted CONNECT becomes one `direct-tcpip` channel through the
 server (which resolves and dials the real target). Only TCP CONNECT is
 supported, like OpenSSH: UDP ASSOCIATE and BIND are refused cleanly.

 Supported (like OpenSSH):
 * SOCKS5 (RFC 1928): no-auth only, CMD CONNECT, ATYP IPv4 / DOMAIN /
   IPv6. Username/password methods are refused (no acceptable methods).
 * SOCKS4 (classic): CMD CONNECT only.
"""
from __future__ import annotations

import struct


class SocksError(ValueError):
    pass


# SOCKS5 greeting / reply constants.
S5_VERSION = 0x05
S5_NO_AUTH = 0x00
S5_NO_ACCEPTABLE = 0xFF
S5_CMD_CONNECT = 0x01
S5_ATYP_V4 = 0x01
S5_ATYP_DOMAIN = 0x03
S5_ATYP_V6 = 0x04
S5_REP_OK = 0x00
S5_REP_REFUSED = 0x05  # connection refused (also used as generic failure)
S5_REP_CMD = 0x07  # command not supported

MAX_DOMAIN = 255
MAX_REQ = 512  # longest single SOCKS request we ever parse


def greeting_reply(data: bytes) -> tuple[bytes, bool]:
    """
     Parse one SOCKS5 greeting, return (reply, acceptable).

     ``acceptable`` is True only for "no authentication required".
     Anything else (including a SOCKS4-shaped first byte) yields
     (b"\\x05\\xff", False) so the caller closes the connection.
    """
    if len(data) < 3 or len(data) > MAX_REQ:
        raise SocksError("bad SOCKS5 greeting length")
    if data[0] != S5_VERSION:
        raise SocksError("not a SOCKS5 greeting")
    nmethods = data[1]
    if nmethods == 0 or len(data) != 2 + nmethods:
        raise SocksError("bad SOCKS5 method list")
    if S5_NO_AUTH in data[2:2 + nmethods]:
        return bytes([S5_VERSION, S5_NO_AUTH]), True
    return bytes([S5_VERSION, S5_NO_ACCEPTABLE]), False


def parse_s5_request(data: bytes) -> tuple[str, int]:
    """Parse one SOCKS5 CONNECT request, return (host, port)."""
    if len(data) < 7 or len(data) > MAX_REQ:
        raise SocksError("bad SOCKS5 request length")
    if data[0] != S5_VERSION:
        raise SocksError("bad SOCKS version in request")
    if data[1] != S5_CMD_CONNECT:
        raise SocksError(f"unsupported SOCKS5 command {data[1]}")
    atyp = data[3]
    if atyp == S5_ATYP_V4:
        if len(data) != 10:
            raise SocksError("bad SOCKS5 IPv4 request")
        host = ".".join(str(b) for b in data[4:8])
        port = struct.unpack(">H", data[8:10])[0]
    elif atyp == S5_ATYP_DOMAIN:
        ln = data[4]
        if ln == 0 or len(data) != 5 + ln + 2:
            raise SocksError("bad SOCKS5 domain request")
        try:
            host = data[5:5 + ln].decode("ascii")
        except UnicodeDecodeError as e:
            raise SocksError("non-ascii SOCKS5 domain") from e
        if not host:
            raise SocksError("empty SOCKS5 domain")
        port = struct.unpack(">H", data[5 + ln:7 + ln])[0]
    elif atyp == S5_ATYP_V6:
        if len(data) != 22:
            raise SocksError("bad SOCKS5 IPv6 request")
        host = ":".join(f"{struct.unpack('>H', data[4 + i:6 + i])[0]:x}" for i in range(0, 16, 2))
        port = struct.unpack(">H", data[20:22])[0]
    else:
        raise SocksError(f"unsupported SOCKS5 address type {atyp}")
    if not 1 <= port <= 65535:
        raise SocksError(f"bad SOCKS5 port {port}")
    return host, port


def s5_reply_ok() -> bytes:
    """Success reply (bound address 0.0.0.0:0, like OpenSSH)."""
    return bytes([S5_VERSION, S5_REP_OK, 0x00, S5_ATYP_V4, 0, 0, 0, 0, 0, 0])


def s5_reply_fail(code: int = S5_REP_REFUSED) -> bytes:
    return bytes([S5_VERSION, code, 0x00, S5_ATYP_V4, 0, 0, 0, 0, 0, 0])


# SOCKS4 (CONNECT only): VN(04) CD(01) DSTPORT(2) DSTIP(4) USERID(0-term).
def parse_s4_request(data: bytes) -> tuple[str, int]:
    if len(data) < 9 or len(data) > MAX_REQ:
        raise SocksError("bad SOCKS4 request length")
    if data[0] != 0x04:
        raise SocksError("not a SOCKS4 request")
    if data[1] != 0x01:
        raise SocksError(f"unsupported SOCKS4 command {data[1]}")
    port = struct.unpack(">H", data[2:4])[0]
    ip = data[4:8]
    # SOCKS4a (hostname extension): 0.0.0.x with domain after USERID.
    if ip[:3] == b"\x00\x00\x00" and ip[3] != 0:
        try:
            nul = data.index(b"\x00", 8)
        except ValueError as e:
            raise SocksError("bad SOCKS4a userid terminator") from e
        rest = data[nul + 1:]
        if not rest or len(rest) > MAX_DOMAIN + 1:
            raise SocksError("bad SOCKS4a hostname")
        if rest[-1:] != b"\x00":
            raise SocksError("bad SOCKS4a hostname terminator")
        try:
            host = rest[:-1].decode("ascii")
        except UnicodeDecodeError as e:
            raise SocksError("non-ascii SOCKS4a hostname") from e
        if not host:
            raise SocksError("empty SOCKS4a hostname")
    else:
        host = ".".join(str(b) for b in ip)
    if not 1 <= port <= 65535:
        raise SocksError(f"bad SOCKS4 port {port}")
    return host, port


def s4_reply_ok() -> bytes:
    return b"\x00\x5a\x00\x00\x00\x00\x00\x00"


def s4_reply_fail() -> bytes:
    return b"\x00\x5b\x00\x00\x00\x00\x00\x00"
