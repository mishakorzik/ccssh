"""
 Channel message codecs, RFC 4254: session open, exec/subsystem requests,
 direct-tcpip open, data, window adjust, close.
"""
from __future__ import annotations

from ccssh import wire as W

MSG_CHANNEL_OPEN = 90
MSG_CHANNEL_OPEN_CONFIRM = 91
MSG_CHANNEL_OPEN_FAILURE = 92
MSG_WINDOW_ADJUST = 93
MSG_CHANNEL_DATA = 94
MSG_CHANNEL_EXTENDED_DATA = 95
MSG_CHANNEL_EOF = 96
MSG_CHANNEL_CLOSE = 97
MSG_CHANNEL_REQUEST = 98
MSG_CHANNEL_SUCCESS = 99
MSG_CHANNEL_FAILURE = 100

WINDOW = 2 * 1024 * 1024
MAXPKT = 32768
# Send WINDOW_ADJUST after consuming this many channel bytes (half a window).
WINDOW_THRESHOLD = 1024 * 1024
# Per-channel relay backlog cap (forwarders, jump sockets): a slow reader
# must fail its channel, never OOM the process.
MAX_BUFFER = 16 * 1024 * 1024


def enc_open_session(sender: int) -> bytes:
    return (bytes([MSG_CHANNEL_OPEN]) + W.enc_string(b"session") + W.enc_u32(sender) + W.enc_u32(WINDOW) + W.enc_u32(MAXPKT))


def enc_exec(recipient: int, command: str, *, want_reply: bool = True) -> bytes:
    return (bytes([MSG_CHANNEL_REQUEST])
            + W.enc_u32(recipient)
            + W.enc_string(b"exec")
            + W.enc_bool(want_reply)
            + W.enc_string(command.encode()))


def enc_subsystem(recipient: int, name: str = "sftp", *, want_reply: bool = True) -> bytes:
    return (bytes([MSG_CHANNEL_REQUEST])
            + W.enc_u32(recipient)
            + W.enc_string(b"subsystem")
            + W.enc_bool(want_reply)
            + W.enc_string(name.encode()))


def enc_pty_req(recipient: int, term: str = "xterm", cols: int = 80, rows: int = 24, width_px: int = 0, height_px: int = 0, modes: bytes = b"", *, want_reply: bool = True) -> bytes:
    """RFC 4254 section 6.2 pty-req. Empty modes = all opcodes stay default."""
    return (bytes([MSG_CHANNEL_REQUEST])
            + W.enc_u32(recipient)
            + W.enc_string(b"pty-req")
            + W.enc_bool(want_reply)
            + W.enc_string(term.encode())
            + W.enc_u32(cols)
            + W.enc_u32(rows)
            + W.enc_u32(width_px)
            + W.enc_u32(height_px)
            + W.enc_string(modes))


def enc_shell(recipient: int, *, want_reply: bool = True) -> bytes:
    """RFC 4254 section 6.5 shell request."""
    return (bytes([MSG_CHANNEL_REQUEST])
            + W.enc_u32(recipient)
            + W.enc_string(b"shell")
            + W.enc_bool(want_reply))


def enc_window_change(recipient: int, cols: int, rows: int, width_px: int = 0, height_px: int = 0) -> bytes:
    """RFC 4254 section 6.7. Always want_reply=False (no reply is sent)."""
    return (bytes([MSG_CHANNEL_REQUEST])
            + W.enc_u32(recipient)
            + W.enc_string(b"window-change")
            + W.enc_bool(False)
            + W.enc_u32(cols)
            + W.enc_u32(rows)
            + W.enc_u32(width_px)
            + W.enc_u32(height_px))


def enc_eof(recipient: int) -> bytes:
    """RFC 4254 section 5.3: no more data will be sent (stdin EOF)."""
    return bytes([MSG_CHANNEL_EOF]) + W.enc_u32(recipient)


def enc_open_direct_tcpip(sender: int, host: str, port: int, orig_host: str = "127.0.0.1", orig_port: int = 0) -> bytes:
    return (bytes([MSG_CHANNEL_OPEN])
            + W.enc_string(b"direct-tcpip")
            + W.enc_u32(sender)
            + W.enc_u32(WINDOW)
            + W.enc_u32(MAXPKT)
            + W.enc_string(host.encode())
            + W.enc_u32(port)
            + W.enc_string(orig_host.encode())
            + W.enc_u32(orig_port))


def enc_data(recipient: int, data: bytes) -> bytes:
    if len(data) > MAXPKT:
        raise ValueError(f"channel data chunk exceeds MAXPKT ({len(data)} > {MAXPKT})")
    return bytes([MSG_CHANNEL_DATA]) + W.enc_u32(recipient) + W.enc_string(data)


def enc_window_adjust(recipient: int, delta: int) -> bytes:
    if not 0 < delta < 2**32:
        raise ValueError(f"window adjust delta out of range: {delta}")
    return bytes([MSG_WINDOW_ADJUST]) + W.enc_u32(recipient) + W.enc_u32(delta)


def check_window(window: int, delta: int) -> int:
    """Add a WINDOW_ADJUST credit, enforcing RFC 4254 section 5.2 limits."""
    if not 0 < delta < 2**32:
        raise ValueError(f"bad window increment {delta}")
    new = window + delta
    if new > 0xFFFFFFFF:
        raise ValueError("channel window exceeds 2^32-1")
    return new


def enc_close(recipient: int) -> bytes:
    return bytes([MSG_CHANNEL_CLOSE]) + W.enc_u32(recipient)
