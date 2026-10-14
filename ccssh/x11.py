"""
 X11 forwarding (`ssh -X` / `ssh -Y`, RFC 4254 section 6.3).

 Flow (client side):
 1. Parse the local ``$DISPLAY`` (``host:n[.m]`` or ``:n[.m]``).
 2. Mint a fresh MIT-MAGIC-COOKIE-1 (16 bytes, hex on the wire) and send
    ``x11-req`` on the session channel before shell/exec.
 3. The server sets ``$DISPLAY`` to its proxy offset (usually ``:10``) and,
    for every X application connection, opens an ``x11`` channel back with
    the originator address/port.
 4. Each inbound ``x11`` channel is relayed to the real local X server
    (Unix ``/tmp/.X11-unix/Xn`` preferred, else TCP ``6000+n``).

 Trusted (`-Y`) vs untrusted (`-X`) only changes the timeout/extension
 policy server-side; the wire format is identical. Like OpenSSH, a refused
 ``x11-req`` is tolerated with a warning (the session continues without
 forwarding) rather than killing the login.
"""
from __future__ import annotations

import os
import re
import socket

from ccssh import wire as W

AUTH_PROTO = b"MIT-MAGIC-COOKIE-1"
COOKIE_LEN = 16  # 128-bit cookie, like OpenSSH's generated fake cookie
MAX_DISPLAY_NUM = 999  # sanity cap for parsed display numbers


class X11Error(Exception):
    pass


def gen_cookie() -> bytes:
    """Fresh 16-byte X11 auth cookie (binary; hex-encoded on the wire)."""
    return os.urandom(COOKIE_LEN)


def parse_display(display: str | None = None) -> tuple[str, int, int]:
    """
     Parse ``$DISPLAY`` into (host, display_number, screen).

     Accepts ``:n[.m]``, ``host:n[.m]``, ``/tmp/...:n``-style values.
     Returns host "" for local (Unix-socket) displays. Raises X11Error on
     anything unparseable (never connect somewhere surprising).
    """
    raw = display if display is not None else os.environ.get("DISPLAY", "")
    raw = (raw or "").strip()
    if not raw:
        raise X11Error("no local DISPLAY (set $DISPLAY or drop -X/-Y)")
    # Strip a unix-socket path prefix if present (rare, but harmless).
    if "/" in raw:
        raw = raw.rsplit("/", 1)[-1]
        if not raw.startswith(":"):
            raise X11Error(f"bad DISPLAY {raw!r}")
    m = re.fullmatch(r"(.*?):(\d+)(?:\.(\d+))?", raw)
    if not m:
        raise X11Error(f"bad DISPLAY {raw!r}")
    host, disp_s, screen_s = m.group(1), m.group(2), m.group(3) or "0"
    try:
        disp, screen = int(disp_s), int(screen_s)
    except ValueError as e:
        raise X11Error(f"bad DISPLAY {raw!r}") from e
    if not 0 <= disp <= MAX_DISPLAY_NUM or not 0 <= screen <= 99:
        raise X11Error(f"DISPLAY out of range: {raw!r}")
    # "unix" explicitly means local socket; treat like empty host.
    if host.lower() == "unix":
        host = ""
    return host, disp, screen


def dial_display(display: str | None = None, *, timeout: float = 10.0) -> socket.socket:
    """
     Connect to the real local X server for a parsed DISPLAY.

     Local displays (empty host / localhost) try the Unix socket first,
     then TCP loopback; remote DISPLAY hosts go straight to TCP 6000+n.
    """
    host, disp, _screen = parse_display(display)
    port = 6000 + disp
    last: OSError | None = None
    if host in ("", "localhost", "127.0.0.1", "::1"):
        for path in (f"/tmp/.X11-unix/X{disp}",):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect(path)
                return s
            except OSError as e:
                last = e
                try:
                    s.close()
                except Exception:
                    pass
        for h in ("127.0.0.1", "::1"):
            try:
                s = socket.create_connection((h, port), timeout=timeout)
                return s
            except OSError as e:
                last = e
        raise X11Error(f"cannot reach local X display (tried unix socket + TCP :{port}): {last}")
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise X11Error(f"cannot reach X display {host}:{port}: {e}") from e


def enc_x11_req(recipient: int, *, single_connection: bool = False, cookie: bytes, screen: int = 0, want_reply: bool = True) -> bytes:
    """Encode an x11-req channel request (RFC 4254 6.3.1)."""
    if len(cookie) != COOKIE_LEN:
        raise X11Error("x11 cookie must be 16 bytes")
    if not 0 <= screen <= 99:
        raise X11Error("x11 screen out of range")
    return (bytes([98]) + W.enc_u32(recipient)
            + W.enc_string(b"x11-req") + W.enc_bool(want_reply)
            + W.enc_bool(single_connection)
            + W.enc_string(AUTH_PROTO)
            + W.enc_string(cookie.hex().encode("ascii"))
            + W.enc_u32(screen))


def dec_x11_open(payload: bytes) -> dict:
    """
     Parse an inbound ``x11`` CHANNEL_OPEN (RFC 4254 6.3.2).

     Returns {"sender", "originator", "originator_port"}. Raises X11Error
     on any malformed data.
    """
    from ccssh import channel as CH
    r = W.Reader(payload)
    try:
        if r.byte() != CH.MSG_CHANNEL_OPEN:
            raise X11Error("not a CHANNEL_OPEN")
        ctype = r.string()
        if ctype != b"x11":
            raise X11Error(f"not an x11 open (got {ctype!r})")
        sender = r.u32()
        r.u32() # initial window (flow state lives in the forwarder)
        r.u32() # maxpacket
        originator = r.string()
        originator_port = r.u32()
        r.assert_end()
    except W.WireError as e:
        raise X11Error(f"bad x11 open: {e}") from e
    return {"sender": sender, "originator": originator,
            "originator_port": originator_port}
