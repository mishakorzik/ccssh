"""
 A socket-like object tunneled over one SSH direct-tcpip channel.

 Used for -J (ProxyJump): the outer SSH handshake runs over a plain TCP
 socket, the inner one over this. Implements the small surface SyncTransport
 needs: sendall / recv / settimeout / close.
"""
from __future__ import annotations

import time
from typing import Protocol

from ccssh import channel as CH
from ccssh import wire as W
from ccssh.transport import CCSSHTimeoutError


class StreamSocket(Protocol):
    """
     The socket surface SyncTransport needs. Real sockets and ChannelSocket
     both satisfy it structurally.
    """

    def sendall(self, data: bytes) -> None: ...
    def recv(self, n: int) -> bytes: ...
    def settimeout(self, timeout: float | None) -> None: ...
    def close(self) -> None: ...


class ChannelSocket(StreamSocket):
    """
     One direct-tcpip channel, socket-shaped. Single-threaded by design:
     the owning connection must not run concurrent channel operations
     (same rule as exec/sftp/shell).
    """

    def __init__(self, transport, srv: int, window: int, maxpacket: int, timeout: float | None = 10.0, mux=None, chan: int | None = None):
        self._t = transport
        self._srv = srv
        self._window = window
        # Honor the server's maxpacket but never exceed ours: a rogue
        # server announcing megabytes would make enc_data raise mid-send.
        self._maxpacket = max(1024, min(maxpacket, CH.MAXPKT))
        self._timeout = timeout
        self._mux = mux
        self._chan = chan
        self._rbuf = b""
        self._consumed = 0
        self._closed = False
        self._eof = False
        self._skips = 0

    def _deadline(self) -> float | None:
        if self._timeout is None:
            return None  # blocking mode, like a plain socket
        return time.monotonic() + self._timeout

    def _expired(self, deadline: float | None) -> bool:
        return deadline is not None and time.monotonic() > deadline

    def _check_chan(self, rr: W.Reader) -> bool:
        """
         True if this packet is addressed to our channel.

         With a mux the queue is already per-channel; without one the jump
         connection carries only this channel. Either way, a foreign id is
         never ours - skip it instead of crediting/buffering it.
        """
        try:
            rcpt = rr.u32()
        except Exception:
            return False
        if self._chan is not None and rcpt != self._chan and rcpt != self._srv:
            return False
        return True

    def _recv_one(self, timeout: float | None = None):
        """One inbound packet: mux queue when shared, else direct read."""
        if self._mux is not None and self._chan is not None:
            return self._mux.recv_chan(self._chan, timeout)
        return self._t.recv_packet(keepalive=False)

    def settimeout(self, timeout: float | None) -> None:
        # None means blocking mode, like a plain socket (never 3600s).
        self._timeout = timeout

    def sendall(self, data: bytes) -> None:
        if self._closed:
            raise OSError("channel closed")
        off = 0
        while off < len(data):
            chunk = data[off:off + self._maxpacket]
            self._top_up(len(chunk))
            self._t.send_packet(CH.enc_data(self._srv, chunk))
            off += len(chunk)

    def _got_data(self, chunk: bytes) -> None:
        """
         Buffer inbound channel data and re-credit the server window.
        """
        if len(self._rbuf) + len(chunk) > CH.MAX_BUFFER:
            self._closed = True
            raise OSError("channel receive buffer exceeded")
        self._rbuf += chunk
        self._consumed += len(chunk)
        if self._consumed >= CH.WINDOW_THRESHOLD:
            try:
                self._t.send_packet(CH.enc_window_adjust(self._srv, self._consumed))
            except Exception:
                return # keep the credit: retry on the next chunk
            self._consumed = 0

    def _note_service(self) -> None:
        """Count non-channel service packets inside a window/recv wait."""
        self._skips += 1
        if self._skips > 64:
            raise OSError("too many service messages")

    def _top_up(self, need: int) -> None:
        """
         Wait for channel window, answering service traffic meanwhile.
         The jump connection carries only this channel, so any DATA that
         is not ours cannot arrive; anything else is service noise.
        """
        deadline = self._deadline()
        while self._window < need:
            if self._expired(deadline):
                raise OSError("channel send window exhausted")
            try:
                p = self._recv_one(timeout=None if deadline is None else max(0.01, deadline - time.monotonic()))
            except CCSSHTimeoutError as e:
                raise OSError("channel send window exhausted") from e
            m = p[0]
            rr = W.Reader(p)
            rr.byte()
            if m == CH.MSG_WINDOW_ADJUST:
                if not self._check_chan(rr):
                    self._note_service()
                    continue
                try:
                    self._window = CH.check_window(self._window, rr.u32())
                except ValueError as e:
                    raise OSError(f"bad window adjust: {e}") from e
                self._skips = 0
            elif m == CH.MSG_CHANNEL_DATA:
                if not self._check_chan(rr):
                    self._note_service()
                    continue
                self._got_data(rr.string())
                self._skips = 0
            elif m == CH.MSG_CHANNEL_CLOSE:
                self._closed = True
                raise OSError("channel closed by peer")
            elif m == CH.MSG_CHANNEL_EOF:
                self._eof = True
                continue
            elif m == 20:
                raise OSError("peer started rekey with an open channel")
            else:
                self._note_service()

    def recv(self, n: int) -> bytes:
        if n <= 0:
            return b""
        if (self._closed or self._eof) and not self._rbuf:
            return b""
        deadline = self._deadline()
        while len(self._rbuf) < n:
            if self._expired(deadline):
                if self._rbuf:
                    break
                raise CCSSHTimeoutError("channel read timeout")
            try:
                p = self._recv_one(timeout=None if deadline is None else max(0.01, deadline - time.monotonic()))
            except CCSSHTimeoutError:
                if self._rbuf:
                    break
                raise
            m = p[0]
            rr = W.Reader(p)
            rr.byte()
            if m == CH.MSG_CHANNEL_DATA:
                if not self._check_chan(rr):
                    self._note_service()
                    continue
                self._got_data(rr.string())
                self._skips = 0
            elif m == CH.MSG_WINDOW_ADJUST:
                if not self._check_chan(rr):
                    self._note_service()
                    continue
                try:
                    self._window = CH.check_window(self._window, rr.u32())
                except ValueError as e:
                    raise OSError(f"bad window adjust: {e}") from e
                self._skips = 0
            elif m == CH.MSG_CHANNEL_EOF:
                rr.u32()
                self._eof = True
                break
            elif m == CH.MSG_CHANNEL_CLOSE:
                rr.u32()
                self._closed = True
                break
            elif m == 20:
                raise OSError("peer started rekey with an open channel")
            else:
                self._note_service()
        out, self._rbuf = self._rbuf[:n], self._rbuf[n:]
        return out

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._t.send_packet(CH.enc_eof(self._srv))
            except Exception:
                pass
            try:
                self._t.send_packet(CH.enc_close(self._srv))
            except Exception:
                pass
            if self._mux is not None and self._chan is not None:
                try:
                    self._mux.unregister(self._chan)
                except Exception:
                    pass
