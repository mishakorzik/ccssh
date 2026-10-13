"""
 Local (-L) and remote (-R) TCP forwarding over SSH channels.

 The forwarders share the connection through the channel multiplexer
 (:class:`ccssh.mux.ChannelMux`), ssh-like: exec/sftp/shell may run on
 the same connection while forwarding is active. Each forwarder runs one
 pump thread that multiplexes local sockets and its mux queues; the mux
 owns the only transport reader, so concurrent channels never interleave
 the framing (the pre-mux single-reader deadlock is gone by construction:
 no lock is ever held across a blocking receive).

 Orderly shutdown is a half-close: local EOF sends ``CHANNEL_EOF`` and
 keeps relaying server->local until the server closes (no data loss).
"""
from __future__ import annotations
import queue
import select
import socket
import threading
import time

from ccssh import channel as CH
from ccssh import wire as W


class ForwardError(Exception):
    pass


def _listen(bind: str, lport: int) -> socket.socket:
    """Listener socket for v4/v6 hostnames and literal addresses."""
    last: OSError | None = None
    try:
        infos = socket.getaddrinfo(bind or "127.0.0.1", lport, type=socket.SOCK_STREAM)
    except OSError:
        infos = []
    for af, st, proto, _canon, sa in infos or [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (bind, lport))]:
        s: socket.socket | None = None
        try:
            s = socket.socket(af, st, proto)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except Exception:
                pass
            s.bind(sa)
            s.listen(16)
            return s
        except OSError as e:
            last = e
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            continue
    raise ForwardError(f"listen {bind}:{lport} failed: {last}")


class _PendingOpen:
    __slots__ = ("event", "srv", "window", "maxpacket", "failure")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.srv: int | None = None
        self.window = 0
        self.maxpacket = 0
        self.failure = False


class BaseForwarder:
    """Shared pump/pending-open machinery for -L and -R (mux-fed)."""

    def __init__(self, mux) -> None:
        self._mux = mux
        # Lock order is ALWAYS map_lock -> send_lock, never the reverse.
        # send_lock is held only for a single non-blocking mux.send call.
        self._send_lock = threading.Lock()
        self._map_lock = threading.Lock()
        self._stop = threading.Event()
        self.closed = False
        self._pending: dict[int, _PendingOpen] = {}
        self._chans: dict[int, socket.socket] = {}  # our id -> local socket
        self._srv_to_my: dict[int, int] = {}  # server id -> our id
        self._my_to_srv: dict[int, int] = {}  # our id -> server id
        self._consumed: dict[int, int] = {}
        self._pending_in: dict[int, bytes] = {}  # local->server backlog
        self._pending_out: dict[int, bytes] = {}  # server->local backlog
        self._eof_local: set[int] = set()  # local EOF seen, backlog pending
        self._send_window: dict[int, int] = {}  # our id -> remaining window
        self._send_max: dict[int, int] = {}
        self._eof_sent: set[int] = set()
        self._th = threading.Thread(target=self._pump, daemon=True)

    # transport IO
    def _send(self, payload: bytes) -> None:
        with self._send_lock:
            self._mux.send(payload)

    def _timeout(self) -> float:
        try:
            return float(self._mux.timeout)
        except Exception:
            return 10.0

    def _wait_pending(self, my_id: int, pend: _PendingOpen, timeout: float) -> None:
        """
         Wait for a channel-open confirm while draining mux queues.

         Every installed channel (not just ours) is drained through
         _handle while we wait, so a slow/dead peer on one accept cannot
         head-of-line-block the rest; no lock is held while waiting.
        """
        deadline = time.monotonic() + timeout
        # The confirm for THIS channel must have a queue to land in. Note
        # it is NOT installed yet, so _pump_drain_mux (installed channels
        # + catch-all) will not see it: drain it explicitly below.
        my_q = self._mux.register(my_id)
        while not pend.event.is_set():
            if self._mux.dead:
                raise ForwardError("transport closed during channel open")
            if time.monotonic() > deadline:
                break
            if not self._pump_drain_mux():
                raise ForwardError("forwarder draining failed during channel open")
            try:
                p = my_q.get_nowait()
            except queue.Empty:
                pass
            else:
                if isinstance(p, (bytes, bytearray)):
                    self._handle(p)
            if pend.event.is_set():
                break
            if self._stop.is_set():
                break
            time.sleep(0.01)
        if not pend.event.is_set():
            raise ForwardError("channel open confirm timeout")
        if pend.failure:
            raise ForwardError("server refused channel open")

    # to be specialised
    def _handle(self, p: bytes) -> None:
        raise NotImplementedError

    def _pump(self) -> None:
        raise NotImplementedError

    def _pump_drain_mux(self) -> bool:
        """Drain our channel queues + catch-all once. False to shut down."""
        with self._map_lock:
            chan_ids = list(self._chans)
        catch = self._mux.catch_all()
        queues = []
        for k in chan_ids:
            q = self._mux._queue_for(k)
            if q is not None:
                queues.append(q)
        for q in queues + [catch]:
            while True:
                try:
                    p = q.get_nowait()
                except queue.Empty:
                    break
                if not isinstance(p, (bytes, bytearray)):
                    continue # mux sentinel: death is reported via mux.dead
                try:
                    self._handle(p)
                except ForwardError:
                    return False
                except Exception:
                    pass
        if self._mux.dead:
            return False
        return True

    # shared channel helpers (brief map_lock)
    def _install_channel(self, my_id: int, sock: socket.socket, srv: int, window: int, maxpacket: int) -> None:
        # The mux queue must exist before any DATA can arrive (server-
        # initiated opens never went through _wait_pending registration).
        try:
            self._mux.register(my_id)
        except Exception:
            pass
        with self._map_lock:
            if my_id in self._chans:
                raise ForwardError(f"channel id collision: {my_id} already open")
            self._pending.pop(my_id, None)
            self._chans[my_id] = sock
            self._srv_to_my[srv] = my_id
            self._my_to_srv[my_id] = srv
            self._consumed[my_id] = 0
            # Send window is keyed by OUR id: WINDOW_ADJUST from the peer
            # carries our channel number as recipient (RFC 4254 section 5.2).
            self._send_window[my_id] = window
            self._send_max[my_id] = max(1024, maxpacket)

    def _resolve_my_locked(self, recipient: int) -> int | None:
        """
         Map an inbound recipient field to our channel id.

         Peers address our channel number; accept the peer's own number too
         (liberal in what you accept - some stacks echo it).
        """
        if recipient in self._chans:
            return recipient
        return self._srv_to_my.get(recipient)

    def _on_data(self, recipient: int, data: bytes) -> None:
        """Server->local direction with partial-write-safe backlog."""
        with self._map_lock:
            my_id = self._resolve_my_locked(recipient)
            if my_id is None:
                return
            s = self._chans.get(my_id)
            if s is None:
                return
            data = self._pending_out.pop(my_id, b"") + data
            if len(data) > CH.MAX_BUFFER:
                # Slow local reader vs fast server: fail the channel closed
                # instead of letting one connection OOM the process.
                over = True
            else:
                over = False
        if over:
            self._drop(my_id)
            return
        try:
            n = s.send(data)
        except BlockingIOError:
            with self._map_lock:
                if my_id in self._chans:
                    self._pending_out[my_id] = data
            return
        except Exception:
            self._drop(my_id)
            return
        if n < len(data):
            with self._map_lock:
                if my_id in self._chans:
                    self._pending_out[my_id] = data[n:]
            data = data[:n]
        self._credit(my_id, len(data))

    def _credit(self, my_id: int, n: int) -> None:
        with self._map_lock:
            self._consumed[my_id] = self._consumed.get(my_id, 0) + n
            if self._consumed.get(my_id, 0) < CH.WINDOW_THRESHOLD:
                return
            srv = self._my_to_srv.get(my_id)
            delta = self._consumed.get(my_id, 0)
            self._consumed[my_id] = 0
        if srv is not None:
            try:
                self._send(CH.enc_window_adjust(srv, delta))
            except Exception:
                pass

    def _on_window(self, recipient: int, delta: int) -> None:
        with self._map_lock:
            my_id = self._resolve_my_locked(recipient)
            if my_id is None:
                return
            try:
                self._send_window[my_id] = CH.check_window(
                    self._send_window.get(my_id, 0), delta)
            except ValueError:
                pass # bogus increment: ignore, fail closed elsewhere

    def _flush_out(self, s: socket.socket) -> None:
        with self._map_lock:
            my_id = next((k for k, v in self._chans.items() if v is s), None)
            if my_id is None:
                return
            data = self._pending_out.pop(my_id, b"")
            if not data:
                return
        try:
            n = s.send(data)
        except BlockingIOError:
            with self._map_lock:
                if my_id in self._chans:
                    self._pending_out[my_id] = data
            return
        except Exception:
            self._drop(my_id)
            return
        if n < len(data):
            with self._map_lock:
                if my_id in self._chans:
                    self._pending_out[my_id] = data[n:]
        # Credit the server window for what actually left, like _on_data.
        self._credit(my_id, n)

    def _on_local(self, s: socket.socket) -> None:
        with self._map_lock:
            my_id = next((k for k, v in self._chans.items() if v is s), None)
            if my_id is None:
                return
            data = self._pending_in.pop(my_id, b"")
        try:
            got = s.recv(32768)
        except BlockingIOError:
            got = None # spurious readiness: keep channel
        except Exception:
            self._drop(my_id)
            return
        if got is None:
            if data:
                self._forward_local(my_id, data)
            return
        if got == b"":
            # Local EOF is terminal for this direction: arm it, flush what
            # remains, and stop selecting the socket (it would spin: EOF
            # sockets are always "readable").
            with self._map_lock:
                if my_id in self._chans:
                    self._eof_local.add(my_id)
            if data:
                self._forward_local(my_id, data)
            self._maybe_half_close(my_id)
            return
        self._forward_local(my_id, data + got)

    def _flush_in(self, my_id: int) -> None:
        """Retry a backlogged local->server write (window opened up)."""
        with self._map_lock:
            if my_id not in self._chans:
                self._eof_local.discard(my_id)
                return
            data = self._pending_in.pop(my_id, b"")
            if not data:
                return
        self._forward_local(my_id, data)
        self._maybe_half_close(my_id)

    def _maybe_half_close(self, my_id: int) -> None:
        """Deliver an armed local EOF once its backlog fully drained."""
        with self._map_lock:
            armed = my_id in self._eof_local
            drained = not self._pending_in.get(my_id)
            live = my_id in self._chans
            if armed and drained and live:
                self._eof_local.discard(my_id)
                do_half = True
            else:
                do_half = False
        if do_half:
            self._half_close(my_id)

    def _forward_local(self, my_id: int, data: bytes) -> None:
        with self._map_lock:
            srv = self._my_to_srv.get(my_id)
            if srv is None:
                return
            # Honor the server's maxpacket but never exceed ours: a rogue
            # server announcing megabytes would make enc_data raise.
            maxp = min(self._send_max.get(my_id, 32768), CH.MAXPKT)
            if len(self._pending_in.get(my_id, b"")) + len(data) > CH.MAX_BUFFER:
                over = True
            else:
                over = False
        if over:
            self._drop(my_id)
            return
        off = 0
        try:
            while off < len(data):
                chunk = data[off:off + maxp]
                with self._map_lock:
                    window = self._send_window.get(my_id, 0)
                    if window < len(chunk):
                        self._pending_in[my_id] = data[off:]
                        return
                    self._send_window[my_id] = window - len(chunk)
                self._send(CH.enc_data(srv, chunk))
                off += len(chunk)
        except Exception:
            self._drop(my_id)
            return
        if off < len(data):
            with self._map_lock:
                if my_id in self._chans:
                    self._pending_in[my_id] = data[off:]

    def _half_close(self, my_id: int) -> None:
        """Local EOF: CHANNEL_EOF to the server, keep the reverse path open."""
        with self._map_lock:
            if my_id not in self._chans or my_id in self._eof_sent:
                return
            srv = self._my_to_srv.get(my_id)
            self._eof_sent.add(my_id)
            try:
                s = self._chans.get(my_id)
                if s is not None:
                    try:
                        s.shutdown(socket.SHUT_RD)
                    except Exception:
                        pass
            except Exception:
                pass
        if srv is not None:
            try:
                self._send(CH.enc_eof(srv))
            except Exception:
                pass

    def _on_remote_eof(self, recipient: int) -> None:
        with self._map_lock:
            my_id = self._resolve_my_locked(recipient)
            if my_id is None:
                return
            s = self._chans.get(my_id)
        if s is not None:
            try:
                s.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def _on_remote_close(self, recipient: int) -> None:
        with self._map_lock:
            my_id = self._resolve_my_locked(recipient)
        if my_id is not None:
            self._drop(my_id)

    def _route_confirm(self, my_id: int, srv: int, window: int, maxpacket: int) -> bool:
        """Complete a pending open. True if it was ours."""
        with self._map_lock:
            pend = self._pending.get(my_id)
            if pend is None:
                return False
            pend.srv = srv
            pend.window = window
            pend.maxpacket = max(1024, maxpacket)
            pend.event.set()
            return True

    def _route_failure(self, my_id: int) -> bool:
        with self._map_lock:
            pend = self._pending.get(my_id)
            if pend is None:
                return False
            pend.failure = True
            pend.event.set()
            return True

    def _drop(self, my_id: int) -> None:
        with self._map_lock:
            s = self._chans.pop(my_id, None)
            self._consumed.pop(my_id, None)
            self._pending_in.pop(my_id, None)
            self._pending_out.pop(my_id, None)
            self._eof_sent.discard(my_id)
            self._eof_local.discard(my_id)
            self._pending.pop(my_id, None)
            srv = self._my_to_srv.pop(my_id, None)
            if srv is not None:
                self._srv_to_my.pop(srv, None)
            self._send_window.pop(my_id, None)
            self._send_max.pop(my_id, None)
        try:
            self._mux.unregister(my_id)
        except Exception:
            pass
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        if srv is not None:
            try:
                self._send(CH.enc_close(srv))
            except Exception:
                pass

    def _close_channels(self) -> None:
        for my_id in list(self._chans):
            self._drop(my_id) # closes the local socket, sends CHANNEL_CLOSE


class LocalForwarder(BaseForwarder):
    def __init__(self, mux, lport: int, rhost: str, rport: int,
                 bind: str = "127.0.0.1"):
        super().__init__(mux)
        self._target = (rhost, rport)
        self._bind = bind
        self._ls = _listen(bind, lport)
        self.port = self._ls.getsockname()[1]

    def start(self) -> "LocalForwarder":
        self._th.start()
        return self

    def close(self) -> None:
        self.closed = True
        self._stop.set()
        try:
            self._ls.close()
        except Exception:
            pass
        self._close_channels()
        # NOTE: the client-owned mux keeps running (exec may continue).
        try:
            if self._th.is_alive():
                self._th.join(timeout=2.0)
        except Exception:
            pass

    def _pump(self) -> None:
        try:
            while not self._stop.is_set():
                if not self._pump_drain_mux():
                    return
                with self._map_lock:
                    chans = [(k, v) for k, v in self._chans.items() if k not in self._eof_local]
                    wlist = [self._chans[k] for k in self._pending_out if k in self._chans]
                    eof_backlog = [k for k in self._eof_local if k in self._chans and self._pending_in.get(k)]
                for my_id in eof_backlog:
                    self._flush_in(my_id)
                try:
                    rd, wr, _ = select.select([self._ls] + [s for _, s in chans], wlist, [], 0.2)
                except Exception:
                    if self.closed:
                        return
                    continue
                for s in wr:
                    self._flush_out(s)
                for s in rd:
                    if s is self._ls:
                        try:
                            conn, _ = self._ls.accept()
                        except Exception:
                            continue
                        try:
                            self._open_channel(conn)
                        except Exception:
                            try:
                                conn.close()
                            except Exception:
                                pass
                    else:
                        self._on_local(s)
        finally:
            # A dying pump must not strand open sockets/queues behind.
            self._stop.set()
            self._close_channels()

    def _open_channel(self, conn: socket.socket) -> None:
        # Channel ids come from the single mux-shared namespace: disjoint
        # local counters would eventually collide and misroute packets.
        my_id = self._mux.alloc_chan()
        with self._map_lock:
            pend = _PendingOpen()
            self._pending[my_id] = pend
        try:
            peer = conn.getpeername()
        except Exception:
            peer = ("127.0.0.1", 0)
        self._send(CH.enc_open_direct_tcpip(my_id, self._target[0], self._target[1], orig_host=peer[0], orig_port=peer[1]))
        # Wait for OUR confirm while other channels keep flowing.
        try:
            self._wait_pending(my_id, pend, self._timeout())
        except Exception:
            with self._map_lock:
                self._pending.pop(my_id, None)
            try:
                self._mux.unregister(my_id)
            except Exception:
                pass
            raise
        assert pend.srv is not None
        self._install_channel(my_id, conn, pend.srv, pend.window, pend.maxpacket)
        try:
            conn.setblocking(False)
        except Exception:
            pass

    def _handle(self, p: bytes) -> None:
        r = W.Reader(p)
        try:
            m = r.byte()
        except Exception:
            return
        if m in (2, 4, 20, 80, 81, 82):
            # Service traffic never reaches here (mux handles it); a KEX
            # broadcast means rekey with open channels: fail loudly.
            if m == 20:
                raise ForwardError("peer started rekey during forwarding: close it and call rekey()")
            return
        if m == CH.MSG_CHANNEL_OPEN_CONFIRM:
            try:
                rcpt, srv, w, mx = r.u32(), r.u32(), r.u32(), r.u32()
            except Exception:
                return
            self._route_confirm(rcpt, srv, w, mx)
            return
        if m == CH.MSG_CHANNEL_OPEN:
            # A local (-L) forwarder never expects server-initiated opens:
            # refuse so the peer doesn't hang waiting for an answer.
            rr = W.Reader(p)
            try:
                rr.byte()
                rr.string()
                srv = rr.u32()
            except Exception:
                return
            try:
                self._send(bytes([CH.MSG_CHANNEL_OPEN_FAILURE])
                           + W.enc_u32(srv)
                           + W.enc_u32(3)
                           + W.enc_string(b"forwarding not supported here")
                           + W.enc_string(b""))
            except Exception:
                pass
            return
        if m == CH.MSG_CHANNEL_OPEN_FAILURE:
            try:
                rcpt = r.u32()
            except Exception:
                return
            if not self._route_failure(rcpt):
                return
            return
        if m == CH.MSG_CHANNEL_DATA:
            try:
                rcpt, data = r.u32(), r.string()
            except Exception:
                return
            self._on_data(rcpt, data)
            return
        if m == CH.MSG_WINDOW_ADJUST:
            try:
                rcpt, delta = r.u32(), r.u32()
            except Exception:
                return
            self._on_window(rcpt, delta)
            return
        if m == CH.MSG_CHANNEL_EOF:
            try:
                rcpt = r.u32()
            except Exception:
                return
            self._on_remote_eof(rcpt)
            return
        if m == CH.MSG_CHANNEL_CLOSE:
            try:
                rcpt = r.u32()
            except Exception:
                return
            self._on_remote_close(rcpt)
            return


def enc_global_tcpip_forward(bind: str, port: int) -> bytes:
    """
     SSH_MSG_GLOBAL_REQUEST for tcpip-forward (RFC 4254 section 7.1).
    """
    return (bytes([80]) + W.enc_string(b"tcpip-forward") + W.enc_bool(True) + W.enc_string(bind.encode()) + W.enc_u32(port))


def enc_global_cancel_forward(bind: str, port: int) -> bytes:
    """
     cancel-tcpip-forward. want_reply=False: fire-and-forget on close.
    """
    return (bytes([80]) + W.enc_string(b"cancel-tcpip-forward") + W.enc_bool(False) + W.enc_string(bind.encode()) + W.enc_u32(port))


class RemoteForwarder(BaseForwarder):
    """
     Server-side listener relayed to a local target (`ssh -R`).

     The server binds (bind, sport) - sport 0 means auto-assign, the real
     port lands in .port (OpenSSH returns it in REQUEST_SUCCESS). Inbound
     connections arrive as forwarded-tcpip channel opens; each is dialed
     to (rhost, rport) locally and relayed in the background loop.
     Same single-forwarder-per-connection rule as -L (see client).
    """

    def __init__(self, mux, sport: int, rhost: str, rport: int, bind: str = "localhost"):
        super().__init__(mux)
        self._bind = bind
        self._req_port = sport
        self.port = sport
        self._target = (rhost, rport)

    def start(self) -> "RemoteForwarder":
        """
         Register the remote listener. Other channel traffic arriving
         during registration is handled, never dropped.
        """
        self._send(enc_global_tcpip_forward(self._bind, self._req_port))
        deadline = time.monotonic() + self._timeout()
        catch = self._mux.catch_all()
        while True:
            if self._mux.dead:
                raise ForwardError("transport closed during tcpip-forward")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ForwardError(f"tcpip-forward {self._bind}:{self._req_port} timed out")
            try:
                p = catch.get(timeout=min(0.5, remaining))
            except queue.Empty:
                if self._stop.is_set():
                    raise ForwardError("forwarder closing during tcpip-forward")
                continue
            if not isinstance(p, (bytes, bytearray)):
                continue
            r = W.Reader(p)
            try:
                m = r.byte()
            except Exception:
                continue
            if m == 81: # REQUEST_SUCCESS (+optional bound port, OpenSSH sends it)
                try:
                    rr = W.Reader(p)
                    rr.byte()
                    self.port = rr.u32()
                except Exception:
                    pass
                break
            if m == 82:
                raise ForwardError(f"server refused -R {self._bind}:{self._req_port}")
            self._handle(p)
        self._th.start()
        return self

    def close(self) -> None:
        self.closed = True
        self._stop.set()
        try:
            self._send(enc_global_cancel_forward(self._bind, self.port))
        except Exception:
            pass
        self._close_channels()
        # NOTE: the client-owned mux keeps running (exec may continue).
        try:
            if self._th.is_alive():
                self._th.join(timeout=2.0)
        except Exception:
            pass

    def _pump(self) -> None:
        try:
            while not self._stop.is_set():
                if not self._pump_drain_mux():
                    return
                with self._map_lock:
                    chans = [(k, v) for k, v in self._chans.items() if k not in self._eof_local]
                    wlist = [self._chans[k] for k in self._pending_out if k in self._chans]
                    eof_backlog = [k for k in self._eof_local if k in self._chans and self._pending_in.get(k)]
                for my_id in eof_backlog:
                    self._flush_in(my_id)
                if not chans and not wlist:
                    # No channels yet: idle-wait so a dead transport is noticed
                    # via the queue drain above instead of blocking in select.
                    time.sleep(0.05)
                    continue
                try:
                    rd, wr, _ = select.select([s for _, s in chans], wlist, [], 0.2)
                except Exception:
                    if self.closed:
                        return
                    continue
                for s in wr:
                    self._flush_out(s)
                for s in rd:
                    self._on_local(s)
        finally:
            # A dying pump must not strand open sockets/queues behind.
            self._stop.set()
            self._close_channels()

    def _handle(self, p: bytes) -> None:
        r = W.Reader(p)
        try:
            m = r.byte()
        except Exception:
            return
        if m in (2, 4, 81, 82):
            return
        if m == 20:
            raise ForwardError("peer started rekey during forwarding: close it and call rekey()")
        if m == CH.MSG_CHANNEL_OPEN:
            rr = W.Reader(p)
            try:
                rr.byte()
                if rr.string() != b"forwarded-tcpip":
                    self._refuse_open(rr)
                    return
                srv = rr.u32()
                srv_window = rr.u32()
                srv_maxpacket = rr.u32()
                rr.string()
                rr.u32()  # connected host/port (our listener side; informational)
                rr.string()
                rr.u32()  # originator host/port (informational)
            except Exception:
                return
            my_id = self._mux.alloc_chan()
            try:
                tcp = socket.create_connection(self._target, timeout=self._timeout())
            except Exception:
                try:
                    self._send(bytes([CH.MSG_CHANNEL_OPEN_FAILURE])
                               + W.enc_u32(srv)
                               + W.enc_u32(2)
                               + W.enc_string(b"dial failed")
                               + W.enc_string(b""))
                except Exception:
                    pass
                return
            try:
                self._send(bytes([CH.MSG_CHANNEL_OPEN_CONFIRM])
                           + W.enc_u32(srv)
                           + W.enc_u32(my_id)
                           + W.enc_u32(CH.WINDOW)
                           + W.enc_u32(CH.MAXPKT))
            except Exception:
                try:
                    tcp.close()
                except Exception:
                    pass
                return
            self._install_channel(my_id, tcp, srv, srv_window, srv_maxpacket)
            try:
                tcp.setblocking(False)
            except Exception:
                pass
            return
        if m == CH.MSG_CHANNEL_DATA:
            try:
                rcpt, data = r.u32(), r.string()
            except Exception:
                return
            self._on_data(rcpt, data)
            return
        if m == CH.MSG_WINDOW_ADJUST:
            try:
                rcpt, delta = r.u32(), r.u32()
            except Exception:
                return
            self._on_window(rcpt, delta)
            return
        if m == CH.MSG_CHANNEL_EOF:
            try:
                rcpt = r.u32()
            except Exception:
                return
            self._on_remote_eof(rcpt)
            return
        if m == CH.MSG_CHANNEL_CLOSE:
            try:
                rcpt = r.u32()
            except Exception:
                return
            self._on_remote_close(rcpt)
            return

    def _refuse_open(self, rr: W.Reader) -> None:
        try:
            srv = rr.u32()
        except Exception:
            return
        try:
            self._send(bytes([CH.MSG_CHANNEL_OPEN_FAILURE])
                       + W.enc_u32(srv)
                       + W.enc_u32(3)
                       + W.enc_string(b"unsupported channel type")
                       + W.enc_string(b""))
        except Exception:
            pass
