"""
 Local (-L), dynamic (-D, SOCKS) and remote (-R) TCP forwarding over SSH
 channels, plus server-initiated relays (X11, ssh-agent).

 The forwarders share the connection through the channel multiplexer
 (:class:`ccssh.mux.ChannelMux`), ssh-like: exec/sftp/shell may run on
 the same connection while forwarding is active. Each forwarder runs one
 pump thread that multiplexes local sockets and its mux queues; the mux
 owns the only transport reader, so concurrent channels never interleave
 the framing (the pre-mux single-reader deadlock is gone by construction:
 no lock is ever held across a blocking receive).

 Server-initiated channel types (`forwarded-tcpip`, `x11`,
 `auth-agent@openssh.com`) each get a dedicated mux inbound queue (see
 ``ChannelMux.register_inbound``), so a remote (-R) forwarder, an X11
 forwarder and an agent forwarder share one connection without stealing
 each other's opens. Unexpected channel types land in the catch-all and
 are refused (never silently dropped).

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
        """Drain our channel queues + inbound/type queues + catch-all once."""
        with self._map_lock:
            chan_ids = list(self._chans)
        catch = self._mux.catch_all()
        queues = []
        for k in chan_ids:
            q = self._mux._queue_for(k)
            if q is not None:
                queues.append(q)
        for q in queues + self._extra_queues() + [catch]:
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

    def _extra_queues(self) -> list:
        """Dedicated inbound queues (server-initiated opens by type)."""
        return []

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
        self._inbound_q = None

    def _extra_queues(self) -> list:
        return [self._inbound_q] if self._inbound_q is not None else []

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
            if p and p[0] == 90:
                # A sibling inbound forwarder (x11/agent) may already be up:
                # hand its opens to the typed queues instead of refusing.
                # (Falls through to _handle when nobody registered them.)
                from ccssh.mux import ChannelMux as _Mux
                ctype = _Mux._open_type(bytes(p))
                if ctype in (b"x11", b"auth-agent@openssh.com") \
                        and ctype in getattr(self._mux, "_inbound", {}):
                    try:
                        self._mux._route(bytes(p))
                    except Exception:
                        pass
                    continue
            self._handle(p)
        self._inbound_q = self._mux.register_inbound(b"forwarded-tcpip")
        self._th.start()
        return self

    def close(self) -> None:
        self.closed = True
        self._stop.set()
        try:
            self._mux.unregister_inbound(b"forwarded-tcpip")
        except Exception:
            pass
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


def _recvn_sock(s: socket.socket, n: int, timeout: float) -> bytes:
    """Read exactly n bytes from a (blocking) socket, bounded."""
    import time as _time
    out = b""
    deadline = _time.monotonic() + timeout
    while len(out) < n:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            raise ForwardError("SOCKS handshake timed out")
        s.settimeout(remaining)
        try:
            chunk = s.recv(n - len(out))
        except socket.timeout as e:
            raise ForwardError(f"SOCKS handshake timed out: {e}") from e
        if not chunk:
            raise ForwardError("SOCKS client closed the connection")
        out += chunk
    return out


class DynamicForwarder(BaseForwarder):
    """
     Dynamic forwarding (`ssh -D`): a local SOCKS listener.

     Each accepted connection performs a SOCKS4/4a/5 handshake locally;
     the requested host:port becomes one `direct-tcpip` channel through
     the server (which resolves and dials it). Only TCP CONNECT is
     supported, like OpenSSH; anything else is refused cleanly.
    """

    def __init__(self, mux, lport: int, bind: str = "127.0.0.1"):
        super().__init__(mux)
        self._bind = bind
        self._ls = _listen(bind, lport)
        self.port = self._ls.getsockname()[1]

    def start(self) -> "DynamicForwarder":
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
        from ccssh import socks as _socks
        timeout = self._timeout()
        try:
            target, ver = self._socks_handshake(conn, timeout)
        except Exception:
            raise
        try:
            peer = conn.getpeername()
        except Exception:
            peer = ("127.0.0.1", 0)
        # Channel ids come from the single mux-shared namespace (same rule
        # as -L: disjoint local counters would collide and misroute).
        my_id = self._mux.alloc_chan()
        with self._map_lock:
            pend = _PendingOpen()
            self._pending[my_id] = pend
        self._send(CH.enc_open_direct_tcpip(my_id, target[0], target[1],
                                            orig_host=peer[0], orig_port=peer[1]))
        try:
            self._wait_pending(my_id, pend, timeout)
        except Exception:
            with self._map_lock:
                self._pending.pop(my_id, None)
            try:
                self._mux.unregister(my_id)
            except Exception:
                pass
            try:
                conn.sendall(_socks.s5_reply_fail() if ver == 5 else _socks.s4_reply_fail())
            except Exception:
                pass
            raise
        assert pend.srv is not None
        self._install_channel(my_id, conn, pend.srv, pend.window, pend.maxpacket)
        try:
            conn.sendall(_socks.s5_reply_ok() if ver == 5 else _socks.s4_reply_ok())
        except Exception:
            self._drop(my_id)
            raise ForwardError("SOCKS reply send failed")
        try:
            conn.setblocking(False)
        except Exception:
            pass

    def _socks_handshake(self, conn: socket.socket, timeout: float) -> tuple[tuple[str, int], int]:
        """SOCKS4/4a/5 handshake. Returns ((host, port), version)."""
        from ccssh import socks as _socks
        first = _recvn_sock(conn, 2, timeout)
        if first[0] == 0x05:
            nmethods = first[1]
            if nmethods == 0 or nmethods > 255:
                raise ForwardError("bad SOCKS5 method count")
            methods = _recvn_sock(conn, nmethods, timeout)
            try:
                reply, ok = _socks.greeting_reply(first + methods)
            except _socks.SocksError as e:
                raise ForwardError(f"SOCKS5 greeting rejected: {e}") from e
            try:
                conn.sendall(reply)
            except Exception as e:
                raise ForwardError(f"SOCKS5 greeting reply failed: {e}") from e
            if not ok:
                raise ForwardError("SOCKS5 client offered no acceptable auth method")
            hdr = _recvn_sock(conn, 4, timeout)
            atyp = hdr[3]
            if atyp == _socks.S5_ATYP_V4:
                rest = _recvn_sock(conn, 6, timeout)
                req = hdr + rest
            elif atyp == _socks.S5_ATYP_DOMAIN:
                ln = _recvn_sock(conn, 1, timeout)[0]
                if ln == 0 or ln > _socks.MAX_DOMAIN:
                    raise ForwardError("bad SOCKS5 domain length")
                rest = _recvn_sock(conn, ln + 2, timeout)
                req = hdr + bytes([ln]) + rest
            elif atyp == _socks.S5_ATYP_V6:
                rest = _recvn_sock(conn, 18, timeout)
                req = hdr + rest
            else:
                try:
                    conn.sendall(_socks.s5_reply_fail(_socks.S5_REP_CMD))
                except Exception:
                    pass
                raise ForwardError(f"unsupported SOCKS5 address type {atyp}")
            try:
                host, port = _socks.parse_s5_request(req)
            except _socks.SocksError as e:
                try:
                    conn.sendall(_socks.s5_reply_fail())
                except Exception:
                    pass
                raise ForwardError(f"bad SOCKS5 request: {e}") from e
            return (host, port), 5
        if first[0] == 0x04:
            if first[1] != 0x01:
                try:
                    conn.sendall(_socks.s4_reply_fail())
                except Exception:
                    pass
                raise ForwardError(f"unsupported SOCKS4 command {first[1]}")
            rest = _recvn_sock(conn, 6, timeout)
            head = first + rest
            # USERID (NUL-terminated, capped) + optional SOCKS4a hostname.
            userid = b""
            while True:
                b = _recvn_sock(conn, 1, timeout)
                if b == b"\x00":
                    break
                userid += b
                if len(userid) > _socks.MAX_DOMAIN:
                    raise ForwardError("SOCKS4 userid too long")
            req = head + userid + b"\x00"
            if head[4:7] == b"\x00\x00\x00" and head[7] != 0:
                domain = b""
                while True:
                    b = _recvn_sock(conn, 1, timeout)
                    if b == b"\x00":
                        break
                    domain += b
                    if len(domain) > _socks.MAX_DOMAIN:
                        raise ForwardError("SOCKS4a hostname too long")
                req += domain + b"\x00"
            try:
                host, port = _socks.parse_s4_request(req)
            except _socks.SocksError as e:
                try:
                    conn.sendall(_socks.s4_reply_fail())
                except Exception:
                    pass
                raise ForwardError(f"bad SOCKS4 request: {e}") from e
            return (host, port), 4
        raise ForwardError(f"unknown SOCKS version {first[0]}")

    def _handle(self, p: bytes) -> None:
        # Same channel traffic as -L (client-initiated direct-tcpip only).
        r = W.Reader(p)
        try:
            m = r.byte()
        except Exception:
            return
        if m in (2, 4, 20, 80, 81, 82):
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
            # Dynamic (-D) never expects server-initiated opens: refuse so
            # the peer doesn't hang (same rule as -L).
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


class _ServerBoundRelay(BaseForwarder):
    """
     Shared pump for server-initiated channel relays (remote -R, x11,
     ssh-agent): each inbound open is dialed to a local target (TCP host,
     X display, agent socket) and relayed. Subclasses define CTYPE,
     _parse_open() and _dial().
    """

    #: Channel type this relay serves (b"forwarded-tcpip" etc.).
    CTYPE: bytes = b""

    def _extra_queues(self) -> list:
        q = getattr(self, "_inbound_q", None)
        return [q] if q is not None else []

    def start(self) -> "_ServerBoundRelay":
        self._inbound_q = self._mux.register_inbound(self.CTYPE)
        self._th.start()
        return self

    def close(self) -> None:
        self.closed = True
        self._stop.set()
        try:
            if self.CTYPE:
                self._mux.unregister_inbound(self.CTYPE)
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

    def _parse_open(self, p: bytes):
        """Return (server_chan, window, maxpacket) or None to refuse."""
        raise NotImplementedError

    def _dial(self):
        """Connect to the local target. Returns a socket."""
        raise NotImplementedError

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
            parsed = self._parse_open(p)
            if parsed is None:
                return  # refusal already sent by the parser
            srv, srv_window, srv_maxpacket = parsed
            try:
                target = self._dial()
            except Exception:
                try:
                    self._send(CH.enc_open_failure(srv, 2, b"dial failed"))
                except Exception:
                    pass
                return
            my_id = self._mux.alloc_chan()
            try:
                self._send(CH.enc_open_confirm(srv, my_id))
            except Exception:
                try:
                    target.close()
                except Exception:
                    pass
                return
            self._install_channel(my_id, target, srv, srv_window, srv_maxpacket)
            try:
                target.setblocking(False)
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


class AgentForwarder(_ServerBoundRelay):
    """
     ssh-agent forwarding (`ssh -A`): relay each server-opened
     ``auth-agent@openssh.com`` channel to the local agent socket.
    """

    CTYPE = b"auth-agent@openssh.com"

    def __init__(self, mux, agent_path: str | None = None):
        super().__init__(mux)
        from ccssh import agent as _agent_mod
        resolved = agent_path or _agent_mod.default_agent_path()
        if not resolved:
            raise ForwardError("agent forwarding needs SSH_AUTH_SOCK or an explicit agent_path")
        self._agent_path = resolved

    def _parse_open(self, p: bytes):
        from ccssh import agent as _agent_mod
        try:
            srv = _agent_mod.dec_agent_open(p)
        except _agent_mod.AgentError:
            return None
        try:
            r = W.Reader(p)
            r.byte()
            r.string()
            r.u32()
            window = r.u32()
            maxpacket = r.u32()
        except Exception:
            return None
        return srv, window, maxpacket

    def _dial(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(self._timeout())
            s.connect(self._agent_path)
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            raise
        return s


class X11Forwarder(_ServerBoundRelay):
    """
     X11 forwarding (`ssh -X`/`ssh -Y`): relay each server-opened ``x11``
     channel to the real local X server.
    """

    CTYPE = b"x11"

    def __init__(self, mux, display: str | None = None):
        super().__init__(mux)
        from ccssh import x11 as _x11_mod
        # Like OpenSSH ("No xauth data; using fake authentication data"):
        # a missing/unparseable DISPLAY never fails the login. The session
        # still gets x11-req with a fresh fake cookie; each inbound x11
        # channel that cannot be relayed is refused individually.
        try:
            _host, _disp, screen = _x11_mod.parse_display(display)
            self.display_ok = True
        except _x11_mod.X11Error:
            screen = 0
            self.display_ok = False
        self._display = display
        self.screen = screen
        self.cookie = _x11_mod.gen_cookie()

    def _parse_open(self, p: bytes):
        from ccssh import x11 as _x11_mod
        try:
            _x11_mod.dec_x11_open(p)
        except _x11_mod.X11Error:
            return None
        try:
            r = W.Reader(p)
            r.byte()
            r.string()
            srv = r.u32()
            window = r.u32()
            maxpacket = r.u32()
        except Exception:
            return None
        return srv, window, maxpacket

    def _dial(self):
        from ccssh import x11 as _x11_mod
        return _x11_mod.dial_display(self._display, timeout=self._timeout())
