"""
 Channel multiplexer: share one SSH transport between exec/sftp/shell
 channels and port forwarders.

 SSH has a single transport stream, so exactly one thread may read it.
 Without a multiplexer, two concurrent readers (e.g. an exec loop and a
 forwarding pump) steal each other's packets and both stall. The mux owns
 the only reader thread; everyone else consumes per-channel queues:

 * channel messages carrying our channel id go to that channel's queue;
 * ``CHANNEL_SUCCESS``/``CHANNEL_FAILURE`` (99/100, which carry NO channel
   id on the wire) go to the channel with the oldest outstanding channel
   request (see :meth:`expect_reply` - register *before* sending);
 * server-initiated ``CHANNEL_OPEN`` and stray 81/82 go to the catch-all
   queue (port forwarders);
 * ``DISCONNECT``/``KEXINIT`` are broadcast to every queue (in-flight
   operations keep their existing "peer rekey/closed" error paths);
 * ``IGNORE``/``DEBUG`` are skipped, ``GLOBAL_REQUEST`` answered centrally.

 Rekey still needs idle channels (same rule as before): :meth:`busy`
 reports whether any channel is registered. The reader also emits idle
 SSH ``IGNORE`` keepalives so quiet forward-only connections survive.
"""
from __future__ import annotations
import queue
import struct
import threading
import time

from ccssh.transport import CCSSHError, CCSSHTimeoutError, enc_ignore

_DEAD = object() # sentinel: connection died, wake every blocked getter


class ChannelMux:
    """Demultiplex one transport into per-channel queues (sync only)."""

    def __init__(self, transport, *, idle_keepalive: float = 30.0):
        self._t = transport
        self._idle_keepalive = idle_keepalive
        self._lock = threading.Lock()
        self._queues: dict[int, queue.Queue] = {}
        self._catch: queue.Queue = queue.Queue()
        self._expect: list[int] = [] # channels awaiting 99/100, oldest first
        self._stop = threading.Event()
        self._dead = threading.Event()
        self._dead_err: Exception | None = None
        self._paused = threading.Event()
        self._parked = threading.Event()
        # Locks: _lock guards maps/queues; request_lock serialises
        # expect_reply()+send pairs so 99/100 replies cannot be misrouted
        # when two threads set up channels concurrently.
        self.request_lock = threading.Lock()
        self._chan_next = 1
        self._last_io = time.monotonic()
        self._th = threading.Thread(target=self._reader, daemon=True)

    # lifecycle
    def start(self) -> "ChannelMux":
        self._th.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._paused.clear() # let a parked reader observe the stop
        self._die(CCSSHError("multiplexer stopped"))
        th = self._th
        if th.is_alive():
            th.join(timeout=2.0)

    def pause(self) -> None:
        """Park the reader outside any transport read (for rekey).

        Rekey swaps the transport's crypto state mid-stream; a concurrent
        reader would decrypt one half of a packet with the old keys and
        the other half with the new ones. Blocks (bounded) until parked.
        No-op when the reader isn't running yet.
        """
        self._paused.set()
        if not self._th.is_alive():
            # Reader not running (e.g. pause-before-start): just latch the
            # flag; the first loop iteration will park on it.
            return
        try:
            margin = self.timeout
        except Exception:
            margin = 10.0
        deadline = time.monotonic() + max(2.0, margin + 1.0)
        while not self._parked.is_set():
            if self._dead.is_set() or self._stop.is_set():
                break
            if time.monotonic() > deadline:
                raise CCSSHError("timed out parking the mux reader")
            time.sleep(0.01)

    def resume(self) -> None:
        self._paused.clear()
        # The reader may be inside its park-wait: give it a beat to
        # observe the cleared flag and leave the parked state, otherwise
        # a stale parked bit would confuse the next pause().
        deadline = time.monotonic() + 2.0
        while self._parked.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)
        self._parked.clear()

    def busy(self) -> bool:
        """
         Any registered channel queues (open or pending channels).

         A forwarder with zero open channels does not count: its pump only
         consumes mux queues and idle-sends nothing that a rekey could
         corrupt (rekey pauses the reader; sends are atomic per packet).
        """
        with self._lock:
            return bool(self._queues)

    @property
    def dead(self) -> bool:
        return self._dead.is_set()

    # channels
    def register(self, chan_id: int) -> queue.Queue:
        """Create (or reuse) the inbound queue for our channel id."""
        with self._lock:
            q = self._queues.get(chan_id)
            if q is None:
                q = queue.Queue()
                self._queues[chan_id] = q
            return q

    def alloc_chan(self) -> int:
        """
         Allocate a fresh channel id from the single shared namespace.

         All mux users (exec/shell/sftp/tunnels/forwards) must allocate
         here: disjoint local counters would eventually collide on the
         shared queues and misroute packets (channel-confusion).
        """
        with self._lock:
            n = self._chan_next
            self._chan_next = n + 1
            return n

    def _queue_for(self, chan_id: int) -> queue.Queue | None:
        """Queue lookup without creating (for drain loops)."""
        with self._lock:
            return self._queues.get(chan_id)

    def unregister(self, chan_id: int) -> None:
        with self._lock:
            self._queues.pop(chan_id, None)
            self._expect = [c for c in self._expect if c != chan_id]

    def expect_reply(self, chan_id: int) -> None:
        """
         Record an outstanding channel request (call BEFORE sending it,
         so a fast reply can never overtake the registration).
        """
        with self._lock:
            self._expect.append(chan_id)

    def catch_all(self) -> queue.Queue:
        return self._catch

    def send(self, payload: bytes) -> None:
        self._t.send_packet(payload)

    @property
    def timeout(self) -> float:
        try:
            return float(getattr(self._t, "timeout", 10.0))
        except Exception:
            return 10.0

    # consumption
    def _raise_if_dead(self) -> None:
        if self._dead.is_set():
            raise CCSSHError(str(self._dead_err or "connection closed by peer"))

    def recv_chan(self, chan_id: int, timeout: float | None = None) -> bytes:
        """Next packet for a channel (None timeout blocks until it arrives
        or the connection dies; a numeric timeout raises
        CCSSHTimeoutError like a direct transport read)."""
        with self._lock:
            q = self._queues.get(chan_id)
        if q is None:
            raise CCSSHError(f"channel {chan_id} is not registered with the mux")
        while True:
            try:
                p = q.get(timeout=timeout)
            except queue.Empty:
                self._raise_if_dead()
                raise CCSSHTimeoutError("channel read timeout")
            if p is _DEAD:
                # Re-queue for any other getter on this channel, then fail.
                try:
                    q.put(_DEAD)
                except Exception:
                    pass
                self._raise_if_dead()
                raise CCSSHError("connection closed by peer")
            return p

    # the only transport reader
    def _die(self, err: Exception) -> None:
        with self._lock:
            if self._dead.is_set():
                return
            self._dead_err = err
            self._dead.set()
            targets = list(self._queues.values()) + [self._catch]
        for q in targets:
            try:
                q.put(_DEAD)
            except Exception:
                pass

    def _broadcast(self, p: bytes) -> None:
        with self._lock:
            targets = list(self._queues.values()) + [self._catch]
        for q in targets:
            try:
                q.put(p)
            except Exception:
                pass

    def _route(self, p: bytes) -> None:
        # NB: IGNORE/DEBUG/GLOBAL_REQUEST never reach here: the reader uses
        # transport.recv_packet(), which skips and answers them centrally.
        if not p:
            return
        m = p[0]
        if m in (1, 20): # DISCONNECT, KEXINIT: everyone must see these
            self._broadcast(p)
            if m == 1:
                self._die(CCSSHError("connection closed by peer"))
            return
        if m in (99, 100):  # SUCCESS/FAILURE carry no channel id
            with self._lock:
                chan = self._expect.pop(0) if self._expect else None
                q = self._queues.get(chan) if chan is not None else None
            if q is not None:
                try:
                    q.put(p)
                except Exception:
                    pass
            return
        if m == 90:
            # Server-initiated open (forwarded-tcpip): p[1:5] is the type
            # string length, NOT a channel id - always to catch-all.
            try:
                self._catch.put(p)
            except Exception:
                pass
            return
        if len(p) >= 5 and m in (91, 92, 93, 94, 95, 96, 97, 98):
            try:
                (rcpt,) = struct.unpack(">I", p[1:5])
            except Exception:
                return
            with self._lock:
                q = self._queues.get(rcpt)
            if q is not None:
                try:
                    q.put(p)
                except Exception:
                    pass
            # anything else for an unknown/stale channel is dropped
            return
        try:
            self._catch.put(p)
        except Exception:
            pass

    def _reader(self) -> None:
        while not self._stop.is_set():
            if self._paused.is_set():
                self._parked.set()
                self._paused.wait(0.5)
                continue
            self._parked.clear()
            try:
                p = self._t.recv_packet(keepalive=False)
            except CCSSHTimeoutError:
                if self._idle_keepalive > 0 and not self._stop.is_set() \
                        and time.monotonic() - self._last_io >= self._idle_keepalive:
                    try:
                        self.send(enc_ignore())
                    except Exception:
                        self._die(CCSSHError("connection closed by peer"))
                        return
                    self._last_io = time.monotonic()
                continue
            except Exception as e:
                self._die(e)
                return
            self._last_io = time.monotonic()
            try:
                self._route(p)
            except Exception:
                pass
