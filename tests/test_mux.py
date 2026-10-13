"""ChannelMux unit tests: routing, request correlation, broadcast, death."""
from __future__ import annotations
import queue
import struct
import threading
import time

import pytest

from ccssh import wire as W
from ccssh.mux import ChannelMux
from ccssh.transport import CCSSHError, CCSSHTimeoutError


class FakeTransport:
    """Scripted transport: recv_packet pops, send_packet records."""

    def __init__(self, packets, timeout: float = 5.0):
        self.q: queue.Queue = queue.Queue()
        for p in packets:
            self.q.put(p)
        self.sent: list[bytes] = []
        self.timeout = timeout
        self._lock = threading.Lock()

    def recv_packet(self, keepalive=True):
        try:
            p = self.q.get(timeout=0.2)
        except queue.Empty:
            raise CCSSHTimeoutError("t/o")
        if isinstance(p, Exception):
            raise p
        return p

    def send_packet(self, payload: bytes) -> None:
        with self._lock:
            self.sent.append(payload)


def _chan(m: int, rcpt: int, body: bytes = b"") -> bytes:
    return bytes([m]) + W.enc_u32(rcpt) + body


def test_routes_by_recipient():
    t = FakeTransport([_chan(94, 7, W.enc_string(b"a")), _chan(94, 9, W.enc_string(b"b"))])
    mux = ChannelMux(t)
    mux.register(7)
    mux.register(9)
    mux.start()
    try:
        assert mux.recv_chan(7, timeout=2)[0] == 94
        assert mux.recv_chan(9, timeout=2)[0] == 94
    finally:
        mux.stop()


def test_success_goes_to_expecting_channel():
    t = FakeTransport([bytes([99]), bytes([100])])
    mux = ChannelMux(t)
    mux.register(3)
    mux.register(5)
    mux.expect_reply(5)
    mux.expect_reply(3)
    mux.start()
    try:
        assert mux.recv_chan(5, timeout=2) == bytes([99]) # oldest expectation first
        assert mux.recv_chan(3, timeout=2) == bytes([100])
    finally:
        mux.stop()


def test_success_without_expectation_dropped():
    t = FakeTransport([bytes([99])])
    mux = ChannelMux(t).start()
    try:
        mux.register(3)
        with pytest.raises(CCSSHTimeoutError):
            mux.recv_chan(3, timeout=0.3)
    finally:
        mux.stop()


def test_kex_and_disconnect_broadcast():
    t = FakeTransport([bytes([20]) + b"\x00" * 8])
    mux = ChannelMux(t)
    mux.register(3)
    mux.register(5)
    mux.start()
    try:
        assert mux.recv_chan(3, timeout=2)[0] == 20
        assert mux.recv_chan(5, timeout=2)[0] == 20
    finally:
        mux.stop()


def test_server_open_goes_to_catch_all():
    pkt = bytes([90]) + W.enc_string(b"forwarded-tcpip") + W.enc_u32(11)
    t = FakeTransport([pkt])
    mux = ChannelMux(t).start()
    try:
        mux.register(3)
        got = mux.catch_all().get(timeout=2)
        assert got[0] == 90
        with pytest.raises(CCSSHTimeoutError):
            mux.recv_chan(3, timeout=0.2)
    finally:
        mux.stop()


def test_global_request_stays_with_transport():
    # The transport's recv_packet() answers GLOBAL_REQUEST centrally, so
    # the mux never sees one in production; fed one directly it stays
    # silent (no double answers on the wire).
    glob = bytes([80]) + W.enc_string(b"hostkeys-00@openssh.com") + W.enc_bool(True)
    t = FakeTransport([glob])
    mux = ChannelMux(t)
    mux.start()
    try:
        mux._route(glob)
        time.sleep(0.2)
        assert t.sent == []
    finally:
        mux.stop()


def test_dead_transport_wakes_blocked_getters():
    t = FakeTransport([CCSSHError("boom")])
    mux = ChannelMux(t)
    mux.register(3)
    mux.start()
    try:
        with pytest.raises(CCSSHError):
            mux.recv_chan(3, timeout=5)
    finally:
        mux.stop()


def test_stop_wakes_getters_instead_of_hanging():
    t = FakeTransport([])
    mux = ChannelMux(t)
    mux.register(3)
    mux.start()
    try:
        errs = []

        def getter():
            try:
                mux.recv_chan(3) # blocks forever without the sentinel
            except CCSSHError as e:
                errs.append(e)

        th = threading.Thread(target=getter, daemon=True)
        th.start()
        time.sleep(0.2)
        mux.stop()
        th.join(timeout=3)
        assert errs and not th.is_alive()
    finally:
        mux.stop()


def test_unregister_forgets_channel_and_expectations():
    t = FakeTransport([_chan(94, 7)])
    mux = ChannelMux(t).start()
    try:
        mux.register(7)
        mux.expect_reply(7)
        mux.unregister(7)
        assert not mux.busy()
        with pytest.raises(CCSSHError, match="not registered"):
            mux.recv_chan(7, timeout=0.2)
    finally:
        mux.stop()


def test_unknown_recipient_dropped():
    t = FakeTransport([_chan(94, 4242, W.enc_string(b"ghost"))])
    mux = ChannelMux(t)
    mux.register(7)
    mux.start()
    try:
        with pytest.raises(CCSSHTimeoutError):
            mux.recv_chan(7, timeout=0.3)
        assert mux.catch_all().empty()
    finally:
        mux.stop()


def test_pause_parks_reader_outside_reads():
    t = FakeTransport([])
    mux = ChannelMux(t).start()
    try:
        mux.pause() # no traffic: parks immediately
        assert mux._parked.is_set()
        mux.resume()
        assert not mux._parked.is_set()
        mux.pause()
        mux.resume()
    finally:
        mux.stop()


def test_pause_blocks_routing_until_resume():
    t = FakeTransport([_chan(94, 7, W.enc_string(b"held"))])
    mux = ChannelMux(t)
    mux.register(7)
    mux.pause() # park before the reader ever reads: fully deterministic
    mux.start()
    try:
        time.sleep(0.3)
        assert mux._parked.is_set()
        # packet still queued server-side (reader parked): nothing routed yet
        with pytest.raises(CCSSHTimeoutError):
            mux.recv_chan(7, timeout=0.2)
        mux.resume()
        assert mux.recv_chan(7, timeout=2)[0] == 94
    finally:
        mux.stop()
