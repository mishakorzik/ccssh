"""
 SFTP version 3 client (draft-ietf-secsh-filexfer-02): stat, list, get, put,
 remove, mkdir over a subsystem channel.

 SFTP packets may straddle SSH channel messages, so responses accumulate in
 a length-prefixed buffer. Each request goes out as a single CHANNEL_DATA
 message within the server's maxpacket (servers drop oversized ones).
"""
from __future__ import annotations

from ccssh import wire as W

# Message types.
F_INIT, F_VERSION = 1, 2
F_OPEN, F_CLOSE, F_READ, F_WRITE = 3, 4, 5, 6
F_OPENDIR, F_READDIR = 11, 12
F_REMOVE, F_MKDIR = 13, 14
F_REALPATH, F_STAT = 16, 17
F_HANDLE, F_DATA, F_NAME, F_ATTRS, F_STATUS = 102, 103, 104, 105, 101

# Status codes.
S_OK, S_EOF = 0, 1
S_NO_SUCH_FILE, S_FAILURE = 2, 4
S_OP_UNSUPPORTED = 8

# OPEN pflags.
P_READ, P_WRITE, P_APPEND, P_CREAT, P_TRUNC, P_EXCL = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

# Attribute flags.
A_SIZE, A_PERM, A_ACMOD = 0x01, 0x04, 0x08
A_EXTENDED = 0x80000000

CHUNK = 32768


class SFTPError(ValueError):
    pass


def _req(t: int, rid: int, body: bytes) -> bytes:
    return W.enc_u32(1 + 4 + len(body)) + bytes([t]) + W.enc_u32(rid) + body


def _dec_attrs_reader(r: W.Reader) -> dict:
    fl = r.u32()
    out: dict = {}
    if fl & A_SIZE:
        out["size"] = r.u64()
    if fl & 0x02:
        out["uid"], out["gid"] = r.u32(), r.u32()
    if fl & A_PERM:
        out["permissions"] = r.u32()
    if fl & A_ACMOD:
        out["atime"], out["mtime"] = r.u32(), r.u32()
    if fl & A_EXTENDED:
        n = r.u32()
        if n > 64:
            raise SFTPError("too many extended attrs")
        for _ in range(n):
            r.string()
            r.string()
    return out


def dec_attrs(buf: bytes) -> dict:
    return _dec_attrs_reader(W.Reader(buf))


class SFTPClient:
    """An open SFTP channel. Use CCSSHClient.open_sftp()."""

    """
     Upper bound on one SFTP reply (length prefix). Our own requests are
     small (reads are <= maxpacket); anything bigger is a malicious or
     broken server - fail instead of buffering it into memory.
    """
    MAX_REPLY = 1024 * 1024

    def __init__(self, send_chan_data, recv_packet_fn, server_chan: int, on_close=None, maxpacket: int = 32768):
        self._send = send_chan_data # fn(server_chan, bytes)
        self._recv = recv_packet_fn # fn() -> channel-data bytes (one message)
        self._srv = server_chan
        self._on_close = on_close
        """
         Servers drop CHANNEL_DATA beyond their maxpacket ("rcvd big packet"),
         so every request goes out as one message within maxpacket.
        """
        self._maxpacket = max(1024, maxpacket)
        self._rid = 1
        self._buf = b""
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._on_close:
            self._on_close()

    def _call(self, ftype: int, body: bytes) -> tuple[int, bytes]:
        rid = self._rid & 0xFFFFFFFF
        if rid == 0:  # 0 is never used on the wire: skip it explicitly
            rid = 1
            self._rid = 2
        else:
            self._rid += 1
        req = _req(ftype, rid, body)
        if len(req) > self._maxpacket:
            raise SFTPError("sftp request exceeds server maxpacket")
        self._send(self._srv, req)
        while True:
            data = self._recv()
            self._buf += data
            if len(self._buf) > 2 * self.MAX_REPLY + 4:
                # Pipelined/garbage bytes beyond any single reply: fail
                # closed instead of buffering a runaway server into OOM.
                try:
                    self.close()
                except Exception:
                    pass
                raise SFTPError("sftp: reply buffer exceeded")
            if len(self._buf) < 4:
                continue
            ln = int.from_bytes(self._buf[:4], "big")
            if ln > self.MAX_REPLY:
                raise SFTPError(f"sftp: reply too big ({ln} bytes)")
            if len(self._buf) < 4 + ln:
                continue
            pkt, self._buf = self._buf[4:4 + ln], self._buf[4 + ln:]
            r = W.Reader(pkt)
            rt, rr = r.byte(), r.u32()
            if rr != rid:
                # Desynchronised stream: fail closed, do not continue on a
                # half-consumed buffer.
                try:
                    self.close()
                except Exception:
                    pass
                raise SFTPError(f"sftp: id mismatch {rr}!={rid}")
            return rt, pkt[5:]

    def _check(self, rtype: int, rest: bytes, want: int) -> bytes:
        if rtype == F_STATUS:
            r = W.Reader(rest)
            code = r.u32()
            msg = r.string().decode(errors="replace")
            if code != S_OK:
                raise SFTPError(f"sftp status {code}: {msg}")
            return b""
        if rtype != want:
            raise SFTPError(f"sftp: expected {want}, got {rtype}")
        return rest

    def realpath(self, path: str) -> str:
        t, rest = self._call(F_REALPATH, W.enc_string(path.encode()))
        r = W.Reader(self._check(t, rest, F_NAME))
        r.u32() # count, always 1 here
        return r.string().decode()

    def stat(self, path: str) -> dict:
        t, rest = self._call(F_STAT, W.enc_string(path.encode()))
        return dec_attrs(self._check(t, rest, F_ATTRS))

    def listdir(self, path: str, *, max_entries: int = 50000) -> list[str]:
        t, rest = self._call(F_OPENDIR, W.enc_string(path.encode()))
        handle = W.Reader(self._check(t, rest, F_HANDLE)).string()
        out: list[str] = []
        out_bytes = 0
        try:
            while True:
                t2, r2 = self._call(F_READDIR, W.enc_string(handle))
                if t2 == F_STATUS:
                    r = W.Reader(r2)
                    if r.u32() == S_EOF:
                        break
                    raise SFTPError("readdir failed")
                r = W.Reader(self._check(t2, r2, F_NAME))
                n = r.u32()
                if n > 1024:
                    raise SFTPError("readdir count too large")
                for _ in range(n):
                    name = r.string().decode()
                    r.string() # longname
                    _dec_attrs_reader(r)
                    out_bytes += len(name.encode())
                    if len(out) >= max_entries or out_bytes > 4 * 1024 * 1024:
                        raise SFTPError("directory listing too large")
                    out.append(name)
        finally:
            try:
                self._call(F_CLOSE, W.enc_string(handle))
            except Exception:
                pass # never mask the original error with a close failure
        return out

    def _open(self, path: str, pflags: int) -> bytes:
        t, rest = self._call(F_OPEN, W.enc_string(path.encode()) + W.enc_u32(pflags) + W.enc_u32(0))
        return W.Reader(self._check(t, rest, F_HANDLE)).string()

    def _close(self, handle: bytes) -> None:
        t, rest = self._call(F_CLOSE, W.enc_string(handle))
        if t == F_STATUS:
            r = W.Reader(rest)
            if r.u32() != S_OK:
                raise SFTPError("close failed")

    def get(self, path: str, *, max_bytes: int | None = 1 << 30) -> bytes:
        """
         Download a whole file. A server error mid-transfer raises
         (never silent truncation); max_bytes caps a runaway server
         (None disables the cap).
        """
        h = self._open(path, P_READ)
        chunks: list[bytes] = []
        off = 0
        try:
            while True:
                t, rest = self._call(F_READ, W.enc_string(h) + W.enc_u64(off) + W.enc_u32(CHUNK))
                if t == F_STATUS:
                    r = W.Reader(rest)
                    if r.u32() == S_EOF:
                        break
                    raise SFTPError(f"read failed: {r.string().decode(errors='replace')}")
                data = W.Reader(self._check(t, rest, F_DATA)).string()
                if not data:
                    break
                chunks.append(data)
                off += len(data)
                if max_bytes is not None and off > max_bytes:
                    raise SFTPError(f"file exceeds max_bytes={max_bytes}")
        finally:
            try:
                self._close(h)
            except Exception:
                pass # never mask the transfer error with a close failure
        return b"".join(chunks)

    def put(self, path: str, data: bytes, *, mode: int = 0o644) -> None:
        attrs = W.enc_u32(A_PERM) + W.enc_u32(mode)
        t, rest = self._call(F_OPEN, W.enc_string(path.encode()) + W.enc_u32(P_WRITE | P_CREAT | P_TRUNC) + attrs)
        h = W.Reader(self._check(t, rest, F_HANDLE)).string()
        if not data:
            # Empty file: OPEN|TRUNC already truncated it; no zero-WRITE.
            self._close(h)
            return
        wchunk = max(1024, self._maxpacket - 128)
        try:
            off = 0
            while off < len(data):
                chunk = data[off:off + wchunk]
                t2, r2 = self._call(F_WRITE, W.enc_string(h) + W.enc_u64(off) + W.enc_string(chunk))
                if t2 == F_STATUS:
                    r = W.Reader(r2)
                    if r.u32() != S_OK:
                        raise SFTPError("write failed")
                off += len(chunk)
        finally:
            try:
                self._close(h)
            except Exception:
                pass # never mask the transfer error with a close failure

    def remove(self, path: str) -> None:
        t, rest = self._call(F_REMOVE, W.enc_string(path.encode()))
        self._check(t, rest, F_STATUS)

    def mkdir(self, path: str, *, mode: int = 0o755) -> None:
        attrs = W.enc_u32(A_PERM) + W.enc_u32(mode)
        t, rest = self._call(F_MKDIR, W.enc_string(path.encode()) + attrs)
        self._check(t, rest, F_STATUS)
