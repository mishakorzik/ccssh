"""
 SSH binary packet transports: blocking sockets (sync) and asyncio (async).

 Cipher coverage: AES-CTR with HMAC (plain and -etm), AES-GCM (RFC 5647),
 chacha20-poly1305 (IETF draft). Compression: zlib / zlib@openssh.com
 (RFC 4253 section 6.2, delayed draft) - only the payload is compressed,
 after auth (delayed) or after NEWKEYS (legacy zlib), with per-direction
 stateful streams and Z_PARTIAL_FLUSH per packet (see ccssh.compress).
 Framing notes:

 * non-ETM CTR encrypts length + payload; MAC over sequence + plaintext.
 * ETM (see OpenSSH packet.c, aadlen=4): length travels in the CLEAR,
  the CTR stream does not cover it, MAC over sequence + length + ciphertext,
  padding excludes the length field.
 * GCM/ChaCha behave like ETM (length in clear/separate, tag over it + CT).
 * Before NEWKEYS everything is plaintext without MAC.
 * With compression, packet_length/MAC are computed from the COMPRESSED
  payload; encryption happens after compression (and decryption before
  decompression).
"""
from __future__ import annotations
import asyncio
import socket
import struct
import threading
import time
import hmac as pyhmac
from typing import TYPE_CHECKING

from ccssh import chacha as _chacha_mod
from ccssh import gcm as _gcm_mod
from ccssh import wire as _wire
from ccssh.crypto import (
    AesCtrHmacCtx,
    CBC_SPECS,
    CIPHER_SPECS,
    CbcHmacCtx,
    build_aad_block,
    build_unencrypted_block,
)

if TYPE_CHECKING:
    from ccssh.chansock import StreamSocket

GCM_CIPHERS = ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com")
CHACHA_CIPHER = "chacha20-poly1305@openssh.com"
MAX_PACKET = 35000


def _new_compressor(level: int):
    from ccssh import compress as _comp_mod
    return _comp_mod.Compressor(level)


def _new_decompressor():
    from ccssh import compress as _comp_mod
    return _comp_mod.Decompressor()


class CCSSHError(Exception):
    pass


class CCSSHTimeoutError(CCSSHError):
    """
     A socket read timed out. Subclass of CCSSHError, so existing handlers
     keep working; catch it separately only to tell idleness from failure.
    """


def enc_ignore(data: bytes = b"") -> bytes:
    """
     SSH_MSG_IGNORE (RFC 4253 section 11.1). Every peer MUST ignore it;
     used as a keepalive that also defeats idle NAT timeouts.
    """
    return bytes([2]) + _wire.enc_string(data)


def _global_success(name: bytes) -> bytes:
    """
     GLOBAL_REQUEST reply: hostkeys-00 and keepalive probes succeed (81),
     everything else fails (82). Shared by both transports and the mux.
    """
    ok = name in (b"hostkeys-00@openssh.com", b"keepalive@openssh.com")
    return bytes([81]) if ok else bytes([82])


def _recvn_blocking(sock: socket.socket, n: int, timeout: float, buf: bytearray) -> bytes:
    """
     Read exactly n bytes, keeping partial progress in `buf`.

     The buffer belongs to the transport and survives timeouts: a slow
     drip-feed must not lose bytes (that would desync the framing), it
     only costs extra keepalive rounds. Exactly n bytes are consumed.
    """
    deadline = time.monotonic() + timeout
    try:
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CCSSHTimeoutError("socket read timeout")
            try:
                sock.settimeout(remaining)
                ch = sock.recv(n - len(buf))
            except (TimeoutError, socket.timeout) as e:
                raise CCSSHTimeoutError("socket read timeout") from e
            if not ch:
                raise CCSSHError("connection closed by peer")
            buf += ch
    finally:
        # Always restore the steady-state timeout: a read timeout must not
        # leave a ~0 timeout behind that breaks the next send/recv.
        try:
            sock.settimeout(timeout)
        except Exception:
            pass
    out = bytes(buf[:n])
    del buf[:n]
    return out


async def _recvn_async(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
    try:
        if hasattr(asyncio, "timeout"):
            async with asyncio.timeout(timeout):
                return await reader.readexactly(n)
        return await asyncio.wait_for(reader.readexactly(n), timeout)
    except asyncio.IncompleteReadError as e:
        raise CCSSHError("connection closed by peer (async)") from e
    except (asyncio.TimeoutError, TimeoutError) as e:
        raise CCSSHTimeoutError("socket read timeout (async)") from e


def _check_padding(pad: int, pl: int) -> None:
    """
     RFC 4253 section 6: 4 <= pad, and at least 1 payload byte
     (packet_length = 1 + payload + pad, so pad + 2 <= pl).
    """
    if pad < 4 or pad + 2 > pl:
        raise CCSSHError(f"bad padding (pad={pad} pl={pl})")


def _new_ctr_pair(cipher: str, mac: str, keys: dict[str, bytes], *, is_client: bool):
    if is_client:
        s = AesCtrHmacCtx(cipher, mac, keys["enc_c2s"], keys["iv_c2s"], keys["mac_c2s"])
        r = AesCtrHmacCtx(cipher, mac, keys["enc_s2c"], keys["iv_s2c"], keys["mac_s2c"])
    else:
        s = AesCtrHmacCtx(cipher, mac, keys["enc_s2c"], keys["iv_s2c"], keys["mac_s2c"])
        r = AesCtrHmacCtx(cipher, mac, keys["enc_c2s"], keys["iv_c2s"], keys["mac_c2s"])
    return s, r


def _new_cbc_pair(cipher: str, mac: str, keys: dict[str, bytes], *, is_client: bool):
    if is_client:
        s = CbcHmacCtx(cipher, mac, keys["enc_c2s"], keys["iv_c2s"], keys["mac_c2s"])
        r = CbcHmacCtx(cipher, mac, keys["enc_s2c"], keys["iv_s2c"], keys["mac_s2c"])
    else:
        s = CbcHmacCtx(cipher, mac, keys["enc_s2c"], keys["iv_s2c"], keys["mac_s2c"])
        r = CbcHmacCtx(cipher, mac, keys["enc_c2s"], keys["iv_c2s"], keys["mac_c2s"])
    return s, r


def _new_stream_pair(kind: str, cipher: str, mac: str, keys: dict[str, bytes], *, is_client: bool):
    """
     CTR or chained-IV CBC direction pair. Both share one framing and one
     MAC interface, so they ride the same transport slots.
    """
    maker = _new_ctr_pair if kind == "ctr" else _new_cbc_pair
    return maker(cipher, mac, keys, is_client=is_client)


def _new_gcm_pair(cipher: str, keys: dict[str, bytes], *, is_client: bool):
    if is_client:
        s = _gcm_mod.AesGcmCtx(cipher, keys["enc_c2s"], keys["iv_c2s"])
        r = _gcm_mod.AesGcmCtx(cipher, keys["enc_s2c"], keys["iv_s2c"])
    else:
        s = _gcm_mod.AesGcmCtx(cipher, keys["enc_s2c"], keys["iv_s2c"])
        r = _gcm_mod.AesGcmCtx(cipher, keys["enc_c2s"], keys["iv_c2s"])
    return s, r


def _new_chacha_pair(keys: dict[str, bytes], *, is_client: bool):
    if is_client:
        return (_chacha_mod.ChachaSshCtx(keys["enc_c2s"]),
                _chacha_mod.ChachaSshCtx(keys["enc_s2c"]))
    return (_chacha_mod.ChachaSshCtx(keys["enc_s2c"]),
            _chacha_mod.ChachaSshCtx(keys["enc_c2s"]))


def _encode_kind(cipher: str) -> str:
    if cipher in CIPHER_SPECS:
        return "ctr"
    if cipher in CBC_SPECS:
        return "cbc"
    if cipher in GCM_CIPHERS:
        return "gcm"
    if cipher == CHACHA_CIPHER:
        return "chacha"
    raise CCSSHError(f"unsupported cipher {cipher}")


def _encode_encrypted(cipher: str, s, gs, cs, seq: int, payload: bytes) -> bytes:
    """
     Build one encrypted wire packet (no I/O). Shared by the sync and
     async transports so the framing cannot drift between them.
    """
    if cipher in CIPHER_SPECS or cipher in CBC_SPECS:
        if s is None:
            raise CCSSHError("stream sender not activated")
        if s.etm:
            length, body = build_aad_block(payload, s.block_size)
            ct = s.encrypt_stream(body)
            return length + ct + s.mac_of(seq, length + ct)
        blk = build_unencrypted_block(payload, s.block_size)
        return s.encrypt_stream(blk) + s.mac_of(seq, blk)
    if cipher in GCM_CIPHERS:
        if gs is None:
            raise CCSSHError("GCM sender not activated")
        return gs.seal(payload)
    if cipher == CHACHA_CIPHER:
        if cs is None:
            raise CCSSHError("ChaCha sender not activated")
        length, pblk = build_aad_block(payload, 8)
        return cs.seal(seq, length, pblk)
    raise CCSSHError(f"send: unsupported cipher {cipher}")


class SyncTransport:
    def __init__(self, sock: "socket.socket | StreamSocket", version: bytes,
                 *, timeout: float = 10.0):
        self.sock = sock
        self.version = version
        self.timeout = timeout
        self.peer_version: bytes | None = None
        self.send_seq = 0
        self.recv_seq = 0
        self.cipher = "none"
        self.mac = "none"
        self._s: AesCtrHmacCtx | CbcHmacCtx | None = None
        self._r: AesCtrHmacCtx | CbcHmacCtx | None = None
        self._gs = self._gr = self._cs = self._cr = None
        self._enc_on_send = False
        self._enc_on_recv = False
        # Compression negotiation (RFC 4253 6.2 + delayed draft). Names are
        # per direction ("none" | "zlib" | "zlib@openssh.com"); streams exist
        # only while that direction is actually compressing.
        self.comp_c2s = "none"
        self.comp_s2c = "none"
        self.comp_level = 6
        self._compressor = None
        self._decompressor = None
        self.bytes_out = 0
        self.bytes_in = 0
        self.kex_at = time.monotonic()
        self._send_lock = threading.Lock()
        self._staged = None
        self._rxbuf = bytearray()

    # -- compression (1:1 with OpenSSH compress.c / packet.c) --
    def set_compression(self, c2s: str, s2c: str, level: int = 6, *, is_client: bool = True) -> None:
        """
         Record the negotiated methods and activate immediate ("zlib")
         directions at once. Delayed ("zlib@openssh.com") directions stay
         pending until enable_delayed_compression() after USERAUTH_SUCCESS.

         c2s/s2c are always client->server / server->client (RFC 4253),
         regardless of our role: a server's sends are s2c, recvs are c2s.
        """
        from ccssh import compress as _comp_mod
        _comp_mod.check_name(c2s)
        _comp_mod.check_name(s2c)
        _comp_mod.check_level(level)
        self.comp_c2s, self.comp_s2c, self.comp_level = c2s, s2c, level
        self._comp_is_client = is_client
        self._compressor = None
        self._decompressor = None
        send_name = c2s if is_client else s2c
        recv_name = s2c if is_client else c2s
        if send_name == _comp_mod.ZLIB:
            self._compressor = _comp_mod.Compressor(level)
        if recv_name == _comp_mod.ZLIB:
            self._decompressor = _comp_mod.Decompressor()

    def _send_comp_name(self) -> str:
        return self.comp_c2s if getattr(self, "_comp_is_client", True) else self.comp_s2c

    def _recv_comp_name(self) -> str:
        return self.comp_s2c if getattr(self, "_comp_is_client", True) else self.comp_c2s

    def enable_delayed_compression(self) -> None:
        """Start delayed directions after USERAUTH_SUCCESS (idempotent)."""
        from ccssh import compress as _comp_mod
        if self._send_comp_name() == _comp_mod.DELAYED and self._compressor is None:
            self._compressor = _comp_mod.Compressor(self.comp_level)
        if self._recv_comp_name() == _comp_mod.DELAYED and self._decompressor is None:
            self._decompressor = _comp_mod.Decompressor()

    def _reset_compression_send(self) -> None:
        """Re-init the send stream after a key exchange (RFC 4253)."""
        from ccssh import compress as _comp_mod
        name = self._send_comp_name()
        if name == _comp_mod.ZLIB:
            self._compressor = _comp_mod.Compressor(self.comp_level)
        elif name == _comp_mod.DELAYED:
            if self._compressor is not None:  # post-auth rekey: fresh dict
                self._compressor = _comp_mod.Compressor(self.comp_level)
            # pre-auth rekey: stays pending (no compression yet)
        else:
            self._compressor = None

    def _reset_compression_recv(self) -> None:
        from ccssh import compress as _comp_mod
        name = self._recv_comp_name()
        if name == _comp_mod.ZLIB:
            self._decompressor = _comp_mod.Decompressor()
        elif name == _comp_mod.DELAYED:
            if self._decompressor is not None:
                self._decompressor = _comp_mod.Decompressor()
        else:
            self._decompressor = None

    def _compress_payload(self, payload: bytes) -> bytes:
        comp = self._compressor
        if comp is None:
            return payload
        try:
            return comp.compress(payload)
        except ValueError as e:
            raise CCSSHError(f"compression failed: {e}") from e

    def _decompress_payload(self, data: bytes) -> bytes:
        decomp = self._decompressor
        if decomp is None:
            return data
        try:
            return decomp.decompress(data)
        except ValueError as e:
            raise CCSSHError(f"decompression failed: {e}") from e

    def _recvn(self, n: int) -> bytes:
        return _recvn_blocking(self.sock, n, self.timeout, self._rxbuf)

    def do_version(self) -> bytes:
        self.sock.sendall(self.version + b"\r\n")
        self.sock.settimeout(self.timeout)
        buf = b""
        lines = 0
        t0 = time.monotonic()
        while True:
            if time.monotonic() - t0 > self.timeout:
                raise CCSSHError("version exchange timeout")
            try:
                ch = self.sock.recv(1)
            except (TimeoutError, socket.timeout) as e:
                raise CCSSHTimeoutError("version exchange timeout") from e
            if not ch:
                raise CCSSHError("closed before version string")
            buf += ch
            if len(buf) > 255:
                raise CCSSHError("version line too long")
            if buf.endswith(b"\n"):
                line = buf.strip(b"\r\n")
                if line.startswith(b"SSH-"):
                    self.peer_version = line
                    return line
                lines += 1
                if lines > 10:
                    raise CCSSHError("too many pre-version banners")
                buf = b""

    def _reset_stats(self) -> None:
        self.kex_at = time.monotonic()
        self.bytes_out = 0
        self.bytes_in = 0

    def activate(self, keys: dict[str, bytes], cipher: str, mac: str, *, is_client: bool, reset_seq: bool = False) -> None:
        self.cipher, self.mac = cipher, mac
        self._reset_stats()
        if reset_seq:
            self.send_seq = 0
            self.recv_seq = 0
        self._s = self._r = self._gs = self._gr = self._cs = self._cr = None
        self._staged = None
        # Fresh keys mean fresh compression dictionaries too (RFC 4253), but
        # the negotiated names survive: set_compression() right after decides
        # whether streams start now (zlib) or after auth (delayed).
        self._compressor = None
        self._decompressor = None
        if cipher == "none":
            return
        kind = _encode_kind(cipher)
        if kind in ("ctr", "cbc"):
            self._s, self._r = _new_stream_pair(kind, cipher, mac, keys, is_client=is_client)
        elif kind == "gcm":
            self._gs, self._gr = _new_gcm_pair(cipher, keys, is_client=is_client)
        else:
            self._cs, self._cr = _new_chacha_pair(keys, is_client=is_client)

    def stage_rekey(self, keys: dict[str, bytes], cipher: str, mac: str, *, is_client: bool) -> None:
        """Stage new contexts; NEWKEYS itself still travels under old keys."""
        if self._staged is not None:
            raise CCSSHError("rekey already staged")
        kind = _encode_kind(cipher)
        if kind in ("ctr", "cbc"):
            s, r = _new_stream_pair(kind, cipher, mac, keys, is_client=is_client)
        elif kind == "gcm":
            s, r = _new_gcm_pair(cipher, keys, is_client=is_client)
        else:
            s, r = _new_chacha_pair(keys, is_client=is_client)
        self._staged = (kind, cipher, mac, s, r)

    def commit_rekey_send(self, *, reset_seq: bool = False) -> None:
        if self._staged is None:
            raise CCSSHError("no staged rekey to commit (send)")
        kind, _cipher, _mac, s, _r = self._staged
        if reset_seq:
            self.send_seq = 0
        if kind in ("ctr", "cbc"):
            self._s = s
        elif kind == "gcm":
            self._gs = s
        else:
            self._cs = s
        self._reset_compression_send()

    def commit_rekey_recv(self, *, reset_seq: bool = False) -> None:
        if self._staged is None:
            raise CCSSHError("no staged rekey to commit (recv)")
        kind, cipher, mac, _s, r = self._staged
        self._reset_stats()
        if reset_seq:
            self.recv_seq = 0
        self.cipher, self.mac = cipher, mac
        if kind in ("ctr", "cbc"):
            self._r = r
        elif kind == "gcm":
            self._gr = r
        else:
            self._cr = r
        self._staged = None
        self._reset_compression_recv()

    def send_packet(self, payload: bytes) -> None:
        """
         One lock covers crypto stream state, seq assignment, and the
         sendall, so threads sharing a transport cannot interleave.
         If sendall fails the stream state is already consumed: treat
         the transport as dead and reconnect instead of retrying.
        """
        with self._send_lock:
            if self.send_seq >= 0xFFFFFFFF:
                raise CCSSHError("sequence number exhausted: rekey required")
            wire = self._encode_packet(payload)
            self.sock.sendall(wire)
            self.bytes_out += len(payload)
            self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF

    def _encode_packet(self, payload: bytes) -> bytes:
        # RFC 4253 6.2: only the payload compresses; packet_length/MAC are
        # computed from the compressed form, encryption goes last.
        payload = self._compress_payload(payload)
        if self._plain_sending():
            return build_unencrypted_block(payload, 8)
        return _encode_encrypted(self.cipher, self._s, self._gs, self._cs,
                                 self.send_seq, payload)

    def _plain_sending(self) -> bool:
        return (self.cipher in ("none",) or not self._enc_on_send or (
            self._s is None and self._gs is None and self._cs is None))

    def recv_packet(self, *, keepalive: bool = True) -> bytes:
        """
         Next non-service packet. Skips IGNORE/DEBUG and answers
         GLOBAL_REQUEST (hostkeys-00 -> SUCCESS, anything else -> FAILURE).

         More than 64 service messages in a row means a flooding peer:
         fail instead of spinning. An idle read in steady state (after
         NEWKEYS) sends SSH IGNORE and waits on - an `ssh`-like session
         survives silence instead of dying on the read timeout; pass
         keepalive=False where a stall must stay fatal (e.g. the SFTP
         window top-up, which enforces its own deadline). Handshake reads
         (before NEWKEYS) always fail fast.
        """
        skips = 0
        idle_rounds = 0
        while True:
            try:
                p = self._read_one()
            except CCSSHTimeoutError:
                if not keepalive or not self._enc_on_recv:
                    raise
                idle_rounds += 1
                if idle_rounds > 100:
                    raise CCSSHError("peer idle: keepalive limit reached")
                self.send_packet(enc_ignore()) # may raise on a dead socket
                continue
            self.bytes_in += len(p)
            m = p[0] if p else -1
            if m in (2, 4): # IGNORE, DEBUG
                skips += 1
                if skips > 64:
                    raise CCSSHError("too many service messages")
                continue
            if m == 80: # GLOBAL_REQUEST
                self._answer_global(p)
                skips += 1
                if skips > 64:
                    raise CCSSHError("too many service messages")
                continue
            return p

    def recv_raw(self) -> bytes:
        """
         Exactly one message, no service loop (for select loops: handle it
         and return to select instead of blocking on the next one).
        """
        p = self._read_one()
        self.bytes_in += len(p)
        return p

    def _answer_global(self, p: bytes) -> None:
        try:
            r = _wire.Reader(p)
            r.byte()
            name, want = r.string(), r.bool()
        except Exception:
            return
        if want:
            self.send_packet(_global_success(name))

    def _read_one(self) -> bytes:
        if self._plain_receiving():
            hdr = self._recvn(4)
            (pl,) = struct.unpack(">I", hdr)
            if pl < 12 or pl > MAX_PACKET or (4 + pl) % 8 != 0:
                raise CCSSHError(f"packet_length {pl}")
            body = self._recvn(pl)
            _check_padding(body[0], pl)
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return self._decompress_payload(body[1:len(body) - body[0]])
        if self.cipher in GCM_CIPHERS:
            if self._gr is None:
                raise CCSSHError("GCM receiver not activated")
            hdr = self._recvn(4)
            (pl,) = struct.unpack(">I", hdr)
            if pl < 16 or pl > MAX_PACKET or pl % 16 != 0:
                raise CCSSHError(f"gcm packet_length {pl}")
            rest = self._recvn(pl + 16)
            pt = self._gr.open(hdr + rest)
            _check_padding(pt[0], pl)
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return self._decompress_payload(pt[1:len(pt) - pt[0]])
        if self.cipher == CHACHA_CIPHER:
            if self._cr is None:
                raise CCSSHError("ChaCha receiver not activated")
            enc_len = self._recvn(4)
            packet_len = self._cr.decrypt_length(self.recv_seq, enc_len)
            (pl,) = struct.unpack(">I", packet_len)
            if pl < 8 or pl > MAX_PACKET or pl % 8 != 0:
                raise CCSSHError(f"chacha packet_length {pl}")
            rest = self._recvn(pl + 16)
            _plen, pblk = self._cr.open(self.recv_seq, enc_len + rest)
            _check_padding(pblk[0], pl)
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return self._decompress_payload(pblk[1:len(pblk) - pblk[0]])
        ctx = self._r
        if ctx is None:
            raise CCSSHError("stream receiver not activated")
        blk_size = ctx.block_size
        if ctx.etm:
            # Length in the clear; CT of length pl; MAC over seq+length+CT.
            length = self._recvn(4)
            (pl,) = struct.unpack(">I", length)
            if pl < blk_size or pl > MAX_PACKET or pl % blk_size != 0:
                raise CCSSHError(f"ETM packet_length {pl}")
            rest = self._recvn(pl + ctx.mac_len)
            ct, mac_recv = rest[:pl], rest[pl:]
            if not pyhmac.compare_digest(ctx.mac_of(self.recv_seq, length + ct), mac_recv):
                raise CCSSHError("packet integrity failed")
            plain = ctx.decrypt_stream(ct)
            _check_padding(plain[0], pl)
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return self._decompress_payload(plain[1:len(plain) - plain[0]])
        first = self._recvn(blk_size)
        pf = ctx.decrypt_stream(first)
        (pl,) = struct.unpack(">I", pf[:4])
        if pl < 12 or pl > MAX_PACKET or (4 + pl) % blk_size != 0:
            # Same message as a MAC failure: the length field is decrypted
            # before the MAC is checked, so distinguishing the two would
            # give a padding oracle on legacy CBC.
            raise CCSSHError("packet integrity failed")
        total = 4 + pl + ctx.mac_len
        rest = self._recvn(total - blk_size)
        ct_rest, mac_recv = rest[:len(rest) - ctx.mac_len], rest[len(rest) - ctx.mac_len:]
        plain = pf + ctx.decrypt_stream(ct_rest)
        if not pyhmac.compare_digest(ctx.mac_of(self.recv_seq, plain), mac_recv):
            raise CCSSHError("packet integrity failed")
        if len(plain) != 4 + pl:
            raise CCSSHError("packet integrity failed")
        _check_padding(plain[4], pl)
        self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
        return self._decompress_payload(plain[5:4 + pl - plain[4]])

    def _plain_receiving(self) -> bool:
        return (self.cipher in ("none",) or (self._r is None and self._gr is None and self._cr is None) or not self._enc_on_recv)


class AsyncTransport:
    """Same protocol over asyncio streams."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 version: bytes, *, timeout: float = 10.0):
        self.reader, self.writer = reader, writer
        self.version = version
        self.timeout = timeout
        self.peer_version: bytes | None = None
        self.send_seq = 0
        self.recv_seq = 0
        self.cipher = "none"
        self.mac = "none"
        self._s: AesCtrHmacCtx | CbcHmacCtx | None = None
        self._r: AesCtrHmacCtx | CbcHmacCtx | None = None
        self._gs = self._gr = self._cs = self._cr = None
        self._enc_on_send = False
        self._enc_on_recv = False
        self.comp_c2s = "none"
        self.comp_s2c = "none"
        self.comp_level = 6
        self._compressor = None
        self._decompressor = None
        self.bytes_out = 0
        self.bytes_in = 0
        self.kex_at = time.monotonic()
        self._staged = None
        self._send_lock = asyncio.Lock()

    def set_compression(self, c2s: str, s2c: str, level: int = 6, *, is_client: bool = True) -> None:
        from ccssh import compress as _comp_mod
        _comp_mod.check_name(c2s)
        _comp_mod.check_name(s2c)
        _comp_mod.check_level(level)
        self.comp_c2s, self.comp_s2c, self.comp_level = c2s, s2c, level
        self._comp_is_client = is_client
        self._compressor = None
        self._decompressor = None
        send_name = c2s if is_client else s2c
        recv_name = s2c if is_client else c2s
        if send_name == _comp_mod.ZLIB:
            self._compressor = _comp_mod.Compressor(level)
        if recv_name == _comp_mod.ZLIB:
            self._decompressor = _comp_mod.Decompressor()

    def _send_comp_name(self) -> str:
        return self.comp_c2s if getattr(self, "_comp_is_client", True) else self.comp_s2c

    def _recv_comp_name(self) -> str:
        return self.comp_s2c if getattr(self, "_comp_is_client", True) else self.comp_c2s

    def enable_delayed_compression(self) -> None:
        from ccssh import compress as _comp_mod
        if self._send_comp_name() == _comp_mod.DELAYED and self._compressor is None:
            self._compressor = _comp_mod.Compressor(self.comp_level)
        if self._recv_comp_name() == _comp_mod.DELAYED and self._decompressor is None:
            self._decompressor = _comp_mod.Decompressor()

    def _reset_compression_send(self) -> None:
        from ccssh import compress as _comp_mod
        name = self._send_comp_name()
        if name == _comp_mod.ZLIB:
            self._compressor = _comp_mod.Compressor(self.comp_level)
        elif name == _comp_mod.DELAYED:
            if self._compressor is not None:
                self._compressor = _comp_mod.Compressor(self.comp_level)
        else:
            self._compressor = None

    def _reset_compression_recv(self) -> None:
        from ccssh import compress as _comp_mod
        name = self._recv_comp_name()
        if name == _comp_mod.ZLIB:
            self._decompressor = _comp_mod.Decompressor()
        elif name == _comp_mod.DELAYED:
            if self._decompressor is not None:
                self._decompressor = _comp_mod.Decompressor()
        else:
            self._decompressor = None

    def _compress_payload(self, payload: bytes) -> bytes:
        comp = self._compressor
        if comp is None:
            return payload
        try:
            return comp.compress(payload)
        except ValueError as e:
            raise CCSSHError(f"compression failed: {e}") from e

    def _decompress_payload(self, data: bytes) -> bytes:
        decomp = self._decompressor
        if decomp is None:
            return data
        try:
            return decomp.decompress(data)
        except ValueError as e:
            raise CCSSHError(f"decompression failed: {e}") from e

    async def do_version(self) -> bytes:
        self.writer.write(self.version + b"\r\n")
        await self.writer.drain()
        buf = b""
        lines = 0
        t0 = time.monotonic()
        while True:
            if time.monotonic() - t0 > self.timeout:
                raise CCSSHError("version exchange timeout (async)")
            ch = await _recvn_async(self.reader, 1, self.timeout)
            buf += ch
            if len(buf) > 255:
                raise CCSSHError("version line too long (async)")
            if buf.endswith(b"\n"):
                line = buf.strip(b"\r\n")
                if line.startswith(b"SSH-"):
                    self.peer_version = line
                    return line
                lines += 1
                if lines > 10:
                    raise CCSSHError("too many pre-version banners (async)")
                buf = b""

    def _reset_stats(self) -> None:
        self.kex_at = time.monotonic()
        self.bytes_out = 0
        self.bytes_in = 0

    def activate(self, keys: dict[str, bytes], cipher: str, mac: str, *, is_client: bool, reset_seq: bool = False) -> None:
        self.cipher, self.mac = cipher, mac
        self._reset_stats()
        if reset_seq:
            self.send_seq = 0
            self.recv_seq = 0
        self._s = self._r = self._gs = self._gr = self._cs = self._cr = None
        self._staged = None
        self._compressor = None
        self._decompressor = None
        if cipher == "none":
            return
        kind = _encode_kind(cipher)
        if kind in ("ctr", "cbc"):
            self._s, self._r = _new_stream_pair(kind, cipher, mac, keys, is_client=is_client)
        elif kind == "gcm":
            self._gs, self._gr = _new_gcm_pair(cipher, keys, is_client=is_client)
        else:
            self._cs, self._cr = _new_chacha_pair(keys, is_client=is_client)

    def stage_rekey(self, keys: dict[str, bytes], cipher: str, mac: str, *, is_client: bool) -> None:
        if self._staged is not None:
            raise CCSSHError("rekey already staged")
        kind = _encode_kind(cipher)
        if kind in ("ctr", "cbc"):
            s, r = _new_stream_pair(kind, cipher, mac, keys, is_client=is_client)
        elif kind == "gcm":
            s, r = _new_gcm_pair(cipher, keys, is_client=is_client)
        else:
            s, r = _new_chacha_pair(keys, is_client=is_client)
        self._staged = (kind, cipher, mac, s, r)

    def commit_rekey_send(self, *, reset_seq: bool = False) -> None:
        if self._staged is None:
            raise CCSSHError("no staged rekey to commit (send)")
        kind, _cipher, _mac, s, _r = self._staged
        if reset_seq:
            self.send_seq = 0
        if kind in ("ctr", "cbc"):
            self._s = s
        elif kind == "gcm":
            self._gs = s
        else:
            self._cs = s
        self._reset_compression_send()

    def commit_rekey_recv(self, *, reset_seq: bool = False) -> None:
        if self._staged is None:
            raise CCSSHError("no staged rekey to commit (recv)")
        kind, cipher, mac, _s, r = self._staged
        self._reset_stats()
        if reset_seq:
            self.recv_seq = 0
        self.cipher, self.mac = cipher, mac
        if kind in ("ctr", "cbc"):
            self._r = r
        elif kind == "gcm":
            self._gr = r
        else:
            self._cr = r
        self._staged = None
        self._reset_compression_recv()

    async def send_packet(self, payload: bytes) -> None:
        async with self._send_lock:
            if self.send_seq >= 0xFFFFFFFF:
                raise CCSSHError("sequence number exhausted: rekey required")
            orig_len = len(payload)
            payload = self._compress_payload(payload)
            if self._plain_sending():
                wire = build_unencrypted_block(payload, 8)
            else:
                wire = _encode_encrypted(self.cipher, self._s, self._gs, self._cs, self.send_seq, payload)
            self.writer.write(wire)
            await self.writer.drain()
            self.bytes_out += orig_len
            self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF

    def _plain_sending(self) -> bool:
        return (self.cipher in ("none",) or not self._enc_on_send or (
            self._s is None and self._gs is None and self._cs is None))

    async def recv_packet(self, *, keepalive: bool = True) -> bytes:
        skips = 0
        idle_rounds = 0
        while True:
            try:
                p = await self._read_one()
            except CCSSHTimeoutError:
                if not keepalive or not self._enc_on_recv:
                    raise
                idle_rounds += 1
                if idle_rounds > 100:
                    raise CCSSHError("peer idle: keepalive limit reached (async)")
                await self.send_packet(enc_ignore())  # may raise on a dead socket
                continue
            self.bytes_in += len(p)
            m = p[0] if p else -1
            if m in (2, 4):
                skips += 1
                if skips > 64:
                    raise CCSSHError("too many service messages (async)")
                continue
            if m == 80:
                await self._answer_global(p)
                skips += 1
                if skips > 64:
                    raise CCSSHError("too many service messages (async)")
                continue
            return p

    async def recv_raw(self) -> bytes:
        """Single message without the service loop, for async select loops."""
        p = await self._read_one()
        self.bytes_in += len(p)
        return p

    async def _answer_global(self, p: bytes) -> None:
        try:
            r = _wire.Reader(p)
            r.byte()
            name, want = r.string(), r.bool()
        except Exception:
            return
        if want:
            await self.send_packet(_global_success(name))

    async def _read_one(self) -> bytes:
        if self._plain_receiving():
            hdr = await _recvn_async(self.reader, 4, self.timeout)
            (pl,) = struct.unpack(">I", hdr)
            if pl < 12 or pl > MAX_PACKET or (4 + pl) % 8 != 0:
                raise CCSSHError(f"packet_length {pl}")
            body = await _recvn_async(self.reader, pl, self.timeout)
            _check_padding(body[0], pl)
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return self._decompress_payload(body[1:len(body) - body[0]])
        if self.cipher in GCM_CIPHERS:
            if self._gr is None:
                raise CCSSHError("GCM receiver not activated")
            hdr = await _recvn_async(self.reader, 4, self.timeout)
            (pl,) = struct.unpack(">I", hdr)
            if pl < 16 or pl > MAX_PACKET or pl % 16 != 0:
                raise CCSSHError(f"gcm packet_length {pl}")
            rest = await _recvn_async(self.reader, pl + 16, self.timeout)
            pt = self._gr.open(hdr + rest)
            _check_padding(pt[0], pl)
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return self._decompress_payload(pt[1:len(pt) - pt[0]])
        if self.cipher == CHACHA_CIPHER:
            if self._cr is None:
                raise CCSSHError("ChaCha receiver not activated")
            enc_len = await _recvn_async(self.reader, 4, self.timeout)
            (pl,) = struct.unpack(">I", self._cr.decrypt_length(self.recv_seq, enc_len))
            if pl < 8 or pl > MAX_PACKET or pl % 8 != 0:
                raise CCSSHError(f"chacha packet_length {pl}")
            rest = await _recvn_async(self.reader, pl + 16, self.timeout)
            _plen, pblk = self._cr.open(self.recv_seq, enc_len + rest)
            _check_padding(pblk[0], pl)
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return self._decompress_payload(pblk[1:len(pblk) - pblk[0]])
        ctx = self._r
        if ctx is None:
            raise CCSSHError("stream receiver not activated (async)")
        blk_size = ctx.block_size
        if ctx.etm:
            length = await _recvn_async(self.reader, 4, self.timeout)
            (pl,) = struct.unpack(">I", length)
            if pl < blk_size or pl > MAX_PACKET or pl % blk_size != 0:
                raise CCSSHError(f"ETM packet_length {pl}")
            rest = await _recvn_async(self.reader, pl + ctx.mac_len, self.timeout)
            ct, mac_recv = rest[:pl], rest[pl:]
            if not pyhmac.compare_digest(ctx.mac_of(self.recv_seq, length + ct), mac_recv):
                raise CCSSHError("packet integrity failed (async)")
            plain = ctx.decrypt_stream(ct)
            _check_padding(plain[0], pl)
            self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
            return self._decompress_payload(plain[1:len(plain) - plain[0]])
        first = await _recvn_async(self.reader, blk_size, self.timeout)
        pf = ctx.decrypt_stream(first)
        (pl,) = struct.unpack(">I", pf[:4])
        if pl < 12 or pl > MAX_PACKET or (4 + pl) % blk_size != 0:
            # Same message as a MAC failure: the length field is decrypted
            # before the MAC is checked, so distinguishing the two would
            # give a padding oracle on legacy CBC.
            raise CCSSHError("packet integrity failed (async)")
        total = 4 + pl + ctx.mac_len
        rest = await _recvn_async(self.reader, total - blk_size, self.timeout)
        ct_rest, mac_recv = rest[:len(rest) - ctx.mac_len], rest[len(rest) - ctx.mac_len:]
        plain = pf + ctx.decrypt_stream(ct_rest)
        if not pyhmac.compare_digest(ctx.mac_of(self.recv_seq, plain), mac_recv):
            raise CCSSHError("packet integrity failed (async)")
        if len(plain) != 4 + pl:
            raise CCSSHError("packet integrity failed (async)")
        _check_padding(plain[4], pl)
        self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
        return self._decompress_payload(plain[5:4 + pl - plain[4]])

    def _plain_receiving(self) -> bool:
        return (self.cipher in ("none",) or (self._r is None and self._gr is None and self._cr is None) or not self._enc_on_recv)
