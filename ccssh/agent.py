"""
 SSH agent (RFC 9987 core + OpenSSH PROTOCOL.agent): local key use and
 agent forwarding (`ssh -A`).

 Two halves:

 * :class:`AgentClient` talks to a local ``ssh-agent`` over its Unix-domain
   socket (``$SSH_AUTH_SOCK`` by default): list public identities and ask
   the agent to sign userauth blobs. Private key material never leaves the
   agent process.
 * Forwarding: after ``auth-agent-req@openssh.com`` on a session channel,
   the server opens ``auth-agent@openssh.com`` channels back; each one is
   relayed byte-for-byte to the local agent socket (see
   ``ccssh.forward.AgentForwarder``).

 Wire framing on the agent socket is ``uint32 length + payload`` (NOT SSH
 binary packets). Message numbers (stable since the original ssh.com agent,
 now RFC 9987):

 * 11 request-identities, 12 identities-answer
 * 13 sign-request, 14 sign-response
 * 5 failure, 6 success
 * sign flags: 2 = RSA-SHA2-256, 4 = RSA-SHA2-512 (0 otherwise)
"""
from __future__ import annotations

import os
import socket
import struct

from ccssh import wire as W

REQ_IDENTITIES = 11
IDENTITIES_ANSWER = 12
SIGN_REQUEST = 13
SIGN_RESPONSE = 14
AGENT_FAILURE = 5
AGENT_SUCCESS = 6

FLAG_RSA_SHA2_256 = 2
FLAG_RSA_SHA2_512 = 4

MAX_AGENT_MSG = 256 * 1024  # one agent message must never OOM us
MAX_IDENTITIES = 256  # a rogue agent listing thousands of keys fails closed
MAX_BLOB = 16384  # same bound as userauth probes (see auth.py)


class AgentError(Exception):
    pass


def sign_flags_for_alg(alg: str) -> int:
    """Agent sign-request flags for a userauth algorithm name."""
    if alg == "rsa-sha2-256":
        return FLAG_RSA_SHA2_256
    if alg == "rsa-sha2-512":
        return FLAG_RSA_SHA2_512
    return 0


def default_agent_path() -> str | None:
    """$SSH_AUTH_SOCK when set and non-empty, else None."""
    p = os.environ.get("SSH_AUTH_SOCK")
    if p and p.strip():
        return p
    return None


class AgentClient:
    """
     One-shot-per-call client for a local agent socket.

     A fresh Unix connection is opened per call (like OpenSSH's
     ssh_get_agent_identities: short-lived, no shared state), so concurrent
     auth attempts never interleave agent framing.
    """

    def __init__(self, path: str | None = None, *, timeout: float = 10.0):
        resolved = path if path is not None else default_agent_path()
        if not resolved:
            raise AgentError("no agent socket (set SSH_AUTH_SOCK or pass agent_path)")
        self.path = resolved
        self.timeout = timeout

    def _transact(self, payload: bytes) -> bytes:
        if len(payload) > MAX_AGENT_MSG:
            raise AgentError("agent request too big")
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError as e:
            raise AgentError(f"cannot create agent socket: {e}") from e
        try:
            s.settimeout(self.timeout)
            try:
                s.connect(self.path)
            except OSError as e:
                raise AgentError(f"cannot connect to agent {self.path}: {e}") from e
            try:
                s.sendall(struct.pack(">I", len(payload)) + payload)
                hdr = _recvn(s, 4)
                (ln,) = struct.unpack(">I", hdr)
                if ln == 0 or ln > MAX_AGENT_MSG:
                    raise AgentError(f"bad agent reply length {ln}")
                body = _recvn(s, ln)
            except (OSError, AgentError):
                raise
            except Exception as e:
                raise AgentError(f"agent I/O failed: {e}") from e
        finally:
            try:
                s.close()
            except Exception:
                pass
        if not body:
            raise AgentError("empty agent reply")
        return body

    def list_identities(self) -> list[tuple[bytes, str]]:
        """
         Returns [(public_blob, comment)]. Fails closed on any malformed
         data (a hostile $SSH_AUTH_SOCK must never inject keys silently).
        """
        body = self._transact(bytes([REQ_IDENTITIES]))
        r = W.Reader(body)
        try:
            m = r.byte()
        except W.WireError as e:
            raise AgentError(f"bad agent reply: {e}") from e
        if m == AGENT_FAILURE:
            raise AgentError("agent refused identities request")
        if m != IDENTITIES_ANSWER:
            raise AgentError(f"agent sent unexpected message {m}")
        try:
            n = r.u32()
        except W.WireError as e:
            raise AgentError(f"bad agent identities: {e}") from e
        if n > MAX_IDENTITIES:
            raise AgentError(f"agent listed too many identities ({n})")
        out: list[tuple[bytes, str]] = []
        try:
            for _ in range(n):
                blob = r.string()
                comment = r.string().decode("utf-8", errors="replace")
                if not blob or len(blob) > MAX_BLOB:
                    raise AgentError("bad agent key blob length")
                out.append((blob, comment))
            r.assert_end()
        except W.WireError as e:
            raise AgentError(f"bad agent identities: {e}") from e
        return out

    def sign(self, key_blob: bytes, data: bytes, flags: int = 0) -> bytes:
        """
         Ask the agent to sign ``data`` with the key matching ``key_blob``.

         Returns the nested userauth signature (``string(alg) +
         string(sig)``), ready for ``auth.enc_pubkey_signed``. Raises
         AgentError when the agent refuses, the key is unknown, or the
         reply is malformed.
        """
        if not key_blob or len(key_blob) > MAX_BLOB:
            raise AgentError("bad agent key blob")
        if len(data) > 65536:
            raise AgentError("agent sign data too big")
        req = (bytes([SIGN_REQUEST]) + W.enc_string(key_blob)
               + W.enc_string(data) + W.enc_u32(flags))
        body = self._transact(req)
        r = W.Reader(body)
        try:
            m = r.byte()
        except W.WireError as e:
            raise AgentError(f"bad agent reply: {e}") from e
        if m == AGENT_FAILURE:
            raise AgentError("agent refused to sign (key unknown or locked?)")
        if m != SIGN_RESPONSE:
            raise AgentError(f"agent sent unexpected message {m}")
        try:
            sig = r.string()
            r.assert_end()
        except W.WireError as e:
            raise AgentError(f"bad agent signature: {e}") from e
        if not sig:
            raise AgentError("agent returned empty signature")
        return sig


def _recvn(s: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        try:
            chunk = s.recv(n - len(out))
        except socket.timeout as e:
            raise AgentError(f"agent read timeout: {e}") from e
        if not chunk:
            raise AgentError("agent closed the connection")
        out += chunk
        if len(out) > MAX_AGENT_MSG + 4:
            raise AgentError("agent reply too big")
    return out


def dec_agent_open(payload: bytes) -> int:
    """
     Parse an inbound ``auth-agent@openssh.com`` CHANNEL_OPEN.

     The type carries no extra fields (just sender/window/maxpacket);
     returns the sender id. Raises AgentError on malformed data.
    """
    from ccssh import channel as CH
    r = W.Reader(payload)
    try:
        if r.byte() != CH.MSG_CHANNEL_OPEN:
            raise AgentError("not a CHANNEL_OPEN")
        ctype = r.string()
        if ctype != b"auth-agent@openssh.com":
            raise AgentError(f"not an agent open (got {ctype!r})")
        sender = r.u32()
        r.u32()
        r.u32()
        r.assert_end()
    except W.WireError as e:
        raise AgentError(f"bad agent open: {e}") from e
    return sender
