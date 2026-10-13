"""
 User authentication messages, RFC 4252: service request, password and
 publickey methods (probe + signed), keyboard-interactive (RFC 4256),
 plus a request parser for the server side.
"""
from __future__ import annotations

from collections.abc import Callable

from ccssh import wire as W

MSG_SERVICE_REQUEST = 5
MSG_SERVICE_ACCEPT = 6
MSG_USERAUTH_REQUEST = 50
MSG_USERAUTH_FAILURE = 51
MSG_USERAUTH_SUCCESS = 52
MSG_USERAUTH_PK_OK = 60
MSG_USERAUTH_INFO_REQUEST = 60 # same number as PK_OK: context disambiguates
MSG_USERAUTH_INFO_RESPONSE = 61

# DoS caps for keyboard-interactive (a rogue server prompts forever).
MAX_KBDINT_PROMPTS = 16
MAX_KBDINT_ROUNDS = 5


def enc_service_request(service: bytes = b"ssh-userauth") -> bytes:
    return bytes([MSG_SERVICE_REQUEST]) + W.enc_string(service)


def enc_password_request(user: str, password: str, *, service: str = "ssh-connection") -> bytes:
    if len(user.encode()) > 255 or len(password.encode()) > 1024:
        raise ValueError("user/password too long")
    if len(service.encode()) > 255:
        raise ValueError("service name too long")
    return (bytes([MSG_USERAUTH_REQUEST])
            + W.enc_string(user.encode())
            + W.enc_string(service.encode())
            + W.enc_string(b"password")
            + W.enc_bool(False)
            + W.enc_string(password.encode()))


def enc_pubkey_probe(user: str, alg: bytes, key_blob: bytes, *, service: str = "ssh-connection") -> bytes:
    if len(user.encode()) > 255 or len(key_blob) > 16384:
        raise ValueError("pubkey probe too large")
    return (bytes([MSG_USERAUTH_REQUEST])
            + W.enc_string(user.encode())
            + W.enc_string(service.encode())
            + W.enc_string(b"publickey")
            + W.enc_bool(False)
            + W.enc_string(alg)
            + W.enc_string(key_blob))


def enc_pubkey_signed(user: str, alg: bytes, key_blob: bytes, signature_nested: bytes, *, service: str = "ssh-connection") -> bytes:
    """
     Assemble a signed publickey request.

     ``signature_nested`` is the sshkey_sign output buffer, i.e.
     string(alg) + string(signature); it is wrapped here into the
     signature string field.
    """
    return (bytes([MSG_USERAUTH_REQUEST])
            + W.enc_string(user.encode())
            + W.enc_string(service.encode())
            + W.enc_string(b"publickey")
            + W.enc_bool(True)
            + W.enc_string(alg)
            + W.enc_string(key_blob)
            + W.enc_string(signature_nested))


def auth_sign_blob(session_id: bytes, user: str, alg: bytes, key_blob: bytes, *, service: str = "ssh-connection") -> bytes:
    """Data signed by the user's private key (RFC 4252 section 7)."""
    return (W.enc_string(session_id)
            + bytes([MSG_USERAUTH_REQUEST])
            + W.enc_string(user.encode())
            + W.enc_string(service.encode())
            + W.enc_string(b"publickey")
            + W.enc_bool(True)
            + W.enc_string(alg)
            + W.enc_string(key_blob))

def dec_userauth_request(payload: bytes) -> dict:
    r = W.Reader(payload)
    if r.byte() != MSG_USERAUTH_REQUEST:
        raise W.WireError("expected SSH_MSG_USERAUTH_REQUEST")
    try:
        user = r.string().decode(errors="replace")
        service = r.string().decode(errors="replace")
        method = r.string().decode(errors="replace")
    except W.WireError:
        raise
    return {"user": user, "service": service, "method": method, "rest": payload[r.tell():]}


def enc_kbdint_probe(user: str, *, service: str = "ssh-connection") -> bytes:
    """Start keyboard-interactive auth (RFC 4256 section 3.2)."""
    if len(user.encode()) > 255 or len(service.encode()) > 255:
        raise ValueError("user/service name too long")
    return (bytes([MSG_USERAUTH_REQUEST])
            + W.enc_string(user.encode())
            + W.enc_string(service.encode())
            + W.enc_string(b"keyboard-interactive")
            + W.enc_string(b"")
            + W.enc_string(b""))


def dec_info_request(payload: bytes) -> dict:
    """Parse SSH_MSG_USERAUTH_INFO_REQUEST (RFC 4256 section 3.4)."""
    r = W.Reader(payload)
    if r.byte() != MSG_USERAUTH_INFO_REQUEST:
        raise W.WireError("expected SSH_MSG_USERAUTH_INFO_REQUEST")
    try:
        name = r.string().decode(errors="replace")
        instruction = r.string().decode(errors="replace")
        _lang = r.string()
        n = r.u32()
    except W.WireError:
        raise
    if n > MAX_KBDINT_PROMPTS:
        raise W.WireError(f"too many prompts ({n})")
    prompts: list[tuple[str, bool]] = []
    try:
        for _ in range(n):
            prompts.append((r.string().decode(errors="replace"), r.bool()))
    except W.WireError:
        raise
    r.assert_end()
    return {"name": name, "instruction": instruction, "prompts": prompts}


def enc_info_response(responses: list[bytes]) -> bytes:
    """Assemble SSH_MSG_USERAUTH_INFO_RESPONSE (RFC 4256 section 3.5)."""
    if len(responses) > MAX_KBDINT_PROMPTS:
        raise ValueError(f"too many responses ({len(responses)})")
    out = bytes([MSG_USERAUTH_INFO_RESPONSE]) + W.enc_u32(len(responses))
    for resp in responses:
        if len(resp) > 1024:
            raise ValueError("response too long")
        out += W.enc_string(resp)
    return out


def dec_info_response(payload: bytes) -> list[bytes]:
    """Parse SSH_MSG_USERAUTH_INFO_RESPONSE (server/test side)."""
    r = W.Reader(payload)
    if r.byte() != MSG_USERAUTH_INFO_RESPONSE:
        raise W.WireError("expected SSH_MSG_USERAUTH_INFO_RESPONSE")
    n = r.u32()
    if n > MAX_KBDINT_PROMPTS:
        raise W.WireError(f"too many responses ({n})")
    out = [r.string() for _ in range(n)]
    r.assert_end()
    return out


def dec_failure(payload: bytes) -> dict:
    """Parse SSH_MSG_USERAUTH_FAILURE: remaining methods + partial flag."""
    r = W.Reader(payload)
    if r.byte() != MSG_USERAUTH_FAILURE:
        raise W.WireError("expected SSH_MSG_USERAUTH_FAILURE")
    methods = r.namelist()
    partial = r.bool()
    r.assert_end()
    return {"methods": methods, "partial": partial}


# Responder: server prompts [(text, echo)] -> answers. May raise to abort.
KbdintResponder = Callable[[list[tuple[str, bool]]], list[str]]
