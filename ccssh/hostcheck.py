"""
 Shared host-key checking for the sync and async clients.

 Policies: strict (must be in known_hosts or @cert-authority), accept-new
 (appends plain keys; certificates are only verified, never written),
 off (accepts everything; lab use only).
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import os

from ccssh import hostkeys as HK


class HostKeyError(Exception):
    pass


def _match_host(patterns: str, host: str, port: int) -> bool:
    """Match plain lists (host or [host]:port) and hashed |1| entries."""
    for pat in patterns.split(","):
        pat = pat.strip()
        if pat.startswith("|1|"):
            try:
                _, salt_b64, hash_b64 = pat.split("|")[1:]
                salt = base64.b64decode(salt_b64)
                want = base64.b64decode(hash_b64)
            except Exception:
                continue
            if hmac.compare_digest(
                    hmac.new(salt, host.encode(), hashlib.sha1).digest(), want):
                return True
            if port != 22 and hmac.compare_digest(
                    hmac.new(salt, f"[{host}]:{port}".encode(), hashlib.sha1).digest(), want):
                return True
        elif pat == host or (port != 22 and pat == f"[{host}]:{port}"):
            return True
    return False


def _revoked_match(lines: list[str], host: str, port: int, blob_b64: str) -> bool:
    """
     True if a @revoked line pins this exact key blob to this host.

     Revocation is fail-closed under every policy: checked before any
     trust decision, including accept-new (a revoked key must never be
     re-learned).
    """
    for ln in lines:
        s = ln.strip()
        if not s.startswith("@revoked"):
            continue
        p = s.split()
        if len(p) < 4:
            continue
        if p[3] == blob_b64 and _match_host(p[1], host, port):
            return True
    return False

_RSA_FAMILY = {"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}

MAX_KNOWN_HOSTS_SIZE = 1 << 20
MAX_KNOWN_HOSTS_LINES = 20000


def _split_known_hosts(known_hosts: str | list[str] | None) -> list[str]:
    """
     One path or many (OpenSSH splits UserKnownHostsFile on whitespace;
     commas accepted too). The magic name `none` disables file use.
    """
    if known_hosts is None:
        return [os.path.expanduser("~/.ssh/known_hosts")]
    if isinstance(known_hosts, str):
        parts = [p for p in known_hosts.replace(",", " ").split() if p]
        return [os.path.expanduser(p) for p in parts] or [os.path.expanduser("~/.ssh/known_hosts")]
    return [os.path.expanduser(p) for p in known_hosts]


def _read_known_hosts(kh: str) -> list[str]:
    if kh == "/dev/null" or os.path.basename(kh).lower() == "none":
        return []
    if os.path.getsize(kh) > MAX_KNOWN_HOSTS_SIZE:
        raise HostKeyError(f"{kh} too large, refusing to parse")
    with open(kh, encoding="utf-8") as f:
        lines = f.readlines()
    if len(lines) > MAX_KNOWN_HOSTS_LINES:
        raise HostKeyError(f"{kh} has too many entries")
    return lines


def _append_known_host(kh: str, host: str, port: int, inner_alg: str, want: str) -> None:
    """Append a TOFU entry with symlink/permission hardening."""
    if kh == "/dev/null" or os.path.basename(kh).lower() == "none":
        return
    if os.path.islink(kh):
        raise HostKeyError(f"{kh} is a symlink, refusing to append (possible hijack)")
    parent = os.path.dirname(kh)
    if parent:
        if os.path.islink(parent):
            raise HostKeyError(f"{parent} is a symlink, refusing to append (possible hijack)")
        os.makedirs(parent, mode=0o700, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
    entry = f"{host} {inner_alg} {want}\n" if port == 22 else f"[{host}]:{port} {inner_alg} {want}\n"
    # O_NOFOLLOW is POSIX-only; on Windows the flag is 0 (no symlink
    # protection there - the islink() check above still applies).
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(kh, flags, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (OSError, AttributeError):
            pass
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        raise


def check_hostkey(host: str, port: int, Ks: bytes, alg: str, *, policy: str, known_hosts: str | list[str] | None, ask_callback=None) -> None:
    if policy not in ("strict", "accept-new", "off", "ask"):
        raise HostKeyError(f"bad host policy {policy!r} (must be strict|accept-new|ask|off)")
    if policy == "off":
        return
    if not host or any(c.isspace() or ord(c) < 32 for c in host):
        raise HostKeyError(f"bad host name {host!r}")
    try:
        inner_alg, _ = HK.parse_host_blob(Ks)
    except Exception as e:
        raise HostKeyError(f"malformed K_S: {e}") from e
    if inner_alg != alg and not (inner_alg in _RSA_FAMILY and alg in _RSA_FAMILY):
        raise HostKeyError(f"host key type {inner_alg!r} != negotiated {alg!r}")
    paths = _split_known_hosts(known_hosts)
    # (path, lineno, text) so CHANGED errors cite the offending entry.
    entries: list[tuple[str, int, str]] = []
    for kh in paths:
        try:
            for lineno, text in enumerate(_read_known_hosts(kh), 1):
                entries.append((kh, lineno, text))
        except FileNotFoundError:
            continue
        except HostKeyError:
            raise
        except OSError as e:
            # An unreadable file fails closed under every policy: treating
            # it as empty would hand a MitM a learning window.
            raise HostKeyError(f"cannot read {kh}: {e}") from e
    lines = [text for _, _, text in entries]
    want = base64.b64encode(Ks).decode()
    if _revoked_match(lines, host, port, want):
        raise HostKeyError(f"host key for {host} is REVOKED")
    if inner_alg.endswith("-cert-v01@openssh.com") or inner_alg.endswith("-cert"):
        from ccssh import certs as CERT
        cas = CERT.load_ca_keys(paths, host, port)
        if not cas:
            raise HostKeyError(f"no @cert-authority for {host} in {','.join(paths)}")
        try:
            c = CERT.verify_cert(Ks, expected_principal=host, is_host=True, ca_blobs=cas)
        except CERT.CertError as e:
            raise HostKeyError(f"host certificate rejected: {e}") from e
        ca_b64 = base64.b64encode(c["sig_key"]).decode()
        if _revoked_match(lines, host, port, ca_b64):
            raise HostKeyError(f"host certificate CA for {host} is REVOKED")
        return
    for kh, lineno, raw in entries:
        ln = raw.strip()
        if not ln or ln.startswith("#") or ln.startswith("@"):
            continue
        p = ln.split()
        if len(p) < 3:
            continue
        if p[2] == want and _match_host(p[0], host, port):
            return
        same = (p[1] == inner_alg) or (p[1] in _RSA_FAMILY and inner_alg in _RSA_FAMILY)
        if p[2] != want and _match_host(p[0], host, port) and same:
            try:
                old_fp = HK.fingerprint(base64.b64decode(p[2]))
            except Exception:
                old_fp = "<unparseable>"
            try:
                new_fp = HK.fingerprint(Ks)
            except Exception:
                new_fp = "<unparseable>"
            raise HostKeyError(
                f"HOST KEY CHANGED for {host} (possible MitM!)\n"
                f"Offending key in {kh}:{lineno}\n"
                f"Old {p[1]} fingerprint: {old_fp}\n"
                f"New {inner_alg} fingerprint: {new_fp}\n"
                f"Remove the old key with: ssh-keygen -R {host} "
                f"(verify the new fingerprint out-of-band first!)")
    if policy == "strict":
        raise HostKeyError(f"{host} not in {','.join(paths)} (strict)")
    if policy == "ask":
        # Unknown host under ask: prompt (ssh-like). Changed keys above
        # always fail, even under ask. Non-interactive callers pass
        # ask_callback=None and fail closed like strict.
        if ask_callback is None:
            raise HostKeyError(f"{host} not in {','.join(paths)} (strict: no prompt available)")
        try:
            answer = ask_callback(
                f"The authenticity of host '{host}' can't be established. "
                f"{inner_alg} key fingerprint is {want[:44]}... "
                f"Are you sure you want to continue connecting (yes/no)? ")
        except Exception as e:
            raise HostKeyError(f"host key prompt aborted: {e}") from e
        if str(answer).strip().lower() not in ("yes", "y"):
            raise HostKeyError(f"{host} not trusted (answer was not yes)")
    append_to = next((kh for kh in paths if kh != "/dev/null" and os.path.basename(kh).lower() != "none"), paths[0] if paths else os.path.expanduser("~/.ssh/known_hosts"))
    _append_known_host(append_to, host, port, inner_alg, want)
