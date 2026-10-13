"""
 Command line: `python -m ccssh` (or the `ccssh` entry point), OpenSSH-style.

 Options may come before or after the destination (`ccssh -p 2022 h` and
 `ccssh h -p 2022` are the same); the first bare word is the destination
 and everything after it is the remote command. No command means an
 interactive shell (like `ssh host`); -N means verify/forward mode.
 Passwords and key passphrases are prompted on the terminal (never taken
 from argv, so they stay out of `ps`); --password-env covers
 non-interactive use. -L/-R share the connection with shell/exec through
 the channel multiplexer (one forwarder per connection); -J takes comma
 chains (ProxyJump). -v prints OpenSSH-style debug1 progress
 (negotiation, host key fingerprint, auth); -vv adds full offers and
 per-step debug2 traces. A TCP preflight dial runs before any password
 prompt, so dead servers fail fast instead of asking for a password.
"""
from __future__ import annotations
import argparse
import getpass
import os
import re
import socket
import sys
import time
from collections.abc import Callable

from ccssh.client import AuthError, CCSSHClient


class UsageError(Exception):
    """
     Bad command line: reported as `ccssh: ...` with exit 255 (ssh-style).

     argparse/SystemExit paths all funnel here so usage, unknown options
     and bad -o values share one exit code instead of 1/2/255 soup.
    """


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="ccssh", description="ccssh - native from-scratch SSH client")
    p.add_argument("destination", nargs="?", default=None, help="[user@]hostname")
    p.add_argument("command", nargs=argparse.REMAINDER,
                   help="remote command (empty means interactive shell)")
    p.add_argument("-p", dest="port", type=int, default=22)
    p.add_argument("-l", dest="login", default=None)
    p.add_argument("-c", dest="cipher_spec", default=None, metavar="cipher_spec",
                   help="ciphers like ssh -c (comma list, +alg/-alg/^alg allowed)")
    p.add_argument("-m", dest="mac_spec", default=None, metavar="mac_spec",
                   help="MACs like ssh -m (comma list, +alg/-alg/^alg allowed)")
    p.add_argument("-Q", dest="query", default=None, metavar="query",
                   help="query supported algorithms like ssh -Q (cipher, mac, kex, key)")
    p.add_argument("-i", dest="identity", action="append", default=[])
    p.add_argument("--cert", default=None, help="OpenSSH certificate file (~-cert.pub)")
    p.add_argument("-o", dest="options", action="append", default=[],
                   help="-o KexAlgorithms=.. -o Ciphers=.. -o MACs=.. -o HostKeyAlgorithms=.. -o ConnectTimeout=.. -o StrictHostKeyChecking=.. -o UserKnownHostsFile=.. (unknown options fail)")
    p.add_argument("-J", dest="jump", default=None,
                   help="jump host [user@]host[:port], comma chains allowed (ProxyJump)")
    p.add_argument("-L", dest="local_fwd", action="append", default=[],
                   help="local forward [bind:]port:host:port (shares the connection)")
    p.add_argument("-R", dest="remote_fwd", action="append", default=[],
                   help="remote forward [bind:]port:host:port (shares the connection)")
    p.add_argument("-N", action="store_true", help="no remote command (verify/forward mode)")
    p.add_argument("-v", action="count", default=0)
    p.add_argument("-q", action="count", default=0, help="quiet: hush info/diagnostic output")
    p.add_argument("-4", dest="family", action="store_const", const=socket.AF_INET, default=0, help="IPv4 only")
    p.add_argument("-6", dest="family", action="store_const", const=socket.AF_INET6, help="IPv6 only")
    p.add_argument("-t", dest="force_tty", action="store_true", help="force pty allocation (with a command: run it on a pty)")
    p.add_argument("-T", dest="no_pty", action="store_true", help="disable pty allocation for the interactive shell")
    p.add_argument("-n", dest="stdin_null", action="store_true", help="redirect stdin from /dev/null (shell sessions; exec has no stdin)")
    p.add_argument("-V", dest="version", action="store_true", help="print version")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--host-policy", default="strict", choices=["strict", "accept-new", "ask", "off"])
    p.add_argument("--known-hosts", default=None)
    p.add_argument("--password-env", default=None, help="environment variable holding the password")
    return p


def _local_user() -> str:
    """Best-effort local login name ($USER is often unset, e.g. on Termux)."""
    for var in ("USER", "LOGNAME", "USERNAME"):
        u = os.environ.get(var)
        if u:
            return u
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return ""


def parse_destination(dest: str, login_opt: str | None) -> tuple[str, str]:
    if "@" in dest:
        u, h = dest.rsplit("@", 1)
    elif login_opt:
        h, u = dest, login_opt
    else:
        h, u = dest, _local_user()
    if len(h) > 2 and h.startswith("[") and h.endswith("]"):
        h = h[1:-1]  # user@[::1] like ssh
    return h, u


def _valid_port(p: int) -> bool:
    return isinstance(p, int) and 1 <= p <= 65535


def parse_o_options(opts: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for o in opts:
        if "=" not in o:
            raise UsageError(f"bad -o {o!r}, expected -o Key=Value")
        k, v = o.split("=", 1)
        # OpenSSH option names are case-insensitive; normalise to lower.
        out[k.strip().lower()] = v.strip()
    return out


_KNOWN_O_OPTIONS = frozenset({
    "kexalgorithms", "ciphers", "macs", "hostkeyalgorithms",
    "connecttimeout", "stricthostkeychecking", "userknownhostsfile",
})


def _check_known_options(o_opts: dict[str, str]) -> None:
    """Unknown -o keys fail loudly (a typo like StricHostKeyChecking must
    never silently keep the strict default, nor weaken it)."""
    for k in o_opts:
        if k not in _KNOWN_O_OPTIONS:
            print(f"ccssh: Bad configuration option: {k}", file=sys.stderr)
            raise UsageError(f"unknown -o option {k!r}")


# Options taking a separate value (also accepted as -xVALUE / --opt=VALUE).
_VALUE_OPTS = frozenset({
    "-p", "-l", "-c", "-m", "-Q", "-i", "--cert", "-o", "-J", "-L", "-R",
    "--timeout", "--host-policy", "--known-hosts", "--password-env",
})
# Value-less short flags (may cluster: -vv, -vN, -qt).
_FLAG_OPTS = frozenset({"-v", "-N", "-4", "-6", "-q", "-t", "-T", "-n", "-V"})


def _expand_cluster(token: str) -> list[str]:
    """
     Split a short-option cluster: -vv -> [-v, -v], -vp2222 -> [-v, -p2222].
     Anything else (attached values like -p2022, unknowns) passes through
     untouched for _option_kind/argparse to handle.
    """
    if len(token) <= 2 or not token.startswith("-") or token.startswith("--"):
        return [token]
    if all("-" + ch in _FLAG_OPTS for ch in token[1:]):
        return ["-" + ch for ch in token[1:]]
    j = 1
    while j < len(token) and "-" + token[j] in _FLAG_OPTS:
        j += 1
    if j > 1 and j < len(token) and "-" + token[j] in _VALUE_OPTS:
        return ["-" + token[k] for k in range(1, j)] + ["-" + token[j:]]
    return [token]


def _option_kind(token: str) -> str:
    """
     Classify an option-looking token: 'separate' (value is the next argv
     item), 'none' (standalone flag / attached value), or 'unknown' (left for
     argparse to report, like ssh reports unknown options).
    """
    if token.startswith("--"):
        name = "--" + token[2:].split("=", 1)[0]
        if name not in _VALUE_OPTS and name not in ("--version", "--help"):
            return "unknown"
        if "=" in token or name not in _VALUE_OPTS:
            return "none"
        return "separate"
    if len(token) == 2:
        if token in _VALUE_OPTS:
            return "separate"
        return "none" if token in _FLAG_OPTS else "unknown"
    if all("-" + ch in _FLAG_OPTS for ch in token[1:]):
        return "none"  # -vv, -vN, ...
    if "-" + token[1] in _VALUE_OPTS:
        return "none"  # attached value: -p2022, -i/tmp/key
    return "unknown"


def split_argv(argv: list[str] | None) -> tuple[list[str], str | None, list[str]]:
    """
     SSH-style split: (option tokens, destination|None, command words).

     Like OpenSSH (verified against `ssh -G`): options are recognized before
     AND after the destination; after the destination, option parsing stops
     at the first non-option word (or `--`), and everything from there -
     even `-p 2022` - is the remote command, verbatim. So both
     `ccssh -p 2022 user@host` and `ccssh user@host -p 2022` connect to
     port 2022 with no command, while `ccssh user@host echo -p x` runs
     `echo -p x` remotely.
    """
    argv = list(argv or [])
    opts: list[str] = []
    dest: str | None = None
    i, n = 0, len(argv)
    # Phase 1: options until the destination (first bare word).
    while i < n:
        a = argv[i]
        if a == "--":
            i += 1
            if i < n:
                dest = argv[i]
                i += 1
            break
        if len(a) > 1 and a.startswith("-"):
            i = _take_options(argv, i, opts)
            continue
        dest = a
        i += 1
        break
    # Phase 2: leading options still parse; first bare word starts the command.
    while i < n:
        a = argv[i]
        if a == "--":
            i += 1
            break
        if len(a) > 1 and a.startswith("-"):
            i = _take_options(argv, i, opts)
            continue
        break
    return opts, dest, argv[i:]


def _take_options(argv: list[str], i: int, opts: list[str]) -> int:
    """
     Consume one option (cluster-expanded) at argv[i] into opts, plus its
     separate value if it takes one. Returns the next index. Unknown options
     pass through for argparse to report; a missing value is also left for
     argparse ("expected one argument").
    """
    for tok in _expand_cluster(argv[i]):
        opts.append(tok)
        if _option_kind(tok) == "separate":
            i += 1
            if i >= len(argv):
                return i
            opts.append(argv[i])
    return i + 1


def _parse_L(spec: str, default_bind: str = "127.0.0.1") -> tuple[int, str, int, str]:
    """
     [bind:]lport:rhost:rport -> (lport, rhost, rport, bind).
     rhost may be bare IPv6 (split from the right) or bracketed, and so
     may bind: [::1]:8080:[2001:db8::1]:80. Anything ambiguous without
     brackets is rejected with a clean usage error (exit 2, no traceback).
     `default_bind` applies when the spec carries none: OpenSSH sends
     "localhost" for -R (servers like serveo.net match it literally).
    """
    rest, bind = spec, default_bind
    if rest.startswith("["):
        end = rest.find("]")
        if end < 0 or not rest[end + 1:].startswith(":"):
            raise UsageError(f"bad -L {spec!r}, expected [bind:]port:host:port")
        bind, rest = rest[1:end], rest[end + 2:]
    parts = rest.split(":")
    try:
        if len(parts) == 3 and "[" not in rest:
            lp, rh, rp = parts
        elif len(parts) == 4 and "[" not in rest:
            bind, lp, rh, rp = parts
        elif len(parts) >= 3:
            lp, rp = parts[0], parts[-1]
            rh = ":".join(parts[1:-1])
            if rh.startswith("[") and rh.endswith("]"):
                rh = rh[1:-1]
        else:
            raise UsageError(f"bad -L {spec!r}, expected [bind:]port:host:port")
        lport, rport = int(lp), int(rp)
        if not _valid_port(lport) or not _valid_port(rport) or not rh or not bind:
            raise ValueError("bad port/host")
        return lport, rh, rport, bind
    except ValueError:
        raise UsageError(f"bad -L {spec!r}, expected [bind:]port:host:port") from None


def parse_jump(spec: str, default_user: str) -> tuple[str, str, int]:
    """
     [user@]host[:port] for -J (single hop; see parse_jump_chain).
    """
    host, user = parse_destination(spec, default_user)
    port = 22
    m = re.match(r"^\[(.*)\](?::(\d+))?$", host)
    if m:
        host, port = m.group(1), int(m.group(2) or 22)
    elif host.count(":") == 1:
        maybe_h, maybe_p = host.rsplit(":", 1)
        if maybe_p.isdigit():
            host, port = maybe_h, int(maybe_p)
    if not _valid_port(port) or not host or not user:
        raise UsageError(f"bad -J {spec!r}, expected [user@]host[:port]")
    return host, user, port


def parse_jump_chain(spec: str, default_user: str) -> list[tuple[str, str, int]]:
    """Comma-separated -J hops, left to right (OpenSSH ProxyJump chains)."""
    parts = [p.strip() for p in spec.split(",")]
    if not parts or not all(parts):
        raise UsageError(f"bad -J {spec!r}, expected [user@]host[:port][,...]")
    return [parse_jump(p, default_user) for p in parts]


def _needs_passphrase(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return "encrypted" in msg or "password was not given" in msg or "passphrase" in msg


class _KbdintAbort(Exception):
    """User aborted a keyboard-interactive prompt: stop logging in at once."""


def default_identities() -> list[str]:
    """Default key files like OpenSSH (only ones that exist on disk)."""
    cands = ["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519",
             "id_ed25519_sk", "id_mldsa44_ed25519"]
    out = []
    for name in cands:
        p = os.path.expanduser(f"~/.ssh/{name}")
        try:
            if os.path.isfile(p):
                out.append(p)
        except Exception:
            pass
    return out


def _prompt(text: str) -> str | None:
    try:
        return getpass.getpass(text)
    except (EOFError, KeyboardInterrupt):
        return None


def _make_ask_callback():
    """yes/no prompter for StrictHostKeyChecking=ask (ssh-like)."""
    def _ask(prompt_text: str) -> str:
        try:
            ans = input(prompt_text + " ")
        except (EOFError, KeyboardInterrupt):
            raise _KbdintAbort()
        return ans
    return _ask


def _run_query(kind: str) -> None:
    """Print supported algorithms like `ssh -Q` (plus help)."""
    from ccssh import algs
    key = kind.strip().lower().replace("_", "-")
    table = {
        "cipher": algs.SUPPORTED_CIPHERS,
        "cipher-auth": [c for c in algs.SUPPORTED_CIPHERS
                        if "gcm" in c or "poly1305" in c],
        "compression": ["none"],
        "mac": algs.SUPPORTED_MACS,
        "kex": algs.SUPPORTED_KEX,
        "key": algs.SUPPORTED_HOSTKEYS,
        "key-cert": [k for k in algs.OPENSSH_KEYS if "cert" in k],
        "key-plain": [k for k in algs.SUPPORTED_HOSTKEYS],
        "key-sig": sorted({k.replace("-cert-v01@openssh.com", "").replace("-cert", "")
                           for k in algs.OPENSSH_KEYS}),
        "protocol-version": ["2"],
        "sig": sorted({k.replace("-cert-v01@openssh.com", "").replace("-cert", "")
                       for k in algs.OPENSSH_KEYS}),
    }
    if key == "help":
        for name in table:
            print(name)
        return
    names = table.get(key)
    if names is None:
        print(f"ccssh: Unsupported query '{kind}' (try -Q help)", file=sys.stderr)
        raise UsageError(f"bad -Q {kind!r}")
    for name in names:
        print(name)


def _preflight_tcp(host: str, port: int, family: int, timeout: float) -> None:
    """Fail fast if the server TCP port is unreachable — before any prompt.

    Without this, the password loop prompts first and only then dials,
    so a dead server asks for a password and *then* reports
    'Connection refused'. A quick dial here surfaces the network error
    immediately (OpenSSH behaviour).
    """
    try:
        infos = socket.getaddrinfo(host, port, family=family or socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError as e:
        from ccssh.transport import CCSSHError
        raise CCSSHError(f"connect {host}:{port}: {e}") from e
    if not infos:
        from ccssh.transport import CCSSHError
        raise CCSSHError(f"connect {host}:{port}: no addresses")
    last: OSError | None = None
    for af, st, proto, _canon, sa in infos:
        s: socket.socket | None = None
        try:
            s = socket.socket(af, st, proto)
            s.settimeout(timeout)
            s.connect(sa)
            return  # reachable
        except OSError as e:
            last = e
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    from ccssh.transport import CCSSHError
    raise CCSSHError(f"connect {host}:{port}: {last}")


def _connect_first_working(client_opts: dict, host: str, *, port: int, username: str, password: str | None, identities: list[str], cert: str | None, verbose: int, prompt: bool = False, family: int = 0, quiet: bool = False, sock_factory: Callable[[], object] | None = None) -> CCSSHClient:
    """
     Try each -i identity in turn, then password (like OpenSSH).

     With prompt=True (a terminal), ask for key passphrases and retry the
     password up to 3 times, printing `user@host's password:` like ssh does.
     quiet hushes the diagnostic lines (ssh -q); prompts still show.
     sock_factory dials a fresh channel socket per attempt (-J tunnels).
    """
    say = verbose and not quiet
    last: Exception | None = None
    key_attempts: list[tuple[str | None, str | None]] = ([(key, None) for key in identities] if cert is None else [(key, cert) for key in identities] or [(None, cert)])
    passphrase: str | None = None
    for key, cert_file in key_attempts:
        for _ in range(2 if (prompt and key) else 1):
            c = CCSSHClient(**client_opts)
            s = sock_factory() if sock_factory else None
            if say:
                print(f"debug1: trying identity {key}" + (f" + cert {cert_file}" if cert_file else ""), file=sys.stderr)
            try:
                c.connect(host, port=port, username=username, password=None, key_filename=key, cert_filename=cert_file, passphrase=passphrase, family=family, sock=s)
                if say:
                    print(f"debug1: identity {key} accepted", file=sys.stderr)
                return c
            except AuthError as e:
                last = e
                try:
                    c.close()
                except Exception:
                    pass
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                if prompt and key and passphrase is None and _needs_passphrase(e):
                    passphrase = _prompt(f"Enter passphrase for key '{key}': ")
                    if passphrase is None:
                        raise AuthError("no authentication method") from e
                    continue
                if say:
                    print(f"ccssh: identity {key} rejected ({e}), trying next", file=sys.stderr)
                passphrase = None
                break
            except (OSError, ValueError) as e:
                # Unreadable key file, FIDO2 token missing, unsupported key
                # type: never abort the whole login over one -i (ssh warns
                # and moves on to the next method).
                last = e
                try:
                    c.close()
                except Exception:
                    pass
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
                if say:
                    print(f"ccssh: identity {key} unusable ({e}), trying next", file=sys.stderr)
                passphrase = None
                break
    pw = password
    # Fail fast on dead servers: check TCP reachability BEFORE prompting.
    # (Key attempts dial inside connect() and already fail fast; the
    # password path used to prompt first and report 'refused' afterwards.)
    if pw is None and prompt and sock_factory is None and not key_attempts:
        _preflight_tcp(host, port, family, client_opts.get("timeout", 10.0))

    def _kbdint_responder(prompts):
        # ssh-like: zero prompts are answered silently; each real prompt
        # is shown verbatim (no added prefix). Aborting raises out to
        # stop the whole login flow immediately.
        answers = []
        for text, echo in prompts:
            if not prompt:
                return []
            try:
                if echo:
                    ans = input(text or "(server prompt) ")
                else:
                    ans = _prompt(text or "(server prompt) ")
            except (EOFError, KeyboardInterrupt):
                ans = None
            if ans is None:
                raise _KbdintAbort()
            answers.append(ans)
        return answers

    # Keyboard-interactive FIRST (like ssh): servers with zero prompts
    # (e.g. serveo.net free tier) authenticate with no questions at all.
    c = CCSSHClient(**client_opts)
    s = sock_factory() if sock_factory else None
    if say:
        print(f"debug1: trying keyboard-interactive auth as {username}", file=sys.stderr)
    try:
        c.connect(host, port=port, username=username, password=None,
                  key_filename=None, cert_filename=None, family=family, sock=s,
                  kbdint_responder=_kbdint_responder)
        if say:
            print(f"debug1: keyboard-interactive auth accepted", file=sys.stderr)
        return c
    except _KbdintAbort:
        try:
            c.close()
        except Exception:
            pass
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        raise AuthError("no authentication method (aborted during keyboard-interactive)")
    except AuthError as e:
        last = e
        try:
            c.close()
        except Exception:
            pass
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        if say:
            print(f"debug1: keyboard-interactive not accepted ({e})", file=sys.stderr)
    tried_password = False
    for _ in range(3 if prompt else 1):
        if pw is None and prompt:
            pw = _prompt(f"{username}@{host}'s password: ")
            if pw is None:
                break
        c = CCSSHClient(**client_opts)
        s = sock_factory() if sock_factory else None
        if say:
            print(f"debug1: trying password auth as {username}", file=sys.stderr)
        try:
            c.connect(host, port=port, username=username, password=pw, key_filename=None, cert_filename=None, family=family, sock=s)
            if say:
                print(f"debug1: password auth accepted", file=sys.stderr)
            return c
        except AuthError as e:
            last = e
            tried_password = tried_password or pw is not None
            try:
                c.close()
            except Exception:
                pass
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            if not prompt:
                break
            if say:
                print("ccssh: password rejected, trying again", file=sys.stderr)
            pw = None  # force a fresh prompt
            continue
    if not tried_password and pw is None and last is not None and "publickey" in str(last):
        # The user aborted before any password attempt: report that, not a
        # stale key-phase error.
        raise AuthError("no authentication method (aborted before password auth)")
    raise last if last is not None else AuthError("no authentication method")


def _report_connect_error(e: BaseException) -> None:
    """
      Print a connection failure. A changed host key gets the big
      OpenSSH-style REMOTE HOST IDENTIFICATION banner (with the offending
      file:line and both fingerprints, which travel inside the message).
    """
    msg = str(e)
    if "HOST KEY CHANGED" in msg:
        bar = "@" * 60
        print(bar, file=sys.stderr)
        print("@     WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @", file=sys.stderr)
        print(bar, file=sys.stderr)
        print("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!", file=sys.stderr)
        print("The host key of this server changed since the last connection.", file=sys.stderr)
        print("This may mean a man-in-the-middle attack, a reinstalled server,", file=sys.stderr)
        print("or (rarely) a legitimate key rotation. Do NOT accept it blindly.", file=sys.stderr)
    print(f"ccssh: connect: {msg}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    from ccssh import algs
    opt_tokens, dest, command = split_argv(argv if argv is not None else sys.argv[1:])
    rest: list[str] = list(opt_tokens)
    if dest is not None:
        # Guard a dashy destination (only reachable via `--`) from
        # being re-parsed as an option by argparse.
        rest += ["--", dest] if dest.startswith("-") else [dest]
    try:
        # Strict: unknown options fail here (exit 255) instead of being
        # misparsed as destinations/commands downstream.
        args = build_parser().parse_args(rest)
    except UsageError as e:
        print(f"ccssh: {e}", file=sys.stderr)
        return 255
    args.command = command
    try:
        return _main_inner(args, opt_tokens)
    except UsageError as e:
        print(f"ccssh: {e}", file=sys.stderr)
        return 255
    except BrokenPipeError:
        return 141  # dying of SIGPIPE anywhere (like `... | head`)


def _main_inner(args, opt_tokens: list[str]) -> int:
    from ccssh import algs
    # -t/-T: last one wins (like ssh), not a conflict.
    for tok in opt_tokens:
        if tok == "-t":
            args.force_tty, args.no_pty = True, False
        elif tok == "-T":
            args.force_tty, args.no_pty = False, True
    if args.version:
        from ccssh import __version__
        try:
            print(f"ccssh {__version__}", file=sys.stderr)
        except BrokenPipeError:
            return 141
        return 0
    if args.query:
        try:
            _run_query(args.query)
        except UsageError as e:
            print(f"ccssh: {e}", file=sys.stderr)
            return 255
        except BrokenPipeError:
            return 141
        return 0
    if not args.destination:
        print("ccssh: need destination [user@]hostname", file=sys.stderr)
        return 255
    if not _valid_port(args.port):
        print(f"ccssh: bad port {args.port!r} (must be 1..65535)", file=sys.stderr)
        return 255
    host, user = parse_destination(args.destination, args.login)
    if not host or any(c.isspace() or ord(c) < 32 for c in host):
        print(f"ccssh: bad destination {args.destination!r}", file=sys.stderr)
        return 255
    if not user or any(c.isspace() or ord(c) < 32 for c in user):
        print(f"ccssh: no username for {host!r} (use user@host or -l login)",
              file=sys.stderr)
        return 255
    o_opts = parse_o_options(args.options)
    _check_known_options(o_opts)
    # -o wins, then -c/-m flags, then built-in defaults.
    # Comma lists replace; +alg/-alg/^alg are relative to the defaults.
    kex = algs.expand_alg_option(algs.SUPPORTED_KEX, o_opts.get("kexalgorithms", ",".join(algs.SUPPORTED_KEX)))
    ciphers = algs.expand_alg_option(algs.SUPPORTED_CIPHERS, o_opts.get("ciphers") or args.cipher_spec or ",".join(algs.SUPPORTED_CIPHERS))
    macs = algs.expand_alg_option(algs.SUPPORTED_MACS, o_opts.get("macs") or args.mac_spec or ",".join(algs.SUPPORTED_MACS))
    hostkeys = algs.expand_alg_option(algs.SUPPORTED_HOSTKEYS, o_opts.get("hostkeyalgorithms", ",".join(algs.SUPPORTED_HOSTKEYS)))
    try:
        timeout = float(o_opts.get("connecttimeout", args.timeout))
    except ValueError:
        print(f"ccssh: bad ConnectTimeout {o_opts.get('connecttimeout')!r}", file=sys.stderr)
        return 255
    if not (isinstance(timeout, float) and 0 < timeout <= 600):
        print(f"ccssh: bad ConnectTimeout {timeout!r} (must be 0..600s)", file=sys.stderr)
        return 255
    _policy_raw = o_opts.get("stricthostkeychecking", args.host_policy)
    _policy_map = {"yes": "strict", "strict": "strict", "ask": "ask",
                   "accept-new": "accept-new", "no": "off", "off": "off"}
    _norm = str(_policy_raw).lower()
    if _norm not in _policy_map:
        print(f"ccssh: bad StrictHostKeyChecking {_policy_raw!r} "
              f"(must be yes|ask|accept-new|no)", file=sys.stderr)
        return 255
    policy = _policy_map[_norm]
    known = o_opts.get("userknownhostsfile", args.known_hosts)
    if known is not None:
        known = os.path.expandvars(os.path.expanduser(known))
        if not known.strip():
            print("ccssh: bad UserKnownHostsFile (empty)", file=sys.stderr)
            return 255
    if args.password_env and not args.password_env.isidentifier():
        print(f"ccssh: bad --password-env {args.password_env!r}", file=sys.stderr)
        return 255
    password = os.environ.get(args.password_env) if args.password_env else None
    if args.password_env and not args.q:
        print("ccssh: warning: --password-env leaks via process environ; "
              "prefer interactive prompt", file=sys.stderr)
    if policy == "off" and not args.q:
        print("ccssh: WARNING: host key verification is OFF (MitM possible)",
              file=sys.stderr)
    say = args.v >= 1 and not args.q
    say2 = args.v >= 2 and not args.q
    # -t/-T: last one wins (like ssh), never a conflict. The raw token
    # stream preserves order; argparse booleans cannot.
    for _tok in opt_tokens:
        if _tok == "-t":
            args.force_tty, args.no_pty = True, False
        elif _tok == "-T":
            args.force_tty, args.no_pty = False, True
    # OpenSSH-style negotiation summary. -v: one line + policy warning.
    # -vv: full offers, timeouts, jump info (client._log adds per-step debug).
    if say:
        print(f"debug1: Connecting to {host} [{args.port}] as {user}", file=sys.stderr)
        print(f"debug1: kex {kex[0]} cipher {ciphers[0]} mac {macs[0]} hostkey {hostkeys[0]} policy {policy}", file=sys.stderr)
    if say2:
        print(f"debug2: KEX offer: {','.join(kex)}", file=sys.stderr)
        print(f"debug2: cipher offer: {','.join(ciphers)}", file=sys.stderr)
        print(f"debug2: mac offer: {','.join(macs)}", file=sys.stderr)
        print(f"debug2: hostkey offer: {','.join(hostkeys)}", file=sys.stderr)
        print(f"debug2: timeout={timeout}s known_hosts={known or '~/.ssh/known_hosts'}", file=sys.stderr)
    if args.local_fwd and args.remote_fwd:
        print("ccssh: -L and -R cannot share one connection "
              "(one forwarder per connection)", file=sys.stderr)
        return 255
    if args.N and args.command:
        print("ccssh: cannot execute command with -N", file=sys.stderr)
        return 255
    is_tty = sys.stdin.isatty()
    # ask policy needs a prompt hook (tty only; scripts fail closed).
    ask_cb = _make_ask_callback() if (policy == "ask" and is_tty) else None
    client_opts = dict(timeout=timeout, known_hosts=known, host_policy=policy, kex=kex, ciphers=ciphers, macs=macs, hostkeys=hostkeys, verbose=args.v if not args.q else 0, ask_callback=ask_cb)
    # Like OpenSSH: with no -i, offer the default ~/.ssh keys first and
    # only then fall back to the password prompt.
    identities = args.identity or default_identities()
    if say2 and identities != args.identity:
        print(f"debug2: default identities: {','.join(identities) or '(none found)'}",
              file=sys.stderr)
    if say2 and identities != args.identity:
        print(f"debug2: default identities: {','.join(identities) or '(none found)'}",
              file=sys.stderr)
    jump_clients: list = []
    sock_factory = None
    if args.jump:
        hops = parse_jump_chain(args.jump, user)
        prev = None
        try:
            for jhost, juser, jport in hops:
                if say:
                    print(f"debug1: via jump {juser}@{jhost}:{jport}", file=sys.stderr)
                if prev is None:
                    hop_factory = None
                else:
                    _prev = prev
                    _jh, _jp = jhost, jport
                    hop_factory = lambda _p=_prev, _h=_jh, _pt=_jp: _p.open_channel_socket(_h, _pt)
                jc = _connect_first_working(client_opts, jhost, port=jport, username=juser, password=password, identities=identities, cert=args.cert, verbose=args.v, prompt=is_tty, family=args.family, quiet=bool(args.q), sock_factory=hop_factory)
                jump_clients.append(jc)
                prev = jc
        except Exception as e:
            for jc in jump_clients:
                try:
                    jc.close()
                except Exception:
                    pass
            print(f"ccssh: jump: {e}", file=sys.stderr)
            return 255
        jump_client = prev
        sock_factory = lambda: jump_client.open_channel_socket(host, args.port)
    try:
        c = _connect_first_working(client_opts, host, port=args.port, username=user, password=password, identities=identities, cert=args.cert, verbose=args.v, prompt=is_tty, family=args.family, quiet=bool(args.q), sock_factory=sock_factory)
    except AuthError as e:
        for _jc in jump_clients:
            try:
                _jc.close()
            except Exception:
                pass
        print(f"ccssh: Permission denied: {e}", file=sys.stderr)
        return 255
    except Exception as e:
        for _jc in jump_clients:
            try:
                _jc.close()
            except Exception:
                pass
        _report_connect_error(e)
        return 255
    active = []
    try:
        for spec in args.local_fwd:
            lport, rhost, rport, bind = _parse_L(spec)
            fwd = c.forward_local(lport, rhost, rport, bind=bind)
            active.append(fwd)
            if say:
                print(f"debug1: -L {bind}:{fwd.port}:{rhost}:{rport}", file=sys.stderr)
        for spec in args.remote_fwd:
            sport, rhost, rport, bind = _parse_L(spec, default_bind="localhost")
            fwd = c.forward_remote(sport, rhost, rport, bind=bind)
            active.append(fwd)
            if say:
                print(f"debug1: -R {bind}:{fwd.port}:{rhost}:{rport}", file=sys.stderr)
    except Exception as e:
        print(f"ccssh: forward: {e}", file=sys.stderr)
        c.close()
        for _jc in jump_clients:
            try:
                _jc.close()
            except Exception:
                pass
        return 255
    if args.N:
        if say:
            neg = c.negotiated()
            print(f"debug1: connected cipher={neg['cipher']} kex={neg['kex']} mac={neg['mac']} strict={neg['strict']}", file=sys.stderr)
        if active:
            print("ccssh: forwards active, Ctrl-C to exit", file=sys.stderr)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        c.close()
        for _jc in jump_clients:
            try:
                _jc.close()
            except Exception:
                pass
        return 0
    devnull = open(os.devnull, "rb") if args.stdin_null else None
    stdin_fd = devnull.fileno() if devnull is not None else None
    from ccssh import shell as _shell_mod

    def _run_shell(**kw) -> int:
        try:
            return _shell_mod.run_interactive(c, stdin_fd=stdin_fd, **kw)
        except Exception as e:
            print(f"ccssh: shell: {e}", file=sys.stderr)
            return 255
        finally:
            c.close()
            for _jc in jump_clients:
                try:
                    _jc.close()
                except Exception:
                    pass
            if devnull is not None:
                devnull.close()

    if args.command:
        if args.force_tty:  # -t: pty exec, output streams over the terminal
            return _run_shell(command=" ".join(args.command), pty=True)
        cmd = " ".join(args.command)
        try:
            out, err, code = c.exec_command(cmd, raw_bytes=True)
        except Exception as e:
            print(f"ccssh: exec: {e}", file=sys.stderr)
            return 255
        finally:
            c.close()
            for _jc in jump_clients:
                try:
                    _jc.close()
                except Exception:
                    pass
            if devnull is not None:
                try:
                    devnull.close()
                except Exception:
                    pass
        try:
            sys.stdout.buffer.write(out)
            sys.stderr.buffer.write(err)
            sys.stdout.buffer.flush()
            sys.stderr.buffer.flush()
        except BrokenPipeError:
            return 141 # like dying of SIGPIPE under `... | head`
        return code
    # No command and no -N: interactive shell, like `ssh host`.
    return _run_shell(pty=not args.no_pty)
