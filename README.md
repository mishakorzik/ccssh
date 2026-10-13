# Concurrent-Channels SSH

From-scratch SSH-2 client in Python (sync + async + CLI), verified against
real OpenSSH servers - including post-quantum `mlkem768x25519-sha256` KEX
and `ssh-mldsa44-ed25519` host/user keys.

```bash
pip install ccssh
ccssh user@host         # interactive shell
ccssh user@host uptime  # one command
python -m ccssh user@host -N -L 8080:127.0.0.1:80
```

See `tests/test_live_sshd.py` for the live interop proof matrix.

## CLI

Options work before or after the destination (`ccssh -p 2022 h` and
`ccssh h -p 2022` are the same); the first bare word is the destination,
everything after it is the remote command, verbatim.

```bash
ccssh -4 -i ./id_ed25519 he1zen@host -p 2022        # shell over IPv4 with a key
ccssh he1zen@host -p 2022 uptime                    # one command, port after host
ccssh -t he1zen@host htop                           # command on a pty
ccssh -T he1zen@host                                # shell without pty
ccssh -N -L 8080:127.0.0.1:80 he1zen@host           # local forwarding only
ccssh -L 8080:127.0.0.1:80 he1zen@host              # forward + shell (shared connection)
ccssh -R 8080:127.0.0.1:80 he1zen@host uptime       # forward + one command
ccssh -N -R 2022:127.0.0.1:22 he1zen@host           # remote forwarding only
ccssh -J jumpuser@jumphost he1zen@target            # ProxyJump (comma chains ok)
ccssh -q he1zen@host 'echo quiet'                   # quiet: no info output
ccssh -n he1zen@host < script.sh                    # stdin from /dev/null
ccssh -v he1zen@host                                # verbose: debug1 progress
ccssh -vv he1zen@host                               # debug2: full offers + traces
ccssh -V                                            # version
ccssh -l he1zen -p 2022 host                        # explicit login + port
ccssh --cert ~/.ssh/id_ed25519-cert.pub -i ~/.ssh/id_ed25519 he1zen@host
ccssh --password-env SSHPASS he1zen@host            # password from env (never argv)
ccssh -o KexAlgorithms=curve25519-sha256 -o Ciphers=aes256-ctr \
      -o MACs=hmac-sha2-512 -o HostKeyAlgorithms=ssh-ed25519 \
      -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile=~/.ssh/known_hosts he1zen@host
ccssh -c aes256-ctr -m hmac-sha2-512 he1zen@host    # like ssh -c/-m
ccssh -o HostKeyAlgorithms=+ssh-dss he1zen@oldbox   # append to the default set
ccssh -Q cipher                                     # list supported ciphers (mac, kex, key too)
```

No password or key given on a terminal? ccssh prompts
(`he1zen@host's password:`), retrying up to 3 times; encrypted `-i` keys
prompt for their passphrase. Without a terminal it fails fast instead of
hanging - use `--password-env` for scripts.

## Sync client

```python
from ccssh import CCSSHClient

with CCSSHClient() as c:
    c.connect("host", username="user", password="secret")
    print(c.exec_command("uptime")) # (stdout, stderr, exit_status)
    print(c.exec_command("cat disk.iso", raw_bytes=True)) # bytes, no decoding
```

All `connect()` options:

```python
c = CCSSHClient(
    timeout=10.0,                      # socket/connect timeout, seconds
    known_hosts="~/.ssh/known_hosts",  # None -> default path
    host_policy="strict",              # strict | accept-new | off
    kex=["curve25519-sha256"],         # any subset of algs.SUPPORTED_KEX
    ciphers=["aes256-ctr"],            # any subset of algs.SUPPORTED_CIPHERS
    macs=["hmac-sha2-512"],            # any subset of algs.SUPPORTED_MACS
    hostkeys=["ssh-ed25519"],          # any subset of algs.SUPPORTED_HOSTKEYS
    rekey_bytes=4 * 1024**3,           # auto-rekey after this much traffic
    rekey_interval=3600.0,             # ... or this many seconds
)
c.connect("host", port=2222, username="user",
          password="secret",                # or key_filename= / cert_filename=
          key_filename="~/.ssh/id_ed25519",
          passphrase="key-passphrase",      # for encrypted keys
          cert_filename="~/.ssh/id_ed25519-cert.pub",
          family=0)                         # 0:any, socket.AF_INET (-4), AF_INET6 (-6)
print(c.negotiated())  # {"cipher": ..., "mac": ..., "strict": ...}
c.close()
```

Key auth tries each `-i`/`key_filename` in turn, then falls back to the
password - like OpenSSH. If the password method fails, the same secret
is tried via keyboard-interactive (RFC 4256, capped rounds/prompts):
servers like serveo.net that only offer `keyboard-interactive` work with
no extra flags. Certificates pass through opaquely from the
`ssh-ed25519-cert-v01@openssh.com` file (user certs) and are verified
against `@cert-authority` lines in known_hosts (host certs).

Host-key policies: `strict` refuses unknown/changed keys (hashed
known_hosts entries supported), `accept-new` adds unknown hosts,
`ask` prompts on unknown hosts (tty only, fail-closed otherwise),
`off` skips verification (tests only). `UserKnownHostsFile` accepts a
list and the magic name `none`; unknown `-o` keys fail loudly.

Exit codes follow ssh: `0` ok, `255` everything else (usage, auth
`Permission denied`, connect/forward failures), `141` on broken pipe,
remote exit status passed through for commands.

## SFTP (v3)

Bytes in, bytes out - encode text yourself:

```python
s = c.open_sftp()
s.realpath("/")            # canonical path, ends with "/"
s.mkdir("/sub")            # mode= kwarg, default 0o755
s.put("/sub/f.bin", data)  # mode= kwarg, default 0o644
s.stat("/sub/f.bin")       # {"size": ..., "mtime": ..., ...}
s.listdir("/sub")          # ["f.bin"]
assert s.get("/sub/f.bin") == data
s.remove("/sub/f.bin")
s.close()                  # closes the subsystem channel
```

Text files, error handling, big downloads:

```python
s.put("/notes.txt", "привіт\n".encode())
text = s.get("/notes.txt").decode()

from ccssh.sftp import SFTPError
try:
    s.get("/missing")
except SFTPError as e:     # status code + server message, never silent
    print("failed:", e)

big = s.get("/disk.iso", max_bytes=4 * 1024**3)  # cap a runaway server
```

`put` overwrites (`CREAT|TRUNC`) and splits into ~32KB chunks for the
server window automatically; `get` streams in 32KB reads (a mid-transfer
server error raises instead of truncating silently).

Recipes - `mkdir -p` and a recursive walk:

```python
def mkdir_p(s, path):
    parts, cur = [p for p in path.split("/") if p], ""
    for p in parts:
        cur += "/" + p
        try:
            s.mkdir(cur)
        except SFTPError:  # exists (or no permission - then the put fails next)
            pass

def walk(s, path):
    """Yield (dirpath, filenames) like os.walk."""
    yield path, s.listdir(path)

mkdir_p(s, "/a/b/c")
s.put("/a/b/c/f.txt", b"x")
for dirpath, names in walk(s, "/a"):
    print(dirpath, names)
```

## Interactive shell

```python
from ccssh import shell as SH

code = SH.run_interactive(c)                 # ssh-like shell, returns exit status
code = SH.run_interactive(c, pty=False)      # ssh -T: no pty
code = SH.run_interactive(c, command="htop") # ssh -t: pty exec
```

Ctrl+D exits (the remote shell sees EOF and closes; no hanging, no
Ctrl+C needed). Idle sessions stay up: steady-state read timeouts send
SSH IGNORE keepalives instead of dropping (like OpenSSH); handshake and
SFTP window waits still fail fast on a dead peer. Terminal goes to raw
and is always restored. Programmatic use without a terminal:

```python
sess = c.open_shell(cols=80, rows=24) # pty + shell
sess = c.open_shell(pty=False)        # shell without pty
sess = c.open_shell(command="top")    # pty exec channel
sess.send(b"echo hi\n")               # stdin bytes (window-aware)
sess.send_eof()                       # half-close stdin
sess.window_change(132, 50)           # terminal resize
sess.close()                          # send CLOSE, returns last exit status or None
print(sess.exit_status, sess.eof_received, sess.no_pty)
```

Read server output from `sess._client._t.recv_packet()` and parse
`CHANNEL_DATA` / `CHANNEL_EXTENDED_DATA` / `exit-status` / `EOF` / `CLOSE`
(see `tests/test_shell.py` for a full loop). Exactly one thread may
receive per connection.

## Local forwarding (`-L`)

```python
fwd = c.forward_local(8080, "internal.db", 5432)  # -L 8080:internal.db:5432
print(fwd.port)  # actual port (0 means auto-assign)
import socket
s = socket.create_connection(("127.0.0.1", fwd.port))
s.sendall(b"ping")
print(s.recv(4))
print(c.exec_command("uptime"))  # exec works on the same connection (mux)
fwd.close()
```

Exec/sftp/shell share one connection with forwarding through the
channel multiplexer (`ccssh/mux.py`): a single reader thread owns the
transport and routes packets to per-channel queues, so concurrent
channels never interleave the framing. Rekey still needs idle channels
(close channels and forwarders first); auto-rekey is deferred while the
mux is busy.

## Remote forwarding (`-R`) and ProxyJump (`-J`)

```python
rfwd = c.forward_remote(0, "127.0.0.1", 22)  # server listens (0 = auto)
print(rfwd.port)                             # real server-side port, reported back
rfwd.close()                                 # also sends cancel-tcpip-forward

jump = CCSSHClient()
jump.connect("jumphost", username="juser", key_filename="~/.ssh/id_ed25519")
tun = jump.open_channel_socket("target", 22)  # direct-tcpip, socket-shaped
c.connect("target", username="user", password="pw", sock=tun)
```

`-L` and `-R` cannot share one connection (one forwarder per
connection); either one shares it with exec/sftp/shell freely.

## Rekey

```python
out, _, _ = c.exec_command("one")
c.rekey() # new KEX, session_id kept, sequence numbers reset
out, _, _ = c.exec_command("two")
```

Call only with no open channels (between operations, forwarders
closed). Rekey also happens automatically per `rekey_bytes` /
`rekey_interval` (deferred while channels are open).

## Algorithms

```python
from ccssh import algs
print(algs.coverage())
# kex 14/16, ciphers 6/10, MACs 6/16 + certs - all live-verified vs OpenSSH
print(algs.SUPPORTED_KEX)      # incl. "mlkem768x25519-sha256"
print(algs.SUPPORTED_CIPHERS)  # aes*-ctr, aes*gcm, chacha20-poly1305
print(algs.SUPPORTED_MACS)     # hmac-sha2-*, hmac-sha1 (+-etm)
print(algs.SUPPORTED_HOSTKEYS) # incl. "ssh-mldsa44-ed25519"
```

The strict top tier (`algs.MAX_KEX`, `MAX_CIPHERS`, `MAX_MACS`,
`MAX_HOSTKEYS`: PQ hybrids, 256-bit ciphers/MACs only) can be passed
explicitly, e.g. `CCSSHClient(ciphers=algs.MAX_CIPHERS)`. Negotiation
still intersects with the server, so it fails closed when the server
lacks top-tier algorithms instead of silently downgrading.

Legacy algorithms (`algs.LEGACY_KEX`, `LEGACY_CIPHERS`, `LEGACY_MACS`,
`LEGACY_HOSTKEYS`: CBC ciphers, 3DES, MD5/SHA1-96/UMAC MACs, group1-sha1,
gex-sha1, ssh-rsa host keys) are implemented and live-tested but never
offered by default - name them explicitly to interoperate with old
servers. The server side needs them enabled too:

```bash
# sshd_config on the old box
Ciphers +aes256-cbc,3des-cbc
MACs +hmac-md5,umac-64@openssh.com
KexAlgorithms +diffie-hellman-group1-sha1
HostKeyAlgorithms +ssh-rsa
```

```bash
ccssh -o Ciphers=aes256-cbc -o MACs=hmac-sha2-256 he1zen@oldbox
```

Legacy tier: `ssh-dss` (1024-bit DSA/SHA-1, removed from OpenSSH 10.x) is
implemented like every other legacy primitive - never offered by default,
only when named explicitly (e.g. `-o HostKeyAlgorithms=ssh-dss`), and the
server side needs it enabled too.

## Certificates

```python
import base64
from ccssh import certs as CERT

line = open("host-cert.pub").read().split()       # "ssh-ed25519-cert-v01@openssh.com AAAA..."
info = CERT.parse_cert(base64.b64decode(line[1]))
print(info["principals"], info["role"])           # role: CERT.CERT_TYPE_HOST / CERT_TYPE_USER

CERT.verify_cert(base64.b64decode(line[1]), expected_principal="db.internal",
                 is_host=True, ca_blobs=[ca_public_blob])  # raises CERT.CertError if bad
```

In practice you rarely call this: user certs go through
`connect(..., cert_filename=...)`, host certs are verified automatically
from `@cert-authority` lines in known_hosts. To mint test certs:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ccssh import wire as W

ca = Ed25519PrivateKey.generate()
host = Ed25519PrivateKey.generate()
pub_fields = W.enc_string(host.public_key().public_bytes_raw())
blob = CERT.build_cert(
    keytype="ssh-ed25519-cert-v01@openssh.com", pub_fields=pub_fields,
    role=CERT.CERT_TYPE_HOST, principals="db.internal", ca_priv=ca)
```

## ML-DSA (`ssh-mldsa44-ed25519`)

Needs a `cryptography` build with ML-DSA (else `available()` is False
and these raise):

```python
from ccssh import mldsa as ML
print(ML.available())

kp = ML.KeyPair.generate() # or from_seeds(mldsa32, ed32)
open("id_mldsa.pub", "w").write(kp.public_line("comment") + "\n")
ML.save_openssh_private("id_mldsa", kp, "comment")
kp2 = ML.load_openssh_private("id_mldsa") # passphrase=b"..." if encrypted
```

The files are standard `openssh-key-v1` / one-line `.pub`, so
`ssh-keygen` (10.6+) and `sshd` accept them, and ccssh uses them as
`-i` keys and host keys directly.

## Post-quantum sntrup761 (`sntrup761x25519-sha512`)

Needs liboqs installed where the loader finds it (else `max`/defaults
skip it and forcing it raises `BackendMissing` with install hints):

```python
from ccssh import sntrup as SN
be = SN.load_backend() # LibOQSBackend via ctypes, no Python deps
ek, sk = be.generate() # ek 1158 B
ct, ss1 = be.encap(ek) # ct 1039 B, ss 32 B
assert be.decap(sk, ct) == ss1
```

```bash
ccssh -o KexAlgorithms=sntrup761x25519-sha512 he1zen@host
```

## FIDO2 security keys (`sk-ssh-ed25519`, `sk-ecdsa-sha2-nistp256`)

Parsing, verification and userauth assembly follow OpenSSH
PROTOCOL.u2f; only the hardware touch itself needs a token. The touch
is an injectable callback, so any middleware fits:

```python
from ccssh import sk as SK

key = SK.load_openssh_private("~/.ssh/id_sk") # needs key_handle inside
key.signer = lambda app, handle, msg: my_token_sign(app, handle, msg)
c.connect("host", username="u", key_filename="~/.ssh/id_sk")  # uses it

SK.verify_nested(key.public_blob(), message, sig) # True/False, never raises
```

Without a signer, signing raises a clear error (never a silent server
rejection). `-i sk_file` works out of the box; login itself needs the
token attached, so there is no live test - only spec-level tests plus
`ssh-keygen -L` cross-checks of our blobs.

## Async client

```python
import asyncio
from ccssh import AsyncCCSSHClient

async def go():
    c = AsyncCCSSHClient(host_policy="off") # same knobs as sync (no rekey timers yet)
    await c.connect("host", username="u", password="pw", family=0)
    out, err, code = await c.exec_command("echo hi")
    await c.rekey()
    await c.close()
    return out, code

print(asyncio.run(go()))
```

## Errors

```python
from ccssh import CCSSHClient, AuthError, HostKeyError, CCSSHError
try:
    ...
except AuthError: # bad password / rejected key
    ...
except HostKeyError: # unknown or changed host key (strict policy)
    ...
except CCSSHError: # protocol/transport failures (base of the above two)
    ...
```
