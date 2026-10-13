"""
 ccssh - a from-scratch SSH client in Python (sync + async + CLI).

 Native transport on top of `cryptography` primitives; verified against
 real OpenSSH servers (see tests/test_live_sshd.py), including the 10.6
 ssh-mldsa44-ed25519 composite signatures.

 Algorithm parity (see ccssh.algs for the honest matrix):
  KEX 14/16, ciphers 6/10, MACs 6/16, host keys 8/16 + certs with CA verify.
"""
try:
    from ccssh.async_client import AsyncCCSSHClient
    from ccssh.client import CCSSHClient, AuthError, HostKeyError, CCSSHError, ShellSession
    from ccssh.transport import CCSSHTimeoutError
except ImportError as _e:
    if "cryptography" in str(_e).lower():
        raise ImportError(f"ccssh needs a working 'cryptography' package, but it failed to import ({_e}).") from _e
    raise

__all__ = ["CCSSHClient", "AsyncCCSSHClient", "AuthError", "HostKeyError", "CCSSHError", "CCSSHTimeoutError", "ShellSession"]
__version__ = "1.0.0"
