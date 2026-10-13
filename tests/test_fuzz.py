"""
 Decoder fuzzing (deterministic seeds): garbage in → WireError/ValueError,
 never an unhandled crash, hang, or huge allocation.
"""
from __future__ import annotations
import random

import pytest

from ccssh import wire as W


def _rand_bytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(n))


def test_fuzz_wire_decoders():
    rng = random.Random(20261011)
    decoders = [
        lambda b: W.dec_byte(b, 0),
        lambda b: W.dec_bool(b, 0),
        lambda b: W.dec_u32(b, 0),
        lambda b: W.dec_u64(b, 0),
        lambda b: W.dec_string(b, 0),
        lambda b: W.dec_namelist(b, 0),
        lambda b: W.dec_mpint(b, 0),
    ]
    for _ in range(400):
        buf = _rand_bytes(rng, rng.randrange(0, 12))
        for dec in decoders:
            try:
                dec(buf)
            except W.WireError:
                pass
            except ValueError:
                pass  # related checks are fine too


def test_fuzz_reader_sequences():
    rng = random.Random(77)
    for _ in range(300):
        r = W.Reader(_rand_bytes(rng, rng.randrange(0, 24)))
        for _ in range(rng.randrange(1, 5)):
            op = rng.randrange(7)
            try:
                if op == 0:
                    r.byte()
                elif op == 1:
                    r.bool()
                elif op == 2:
                    r.u32()
                elif op == 3:
                    r.string()
                elif op == 4:
                    r.namelist()
                elif op == 5:
                    r.mpint()
                else:
                    r.raw(rng.randrange(0, 10))
            except (W.WireError, ValueError):
                break


def test_fuzz_huge_string_len_no_alloc():
    # claims a 4GB string in a 4-byte buffer - must fail BEFORE allocating
    with pytest.raises((W.WireError, ValueError)):
        W.dec_string(b"\xff\xff\xff\xff")
    with pytest.raises((W.WireError, ValueError)):
        W.dec_string(b"\x7f\x00\x00\x00abc")


def test_fuzz_negotiate_and_parsers():
    from ccssh import kex as K
    with pytest.raises(ValueError):
        K.negotiate([], ["curve25519-sha256"])
    with pytest.raises(ValueError):
        K.negotiate(["curve25519-sha256"], [])
    assert K.negotiate(["a", "b"], ["b", "c"]) == "b"
    # strict markers are never selected as the KEX method
    assert K.negotiate(["curve25519-sha256", K.KEX_STRICT_C], ["curve25519-sha256", K.KEX_STRICT_S]) == "curve25519-sha256"
    rng = random.Random(9)
    from ccssh import certs as CERT
    for _ in range(100):
        try:
            CERT.parse_cert(_rand_bytes(rng, rng.randrange(0, 60)))
        except (CERT.CertError, W.WireError, ValueError):
            pass
    from ccssh import hostkeys as HK
    for _ in range(100):
        try:
            HK.parse_host_blob(_rand_bytes(rng, rng.randrange(0, 60)))
        except ValueError:
            pass
    from ccssh import sftp as SFTP
    for _ in range(100):
        try:
            SFTP.dec_attrs(_rand_bytes(rng, rng.randrange(0, 24)))
        except (W.WireError, ValueError):
            pass
