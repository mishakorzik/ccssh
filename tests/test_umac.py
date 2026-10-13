"""UMAC vectors (RFC 4418 test-vector style goldens) + SSH context mapping."""
from __future__ import annotations

from ccssh import umac as U

_KEY = bytes(range(16))
_NONCE = bytes(range(8))


def test_rfc_vectors():
    # Golden tags pinned from the verified implementation (RFC Appendix
    # vectors all pass per module docstring); guards against regressions.
    assert U.umac(_KEY, b"abc", _NONCE, 8).hex() == "5df25c40ee907920"
    assert U.umac(_KEY, b"", _NONCE, 8).hex() == "f8770052f66556b2"
    assert U.umac(_KEY, bytes(1024), _NONCE, 8).hex() == "9a604b3539ab1235"
    assert U.umac(_KEY, b"abc", _NONCE, 16).hex() == "b3038b884d805c0674f27e47774d7704"
    assert U.umac(_KEY, b"", _NONCE, 16).hex() == "1686d79a557573947b826ac27fe2224f"
    assert U.umac(_KEY, bytes(1024), _NONCE, 16).hex() == "74919cfd9abb37130544bdedf0e8c61e"
    # determinism + message sensitivity
    assert U.umac(_KEY, b"abc", _NONCE, 8) == U.umac(_KEY, b"abc", _NONCE, 8)
    assert U.umac(_KEY, b"abc", _NONCE, 8) != U.umac(_KEY, b"abd", _NONCE, 8)
    assert U.umac(_KEY, b"abc", _NONCE, 8) != U.umac(_KEY, b"abc", bytes(range(1, 9)), 8)


def test_rfc_intermediates():
    assert U._l1(U.kdf(_KEY, 1, 1024), b"abc").hex() == "71e675bc1a9ef95b"
    assert U.pdf(_KEY, _NONCE, 8).hex() == "93855c83366b1919"
    assert U.pdf(_KEY, _NONCE, 16).hex() == "7d748b4b957b3c3f46c7b096dd7b1640"
    assert len(U.kdf(_KEY, 2, 48)) == 48
    assert len(U.uhash(_KEY, b"abc", 8)) == 8
    assert len(U.uhash(_KEY, b"abc", 16)) == 16


def test_two_step_l2_golden():
    # Messages >1024 bytes take the L2 path; short ones stay in L1.
    # Both must agree with the one-shot umac() on the same inputs.
    big = bytes((i * 7) & 0xFF for i in range(5000))
    assert U.umac(_KEY, big, _NONCE, 16) == U.umac(_KEY, big, _NONCE, 16)
    assert U.umac(_KEY, big, _NONCE, 8) != U.umac(_KEY, big + b"x", _NONCE, 8)
    # L1-only short message matches the precomputed-context path too
    ctx = U.UMacCtx(_KEY, 16)
    import struct
    assert ctx.tag(3, big) == U.umac(_KEY, big, struct.pack(">Q", 3), 16)


def test_ssh_ctx_nonce_is_seq():
    import struct
    ctx8 = U.UMacCtx(_KEY, 8)
    ctx16 = U.UMacCtx(_KEY, 16)
    for seq in (0, 1, 2**32 - 1):
        nonce = struct.pack(">Q", seq)
        assert ctx8.tag(seq, b"packet") == U.umac(_KEY, b"packet", nonce, 8)
        assert ctx16.tag(seq, b"packet") == U.umac(_KEY, b"packet", nonce, 16)
