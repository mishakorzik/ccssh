"""ML-KEM-768 + X25519 hybrid handshake math (no network)."""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ccssh import mlkem as M


def test_sizes_11_openssh():
    assert M.MLKEM768_EK_LEN == 1184
    assert M.MLKEM768_CT_LEN == 1088
    assert M.MLKEM768_SS_LEN == 32
    assert M.X25519_SS_LEN == 32
    assert M.C_INIT_LEN == 1184 + 32
    assert M.S_REPLY_LEN == 1088 + 32
    assert M.K_LEN == 32


def test_handshake_both_sides_match():
    host_priv = Ed25519PrivateKey.generate()
    sess_c, sess_s, _ = M.run_handshake(host_priv=host_priv)
    assert sess_c.K == sess_s.K
    assert sess_c.H == sess_s.H
    assert sess_c.session_id == sess_s.H
    assert len(sess_c.K) == 32 and len(sess_c.H) == 32


def test_deterministic_client_keys_still_match():
    host_priv = Ed25519PrivateKey.generate()
    kw = dict(host_priv=host_priv, mlkem_seed=bytes(64), client_x_seed=bytes(32),
              server_x_seed=bytes([1]) * 32)
    a_c, a_s, a_w = M.run_handshake(**kw)
    b_c, b_s, b_w = M.run_handshake(**kw)
    # Same client seeds -> same C_INIT; each handshake still agrees with itself.
    assert a_w["C_INIT"] == b_w["C_INIT"]
    assert a_c.K == a_s.K and b_c.K == b_s.K


def test_tampered_ciphertext_detected():
    import pytest
    host_priv = Ed25519PrivateKey.generate()
    st = M.client_create(b"Vc", b"Ic", mlkem_seed=bytes(64), x_seed=bytes(32))
    _reply, Ks, sig, _sess = M.server_process_init(
        host_priv=host_priv, V_C=b"Vc", V_S=b"Vs", I_C=b"Ic", I_S=b"Is",
        C_INIT=st.C_INIT, x_seed=bytes([1]) * 32)
    good_ct = _reply[:M.MLKEM768_CT_LEN]
    bad_ct = bytes([good_ct[0] ^ 1]) + good_ct[1:]
    bad_reply = bad_ct + _reply[M.MLKEM768_CT_LEN:]
    with pytest.raises(Exception):
        M.client_process_reply(st, V_S=b"Vs", I_S=b"Is", K_S=Ks, S_REPLY=bad_reply, sig_inner=sig)


def test_tampered_x25519_detected():
    import pytest
    from ccssh import kex as K
    host_priv = Ed25519PrivateKey.generate()
    st = M.client_create(b"Vc", b"Ic")
    reply, Ks, sig, _sess = M.server_process_init(
        host_priv=host_priv, V_C=b"Vc", V_S=b"Vs", I_C=b"Ic", I_S=b"Is",
        C_INIT=st.C_INIT)
    bad_reply = reply[:-1] + bytes([reply[-1] ^ 1])
    with pytest.raises(Exception):
        M.client_process_reply(st, V_S=b"Vs", I_S=b"Is", K_S=Ks, S_REPLY=bad_reply, sig_inner=sig)
    # low-order X25519 server share is rejected at the KEX layer
    assert K._LOW_ORDER_X25519  # blacklist is non-empty


def test_k_encoded_as_string_not_mpint():
    from ccssh import wire as W
    raw = bytes(range(32))
    assert W.enc_string(raw) == W.enc_u32(32) + raw
    # hybrid K is hashed raw (K_LEN bytes), never mpint-framed
    assert M.combine_shared(bytes(32), bytes(32)) == M.sha256(bytes(32), bytes(32))


def test_session_data_roundtrip():
    sess_c, sess_s, wire = M.run_handshake()
    assert set(wire) == {"C_INIT", "S_REPLY", "K_S", "sig"}
    assert len(wire["C_INIT"]) == M.C_INIT_LEN
    assert len(wire["S_REPLY"]) == M.S_REPLY_LEN
    assert sess_c.derive("C") == sess_s.derive("C")
    assert sess_c.derive("C", 16) != sess_c.derive("D", 16)
    M.check_secret_nonzero(sess_c.K_pq)
    M.check_secret_nonzero(sess_c.K_ecdh)


def test_ephemeral_handshakes_differ():
    a, _, _ = M.run_handshake()
    b, _, _ = M.run_handshake()
    assert a.K != b.K and a.C_INIT != b.C_INIT


def test_hostkey_sign_verify_roundtrip():
    priv = Ed25519PrivateKey.generate()
    blob = M.hostkey_blob_from_priv(priv)
    H = bytes(32)
    sig = M.sign_exchange_hash(priv, H)
    assert M.verify_exchange_hash(priv.public_key().public_bytes_raw(), H, sig)
    assert M.parse_hostkey_blob(blob) == priv.public_key().public_bytes_raw()
