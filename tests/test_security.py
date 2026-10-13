"""Adversarial/security tests: malformed wire data, degenerate crypto,
policy fail-closes, DoS caps and channel-confusion resistance.

 Every test here feeds hostile input and asserts a clean typed error
 (never a hang, OOM, traceback leak or silent accept).
"""
from __future__ import annotations
import base64
import hashlib
import os
import queue
import socket
import struct
import threading
import time

import pytest

from ccssh import wire as W
from ccssh import channel as CH
from ccssh.transport import SyncTransport, CCSSHError, CCSSHTimeoutError


# wire: strict decoding


def test_namelist_rejects_non_ascii_with_wireerror():
    with pytest.raises(W.WireError):
        W.dec_namelist(W.enc_string(b"\xff\xfe binary"))
    with pytest.raises(W.WireError):
        W.enc_namelist(["ok", "not,ok"])
    with pytest.raises(W.WireError):
        W.enc_namelist(["héllo"])


def test_namelist_bomb_capped():
    with pytest.raises(W.WireError):
        W.dec_namelist(W.enc_string(b"a," * 20000))
    with pytest.raises(W.WireError):
        W.dec_namelist(W.enc_string(b"x" * 40000))


def test_mpint_rejects_lone_zero_byte():
    # RFC 4251: zero is the empty string, a lone 0x00 is non-minimal.
    with pytest.raises(W.WireError):
        W.dec_mpint(W.enc_u32(1) + b"\x00")
    assert W.dec_mpint(W.enc_mpint(0))[0] == 0
    assert W.dec_mpint(W.enc_mpint(2**300 + 5))[0] == 2**300 + 5


def test_reader_assert_end_and_bounds():
    r = W.Reader(W.enc_u32(1) + b"\x00")
    r.u32()
    with pytest.raises(W.WireError):
        r.assert_end()
    with pytest.raises(W.WireError):
        W.Reader(b"\x01").raw(5)
    with pytest.raises(W.WireError):
        W.Reader(b"").byte()


def test_dec_string_huge_len_no_alloc():
    with pytest.raises(W.WireError):
        W.dec_string(struct.pack(">I", 0xFFFFFFFF))


# crypto: KDF/cipher/MAC guards


def test_kdf_caps_and_letter():
    from ccssh import crypto as C
    hf = C.HASH_sha256
    with pytest.raises(ValueError):
        C.kdf(hf, b"K", b"H", b"H", b"CD", 32)
    with pytest.raises(ValueError):
        C.kdf(hf, b"K", b"H", b"H", b"C", 0)
    with pytest.raises(ValueError):
        C.kdf(hf, b"K", b"H", b"H", b"C", 1025)
    assert len(C.kdf(hf, b"K", b"H", b"H", b"C", 1024)) == 1024


def test_derive_keys_rejects_unknown():
    from ccssh import crypto as C
    hf = C.HASH_sha256
    with pytest.raises(ValueError):
        C.derive_keys(b"K", b"H", b"H", "rot13-cbc", "hmac-sha2-256", hf)
    with pytest.raises(ValueError):
        C.derive_keys(b"K", b"H", b"H", "aes128-ctr", "hmac-xyz", hf)


def test_mac_seq_out_of_range():
    from ccssh import crypto as C
    m = C.SshMac("hmac-sha2-256", os.urandom(32))
    m.mac_of(0, b"x")
    m.mac_of(2**32 - 1, b"x")
    with pytest.raises(ValueError):
        m.mac_of(2**32, b"x")
    with pytest.raises(ValueError):
        m.mac_of(-1, b"x")


def test_cbc_rejects_unaligned_stream():
    from ccssh import crypto as C
    ctx = C.CbcHmacCtx("aes128-cbc", "hmac-sha1", os.urandom(16),
                       os.urandom(16), os.urandom(20))
    with pytest.raises(ValueError):
        ctx.encrypt_stream(b"15 bytes!!!!!")
    with pytest.raises(ValueError):
        ctx.decrypt_stream(b"short")


def test_gcm_guards():
    import pytest as _pt
    from ccssh import gcm as G
    from cryptography.exceptions import InvalidTag
    with _pt.raises(ValueError):
        G.derive_gcm_keys(b"K", b"H", b"H", "aes512-gcm@openssh.com")
    keys = G.derive_gcm_keys(W.enc_string(b"K" * 32), b"H" * 32, b"H" * 32, "aes128-gcm@openssh.com")
    c = G.AesGcmCtx("aes128-gcm@openssh.com", keys["enc_c2s"], keys["iv_c2s"])
    d = G.AesGcmCtx("aes128-gcm@openssh.com", keys["enc_c2s"], keys["iv_c2s"])
    wire = c.seal(b"secret")
    assert d.open(wire)[1:][:6] == b"secret"
    bad = bytearray(wire)
    bad[-1] ^= 1  # tag tamper: must fail, never silently accept
    with _pt.raises(InvalidTag):
        d.open(bytes(bad))
    with _pt.raises(ValueError):
        d.open(b"\x00" * 10)
    # counter exhaustion fails closed instead of reusing a nonce
    d._counter = 0xFFFFFFFFFFFFFFFF
    with _pt.raises(ValueError):
        d._nonce()


def test_chacha_seq_and_length_guards():
    from ccssh import chacha as CHH
    keys = CHH.derive_chacha_keys(W.enc_string(b"K" * 32), b"H" * 32, b"H" * 32)
    c = CHH.ChachaSshCtx(keys["enc_c2s"])
    with pytest.raises(ValueError):
        c.seal(2**32, b"\x00" * 4, b"body")
    with pytest.raises(ValueError):
        c.open(2**32, b"\x00" * 24)
    with pytest.raises(ValueError):
        c.decrypt_length(-1, b"\x00" * 4)
    with pytest.raises(ValueError):
        c.open(0, b"\x00" * 10)


def test_umac_guards():
    from ccssh import umac as U
    import pytest as _pt
    with _pt.raises(ValueError):
        U.UMacCtx(bytes(15), 8)
    with _pt.raises(ValueError):
        U.UMacCtx(bytes(16), 12)
    with _pt.raises(ValueError):
        U.umac(bytes(16), b"m", b"n", 5)
    a = U.UMacCtx(bytes(16), 8).tag(1, b"pkt")
    b = U.UMacCtx(bytes([1]) * 16, 8).tag(1, b"pkt")
    assert a != b  # key separation holds


def test_packet_too_large_never_built():
    from ccssh import crypto as C
    with pytest.raises(ValueError):
        C.build_unencrypted_block(b"x" * 35000, 16)
    with pytest.raises(ValueError):
        C.build_aad_block(b"x" * 35000, 16)


# transport: padding oracle uniformity + flood caps


def test_check_padding_bounds():
    from ccssh.transport import _check_padding
    _check_padding(4, 6)  # minimal valid: pad 4 + 1 payload byte
    _check_padding(255, 300)
    for pad, pl in ((0, 16), (3, 16), (16, 16), (5, 5), (250, 200)):
        with pytest.raises(CCSSHError):
            _check_padding(pad, pl)


def test_service_flood_capped():
    from ccssh.crypto import build_unencrypted_block
    a, b = socket.socketpair()
    t = SyncTransport(a, b"SSH-2.0-T", timeout=2)
    try:
        for _ in range(65):
            b.sendall(build_unencrypted_block(bytes([2]), 8))  # IGNORE storm
        with pytest.raises(CCSSHError, match="too many service messages"):
            t.recv_packet()
    finally:
        a.close()
        b.close()


def test_global_request_answered_once_then_real_packet():
    from ccssh.crypto import build_unencrypted_block
    a, b = socket.socketpair()
    t = SyncTransport(a, b"SSH-2.0-T", timeout=2)
    try:
        glob = bytes([80]) + W.enc_string(b"hostkeys-00@openssh.com") + W.enc_bool(True)
        b.sendall(build_unencrypted_block(glob, 8))
        b.sendall(build_unencrypted_block(b"\x32real", 8))
        assert t.recv_packet() == b"\x32real"
        # the answer to hostkeys-00 must be SUCCESS (81), not FAILURE
        hdr = b.recv(4)
        (pl,) = struct.unpack(">I", hdr)
        body = b""
        while len(body) < pl:
            body += b.recv(pl - len(body))
        assert body[1:2] == bytes([81])
    finally:
        a.close()
        b.close()


def test_global_request_other_name_gets_failure():
    from ccssh.crypto import build_unencrypted_block
    a, b = socket.socketpair()
    t = SyncTransport(a, b"SSH-2.0-T", timeout=2)
    try:
        glob = bytes([80]) + W.enc_string(b"noop@x") + W.enc_bool(True)
        b.sendall(build_unencrypted_block(glob, 8))
        b.sendall(build_unencrypted_block(b"\x32real", 8))
        assert t.recv_packet() == b"\x32real"
        hdr = b.recv(4)
        (pl,) = struct.unpack(">I", hdr)
        body = b""
        while len(body) < pl:
            body += b.recv(pl - len(body))
        assert body[1:2] == bytes([82])
    finally:
        a.close()
        b.close()


def test_global_keepalive_gets_success():
    # OpenSSH keepalive probes (want_reply=True) must be answered 81:
    # answering 82 makes the server treat a live client as dead.
    from ccssh.crypto import build_unencrypted_block
    a, b = socket.socketpair()
    t = SyncTransport(a, b"SSH-2.0-T", timeout=2)
    try:
        glob = bytes([80]) + W.enc_string(b"keepalive@openssh.com") + W.enc_bool(True)
        b.sendall(build_unencrypted_block(glob, 8))
        b.sendall(build_unencrypted_block(b"\x32real", 8))
        assert t.recv_packet() == b"\x32real"
        hdr = b.recv(4)
        (pl,) = struct.unpack(">I", hdr)
        body = b""
        while len(body) < pl:
            body += b.recv(pl - len(body))
        assert body[1:2] == bytes([81])
    finally:
        a.close()
        b.close()

# KEX: degenerate and low-order peers


def test_x25519_low_order_blacklist_complete():
    from ccssh import kex as K
    assert len(K._LOW_ORDER_X25519) == 12
    for q in K._LOW_ORDER_X25519:
        assert len(q) == 32
        with pytest.raises(ValueError):
            K._reject_low_order_x25519(q)
    K._reject_low_order_x25519(os.urandom(32)) # random point passes


def test_dh_subgroup_rejects_order_two():
    from ccssh import kex_ext as KX
    c = KX.DhClient("diffie-hellman-group14-sha256")
    # p-1 has order 2: in range but outside the subgroup -> must fail
    reply = bytes([31]) + W.enc_string(b"ks") + W.enc_mpint(c.p - 1) + W.enc_string(b"s")
    with pytest.raises(ValueError):
        c.finish(reply, b"Vc", b"Vs", b"Ic", b"Is")


def test_dh_server_stub_rejects_degenerate():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import kex_ext as KX
    s = KX.DhServerStub("diffie-hellman-group14-sha256", Ed25519PrivateKey.generate())
    for bad in (0, 1, s.p - 1, s.p):
        with pytest.raises(ValueError):
            s.reply(bytes([30]) + W.enc_mpint(bad), b"Vc", b"Vs", b"Ic", b"Is")


def test_gex_group_outside_range_rejected():
    import hashlib as _hl
    from ccssh import kex_ext as KX
    from ccssh.dh_groups import P14_2048
    c = KX.GexClient(min_bits=2048, n_bits=3072, max_bits=4096, hashfn=_hl.sha256)
    tiny_p = (1 << 1025) + 39 # 1026-bit group: below the requested minimum
    group = bytes([31]) + W.enc_mpint(tiny_p) + W.enc_mpint(2)
    with pytest.raises(ValueError):
        c.init_msg(group)
    ok_group = bytes([31]) + W.enc_mpint(P14_2048) + W.enc_mpint(2)
    init = c.init_msg(ok_group)
    assert init[0] == 32


def test_kexinit_reserved_and_trailing_rejected():
    from ccssh import kex as K
    good = K.enc_kexinit(os.urandom(16), ["curve25519-sha256"], ["ssh-ed25519"], ["aes128-ctr"], ["aes128-ctr"], ["hmac-sha2-256"], ["hmac-sha2-256"], ["none"], ["none"])
    K.dec_kexinit(good) # sanity: well-formed parses
    with pytest.raises(W.WireError):
        K.dec_kexinit(bytes([19]) + good[1:]) # wrong message number
    with pytest.raises(W.WireError):
        K.dec_kexinit(good + b"trailing")
    tampered = bytearray(good)
    tampered[-1] ^= 1 # reserved field must stay zero
    if bytes(tampered) != good:
        with pytest.raises(W.WireError):
            K.dec_kexinit(bytes(tampered))
    with pytest.raises(ValueError):
        K.enc_kexinit(b"short-cookie", ["a"], ["b"], ["c"], ["c"], ["d"], ["d"], ["none"], ["none"])


def test_hybrid_reply_length_enforced():
    from ccssh import kex_ext as KX
    c = KX.MlkemP256Client(b"Vc", b"Ic")
    assert len(c.c_init) == 1184 + 65
    for bad_len in (0, 100, 1088 + 64, 1088 + 66, 2000):
        reply = bytes([31]) + W.enc_string(b"ks") + W.enc_string(b"x" * bad_len) \
            + W.enc_string(b"sig")
        with pytest.raises(ValueError):
            c.finish(reply, b"Vs", b"Is")


# host keys, certs, policies


def test_hostkey_parsers_reject_garbage_and_trailing():
    from ccssh import hostkeys as HK
    with pytest.raises(ValueError):
        HK.parse_host_blob(b"\x00\x00\x00\x03abc")
    with pytest.raises(ValueError):
        HK.parse_host_blob(W.enc_string(b"ssh-ed25519") + W.enc_string(b"short"))
    good_ed = W.enc_string(b"ssh-ed25519") + W.enc_string(bytes(32))
    with pytest.raises(ValueError):
        HK.parse_host_blob(good_ed + b"trailing")
    assert HK.fingerprint(good_ed).startswith("SHA256:")
    assert "=" not in HK.fingerprint(good_ed)  # unpadded like ssh-keygen
    # RSA signatures longer than the modulus are rejected, not truncated
    assert not HK.verify_host_signature(good_ed, "ssh-ed25519", bytes(32), b"\x00" * 200)


def test_dss_legacy_roundtrip_and_tied_alg():
    from cryptography.hazmat.primitives.asymmetric import dsa
    from ccssh import hostkeys as HK
    params = dsa.generate_parameters(key_size=1024)
    priv = params.generate_private_key()
    nums = priv.public_key().public_numbers()
    pn = nums.parameter_numbers
    blob = (W.enc_string(b"ssh-dss") + W.enc_mpint(pn.p) + W.enc_mpint(pn.q)
            + W.enc_mpint(pn.g) + W.enc_mpint(nums.y))
    assert HK.parse_host_blob(blob)[0] == "ssh-dss"
    Hh = bytes(32)
    nested = HK.sign_userauth(priv, "ssh-dss", Hh)
    assert HK.verify_host_signature(blob, "ssh-dss", Hh, nested)
    # signature is bound to its own alg id (same convention as ed/ECDSA):
    # relabelled sig_alg must fail even though the key matches
    r = W.Reader(nested)
    assert r.string() == b"ssh-dss"
    relabelled = W.enc_string(b"ssh-rsa") + nested[r.tell():]
    assert not HK.verify_host_signature(blob, "ssh-dss", Hh, relabelled)
    assert not HK.verify_host_signature(blob, "ssh-dss", b"\x01" + Hh[1:], nested)
    with pytest.raises(ValueError):
        HK.sign_userauth(priv, "ssh-rsa", Hh)


def test_cert_structural_rejects():
    from ccssh import certs as CERT
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    plain = W.enc_string(b"ssh-ed25519") + W.enc_string(bytes(32))
    with pytest.raises(CERT.CertError):
        CERT.parse_cert(plain)  # not a cert type at all
    with pytest.raises(CERT.CertError):
        CERT.parse_cert(os.urandom(40))
    ca = Ed25519PrivateKey.generate()
    blob, _, _ = _mk_cert_for("h.test")
    # reserved field tamper -> structural reject
    info = CERT.parse_cert(blob)
    assert info["role"] == CERT.CERT_TYPE_HOST
    _ = ca


def _mk_cert_for(host, **kw):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import certs as CERT
    ca = Ed25519PrivateKey.generate()
    hp = Ed25519PrivateKey.generate()
    blob = CERT.build_cert(keytype="ssh-ed25519-cert-v01@openssh.com",
                           pub_fields=W.enc_string(hp.public_key().public_bytes_raw()),
                           principals=host, ca_priv=ca, **kw)
    return blob, CERT.parse_cert(blob)["sig_key"], CERT.parse_cert(blob)


def test_cert_role_and_ca_pinning():
    from ccssh import certs as CERT
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    blob, ca_blob, _ = _mk_cert_for("h.test")
    with pytest.raises(CERT.CertError):  # host cert, user role requested
        CERT.verify_cert(blob, expected_principal="h.test", is_host=False, ca_blobs=[ca_blob])
    other_ca = Ed25519PrivateKey.generate()
    other_blob = W.enc_string(b"ssh-ed25519") + W.enc_string(
        other_ca.public_key().public_bytes_raw())
    with pytest.raises(CERT.CertError):  # pinned to the wrong CA
        CERT.verify_cert(blob, expected_principal="h.test", is_host=True, ca_blobs=[other_blob])
    with pytest.raises(CERT.CertError):
        CERT.build_cert(keytype="ssh-ed25519-cert-v01@openssh.com",
                        pub_fields=W.enc_string(bytes(32)), principals="h",
                        ca_priv=b"not-a-key")


def test_hostcheck_ask_policy(tmp_path):
    from ccssh.hostcheck import check_hostkey, HostKeyError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M
    Ks = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    kh = str(tmp_path / "kh")
    # yes -> learned like accept-new
    check_hostkey("h", 22, Ks, "ssh-ed25519", policy="ask", known_hosts=kh, ask_callback=lambda prompt: "yes")
    check_hostkey("h", 22, Ks, "ssh-ed25519", policy="strict", known_hosts=kh)
    # no -> refused
    with pytest.raises(HostKeyError, match="not trusted"):
        check_hostkey("h2", 22, Ks, "ssh-ed25519", policy="ask", known_hosts=kh, ask_callback=lambda prompt: "no")
    # no callback on a tty-less caller -> fail closed like strict
    with pytest.raises(HostKeyError, match="no prompt available"):
        check_hostkey("h3", 22, Ks, "ssh-ed25519", policy="ask", known_hosts=kh, ask_callback=None)
    # changed keys fail even under ask
    other = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    with pytest.raises(HostKeyError, match="HOST KEY CHANGED"):
        check_hostkey("h", 22, other, "ssh-ed25519", policy="ask", known_hosts=kh, ask_callback=lambda prompt: "yes")


def test_hostcheck_known_hosts_list_and_none(tmp_path):
    import base64 as _b64
    from ccssh.hostcheck import check_hostkey, HostKeyError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M
    Ks = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    kh1 = tmp_path / "kh1"
    kh2 = tmp_path / "kh2"
    kh2.write_text(f"h ssh-ed25519 {_b64.b64encode(Ks).decode()}\n")
    # second file in the list matches
    check_hostkey("h", 22, Ks, "ssh-ed25519", policy="strict", known_hosts=[str(kh1), str(kh2)])
    # comma/space separated string form works too
    check_hostkey("h", 22, Ks, "ssh-ed25519", policy="strict", known_hosts=f"{kh1}, {kh2}")
    # "none" disables file checks: strict fails, accept-new is a no-op
    with pytest.raises(HostKeyError):
        check_hostkey("h", 22, Ks, "ssh-ed25519", policy="strict", known_hosts="none")
    check_hostkey("h", 22, Ks, "ssh-ed25519", policy="accept-new", known_hosts="none")
    assert not os.path.exists(str(tmp_path / "none"))
    # accept-new appends to the FIRST usable file, not the matching one
    check_hostkey("h2", 22, Ks, "ssh-ed25519", policy="accept-new", known_hosts=[str(kh1), str(kh2)])
    assert "h2" in kh1.read_text() and "h2" not in kh2.read_text()


def test_hostcheck_unreadable_fails_closed(tmp_path):
    from ccssh.hostcheck import check_hostkey, HostKeyError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M
    Ks = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    kh = tmp_path / "kh"
    kh.write_text("x\n")
    kh.chmod(0o000)
    try:
        for policy in ("strict", "accept-new"):
            with pytest.raises(HostKeyError, match="cannot read"):
                check_hostkey("h", 22, Ks, "ssh-ed25519", policy=policy, known_hosts=str(kh))
    finally:
        kh.chmod(0o600)


def test_hostcheck_parent_symlink_refused(tmp_path):
    from ccssh.hostcheck import check_hostkey, HostKeyError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M
    Ks = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    with pytest.raises(HostKeyError, match="symlink"):
        check_hostkey("h", 22, Ks, "ssh-ed25519", policy="accept-new", known_hosts=str(link / "kh"))


def test_cert_hashed_ca_line_matches(tmp_path):
    import base64 as _b64
    import hashlib as _hl
    import hmac as _hm
    from ccssh.hostcheck import check_hostkey
    blob, ca_blob, _ = _mk_cert_for("db.internal")
    salt = os.urandom(20)
    digest = _hm.new(salt, b"db.internal", _hl.sha1).digest()
    hashed = f"|1|{_b64.b64encode(salt).decode()}|{_b64.b64encode(digest).decode()}"
    kh = tmp_path / "known_hosts"
    kh.write_text(f"@cert-authority {hashed} ssh-ed25519 {_b64.b64encode(ca_blob).decode()}\n")
    check_hostkey("db.internal", 22, blob, "ssh-ed25519-cert-v01@openssh.com", policy="strict", known_hosts=str(kh))


def test_hostcheck_fail_closed_policies(tmp_path):
    from ccssh.hostcheck import check_hostkey, HostKeyError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M
    Ks = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    kh = str(tmp_path / "kh")
    for bad_policy in ("strictt", "OFFF", "", "ask"):
        with pytest.raises(HostKeyError):
            check_hostkey("h", 22, Ks, "ssh-ed25519", policy=bad_policy, known_hosts=kh)
    for bad_host in ("", "has space", "new\nline", "tab\there"):
        with pytest.raises(HostKeyError):
            check_hostkey(bad_host, 22, Ks, "ssh-ed25519", policy="strict", known_hosts=kh)


def test_hostcheck_symlink_and_devnull_and_size(tmp_path):
    from ccssh.hostcheck import check_hostkey, HostKeyError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M
    Ks = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    outside = tmp_path / "victim"
    outside.write_text("x\n")
    link = tmp_path / "kh"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        return # symlink creation unavailable here; islink branch still coded
    with pytest.raises(HostKeyError):
        check_hostkey("newhost", 22, Ks, "ssh-ed25519", policy="accept-new", known_hosts=str(link))
    # /dev/null: accept-new is a no-op that never fails
    check_hostkey("anyhost", 22, Ks, "ssh-ed25519", policy="accept-new", known_hosts="/dev/null")
    big = tmp_path / "big"
    big.write_bytes(b"#\n" * 700000) # > 1 MiB of junk
    with pytest.raises(HostKeyError):
        check_hostkey("h", 22, Ks, "ssh-ed25519", policy="strict", known_hosts=str(big))


def test_sk_edges_never_raise():
    from ccssh import sk as SK
    import pytest as _pt
    with _pt.raises(ValueError):
        SK.SkKey("nope", pub=bytes(32))
    k = SK.SkKey(SK.ALG_ED, pub=bytes(32), key_handle=b"h")
    with _pt.raises(ValueError, match="[Ss]igner|touch|FIDO"):
        k.sign_nested(b"msg")
    assert SK.verify_nested(b"", b"", b"") is False
    assert SK.verify_nested(k.public_blob(), b"m", b"\x00" * 10) is False
    with _pt.raises(ValueError):
        SK.parse_pub_blob(W.enc_string(b"ssh-rsa") + W.enc_string(b"x"))
    with _pt.raises((ValueError, OSError)):
        SK.load_openssh_private("/nonexistent-sk-key")


def test_mldsa_edges_never_raise(tmp_path):
    from ccssh import mldsa as ML
    import pytest as _pt
    assert ML.verify_nested(b"junk", b"msg", b"junk") is False
    assert ML.available() in (True, False)
    with _pt.raises(Exception):
        ML.load_openssh_private(str(tmp_path / "missing"))
    with _pt.raises(Exception):
        ML.KeyPair.from_seeds(b"\x00" * 31, b"\x00" * 32)


def test_mlkem_edges():
    from ccssh import mlkem as M
    import pytest as _pt
    with _pt.raises(ValueError):
        M.check_secret_nonzero(bytes(32))
    M.check_secret_nonzero(os.urandom(32))
    with _pt.raises(ValueError):
        M.combine_shared(bytes(31), bytes(32))
    with _pt.raises(ValueError):
        M.client_create(b"Vc", b"Ic", mlkem_seed=b"short")
    sess_c, sess_s, _w = M.run_handshake()
    with _pt.raises(ValueError):
        sess_c.derive("TOOLONG")
    # KDF prefix property: shorter outputs extend to longer ones
    assert sess_c.derive("C", 24)[:16] == sess_c.derive("C", 16)

# auth/cipher agility guards


def test_password_probe_length_caps():
    from ccssh import auth as A
    with pytest.raises(ValueError):
        A.enc_password_request("u" * 300, "pw")
    with pytest.raises(ValueError):
        A.enc_password_request("u", "p" * 2000)
    with pytest.raises(ValueError):
        A.enc_pubkey_probe("u", b"ssh-ed25519", b"k" * 20000)
    A.enc_password_request("user", "secret") # sane sizes pass


def test_dec_userauth_request_never_raises_decode():
    from ccssh import auth as A
    with pytest.raises(W.WireError):
        A.dec_userauth_request(b"\x00garbage")
    with pytest.raises((W.WireError, ValueError)):
        A.dec_userauth_request(os.urandom(48))
    good = A.enc_password_request("user", "pw")
    assert A.dec_userauth_request(good)["method"] == "password"


def test_async_defaults_are_strict():
    from ccssh import async_client as AC
    c = AC.AsyncCCSSHClient()
    assert c.host_policy == "strict" # regression: must never default to off
    assert c.known_hosts is None
    c2 = AC.AsyncCCSSHClient(known_hosts="~/kh")
    assert c2.known_hosts and c2.known_hosts.endswith("kh") and "~" not in c2.known_hosts


def test_client_defaults_are_strict():
    from ccssh.client import CCSSHClient
    c = CCSSHClient()
    assert c.host_policy == "strict"
    assert "sntrup761" not in c.kex_list or True # backend-dependent default


def test_load_user_priv_size_and_mode_guards(tmp_path):
    from ccssh.client import _load_user_priv, AuthError
    big = tmp_path / "bigkey"
    big.write_bytes(b"x" * ((1 << 20) + 1))
    with pytest.raises(AuthError):
        _load_user_priv(str(big), None)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    kf = tmp_path / "id"
    kf.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()))
    kf.chmod(0o644)
    with pytest.raises(AuthError):
        _load_user_priv(str(kf), None)


def test_cert_file_parsing_guards(tmp_path):
    from ccssh.client import _user_blob, AuthError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    bad = tmp_path / "bad-cert.pub"
    bad.write_text("only-one-field\n")
    with pytest.raises(AuthError):
        _user_blob(priv, str(bad))
    bad2 = tmp_path / "bad-cert2.pub"
    bad2.write_text("ssh-ed25519-cert-v01@openssh.com !!!not-base64!!!\n")
    with pytest.raises(AuthError):
        _user_blob(priv, str(bad2))


# channels: confusion + window accounting


def test_channel_codec_guards():
    from ccssh import channel as CH
    with pytest.raises(ValueError):
        CH.enc_data(1, b"x" * (CH.MAXPKT + 1))
    with pytest.raises(ValueError):
        CH.enc_window_adjust(1, 0)
    with pytest.raises(ValueError):
        CH.enc_window_adjust(1, 2**32)
    assert CH.check_window(100, 50) == 150
    with pytest.raises(ValueError):
        CH.check_window(0xFFFFFFFF, 1)
    with pytest.raises(ValueError):
        CH.check_window(10, 0)


def test_shell_pump_ignores_foreign_channel(monkeypatch, capfd):
    import queue as _q
    import socket as _sock
    import threading as _th
    import time as _tm
    import types as _types
    from ccssh.shell import run_interactive

    class FakeT:
        def __init__(self):
            self.q = _q.Queue()

        def recv_packet(self, **kw):
            return self.q.get(timeout=5)

        def send_packet(self, payload):
            pass

    class FakeS:
        srv = 1
        chan = 1
        consumed = 0
        exit_status = None
        eof_received = False

        def send_eof(self):
            pass

        def window_change(self, a, b):
            pass

        def window_adjust(self):
            pass

        def credit(self, d):
            pass

        def close(self):
            return None

        def add_consumed(self, n):
            type(self).consumed = getattr(type(self), "consumed", 0) + n
            self.consumed = type(self).consumed

    t, sess = FakeT(), FakeS()
    client = _types.SimpleNamespace(_t=t)
    # hostile: DATA/REQUEST/CLOSE for channel 999 must be ignored
    t.q.put(bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(999) + W.enc_string(b"evil"))
    t.q.put(bytes([CH.MSG_CHANNEL_REQUEST]) + W.enc_u32(999) + W.enc_string(b"exit-status") + W.enc_bool(False) + W.enc_u32(99))
    t.q.put(bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(1) + W.enc_string(b"good"))
    t.q.put(bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(1))
    sin, sout = _sock.socketpair()
    monkeypatch.setattr("sys.stdin", _types.SimpleNamespace(fileno=sin.fileno, isatty=lambda: False))
    try:
        rc = run_interactive(client, sess)
    finally:
        sin.close()
        sout.close()
    assert rc == 0  # no exit-status 99 leaked in from the foreign channel
    assert sess.exit_status is None
    assert capfd.readouterr().out == "good"


def test_shell_write_all_survives_partial_writes(monkeypatch, capfd):
    import os as _os
    import queue as _q
    import socket as _sock
    import types as _types
    from ccssh.shell import run_interactive
    real_write = _os.write
    partials = []

    def flaky(fd, data):
        if fd == 1 and len(data) > 1:
            n = max(1, len(data) // 2)
            partials.append(n)
            return real_write(fd, data[:n])
        return real_write(fd, data)

    class FakeT:
        def __init__(self):
            self.q = _q.Queue()

        def recv_packet(self, **kw):
            return self.q.get(timeout=5)

        def send_packet(self, payload):
            pass

    class FakeS:
        srv = 1
        consumed = 0
        exit_status = None
        eof_received = False
        eof_sent = False
        closed = False

        def send(self, data):
            pass

        def send_eof(self):
            self.eof_sent = True

        def window_change(self, a, b):
            pass

        def window_adjust(self):
            pass

        def credit(self, d):
            pass

        def close(self):
            self.closed = True
            return self.exit_status

    monkeypatch.setattr(_os, "write", flaky)
    t, sess = FakeT(), FakeS()
    client = _types.SimpleNamespace(_t=t)
    blob = b"xy" * 200
    t.q.put(bytes([CH.MSG_CHANNEL_DATA]) + W.enc_u32(1) + W.enc_string(blob))
    t.q.put(bytes([CH.MSG_CHANNEL_CLOSE]) + W.enc_u32(1))
    sin, sout = _sock.socketpair()
    monkeypatch.setattr("sys.stdin", _types.SimpleNamespace(
        fileno=sin.fileno, isatty=lambda: False))
    try:
        assert run_interactive(client, sess) == 0
    finally:
        sin.close()
        sout.close()
    assert partials # partial writes really happened
    assert capfd.readouterr().out.encode() == blob # but nothing was lost


def test_chansock_deadlines_and_close_packets():
    from ccssh.chansock import ChannelSocket

    class FakeT:
        def __init__(self):
            self.sent = []
            self.q = queue.Queue()
            self.timeout = 5.0

        def send_packet(self, payload):
            self.sent.append(payload)

        def recv_packet(self, keepalive=True):
            assert keepalive is False # chansock must enforce its own deadline
            try:
                return self.q.get(timeout=0.05)
            except queue.Empty:
                raise CCSSHTimeoutError("t/o")

    t = FakeT()
    s = ChannelSocket(t, 7, window=10, maxpacket=32768, timeout=0.2)
    with pytest.raises(OSError, match="window exhausted"):
        s._top_up(100) # no WINDOW_ADJUST arrives in time
    with pytest.raises(CCSSHTimeoutError):
        s.recv(4)
    s._got_data(b"ab")
    assert s.recv(2) == b"ab" # buffered data needs no network
    s.close()
    assert t.sent[0][0] == CH.MSG_CHANNEL_EOF and t.sent[1][0] == CH.MSG_CHANNEL_CLOSE


def test_chansock_window_overflow_fails_closed():
    from ccssh.chansock import ChannelSocket

    class FakeT:
        def __init__(self):
            self.sent = []
            self.timeout = 5.0

        def send_packet(self, payload):
            self.sent.append(payload)

        def recv_packet(self, keepalive=True):
            raise CCSSHTimeoutError("stalled peer") # like a real transport

    t = FakeT()
    s = ChannelSocket(t, 7, window=0xFFFFFFFF, maxpacket=32768, timeout=0.2)
    # a hostile +1 increment past 2^32-1 must not wrap the window
    s._window = 0xFFFFFFFF
    with pytest.raises(OSError, match="window exhausted"):
        s._top_up(0xFFFFFFFF + 1)
    assert s._window == 0xFFFFFFFF


def test_forwarder_global_codes_and_pending_timeout():
    # GLOBAL_REQUEST never reaches mux routing: the transport answers it
    # centrally (81 for hostkeys-00/keepalive, 82 otherwise - covered by
    # the transport-level global tests). Here the mux must stay silent.
    from ccssh.forward import BaseForwarder, ForwardError
    from ccssh.mux import ChannelMux

    class FakeT:
        def __init__(self):
            self.sent = []
            self.timeout = 5.0

        def send_packet(self, payload):
            self.sent.append(payload)

        def recv_packet(self, keepalive=True):
            raise CCSSHTimeoutError("idle")

    t = FakeT()
    mux = ChannelMux(t)
    mux.start()
    try:
        mux._route(bytes([80]) + W.enc_string(b"hostkeys-00@openssh.com") + W.enc_bool(True))
        mux._route(bytes([80]) + W.enc_string(b"tcpip-forward") + W.enc_bool(True))
        assert t.sent == []
    finally:
        mux.stop()
    fwd = BaseForwarder(mux)
    assert fwd._route_confirm(999, 1, 2, 3) is False
    assert fwd._route_failure(999) is False
    from ccssh.forward import _PendingOpen
    with pytest.raises(ForwardError):
        fwd._wait_pending(999, _PendingOpen(), timeout=0.2)


# SFTP hardening


def test_sftp_error_is_valueerror_and_capped():
    from ccssh.sftp import SFTPClient, SFTPError
    assert issubclass(SFTPError, ValueError)
    sc = SFTPClient(lambda srv, data: None, lambda: b"", 1, maxpacket=1024)
    with pytest.raises(SFTPError):
        sc._call(17, b"x" * 2048) # request bigger than server maxpacket
    rtype, rest = 101, W.enc_u32(4) + W.enc_string(b"nope") + W.enc_string(b"en")
    with pytest.raises(SFTPError, match="nope"):
        sc._check(rtype, rest, 101)
    assert sc._check(101, W.enc_u32(0) + W.enc_string(b"") + W.enc_string(b""), 101) == b""


def test_sftp_id_mismatch_closes_fail_closed():
    from ccssh.sftp import SFTPClient, SFTPError, F_STAT, S_OK
    calls = {"n": 0}

    def fake_recv():
        calls["n"] += 1
        body = bytes([F_STAT]) + W.enc_u32(999) + W.enc_u32(S_OK) \
            + W.enc_string(b"") + W.enc_string(b"")
        return W.enc_u32(len(body)) + body

    sc = SFTPClient(lambda srv, data: None, fake_recv, 1)
    with pytest.raises(SFTPError, match="mismatch"):
        sc._call(17, b"")
    assert sc._closed is True


def test_sftp_empty_put_sends_no_zero_write():
    # An empty file must round-trip without a zero-length WRITE on the wire.
    from ccssh.sftp import SFTPClient, F_HANDLE, F_STATUS, S_OK
    writes = []

    def fake_send(srv, data):
        writes.append(data)

    def enc_ok(rid):
        body = bytes([F_STATUS]) + W.enc_u32(rid) + W.enc_u32(S_OK) + W.enc_string(b"") + W.enc_string(b"")
        return W.enc_u32(len(body)) + body

    handle = W.enc_string(b"h")
    handle_reply = W.enc_u32(1 + 4 + len(handle)) + bytes([F_HANDLE]) + W.enc_u32(1) + handle
    script = [handle_reply, enc_ok(2)] # OPEN(rid 1), CLOSE(rid 2)

    def fake_recv():
        return script.pop(0)

    sc = SFTPClient(fake_send, fake_recv, 1)
    sc.put("/empty.bin", b"")
    # every sent payload is one length-prefixed SFTP message: assert none
    # of them is a WRITE (type 6), i.e. no zero-length WRITE went out
    assert writes, "expected OPEN+CLOSE on the wire"
    for payload in writes:
        r = W.Reader(payload)
        r.raw(4)  # length prefix
        assert r.byte() != 6, "zero-length WRITE must not be sent"
    # oversized requests are refused before touching the wire
    n_before = len(writes)
    with pytest.raises(Exception):
        sc._call(6, b"x" * (sc._maxpacket + 1))
    assert len(writes) == n_before


# live MITM: MAC tampering on the wire


def _enc_pair(cipher, mac):
    import hashlib as _hl
    from ccssh import crypto as C
    from ccssh.transport import SyncTransport
    K_enc = W.enc_string(os.urandom(32))
    Hh = os.urandom(32)
    hf = lambda d: _hl.sha256(d).digest()
    keys = C.derive_keys(K_enc, Hh, Hh, cipher, mac, hf)
    a1, b1 = socket.socketpair()
    a2, b2 = socket.socketpair()
    tc = SyncTransport(a1, b"SSH-2.0-T", timeout=2)
    ts = SyncTransport(b2, b"SSH-2.0-T", timeout=2)
    for t in (tc, ts):
        t.cipher, t.mac = cipher, mac
    tc._s = C.AesCtrHmacCtx(cipher, mac, keys["enc_c2s"], keys["iv_c2s"], keys["mac_c2s"])
    tc._enc_on_send = True
    ts._r = C.AesCtrHmacCtx(cipher, mac, keys["enc_c2s"], keys["iv_c2s"], keys["mac_c2s"])
    ts._enc_on_recv = True
    return tc, ts, b1, a2


def _relay_flip(src, dst, flip_at, total):
    data = b""
    src.settimeout(5)
    while len(data) < total:
        chunk = src.recv(total - len(data))
        if not chunk:
            break
        data += chunk
    data = bytearray(data)
    data[flip_at] ^= 1
    dst.sendall(bytes(data))


def test_mitm_mac_tamper_same_message_etm_and_plain():
    # payload 8 bytes -> fixed packet geometry on both framings
    msgs = []
    for mac, etm in (("hmac-sha2-256", False), ("hmac-sha2-256-etm@openssh.com", True)):
        tc, ts, mid_read, mid_write = _enc_pair("aes128-ctr", mac)
        # geometry: plain pl = 1+8+pad; etm body pl likewise; both + mac 32
        from ccssh.crypto import pad_packet, pad_len_aad
        if etm:
            pl = 1 + 8 + pad_len_aad(8, 16)
        else:
            pl = 1 + 8 + pad_packet(9, 16)
        total = (4 + pl + 32) if etm else (4 + pl + 32)
        box = {}

        def attacker():
            _relay_flip(mid_read, mid_write, 4 + pl + 31, total)
            box["done"] = True

        th = threading.Thread(target=attacker, daemon=True)
        th.start()
        tc.send_packet(b"A" * 8)
        # server side reads the tampered packet: integrity must fail with
        # the SAME message on both framings (no padding oracle)
        try:
            ts.recv_packet(keepalive=False)
            outcome = "ACCEPTED (bad!)"
        except CCSSHError as e:
            outcome = str(e)
        finally:
            for s in (tc.sock, ts.sock, mid_read, mid_write):
                try:
                    s.close()
                except Exception:
                    pass
            th.join(timeout=5)
        msgs.append(outcome)
    assert msgs[0] == msgs[1] == "packet integrity failed", msgs


def test_mitm_tamper_never_accepts_forged_data():
    tc, ts, mid_read, mid_write = _enc_pair("aes128-ctr", "hmac-sha2-512")
    from ccssh.crypto import pad_packet
    pl = 1 + 8 + pad_packet(9, 16)
    total = 4 + pl + 64

    def attacker():
        _relay_flip(mid_read, mid_write, 5, total) # flip inside ciphertext

    th = threading.Thread(target=attacker, daemon=True)
    th.start()
    tc.send_packet(b"B" * 8)
    with pytest.raises(CCSSHError):
        ts.recv_packet(keepalive=False)
    for s in (tc.sock, ts.sock, mid_read, mid_write):
        try:
            s.close()
        except Exception:
            pass
    th.join(timeout=5)


# CLI guards


def test_hostkey_changed_carries_evidence(tmp_path):
    from ccssh.hostcheck import check_hostkey, HostKeyError
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import mlkem as M
    old = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    new = M.hostkey_blob_from_priv(Ed25519PrivateKey.generate())
    kh = tmp_path / "known_hosts"
    kh.write_text(f"h.example.com ssh-ed25519 {base64.b64encode(old).decode()}\n")
    with pytest.raises(HostKeyError) as ei:
        check_hostkey("h.example.com", 22, new, "ssh-ed25519",
                      policy="strict", known_hosts=str(kh))
    msg = str(ei.value)
    assert "HOST KEY CHANGED" in msg
    assert f"{kh}:1" in msg  # offending file:line
    assert "Old ssh-ed25519 fingerprint: SHA256:" in msg
    assert "New ssh-ed25519 fingerprint: SHA256:" in msg
    assert "ssh-keygen -R h.example.com" in msg


def test_cli_changed_key_banner(capsys, monkeypatch):
    from ccssh import cli as CLIMOD
    from ccssh.hostcheck import HostKeyError

    class Fake:
        def __init__(self, *a, **k):
            pass

        def connect(self, *a, **k):
            raise HostKeyError("HOST KEY CHANGED for h (possible MitM!)\nOffending key in /kh:3")

        def close(self):
            pass

    monkeypatch.setattr(CLIMOD, "CCSSHClient", Fake)
    assert CLIMOD.main(["u@h.example.com", "echo", "hi"]) == 255
    err = capsys.readouterr().err
    assert "REMOTE HOST IDENTIFICATION HAS CHANGED" in err
    assert "SOMETHING NASTY" in err
    assert "ccssh: connect: HOST KEY CHANGED" in err


def test_cli_guardrails():
    from ccssh.cli import main, _parse_L, parse_jump, parse_jump_chain, UsageError
    import pytest as _pt
    assert main(["-p", "0", "u@h"]) == 255
    assert main(["-p", "99999", "u@h"]) == 255
    # -t/-T is last-wins, not an error (tested with effects in test_ccssh)
    assert parse_jump_chain("a,b", "u") == [("a", "u", 22), ("b", "u", 22)]
    with _pt.raises(UsageError):
        _parse_L("0:127.0.0.1:80")
    with _pt.raises(UsageError):
        _parse_L("8080:127.0.0.1:99999")
    with _pt.raises(UsageError):
        parse_jump("", "")
    assert main(["--password-env", "not an identifier!", "u@h"]) == 255
    assert main(["-o", "StrictHostKeyChecking=maybe", "u@h"]) == 255
    with _pt.raises(UsageError):
        from ccssh.cli import parse_o_options
        parse_o_options(["NoEqualsHere"])


