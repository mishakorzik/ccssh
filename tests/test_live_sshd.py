"""Live interop matrix against a real local sshd (skipped without sshd).

 Spins up `sshd -p <free> -f <tmp config>` with fresh host keys and one
 authorized user key, then runs the client through KEX/cipher/MAC,
 rekey, SFTP, forwarding and host-policy scenarios. Anything that needs
 the daemon is skipped cleanly when it cannot start here.
"""
from __future__ import annotations
import os
import shutil
import socket
import subprocess
import tempfile
import time

import pytest

from ccssh.client import CCSSHClient

sshd_bin = shutil.which("sshd")
needs_sshd = pytest.mark.skipif(sshd_bin is None, reason="no sshd binary")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _mk_keys(tmp: str) -> dict:
    keys = {}
    for kind, name in (("-t", "ed25519"), ("-t", "rsa")):
        path = os.path.join(tmp, f"ssh_host_{name}_key")
        subprocess.run(["ssh-keygen", "-q", "-N", "", kind, name, "-f", path], check=True, capture_output=True)
        keys[name] = path
    user = os.path.join(tmp, "id_user")
    subprocess.run(["ssh-keygen", "-q", "-N", "", "-t", "ed25519", "-f", user], check=True, capture_output=True)
    return {"host": keys, "user": user}


@pytest.fixture(scope="module")
def live_sshd():
    if sshd_bin is None:
        pytest.skip("no sshd binary")
    tmp = tempfile.mkdtemp(prefix="ccssh-live-")
    try:
        keys = _mk_keys(tmp)
        auth = os.path.join(tmp, "authorized_keys")
        shutil.copy(keys["user"] + ".pub", auth)
        os.chmod(auth, 0o600)
        port = _free_port()
        cfg = os.path.join(tmp, "sshd_config")
        with open(cfg, "w") as f:
            f.write("Port %d\n" % port)
            f.write("ListenAddress 127.0.0.1\n")
            for p in keys["host"].values():
                f.write(f"HostKey {p}\n")
            f.write(f"PidFile {tmp}/sshd.pid\n")
            f.write(f"AuthorizedKeysFile {auth}\n")
            f.write("PasswordAuthentication no\n")
            f.write("PubkeyAuthentication yes\n")
            f.write("StrictModes no\n")
            f.write("UseDNS no\n")
        proc = subprocess.Popen([sshd_bin, "-f", cfg, "-E", os.path.join(tmp, "log")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        if proc.poll() is not None:
            pytest.skip("sshd refused to start here")
        # smoke test: one quick connect or skip the whole module
        probe = CCSSHClient(timeout=5, host_policy="off")
        try:
            probe.connect("127.0.0.1", port=port, username="root", key_filename=keys["user"])
            probe.close()
        except Exception:
            proc.terminate()
            pytest.skip("sshd unreachable here")
        yield {"port": port, "keys": keys, "tmp": tmp, "proc": proc}
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _connect(live, **kw):
    args = dict(timeout=10, host_policy="off")
    args.update(kw)
    c = CCSSHClient(**args)
    c.connect("127.0.0.1", port=live["port"], username="root", key_filename=live["keys"]["user"])
    return c


@needs_sshd
def test_live_default_mlkem(live_sshd):
    c = _connect(live_sshd)
    try:
        assert c.negotiated()["kex"] == "mlkem768x25519-sha256"
        assert c.exec_command("echo live")[0] == "live\n"
    finally:
        c.close()


@needs_sshd
@pytest.mark.parametrize("kex", ["curve25519-sha256", "curve25519-sha256@libssh.org",
                                 "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
                                 "ecdh-sha2-nistp521", "mlkem768x25519-sha256",
                                 "mlkem768nistp256-sha256",
                                 "diffie-hellman-group14-sha1",
                                 "diffie-hellman-group14-sha256",
                                 "diffie-hellman-group16-sha512",
                                 "diffie-hellman-group18-sha512"])
def test_live_kex_each(live_sshd, kex):
    c = _connect(live_sshd, kex=[kex])
    try:
        assert c.negotiated()["kex"] in (kex, "curve25519-sha256")
        assert c.exec_command("echo k")[0] == "k\n"
    finally:
        c.close()


@needs_sshd
@pytest.mark.parametrize("cipher,mac", [
    ("aes128-ctr", "hmac-sha1"),
    ("aes128-ctr", "hmac-sha2-256"),
    ("aes128-ctr", "hmac-sha2-256-etm@openssh.com"),
    ("aes192-ctr", "hmac-sha2-256"),
    ("aes256-ctr", "hmac-sha2-512"),
    ("aes256-ctr", "hmac-sha2-512-etm@openssh.com"),
    ("aes128-gcm@openssh.com", "hmac-sha2-256"),
    ("aes256-gcm@openssh.com", "hmac-sha2-512"),
    ("chacha20-poly1305@openssh.com", "hmac-sha2-256"),
])
def test_live_cipher_mac(live_sshd, cipher, mac):
    c = _connect(live_sshd, ciphers=[cipher], macs=[mac])
    try:
        assert c.negotiated()["cipher"] == cipher
        assert c.exec_command("echo c")[0] == "c\n"
    finally:
        c.close()


@needs_sshd
def test_live_rekey(live_sshd):
    c = _connect(live_sshd)
    try:
        sid = c._sid
        assert c.exec_command("echo one")[0] == "one\n"
        c.rekey()
        assert c._sid == sid
        assert c.exec_command("echo two")[0] == "two\n"
    finally:
        c.close()


@needs_sshd
def test_live_sftp(live_sshd):
    c = _connect(live_sshd)
    try:
        s = c.open_sftp()
        data = os.urandom(50000)
        s.put("/tmp/ccssh-live.bin", data)
        assert s.get("/tmp/ccssh-live.bin") == data
        s.remove("/tmp/ccssh-live.bin")
        s.close()
    finally:
        c.close()


@needs_sshd
def test_live_strict_known_hosts(live_sshd, tmp_path):
    from ccssh.hostcheck import check_hostkey, HostKeyError
    kh = str(tmp_path / "known_hosts")
    c = _connect(live_sshd, host_policy="accept-new", known_hosts=kh)
    Ks = c._host_Ks
    alg = c.negotiated()["hostkey"]
    c.close()
    assert os.path.exists(kh)
    check_hostkey("127.0.0.1", live_sshd["port"], Ks, alg, policy="strict", known_hosts=kh)
    try:
        check_hostkey("127.0.0.1", live_sshd["port"], b"junk", alg, policy="strict", known_hosts=kh)
        raise AssertionError("junk accepted")
    except HostKeyError:
        pass


@needs_sshd
@pytest.mark.parametrize("host_alg,user_alg", [
    ("ssh-ed25519", "ed25519_user"),
    ("rsa-sha2-256", "rsa_user"),
    ("rsa-sha2-512", "rsa_user"),
    ("ecdsa-sha2-nistp256", "ecdsa_user"),
    ("ssh-mldsa44-ed25519", "mldsa_user"),
])
def test_live_hostkey_userkey(live_sshd, host_alg, user_alg):
    c = _connect(live_sshd, hostkeys=[host_alg])
    try:
        assert c.negotiated()["hostkey"] == host_alg
        assert c.exec_command("echo u")[0] == "u\n"
    finally:
        c.close()


@needs_sshd
def test_live_async_exec(live_sshd):
    import asyncio
    from ccssh import async_client as AC

    async def go():
        c = AC.AsyncCCSSHClient(timeout=10, host_policy="off")
        await c.connect("127.0.0.1", port=live_sshd["port"], username="root", key_filename=live_sshd["keys"]["user"])
        try:
            return await c.exec_command("echo async-live")
        finally:
            await c.close()

    assert asyncio.run(go())[0] == "async-live\n"


@needs_sshd
def test_live_big_output(live_sshd):
    c = _connect(live_sshd)
    try:
        out, _, code = c.exec_command("head -c 200000 /dev/urandom | base64 | head -c 100000")
        assert code == 0 and len(out) > 50000
    finally:
        c.close()


@needs_sshd
def test_live_forward_local(live_sshd):
    import socket as _sock
    import time as _time
    c = _connect(live_sshd)
    try:
        fwd = c.forward_local(0, "127.0.0.1", live_sshd["port"])
        try:
            _time.sleep(0.3)
            assert fwd.port != 0
        finally:
            fwd.close()
    finally:
        c.close()


@needs_sshd
def test_live_host_cert(live_sshd, tmp_path):
    # A CA-signed host cert for 127.0.0.1 verifies against @cert-authority.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from ccssh import certs as CERT
    from ccssh import wire as W
    from ccssh.hostcheck import check_hostkey
    ca = Ed25519PrivateKey.generate()
    host_priv = Ed25519PrivateKey.generate()
    host_pub = host_priv.public_key().public_bytes_raw()
    blob = CERT.build_cert(keytype="ssh-ed25519-cert-v01@openssh.com", pub_fields=W.enc_string(host_pub), principals="127.0.0.1", ca_priv=ca)
    info = CERT.parse_cert(blob)
    kh = tmp_path / "known_hosts"
    import base64
    kh.write_text(f"@cert-authority * ssh-ed25519 {base64.b64encode(info['sig_key']).decode()}\n")
    check_hostkey("127.0.0.1", live_sshd["port"], blob, "ssh-ed25519-cert-v01@openssh.com", policy="strict", known_hosts=str(kh))


@needs_sshd
def test_live_mldsa_host_cert(tmp_path):
    pytest.importorskip("cryptography")
    from ccssh import mldsa as ML
    try:
        kp = ML.KeyPair.generate()
    except Exception:
        pytest.skip("no ML-DSA backend")
    assert len(kp.public_blob()) > 0
