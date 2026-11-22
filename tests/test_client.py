"""Client tests against the real server (server/server.py).

The server starts through its serve() injection point with two hooks that
exist only for these tests: a fixed password check and a small authorize()
stub. They keep the client tests independent of the project's password
store and policy data.
"""
import asyncio
import io
from pathlib import Path
import socket
import sys

import asyncssh
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "client"))

import server as sftp_server  # noqa: E402
import client as sftp_client  # noqa: E402

USER, PASSWORD = "tester", "test-only-password"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def stub_authorize(user, op, path):
    # Stub for these tests: allow everything except paths under /denied.
    if path == "/denied" or path.startswith("/denied/"):
        return False, "test stub: denied prefix"
    return True, "test stub: allow"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def env(tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = tmp_path / "host_key"
    key.write_private_key(str(key_path))
    jail = tmp_path / "jail"
    jail.mkdir()
    (jail / "denied").mkdir()
    (jail / "denied" / "secret.txt").write_bytes(b"nope")
    return {"key": key, "key_path": key_path, "jail": jail,
            "known": tmp_path / "known_hosts", "port": free_port(), "tmp": tmp_path}


async def start(env):
    return await sftp_server.serve(
        lambda u, p: u == USER and p == PASSWORD, stub_authorize, lambda u, p, k: None,
        root=env["jail"], host_key=env["key_path"], port=env["port"])


async def open_shell(env):
    await sftp_client.ensure_trusted("127.0.0.1", env["port"], env["known"], accept_new=True)
    conn = await sftp_client.connect("127.0.0.1", env["port"], USER, PASSWORD, env["known"])
    sftp = sftp_client.SFTPChannel(conn)
    await sftp.start()
    out = io.StringIO()
    shell = sftp_client.Shell(sftp, out=out)
    await shell.setup()
    return conn, sftp, shell, out


def test_put_get_roundtrip_is_byte_identical(env):
    """Objective: put then get returns the exact bytes, across several READ/WRITE chunks."""
    payload = bytes(range(256)) * 1000 + b"tail"  # 256 004 bytes, about 8 chunks
    src = env["tmp"] / "src.bin"
    src.write_bytes(payload)
    dst = env["tmp"] / "dst.bin"

    async def scenario():
        listener = await start(env)
        try:
            conn, sftp, shell, out = await open_shell(env)
            async with conn:
                await shell.run("mkdir demo")
                await shell.run(f'put "{src}" /demo/src.bin')
                await shell.run(f'get /demo/src.bin "{dst}"')
                await shell.run("stat /demo/src.bin")
                await shell.run("ls /demo")
                sftp.close()
            return out.getvalue()
        finally:
            listener.close()

    output = run(scenario())
    assert dst.read_bytes() == payload
    assert f"Size: {len(payload)} bytes" in output
    assert "src.bin" in output


def test_pwd_cd_and_relative_paths(env):
    """Objective: pwd starts at '/', cd changes it, and relative paths resolve against it."""
    async def scenario():
        listener = await start(env)
        try:
            conn, sftp, shell, out = await open_shell(env)
            async with conn:
                await shell.run("pwd")
                await shell.run("mkdir a")
                await shell.run("cd a")
                await shell.run("pwd")
                await shell.run("mkdir b")
                await shell.run("ls /a")
                sftp.close()
            return out.getvalue().splitlines()
        finally:
            listener.close()

    lines = run(scenario())
    assert lines[0] == "/"
    assert lines[1] == "/a"
    assert any(line.endswith(" b") for line in lines)


def test_errors_are_clear_messages_not_crashes(env):
    """Objective: denied, missing and bad-usage cases print a message and the shell keeps working."""
    async def scenario():
        listener = await start(env)
        try:
            conn, sftp, shell, out = await open_shell(env)
            async with conn:
                await shell.run("get /denied/secret.txt " + str(env["tmp"] / "x"))
                await shell.run("stat /missing.txt")
                await shell.run("mkdir /denied/new")
                await shell.run("frobnicate")
                await shell.run("pwd")  # still alive
                sftp.close()
            return out.getvalue()
        finally:
            listener.close()

    output = run(scenario())
    assert "get: permission denied" in output
    assert "stat: no such file or directory" in output
    assert "mkdir: permission denied" in output
    assert "unknown command" in output
    assert output.rstrip().endswith("/")
    assert not (env["tmp"] / "x").exists()  # no partial download left behind


def test_tofu_pins_key_and_rejects_a_changed_key(env):
    """Objective: first connect pins the host key; a different key on the same host:port aborts."""
    async def scenario():
        listener = await start(env)
        try:
            await sftp_client.ensure_trusted("127.0.0.1", env["port"], env["known"], accept_new=True)
            await sftp_client.ensure_trusted("127.0.0.1", env["port"], env["known"], accept_new=False)
        finally:
            listener.close()
            await listener.wait_closed()
        # Same address, different key, as an impostor server would have.
        other = asyncssh.generate_private_key("ssh-ed25519")
        other.write_private_key(str(env["key_path"]))
        listener = await start(env)
        try:
            with pytest.raises(sftp_client.HostKeyMismatch):
                await sftp_client.ensure_trusted("127.0.0.1", env["port"], env["known"], accept_new=True)
            # Even with TOFU skipped, AsyncSSH's own check refuses the impostor.
            with pytest.raises(asyncssh.HostKeyNotVerifiable):
                await sftp_client.connect("127.0.0.1", env["port"], USER, PASSWORD, env["known"])
        finally:
            listener.close()

    run(scenario())
    assert env["known"].read_text().count("ssh-ed25519") == 1


def test_wrong_password_is_refused(env):
    """Objective: a wrong password raises PermissionDenied (the CLI prints 'Authentication failed')."""
    async def scenario():
        listener = await start(env)
        try:
            await sftp_client.ensure_trusted("127.0.0.1", env["port"], env["known"], accept_new=True)
            with pytest.raises(asyncssh.PermissionDenied):
                await sftp_client.connect("127.0.0.1", env["port"], USER, "wrong", env["known"])
        finally:
            listener.close()

    run(scenario())
