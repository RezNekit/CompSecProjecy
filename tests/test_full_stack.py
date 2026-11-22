"""Acceptance through the production entry point, real AuthN and the raw client."""
import asyncio
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time

import asyncssh
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'client'))
import client as cl
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from make_users import create_user_record

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def production(tmp_path):
    """Launch the real startup path with independent data, credentials, jail and audit."""
    directory = tmp_path / 'data'
    shutil.copytree(ROOT / 'data', directory)
    passwords = {name: secrets.token_urlsafe(24) for name in ('alice', 'bob', 'eve')}
    (directory / 'users.json').write_text(json.dumps([
        create_user_record(name, password) for name, password in passwords.items()]))
    jail = tmp_path / 'jail'
    for name in ('public', 'projects', 'admin'):
        (jail / name).mkdir(parents=True)
        (jail / name / 'seed.txt').write_bytes(b'seed')
    key = asyncssh.generate_private_key('ssh-ed25519')
    key_path = tmp_path / 'host_key'
    key.write_private_key(key_path)
    log_path = tmp_path / 'startup.log'
    audit_path = tmp_path / 'audit.jsonl'
    with log_path.open('w') as log:
        process = subprocess.Popen([sys.executable, str(ROOT / 'server/server.py'),
                                    '--data-dir', str(directory), '--root', str(jail),
                                    '--host-key', str(key_path), '--port', '0',
                                    '--audit-path', str(audit_path)], cwd=tmp_path,
                                   stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                text = log_path.read_text()
                match = re.search(r'listening on 127.0.0.1:(\d+)', text)
                if match:
                    break
                assert process.poll() is None, text
                time.sleep(0.02)
            else:
                pytest.fail('Production startup timed out: ' + log_path.read_text())
            port = int(match[1])
            known = tmp_path / 'known_hosts'
            known.write_bytes(f'[127.0.0.1]:{port} '.encode() + key.export_public_key())
            yield dict(port=port, known=known, passwords=passwords, jail=jail,
                       audit=audit_path, log=log_path, tmp=tmp_path)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


async def connection(env, user, password=None):
    return await cl.connect('127.0.0.1', env['port'], user,
                            env['passwords'][user] if password is None else password,
                            env['known'])


def test_production_multiuser_and_client(production):
    """Actual startup, password store and policy enforce user-specific client operations."""
    env = production
    async def scenario():
        for user, allowed_path, denied_path in (
                ('alice', '/admin/seed.txt', '/public/new.txt'),
                ('bob', '/projects/seed.txt', '/admin/seed.txt'),
                ('eve', '/public/seed.txt', '/projects/seed.txt')):
            async with await connection(env, user) as conn:
                channel = cl.SFTPChannel(conn)
                await channel.start()
                handle = await channel.open(allowed_path, cl.PF_READ)
                assert await channel.read(handle, 0, 64) == b'seed'
                await channel.close_handle(handle)
                flags = cl.PF_WRITE | cl.PF_CREAT if user == 'alice' else cl.PF_READ
                with pytest.raises(cl.SFTPError) as error:
                    await channel.open(denied_path, flags)
                assert error.value.code == 3
                if user == 'bob':
                    import io
                    shell = cl.Shell(channel, out=io.StringIO())
                    await shell.setup()
                    source = env['tmp'] / 'source.bin'
                    target = env['tmp'] / 'target.bin'
                    source.write_bytes(bytes(range(256)) * 500)
                    assert await shell.run('pwd') is not False
                    await shell.run('mkdir /projects/new')
                    await shell.run(f'put "{source}" /projects/new/upload.bin')
                    await shell.run('ls /projects/new')
                    await shell.run('stat /projects/new/upload.bin')
                    await shell.run(f'get /projects/new/upload.bin "{target}"')
                    assert source.read_bytes() == target.read_bytes()
                    await shell.run('quit')
                channel.close()
    asyncio.run(asyncio.wait_for(scenario(), 20))
    records = [json.loads(line) for line in env['audit'].read_text().splitlines()]
    assert {r['user'] for r in records if r['op'] == 'auth' and r['allowed']} == {'alice', 'bob', 'eve'}
    assert any(r['reason'] == 'MAC: no write down' for r in records)
    for name in ('users.json', 'user_roles.json', 'role_perms.csv', 'mac_labels.json',
                 'dac_owners.csv', 'groups.json'):
        assert name in env['log'].read_text()
    assert all(password not in env['log'].read_text() + env['audit'].read_text()
               for password in env['passwords'].values())


def test_production_lockout_over_ssh(production):
    """Five failed SSH logins lock the account and subsequently reject its correct password."""
    env = production
    async def scenario():
        for _ in range(5):
            with pytest.raises(asyncssh.PermissionDenied):
                await connection(env, 'bob', 'incorrect')
        with pytest.raises(asyncssh.PermissionDenied):
            await connection(env, 'bob')
        # Lockout is per user; another account continues to authenticate.
        async with await connection(env, 'eve'):
            pass
    asyncio.run(asyncio.wait_for(scenario(), 20))
    assert any('locked' in json.loads(line)['reason']
               for line in env['audit'].read_text().splitlines())
