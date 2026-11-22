"""Raw SFTP packets over real, host-verified SSH; no built-in SFTP client."""
import asyncio
import struct

import asyncssh
import pytest

import server as s
from test_policy import make_policy


def u32(n):
    return struct.pack('>I', n)


def string(value):
    return u32(len(value)) + value


class Wire:
    def __init__(self, process):
        self.process = process
        self.request_id = 0

    async def packet(self, kind, payload):
        body = bytes([kind]) + payload
        self.process.stdin.write(u32(len(body)) + body)
        size = struct.unpack('>I', await self.process.stdout.readexactly(4))[0]
        return await self.process.stdout.readexactly(size)

    async def request(self, kind, payload=b''):
        self.request_id += 1
        reply = await self.packet(kind, u32(self.request_id) + payload)
        assert struct.unpack('>I', reply[1:5])[0] == self.request_id
        return reply


def status(reply, code):
    assert reply[0] == 101
    assert struct.unpack('>I', reply[5:9])[0] == code


def token(reply):
    assert reply[0] == 102
    length = struct.unpack('>I', reply[5:9])[0]
    return reply[9:9 + length]


async def scenario(tmp_path, action, user='bob'):
    policy = make_policy(tmp_path)
    jail = tmp_path / 'jail'
    (jail / 'projects').mkdir(parents=True)
    (jail / 'projects' / 'seed.txt').write_bytes(b'seed')
    key = asyncssh.generate_private_key('ssh-ed25519')
    key_path = tmp_path / 'host_key'
    key.write_private_key(key_path)
    password = 'ephemeral-test-password'
    listener = await s.serve(lambda name, secret: name == user and secret == password,
                             policy.authorize, policy.inherit, root=jail,
                             host_key=key_path, port=0)
    known_hosts = tmp_path / 'known_hosts'
    known_hosts.write_bytes(b'[127.0.0.1]:' + str(listener.get_port()).encode()
                           + b' ' + key.export_public_key())
    try:
        async with asyncssh.connect('127.0.0.1', port=listener.get_port(), username=user,
                                   password=password, known_hosts=str(known_hosts),
                                   client_keys=[], agent_path=None) as connection:
            async with connection.create_process(subsystem='sftp', encoding=None) as process:
                wire = Wire(process)
                assert await wire.packet(1, u32(3)) == b'\x02' + u32(3)
                await action(wire, jail)
    finally:
        listener.close()
        await listener.wait_closed()


def test_wire_transfer_and_handles(tmp_path):
    """Negotiate v3, round-trip binary chunks, FSTAT and reject closed handles."""
    async def action(wire, jail):
        payload = bytes(range(256)) * 600
        handle = token(await wire.request(3, string(b'/projects/upload.bin') + u32(27) + u32(0)))
        for offset in range(0, len(payload), 32768):
            status(await wire.request(6, string(handle) + struct.pack('>Q', offset)
                                      + string(payload[offset:offset + 32768])), 0)
        assert (await wire.request(8, string(handle)))[0] == 105
        downloaded = bytearray()
        while True:
            reply = await wire.request(5, string(handle) + struct.pack('>Q', len(downloaded)) + u32(32768))
            if reply[0] == 101:
                status(reply, 1)
                break
            assert reply[0] == 103
            length = struct.unpack('>I', reply[5:9])[0]
            downloaded.extend(reply[9:9 + length])
        assert bytes(downloaded) == payload == (jail / 'projects/upload.bin').read_bytes()
        status(await wire.request(4, string(handle)), 0)
        status(await wire.request(8, string(handle)), 4)
        status(await wire.request(255), 4)
    asyncio.run(asyncio.wait_for(scenario(tmp_path, action), 15))


def test_directory_eof_stat_and_mkdir(tmp_path):
    """Exercise directory EOF, metadata, canonical paths and single-level creation."""
    async def action(wire, jail):
        assert (await wire.request(16, string(b'/projects/.')))[0] == 104
        for kind in (7, 17):
            assert (await wire.request(kind, string(b'/projects/seed.txt')))[0] == 105
        status(await wire.request(14, string(b'/projects/new') + u32(0)), 0)
        handle = token(await wire.request(11, string(b'/projects')))
        assert (await wire.request(12, string(handle)))[0] == 104
        status(await wire.request(12, string(handle)), 1)
        status(await wire.request(4, string(handle)), 0)
        status(await wire.request(17, string(b'/projects/missing')), 2)
        status(await wire.request(14, string(b'/projects/missing/child') + u32(0)), 2)
    asyncio.run(asyncio.wait_for(scenario(tmp_path, action), 15))


@pytest.mark.parametrize('path', [b'/../outside', b'/projects/../../outside', b'/projects/..\\outside'])
def test_traversal_denied(tmp_path, path):
    """Reject traversal over the real SSH/SFTP boundary."""
    async def action(wire, jail):
        status(await wire.request(17, string(path)), 3)
    asyncio.run(asyncio.wait_for(scenario(tmp_path, action), 15))


def test_handle_mode_and_symlink(tmp_path):
    """A read handle cannot write and a jail symlink cannot expose outside data."""
    async def action(wire, jail):
        handle = token(await wire.request(3, string(b'/projects/seed.txt') + u32(1) + u32(0)))
        status(await wire.request(6, string(handle) + struct.pack('>Q', 0) + string(b'bad')), 3)
        assert (jail / 'projects/seed.txt').read_bytes() == b'seed'
        outside = tmp_path / 'outside'
        outside.write_bytes(b'private')
        try:
            (jail / 'projects/link').symlink_to(outside)
        except OSError:
            pytest.skip('OS does not permit test symlink creation')
        status(await wire.request(3, string(b'/projects/link') + u32(1) + u32(0)), 3)
    asyncio.run(asyncio.wait_for(scenario(tmp_path, action), 15))
