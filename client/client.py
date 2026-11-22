#!/usr/bin/env python3
"""SFTP v3 command-line client.

AsyncSSH handles the SSH transport, password authentication and the session
channel. On top of that channel this file opens the "sftp" subsystem and builds
and parses each SFTP v3 packet by hand. The brief's academic-integrity rule
forbids asyncssh.start_sftp_client, so it is not used.

Usage:
    python3 client/client.py --host 127.0.0.1 --port 2222 --username bob
    sftp> help
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
from pathlib import Path
import posixpath
import shlex
import stat
import struct
import sys
import time

import asyncssh

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_KNOWN_HOSTS = BASE_DIR / "known_hosts"
CHUNK = 32 * 1024            # bytes per READ/WRITE, far under the server's 256 KiB packet cap
MAX_REPLY = 1024 * 1024      # larger reply frames are treated as a broken or hostile server

# SFTP v3 packet types (draft-ietf-secsh-filexfer-02, section 3)
INIT, VERSION, OPEN, CLOSE, READ, WRITE = 1, 2, 3, 4, 5, 6
LSTAT, FSTAT, OPENDIR, READDIR, MKDIR, REALPATH, STAT = 7, 8, 11, 12, 14, 16, 17
STATUS, HANDLE, DATA, NAME, ATTRS = 101, 102, 103, 104, 105

# STATUS codes (section 7)
OK, EOF, NO_SUCH_FILE, PERMISSION_DENIED, FAILURE = 0, 1, 2, 3, 4
OP_UNSUPPORTED = 8
STATUS_TEXT = {
    OK: "OK",
    EOF: "end of file",
    NO_SUCH_FILE: "no such file or directory",
    PERMISSION_DENIED: "permission denied",
    FAILURE: "failure (the server refused the request)",
    5: "bad message",
    6: "no connection",
    7: "connection lost",
    OP_UNSUPPORTED: "operation not supported",
}

# OPEN pflags (section 6.3)
PF_READ, PF_WRITE, PF_APPEND, PF_CREAT, PF_TRUNC, PF_EXCL = 1, 2, 4, 8, 16, 32

# ATTRS flags (section 5)
ATTR_SIZE, ATTR_UIDGID, ATTR_PERMISSIONS, ATTR_ACMODTIME = 0x1, 0x2, 0x4, 0x8
ATTR_EXTENDED = 0x80000000


# Packet encoding / decoding
def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def sstr(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return u32(len(value)) + value


EMPTY_ATTRS = u32(0)  # flags = 0, so the server and policy pick mode and owner


class Reader:
    """Bounds-checked reader for one reply packet."""

    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ProtocolError("truncated reply from server")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def attrs(self) -> dict:
        flags = self.u32()
        out: dict = {}
        if flags & ATTR_SIZE:
            out["size"] = self.u64()
        if flags & ATTR_UIDGID:
            out["uid"], out["gid"] = self.u32(), self.u32()
        if flags & ATTR_PERMISSIONS:
            out["permissions"] = self.u32()
        if flags & ATTR_ACMODTIME:
            out["atime"], out["mtime"] = self.u32(), self.u32()
        if flags & ATTR_EXTENDED:
            for _ in range(self.u32()):
                self.string()
                self.string()
        return out


class ProtocolError(Exception):
    """The server sent something that is not valid SFTP v3."""


class SFTPError(Exception):
    """The server answered a request with a non-OK STATUS."""

    def __init__(self, code: int, server_message: str = ""):
        self.code = code
        self.server_message = server_message
        super().__init__(STATUS_TEXT.get(code, f"status {code}"))


# SFTP channel. One request at a time; each reply must carry the request's ID.
class SFTPChannel:
    def __init__(self, conn: asyncssh.SSHClientConnection):
        self.conn = conn
        self.writer = self.reader = None
        self.next_id = 1
        self.lock = asyncio.Lock()
        self.version = None

    async def start(self) -> None:
        # Session channel with the "sftp" subsystem (RFC 4254, section 6.5), in binary mode.
        self.writer, self.reader, _ = await self.conn.open_session(
            subsystem="sftp", encoding=None)
        self.writer.write(self._frame(INIT, u32(3)))
        kind, body = await self._read_frame()
        if kind != VERSION:
            raise ProtocolError(f"expected VERSION, got packet type {kind}")
        self.version = Reader(body).u32()
        if self.version != 3:
            raise ProtocolError(f"server speaks SFTP version {self.version}, need 3")

    def close(self) -> None:
        if self.writer is not None:
            self.writer.close()

    @staticmethod
    def _frame(kind: int, payload: bytes) -> bytes:
        body = bytes([kind]) + payload
        return u32(len(body)) + body

    async def _read_frame(self) -> tuple[int, bytes]:
        try:
            size = struct.unpack(">I", await self.reader.readexactly(4))[0]
            if not 1 <= size <= MAX_REPLY:
                raise ProtocolError("invalid reply length from server")
            body = await self.reader.readexactly(size)
        except asyncio.IncompleteReadError:
            raise ConnectionError("server closed the SFTP channel") from None
        return body[0], body[1:]

    async def raw_request(self, kind: int, payload_after_id: bytes) -> tuple[int, Reader]:
        """Send one request and return (reply type, reader positioned after the ID).

        Also used by the CTF attack scripts to send hand-crafted packets.
        """
        async with self.lock:
            req_id = self.next_id
            self.next_id = (self.next_id + 1) & 0xFFFFFFFF or 1
            self.writer.write(self._frame(kind, u32(req_id) + payload_after_id))
            reply_kind, body = await self._read_frame()
            reader = Reader(body)
            if reader.u32() != req_id:
                raise ProtocolError("reply request ID does not match the request")
            return reply_kind, reader

    async def _request(self, kind: int, payload: bytes, expect: int | None) -> Reader | None:
        reply_kind, reader = await self.raw_request(kind, payload)
        if reply_kind == STATUS:
            code = reader.u32()
            message = reader.string().decode("utf-8", "replace")
            if code == OK and expect is None:
                return None
            raise SFTPError(code, message)
        if expect is None or reply_kind != expect:
            raise ProtocolError(f"unexpected reply type {reply_kind}")
        return reader

    # SFTP v3 requests used by the client
    async def realpath(self, path: str) -> str:
        reader = await self._request(REALPATH, sstr(path), NAME)
        if reader.u32() < 1:
            raise ProtocolError("REALPATH returned no name")
        return reader.string().decode("utf-8", "replace")

    async def stat(self, path: str, lstat: bool = False) -> dict:
        reader = await self._request(LSTAT if lstat else STAT, sstr(path), ATTRS)
        return reader.attrs()

    async def fstat(self, handle: bytes) -> dict:
        return (await self._request(FSTAT, sstr(handle), ATTRS)).attrs()

    async def mkdir(self, path: str) -> None:
        await self._request(MKDIR, sstr(path) + EMPTY_ATTRS, None)

    async def open(self, path: str, pflags: int) -> bytes:
        reader = await self._request(OPEN, sstr(path) + u32(pflags) + EMPTY_ATTRS, HANDLE)
        return reader.string()

    async def opendir(self, path: str) -> bytes:
        return (await self._request(OPENDIR, sstr(path), HANDLE)).string()

    async def readdir(self, handle: bytes) -> list[tuple[str, str, dict]]:
        """One batch of entries; empty list means EOF."""
        try:
            reader = await self._request(READDIR, sstr(handle), NAME)
        except SFTPError as exc:
            if exc.code == EOF:
                return []
            raise
        entries = []
        for _ in range(reader.u32()):
            name = reader.string().decode("utf-8", "replace")
            longname = reader.string().decode("utf-8", "replace")
            entries.append((name, longname, reader.attrs()))
        return entries

    async def read(self, handle: bytes, offset: int, length: int) -> bytes:
        """Return data, or b"" at EOF."""
        try:
            reader = await self._request(READ, sstr(handle) + u64(offset) + u32(length), DATA)
        except SFTPError as exc:
            if exc.code == EOF:
                return b""
            raise
        return reader.string()

    async def write(self, handle: bytes, offset: int, data: bytes) -> None:
        await self._request(WRITE, sstr(handle) + u64(offset) + sstr(data), None)

    async def close_handle(self, handle: bytes) -> None:
        await self._request(CLOSE, sstr(handle), None)


# Connecting, with the host key checked by TOFU or against a given known_hosts file
class HostKeyMismatch(Exception):
    pass


def known_host_keys(path: Path, host: str, port: int) -> list:
    """Host keys already trusted for host:port in an OpenSSH known_hosts file."""
    if not path.exists():
        return []
    known = asyncssh.read_known_hosts(str(path))
    return list(known.match(host, "", port)[0])


def host_entry(host: str, port: int, key) -> str:
    name = host if port == 22 else f"[{host}]:{port}"
    return f"{name} {key.export_public_key('openssh').decode('ascii').strip()}\n"


async def ensure_trusted(host: str, port: int, known_hosts: Path, *,
                         accept_new: bool | None = None) -> None:
    """Trust on first use. Raises HostKeyMismatch if a different key is pinned.

    accept_new=None asks the user; True/False answers without asking (tests, batch).
    """
    offered = await asyncssh.get_server_host_key(
        host, port, server_host_key_algs=["ssh-ed25519"])
    if offered is None:
        raise ConnectionError("server did not present an Ed25519 host key")
    fingerprint = offered.get_fingerprint("sha256")
    pinned = known_host_keys(known_hosts, host, port)
    if pinned:
        if any(k.public_data == offered.public_data for k in pinned):
            return
        raise HostKeyMismatch(
            f"WARNING: the host key for {host}:{port} has CHANGED.\n"
            f"  Offered: {fingerprint}\n"
            f"  Pinned in {known_hosts}\n"
            "Someone could be impersonating the server (man-in-the-middle), or the "
            "server key was regenerated. Connection aborted. If the change is "
            "expected, remove the old line from the known_hosts file.")
    print(f"The authenticity of host '{host}:{port}' can't be established.")
    print(f"ED25519 key fingerprint is {fingerprint}.")
    if accept_new is None:
        answer = input("Are you sure you want to continue connecting (yes/no)? ")
        accept_new = answer.strip().lower() == "yes"
    if not accept_new:
        raise HostKeyMismatch("Host key not accepted; connection aborted.")
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    with open(known_hosts, "a", encoding="ascii") as fh:
        fh.write(host_entry(host, port, offered))
    print(f"Permanently added '{host}:{port}' to {known_hosts}.")


async def connect(host: str, port: int, username: str, password: str,
                  known_hosts: Path) -> asyncssh.SSHClientConnection:
    """Open the SSH connection; AsyncSSH verifies the server key against known_hosts."""
    return await asyncssh.connect(
        host, port, username=username, password=password,
        known_hosts=str(known_hosts), server_host_key_algs=["ssh-ed25519"],
        client_keys=None, agent_path=None, preferred_auth="password",
        public_key_auth=False, kbdint_auth=False, login_timeout=30)


# CLI commands
def format_attrs(path: str, attrs: dict) -> str:
    lines = [f"  File: {path}"]
    if "permissions" in attrs:
        mode = attrs["permissions"]
        kind = "directory" if stat.S_ISDIR(mode) else "regular file" if stat.S_ISREG(mode) else "other"
        lines.append(f"  Type: {kind}")
        lines.append(f"  Mode: {stat.filemode(mode)} ({mode & 0o7777:04o})")
    if "size" in attrs:
        lines.append(f"  Size: {attrs['size']} bytes")
    if "uid" in attrs:
        lines.append(f"  UID/GID: {attrs['uid']}/{attrs['gid']}")
    if "mtime" in attrs:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(attrs["mtime"]))
        lines.append(f"  Modified: {stamp}")
    return "\n".join(lines)


HELP = """Commands:
  pwd                     print the remote working directory
  cd <path>               change the remote working directory
  ls [path]               list a directory (OPENDIR/READDIR)
  mkdir <path>            create a directory (MKDIR)
  stat <path>             show attributes (STAT)
  get <rpath> [lpath]     download a file (OPEN read + READ + CLOSE)
  put <lpath> [rpath]     upload a file (OPEN write + WRITE + CLOSE)
  help                    show this help
  quit | exit             close the connection"""


class Shell:
    def __init__(self, sftp: SFTPChannel, out=sys.stdout):
        self.sftp = sftp
        self.cwd = "/"
        self.out = out

    def print(self, *args) -> None:
        print(*args, file=self.out)

    def remote(self, path: str) -> str:
        """Join a user-typed remote path with the cwd; the server canonicalizes it."""
        return path if path.startswith("/") else posixpath.join(self.cwd, path)

    async def setup(self) -> None:
        self.cwd = await self.sftp.realpath(".")

    async def run(self, line: str) -> bool:
        """Execute one command line. Returns False when the user quits."""
        try:
            args = shlex.split(line, posix=(os.name != "nt"))
            if os.name == "nt":
                args = [a[1:-1] if len(a) >= 2 and a[0] == a[-1] == '"' else a for a in args]
        except ValueError as exc:
            self.print(f"error: {exc}")
            return True
        if not args:
            return True
        cmd, rest = args[0].lower(), args[1:]
        handler = getattr(self, f"cmd_{cmd}", None)
        if cmd in ("quit", "exit", "bye"):
            return False
        if handler is None:
            self.print(f"unknown command: {cmd} (type 'help')")
            return True
        try:
            await handler(*rest)
        except TypeError:
            self.print(f"usage error for '{cmd}' (type 'help')")
        except SFTPError as exc:
            self.print(f"{cmd}: {exc}")
        except OSError as exc:  # local file problems (get/put)
            self.print(f"{cmd}: local error: {exc.strerror or exc}")
        return True

    async def cmd_help(self) -> None:
        self.print(HELP)

    async def cmd_pwd(self) -> None:
        self.print(self.cwd)

    async def cmd_cd(self, path: str = "/") -> None:
        target = await self.sftp.realpath(self.remote(path))
        attrs = await self.sftp.stat(target)
        if not stat.S_ISDIR(attrs.get("permissions", 0)):
            self.print(f"cd: {target}: not a directory")
            return
        self.cwd = target

    async def cmd_ls(self, path: str = ".") -> None:
        target = self.remote(path)
        handle = await self.sftp.opendir(target)
        entries = []
        try:
            while batch := await self.sftp.readdir(handle):
                entries.extend(batch)
        finally:
            await self.sftp.close_handle(handle)
        for name, longname, _ in sorted(entries, key=lambda e: e[0]):
            if name in (".", ".."):
                continue
            self.print(longname or name)

    async def cmd_mkdir(self, path: str) -> None:
        await self.sftp.mkdir(self.remote(path))

    async def cmd_stat(self, path: str) -> None:
        target = self.remote(path)
        self.print(format_attrs(target, await self.sftp.stat(target)))

    async def cmd_get(self, rpath: str, lpath: str | None = None) -> None:
        source = self.remote(rpath)
        name = posixpath.basename(source.rstrip("/"))
        if lpath is None:
            if name in ("", ".", ".."):
                self.print("get: give a local file name")
                return
            lpath = name
        local = Path(lpath)
        if local.is_dir():
            local = local / name
        handle = await self.sftp.open(source, PF_READ)
        partial = local.with_name(local.name + ".part")
        total = 0
        try:
            with open(partial, "wb") as fh:
                while chunk := await self.sftp.read(handle, total, CHUNK):
                    fh.write(chunk)
                    total += len(chunk)
            os.replace(partial, local)  # the final name only ever holds a complete file
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
        finally:
            await self.sftp.close_handle(handle)
        self.print(f"Fetched {source} -> {local} ({total} bytes)")

    async def cmd_put(self, lpath: str, rpath: str | None = None) -> None:
        local = Path(lpath)
        if not local.is_file():
            self.print(f"put: {lpath}: not a local file")
            return
        target = self.remote(rpath) if rpath else self.remote(local.name)
        if rpath and rpath.endswith("/"):
            target = posixpath.join(self.remote(rpath), local.name)
        elif rpath:
            try:
                if stat.S_ISDIR((await self.sftp.stat(target)).get("permissions", 0)):
                    target = posixpath.join(target, local.name)
            except SFTPError:
                pass  # the target does not exist yet, which is fine
        handle = await self.sftp.open(target, PF_WRITE | PF_CREAT | PF_TRUNC)
        total = 0
        try:
            with open(local, "rb") as fh:
                while chunk := fh.read(CHUNK):
                    await self.sftp.write(handle, total, chunk)
                    total += len(chunk)
        finally:
            await self.sftp.close_handle(handle)
        self.print(f"Uploaded {local} -> {target} ({total} bytes)")


# Entry point
async def amain(args: argparse.Namespace) -> int:
    known_hosts = Path(args.known_hosts)
    try:
        await ensure_trusted(args.host, args.port, known_hosts,
                             accept_new=True if args.accept_new_host_key else None)
    except HostKeyMismatch as exc:
        print(exc, file=sys.stderr)
        return 2
    except (OSError, asyncssh.Error) as exc:
        print(f"Cannot reach {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1

    # SFTP_PASSWORD is meant for scripted demos; otherwise we ask.
    password = os.environ.get("SFTP_PASSWORD") or getpass.getpass(
        f"{args.username}@{args.host}'s password: ")
    try:
        conn = await connect(args.host, args.port, args.username, password, known_hosts)
    except asyncssh.PermissionDenied:
        print("Authentication failed (wrong username/password, or account locked).",
              file=sys.stderr)
        return 1
    except asyncssh.HostKeyNotVerifiable:
        print("Host key verification failed; connection aborted.", file=sys.stderr)
        return 2
    except (OSError, asyncssh.Error) as exc:
        print(f"Connection failed: {exc}", file=sys.stderr)
        return 1
    finally:
        password = None

    async with conn:
        sftp = SFTPChannel(conn)
        try:
            await sftp.start()
            shell = Shell(sftp)
            await shell.setup()
            print(f"Connected to {args.host}:{args.port} as {args.username}. Type 'help'.")
            lines = None
            if args.batch:
                with open(args.batch, encoding="utf-8") as fh:
                    lines = [ln.rstrip("\n") for ln in fh]
            while True:
                if lines is not None:
                    if not lines:
                        break
                    line = lines.pop(0)
                    print(f"sftp> {line}")
                else:
                    try:
                        line = await asyncio.to_thread(input, "sftp> ")
                    except EOFError:
                        break
                if not await shell.run(line):
                    break
        except (ConnectionError, ProtocolError, asyncssh.Error) as exc:
            print(f"Connection lost: {exc}", file=sys.stderr)
            return 1
        finally:
            sftp.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minimal SFTP v3 client (raw packets over asyncssh)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--username", required=True)
    parser.add_argument("--known-hosts", default=str(DEFAULT_KNOWN_HOSTS),
                        help="OpenSSH known_hosts file used for host-key pinning")
    parser.add_argument("--accept-new-host-key", action="store_true",
                        help="trust an unknown host key without asking (never overrides a mismatch)")
    parser.add_argument("--batch", help="run commands from a file instead of the prompt")
    args = parser.parse_args(argv)
    try:
        return asyncio.run(amain(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
