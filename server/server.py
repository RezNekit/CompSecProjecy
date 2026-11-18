#!/usr/bin/env python3
"""WP1: raw SFTP v3 over AsyncSSH; no built-in SFTP implementation.

Integration contract (WP2/WP3): see policy.md. No permissive production stubs.
Paths and the persistent host key are relative to this file, never the CWD.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import errno
import inspect
import logging
import os
from pathlib import Path
import secrets
import stat
import struct
import time

import asyncssh

BASE_DIR = Path(__file__).resolve().parent
HOST_KEY_PATH = BASE_DIR / "ssh_host_ed25519_key"
JAIL_ROOT = BASE_DIR / "sftp_root"
MAX_PACKET = 256 * 1024
MAX_READ = 64 * 1024
MAX_HANDLES = 128
MAX_OFFSET = (1 << 63) - 1
LOG = logging.getLogger(__name__)

INIT, VERSION, OPEN, CLOSE, READ, WRITE = 1, 2, 3, 4, 5, 6
LSTAT, FSTAT, OPENDIR, READDIR, MKDIR, REALPATH, STAT = 7, 8, 11, 12, 14, 16, 17
STATUS, HANDLE, DATA, NAME, ATTRS = 101, 102, 103, 104, 105
OK, EOF, NO_SUCH_FILE, PERMISSION_DENIED, FAILURE = 0, 1, 2, 3, 4
PF_READ, PF_WRITE, PF_APPEND, PF_CREAT, PF_TRUNC, PF_EXCL = 1, 2, 4, 8, 16, 32


def p_u32(value):
    return struct.pack(">I", value)


def p_str(value):
    return p_u32(len(value)) + value


def pack_pkt(kind, payload):
    body = bytes([kind]) + payload
    return p_u32(len(body)) + body


class Packet:
    """Bounds-checked packet reader; reject truncated and trailing fields."""
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        end = self.offset + size
        if end > len(self.data):
            raise ValueError("truncated packet")
        result = self.data[self.offset:end]
        self.offset = end
        return result

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def u64(self):
        return struct.unpack(">Q", self.take(8))[0]

    def string(self):
        return self.take(self.u32())

    def attrs(self):
        # Creation permissions are controlled by policy, not client attributes.
        flags = self.u32()
        if flags & ~0x8000000F:
            raise ValueError("unknown attribute flags")
        for flag, size in ((1, 8), (2, 8), (4, 4), (8, 8)):
            if flags & flag:
                self.take(size)
        if flags & 0x80000000:
            count = self.u32()
            if count > (len(self.data) - self.offset) // 8:
                raise ValueError("invalid extension count")
            for _ in range(count):
                self.string()
                self.string()

    def end(self):
        if self.offset != len(self.data):
            raise ValueError("trailing fields")


def attrs(st):
    return (p_u32(13) + struct.pack(">Q", st.st_size) + p_u32(st.st_mode)
            + p_u32(max(0, min(int(st.st_atime), 0xFFFFFFFF)))
            + p_u32(max(0, min(int(st.st_mtime), 0xFFFFFFFF))))


def safe_join(jroot, raw):
    """Return (canonical POSIX path, OS path); reject escapes and OS aliases.

    Canonicalization is the sole pre-gate filesystem inspection. Guarded,
    no-follow traversal below rechecks components at use time.
    """
    value = raw.decode("utf-8", "strict") if isinstance(raw, bytes) else raw
    if "\0" in value or "\\" in value or ":" in value:
        raise PermissionError("invalid path")
    parts = []
    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise PermissionError("path escape")
            parts.pop()
            continue
        # Apply portable restrictions on every OS (ADS, DOS aliases, trailing dots).
        device = part.split(".")[0].upper()
        if (part.endswith((".", " ")) or any(ord(c) < 32 for c in part)
                or any(c in '<>"|?*' for c in part)
                or device in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
                or device in {f"{prefix}{i}" for prefix in ("COM", "LPT")
                              for i in "123456789¹²³"}):
            raise PermissionError("invalid path")
        parts.append(part)
    jail = os.path.abspath(jroot)
    full = os.path.join(jail, *parts)
    resolved = os.path.realpath(full)
    try:
        inside = os.path.normcase(os.path.commonpath((jail, resolved))) == os.path.normcase(jail)
    except ValueError:  # Different Windows drives cannot share a jail.
        inside = False
    if (not inside
            or os.path.normcase(resolved) != os.path.normcase(full)):
        raise PermissionError("symlink or path escape")
    if os.name == "nt":
        # Windows is case-insensitive; policy must see the on-disk spelling,
        # otherwise /ADMIN could bypass a rule scoped to existing /admin.
        relative = os.path.relpath(resolved, jail)
        parts = [] if relative == "." else relative.split(os.sep)
        full = resolved
    return "/" + "/".join(parts), full


if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                   wintypes.DWORD, ctypes.c_void_p,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _kernel.CreateFileW.restype = wintypes.HANDLE
    _kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel.CloseHandle.restype = wintypes.BOOL
    _kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                    ctypes.c_void_p, wintypes.DWORD]
    _kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL

    class _TagInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

    def _win_open(path, *, directory=False, read=True, write=False, create=False):
        # No FILE_SHARE_DELETE: opened components cannot be renamed/replaced.
        access = (0x80000000 if read else 0) | (0x40000000 if write else 0)
        if directory:
            access = 0x80  # FILE_READ_ATTRIBUTES
        handle = _kernel.CreateFileW(str(path), access, 3, None,
                                     1 if create else 3, 0x02200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = _TagInfo()
            if not _kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info),
                                                        ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.attributes & 0x400:  # Any reparse point, including junctions.
                raise PermissionError("reparse point")
            if bool(info.attributes & 0x10) != directory:
                raise PermissionError("wrong object type")
            if directory:
                return handle
            mode = os.O_RDWR if read and write else os.O_WRONLY if write else os.O_RDONLY
            fd = msvcrt.open_osfhandle(handle, mode | os.O_BINARY)
            handle = None  # CRT now owns it.
            return fd
        except BaseException:
            if handle is not None:
                _kernel.CloseHandle(handle)
            raise


class Jail:
    """Anchor path operations, rejecting all symlinks/reparse points.

    POSIX uses directory descriptors + O_NOFOLLOW for every component.
    Windows pins ancestors with no-delete-sharing handles and opens the leaf
    with OPEN_REPARSE_POINT before checking its attributes or changing data.
    """
    def __init__(self, root):
        self.root = Path(root).absolute()

    @contextmanager
    def parent(self, path):
        parts = path.strip("/").split("/") if path != "/" else []
        ancestors, leaf = parts[:-1], parts[-1] if parts else "."
        with ExitStack() as stack:
            if os.name == "nt":
                current = self.root
                for part in [None] + ancestors:
                    if part is not None:
                        current = current / part
                    handle = _win_open(current, directory=True)
                    stack.callback(_kernel.CloseHandle, handle)
                yield current / leaf, None
            else:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                fd = os.open(self.root, flags)
                stack.callback(os.close, fd)
                for part in ancestors:
                    fd = os.open(part, flags, dir_fd=fd)
                    stack.callback(os.close, fd)
                yield leaf, fd

    def open_file(self, leaf, parent, read, write, create=False):
        if os.name == "nt":
            return _win_open(leaf, read=read, write=write, create=create)
        flags = os.O_RDWR if read and write else os.O_WRONLY if write else os.O_RDONLY
        flags |= os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT | os.O_EXCL
        return os.open(leaf, flags, 0o600, dir_fd=parent)

    def metadata(self, path):
        with self.parent(path) as (leaf, parent):
            if os.name == "nt":
                # lstat never follows a raced leaf junction/symlink.
                result = os.lstat(leaf)
            else:
                result = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if (stat.S_ISLNK(result.st_mode)
                    or getattr(result, "st_file_attributes", 0) & 0x400):
                raise PermissionError("link")
            return result

    @contextmanager
    def directory(self, path):
        with self.parent(path) as (leaf, parent):
            if os.name == "nt":
                handle = _win_open(leaf, directory=True)
                try:
                    with os.scandir(leaf) as iterator:
                        yield iterator
                finally:
                    _kernel.CloseHandle(handle)
            else:
                fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent)
                try:
                    with os.scandir(fd) as iterator:
                        yield iterator
                finally:
                    os.close(fd)


@dataclass
class Handle:
    kind: str
    path: str
    read: bool = False
    write: bool = False
    append: bool = False
    fd: int | None = None
    iterator: object = None
    context: object = None

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)
        if self.context is not None:
            context, self.context = self.context, None
            context.__exit__(None, None, None)


class SFTPSession(asyncssh.SSHServerSession):
    def __init__(self, root, authorize, inherit):
        self.jail = Jail(root)
        self.authorize, self.inherit = authorize, inherit
        self.buf = bytearray()
        self.handles = {}
        self.initialized = self.sftp = self.closed = False
        self.user = None

    def connection_made(self, channel):
        self.channel = channel
        channel.set_encoding(None)
        self.user = channel.get_extra_info("username")

    def subsystem_requested(self, name):
        self.sftp = name == "sftp"
        return self.sftp

    def shell_requested(self):
        return False

    def exec_requested(self, command):
        return False

    def session_started(self):
        if not self.sftp or not self.user:
            self.shutdown()

    def connection_lost(self, exc):
        self.closed = True
        self.buf.clear()
        for handle in list(self.handles.values()):
            try:
                handle.close()
            except OSError:
                LOG.warning("Handle cleanup failed")
        self.handles.clear()

    def shutdown(self):
        self.connection_lost(None)
        self.channel.close()

    def eof_received(self):
        self.shutdown()
        return False

    def send(self, kind, payload):
        self.channel.write(pack_pkt(kind, payload))

    def status(self, request, code):
        messages = {OK: b"OK", EOF: b"EOF", NO_SUCH_FILE: b"no such file",
                    PERMISSION_DENIED: b"permission denied", FAILURE: b"failure"}
        self.send(STATUS, p_u32(request) + p_u32(code) + p_str(messages[code]) + p_str(b""))

    def data_received(self, data, datatype):
        if self.closed:
            return
        if not self.sftp or not self.user or not isinstance(data, bytes):
            self.shutdown()
            return
        # Copy only enough bytes to finish one frame, even for coalesced input.
        view = memoryview(data)
        while view and not self.closed:
            needed = 4 - len(self.buf) if len(self.buf) < 4 else 0
            if needed:
                chunk, view = view[:needed], view[needed:]
                self.buf.extend(chunk)
                if len(self.buf) < 4:
                    return
            size = struct.unpack_from(">I", self.buf)[0]
            if not 1 <= size <= MAX_PACKET:
                # There is no complete, trustworthy request ID; terminate framing.
                self.status(0, FAILURE)
                self.shutdown()
                return
            needed = size + 4 - len(self.buf)
            chunk, view = view[:needed], view[needed:]
            self.buf.extend(chunk)
            if len(self.buf) == size + 4:
                packet = bytes(self.buf[4:])
                self.buf.clear()
                self.handle_packet(packet)

    def check(self, op, path):
        # Policy owns audit; exceptions, missing/invalid results all fail closed.
        try:
            result = self.authorize(self.user, op, path)
            if (not isinstance(result, tuple) or len(result) != 2
                    or result[0] is not True or not isinstance(result[1], str)):
                raise PermissionError("denied")
        except Exception:
            raise PermissionError("denied") from None

    def path(self, raw, op):
        path, _ = safe_join(self.jail.root, raw)
        self.check(op, path)
        return path

    def get_handle(self, token, kind=None):
        handle = self.handles.get(token)
        if handle is None or (kind and handle.kind != kind):
            raise ValueError("invalid handle")
        return handle

    def capacity(self):
        if len(self.handles) >= MAX_HANDLES:
            raise ValueError("handle limit")

    def add_handle(self, handle):
        token = secrets.token_hex(24).encode("ascii")
        while token in self.handles:
            token = secrets.token_hex(24).encode("ascii")
        self.handles[token] = handle
        return token

    def name_entry(self, name, st):
        encoded = name.encode("utf-8")
        if st is None:
            return p_str(encoded) + p_str(encoded) + p_u32(0)
        date = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
        longname = (f"{stat.filemode(st.st_mode)} {st.st_nlink:3d} "
                    f"{st.st_uid:8d} {st.st_gid:8d} {st.st_size:10d} {date} {name}")
        return p_str(encoded) + p_str(longname.encode("utf-8")) + attrs(st)

    def handle_packet(self, data):
        request = 0
        try:
            packet = Packet(data)
            kind = packet.take(1)[0]
            if not self.initialized:
                if kind != INIT:
                    if len(data) >= 5:
                        request = packet.u32()
                    raise ValueError("expected INIT")
                version = packet.u32()
                while packet.offset < len(packet.data):
                    packet.string()
                    packet.string()
                if version < 3:
                    raise ValueError("unsupported version")
                self.send(VERSION, p_u32(3))
                self.initialized = True
                return
            request = packet.u32()  # Intentionally inside the exception boundary.
            if kind in (REALPATH, STAT, LSTAT, OPENDIR):
                raw = packet.string()
                packet.end()
                op = "realpath" if kind == REALPATH else "list" if kind == OPENDIR else "stat"
                path = self.path(raw, op)
                if kind == REALPATH:
                    try:
                        st = self.jail.metadata(path)
                    except FileNotFoundError:
                        st = None
                    self.send(NAME, p_u32(request) + p_u32(1) + self.name_entry(path, st))
                elif kind in (STAT, LSTAT):
                    self.send(ATTRS, p_u32(request) + attrs(self.jail.metadata(path)))
                else:
                    self.capacity()
                    context = self.jail.directory(path)
                    iterator = context.__enter__()
                    handle = Handle("dir", path, iterator=iterator, context=context)
                    self.send(HANDLE, p_u32(request) + p_str(self.add_handle(handle)))
            elif kind == MKDIR:
                raw = packet.string()
                packet.attrs()
                packet.end()
                path = self.path(raw, "mkdir")
                with self.jail.parent(path) as (leaf, parent):
                    os.mkdir(leaf, 0o700, **({"dir_fd": parent} if parent is not None else {}))
                    try:
                        self.inherit(self.user, path, "dir")
                    except Exception:
                        os.rmdir(leaf, **({"dir_fd": parent} if parent is not None else {}))
                        raise
                self.status(request, OK)
            elif kind == OPEN:
                raw, flags = packet.string(), packet.u32()
                packet.attrs()
                packet.end()
                read, write = bool(flags & PF_READ), bool(flags & PF_WRITE)
                mutation = bool(flags & (PF_WRITE | PF_CREAT | PF_TRUNC | PF_APPEND))
                if (flags & ~63 or not (read or write)
                        or (mutation and not write)
                        or (flags & PF_EXCL and not flags & PF_CREAT)):
                    raise ValueError("invalid open flags")
                path = self.path(raw, "write" if mutation else "read")
                if read and mutation:
                    self.check("read", path)
                self.capacity()
                with self.jail.parent(path) as (leaf, parent):
                    created = False
                    if flags & PF_CREAT:
                        try:
                            fd = self.jail.open_file(leaf, parent, read, write, create=True)
                            created = True
                        except FileExistsError:
                            if flags & PF_EXCL:
                                raise
                            fd = self.jail.open_file(leaf, parent, read, write)
                    else:
                        fd = self.jail.open_file(leaf, parent, read, write)
                    try:
                        if not stat.S_ISREG(os.fstat(fd).st_mode):
                            raise PermissionError("not regular file")
                        if created:
                            self.inherit(self.user, path, "file")
                        if flags & PF_TRUNC:
                            os.ftruncate(fd, 0)
                        handle = Handle("file", path, read, write, bool(flags & PF_APPEND), fd)
                        token = self.add_handle(handle)
                    except BaseException:
                        os.close(fd)
                        if created:
                            os.unlink(leaf, **({"dir_fd": parent} if parent is not None else {}))
                        raise
                self.send(HANDLE, p_u32(request) + p_str(token))
            elif kind in (READ, WRITE, FSTAT, READDIR, CLOSE):
                token = packet.string()
                offset = length = content = None
                if kind in (READ, WRITE):
                    offset = packet.u64()
                    if kind == READ:
                        length = packet.u32()
                    else:
                        content = packet.string()
                packet.end()
                handle = self.get_handle(token)
                if kind == CLOSE:
                    del self.handles[token]
                    handle.close()
                    self.status(request, OK)
                elif kind == FSTAT:
                    self.get_handle(token, "file")
                    self.check("stat", handle.path)
                    self.send(ATTRS, p_u32(request) + attrs(os.fstat(handle.fd)))
                elif kind == READDIR:
                    self.get_handle(token, "dir")
                    self.check("list", handle.path)
                    entries = []
                    # Bounded output; hidden entries don't cause false EOF.
                    for entry in handle.iterator:
                        try:
                            child = self.path((handle.path.rstrip("/") + "/" + entry.name), "stat")
                            st = self.jail.metadata(child)
                            entries.append(self.name_entry(entry.name, st))
                        except (PermissionError, FileNotFoundError, UnicodeError):
                            continue
                        if len(entries) == 64:
                            break
                    if entries:
                        self.send(NAME, p_u32(request) + p_u32(len(entries)) + b"".join(entries))
                    else:
                        self.status(request, EOF)
                else:
                    self.get_handle(token, "file")
                    op = "read" if kind == READ else "write"
                    self.check(op, handle.path)
                    if not (handle.read if kind == READ else handle.write):
                        raise PermissionError("handle mode")
                    size = min(length, MAX_READ) if kind == READ else len(content)
                    if offset > MAX_OFFSET or offset + size > MAX_OFFSET:
                        raise ValueError("invalid offset")
                    os.lseek(handle.fd, 0 if handle.append and kind == WRITE else offset,
                             os.SEEK_END if handle.append and kind == WRITE else os.SEEK_SET)
                    if kind == READ:
                        result = os.read(handle.fd, size)
                        if result or size == 0:
                            self.send(DATA, p_u32(request) + p_str(result))
                        else:
                            self.status(request, EOF)
                    else:
                        remaining = memoryview(content)
                        while remaining:
                            written = os.write(handle.fd, remaining)
                            if written <= 0:
                                raise OSError("short write")
                            remaining = remaining[written:]
                        self.status(request, OK)
            else:
                self.status(request, FAILURE)
        except (PermissionError, UnicodeError):
            self.status(request, PERMISSION_DENIED)
        except (FileNotFoundError, NotADirectoryError):
            self.status(request, NO_SUCH_FILE)
        except OSError as exc:
            code = PERMISSION_DENIED if exc.errno in (errno.ELOOP, errno.EACCES, errno.EPERM) else FAILURE
            self.status(request, code)
        except Exception:
            self.status(request, FAILURE)


class Server(asyncssh.SSHServer):
    def __init__(self, root, verify_password, authorize, inherit):
        self.root, self.verify_password = root, verify_password
        self.authorize, self.inherit = authorize, inherit

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    async def validate_password(self, username, password):
        try:
            result = self.verify_password(username, password)
            if inspect.isawaitable(result):
                result = await result
            return result is True
        except Exception:
            return False

    def session_requested(self):
        return SFTPSession(self.root, self.authorize, self.inherit)


async def serve(verify_password, authorize, inherit, *, root=JAIL_ROOT,
                host_key=HOST_KEY_PATH, host="127.0.0.1", port=2222):
    """Injection seam for WP2/WP3 and isolated WP5 fixtures; no default allow."""
    if not all(callable(hook) for hook in (verify_password, authorize, inherit)):
        raise RuntimeError("Authentication, authorization and inheritance hooks are required")
    root = Path(root).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or os.path.normcase(os.path.realpath(root)) != os.path.normcase(str(root)):
        raise RuntimeError("Jail root must not be a link")
    key = asyncssh.read_private_key(host_key)
    if key.get_algorithm() != "ssh-ed25519":
        raise RuntimeError("An Ed25519 host key is required")
    return await asyncssh.listen(
        host, port, server_host_keys=[key], encoding=None,
        server_factory=lambda: Server(root, verify_password, authorize, inherit),
        public_key_auth=False, kbdint_auth=False, password_auth=True,
        login_timeout=30,
    )


async def main():
    # WP2 owns startup data loading/validation and auth logging. WP3 owns
    # authorization/audit and creation metadata. Missing modules stop startup.
    try:
        if __package__:
            from .auth import verify_password
            from .policy import authorize, inherit
        else:
            from auth import verify_password
            from policy import authorize, inherit
    except ImportError:
        raise RuntimeError("WP2 auth.py and WP3 policy.py with verify_password, "
                           "authorize and inherit hooks must be integrated before startup") from None
    listener = await serve(verify_password, authorize, inherit)
    LOG.info("SFTP listening on 127.0.0.1:2222")
    async with listener:
        await listener.wait_closed()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except (RuntimeError, OSError, asyncssh.Error):
        LOG.error("Server startup failed: check WP2/WP3 hooks, data and persistent Ed25519 key")
        raise SystemExit(1) from None
