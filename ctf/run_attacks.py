#!/usr/bin/env python3
"""CTF: run every attack against the hardened server and the naive starter.

    python3 ctf/run_attacks.py

1. Hardened target: server/server.py through serve(), with a fresh jail
   (flag planted by setup_flag.py) and an audit log. Authorization is
   server/policy.py loaded with the project's data/ files. Passwords are
   checked by server/auth.py when it exists and CTF_PASSWORD_<USER>
   environment variables are set; otherwise by random one-run passwords.
2. Naive target: the unmodified course starter (ctf/naive/starter_main.py),
   which only knows bob/test and has no authorization.

Writes docs/evidence/ctf-attacks.md and docs/evidence/ctf-audit.jsonl.
Every attack uses the client's raw SFTP channel (client/client.py).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
for sub in ("server", "client", "ctf"):
    sys.path.insert(0, str(ROOT / sub))

import asyncssh  # noqa: E402
import server as hardened  # noqa: E402
import client as cl  # noqa: E402
from flag_config import FLAG, FLAG_PATH  # noqa: E402
from setup_flag import plant  # noqa: E402

FLAG_BYTES = FLAG.encode()
EVIDENCE = ROOT / "docs" / "evidence"
CODE = {0: "OK", 1: "EOF", 2: "NO_SUCH_FILE", 3: "PERMISSION_DENIED", 4: "FAILURE"}
DATA_DIR = ROOT / "data"
USERS = sorted(json.loads((DATA_DIR / "user_roles.json").read_text(encoding="utf-8")))
OTHERS = [u for u in USERS if u != "alice"]  # every user except the flag's owner


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Target:
    def __init__(self, name, port, jail, passwords, known_hosts):
        self.name, self.port, self.jail = name, port, jail
        self.passwords, self.known_hosts = passwords, known_hosts
        self.results: list[dict] = []

    async def session(self, user):
        await cl.ensure_trusted("127.0.0.1", self.port, self.known_hosts, accept_new=True)
        conn = await cl.connect("127.0.0.1", self.port, user,
                                self.passwords.get(user, "x"), self.known_hosts)
        sftp = cl.SFTPChannel(conn)
        await sftp.start()
        return conn, sftp

    def record(self, aid, attack, user, request, outcome, leaked, expected):
        if expected == "control":
            verdict = "OK (legitimate access)" if leaked else "UNEXPECTED"
        elif expected == "blocked":
            verdict = "EXPOSED" if leaked else "blocked"
        else:
            verdict = expected
        self.results.append(dict(id=aid, attack=attack, user=user, request=request,
                                 outcome=outcome, leaked=leaked, verdict=verdict))

    def flag_intact(self) -> bool:
        path = self.jail / FLAG_PATH.lstrip("/")
        return path.exists() and FLAG_BYTES in path.read_bytes()


# Low-level helpers built on the client's raw request method
async def raw_open(sftp, path: bytes | str, flags: int):
    """Return (outcome text, handle or None)."""
    if isinstance(path, str):
        path = path.encode()
    kind, r = await sftp.raw_request(cl.OPEN, cl.sstr(path) + cl.u32(flags) + cl.u32(0))
    if kind == cl.HANDLE:
        return "HANDLE", r.string()
    return f"STATUS {CODE.get(r.u32(), '?')}", None


async def read_all(sftp, handle: bytes) -> bytes:
    data, off = b"", 0
    while True:
        try:
            chunk = await sftp.read(handle, off, cl.CHUNK)
        except cl.SFTPError:
            break
        if not chunk:
            break
        data += chunk
        off += len(chunk)
    return data


async def try_read(sftp, path):
    """Open + read a path. Returns (outcome, leaked)."""
    outcome, handle = await raw_open(sftp, path, cl.PF_READ)
    if handle is None:
        return outcome, False
    data = await read_all(sftp, handle)
    await sftp.close_handle(handle)
    leaked = FLAG_BYTES in data
    return (f"DATA {len(data)} bytes" + (" - FLAG returned" if leaked else "")), leaked


async def raw_read(sftp, handle: bytes):
    kind, r = await sftp.raw_request(cl.READ, cl.sstr(handle) + cl.u64(0) + cl.u32(4096))
    if kind == cl.DATA:
        data = r.string()
        return f"DATA {len(data)} bytes", FLAG_BYTES in data
    return f"STATUS {CODE.get(r.u32(), '?')}", False


async def list_names(sftp, path):
    try:
        handle = await sftp.opendir(path)
    except cl.SFTPError as exc:
        return f"STATUS {CODE.get(exc.code)}"
    names = []
    while batch := await sftp.readdir(handle):
        names += [n for n, _, _ in batch]
    await sftp.close_handle(handle)
    return "entries: " + ", ".join(sorted(names))


async def try_login(target, user):
    try:
        conn, sftp = await target.session(user)
    except asyncssh.PermissionDenied:
        return None, None, "login refused"
    return conn, sftp, "logged in"


def plant_links(jail: Path, outside: Path):
    public = jail / "public"
    (outside / "outside-secret.txt").write_text("Host file outside the jail.\n")
    os.symlink("../admin/ctf/flag.txt", public / "link_to_flag")
    os.symlink(str(outside), public / "link_out")


# Attacks on the hardened server
async def hardened_attacks(t: Target):
    sess = {}
    for user in USERS:
        sess[user] = await t.session(user)
    s = {u: v[1] for u, v in sess.items()}

    # Control case: alice (owner, admin role, confidential clearance) can read it.
    out, leak = await try_read(s["alice"], FLAG_PATH)
    t.record("C1", "Legitimate read by owner", "alice", f"OPEN+READ {FLAG_PATH}", out, leak, "control")

    # A1: every other user tries a direct read.
    for user in OTHERS:
        out, leak = await try_read(s[user], FLAG_PATH)
        t.record("A1", "Direct read of the flag", user, f"OPEN+READ {FLAG_PATH}", out, leak, "blocked")

    # A2: path traversal and alias spellings.
    variants = [
        "/public/../admin/ctf/flag.txt",
        "../../../admin/ctf/flag.txt",
        "/../../etc/passwd",
        "/public/..\\..\\admin\\ctf\\flag.txt",
        "/admin//ctf/./flag.txt",
        "/ADMIN/ctf/flag.txt",
        "/public/%2e%2e/admin/ctf/flag.txt",
        b"/admin/ctf/flag.txt\x00.png",
        b"/admin/ctf/fl\xffag.txt",
    ]
    for v in variants:
        out, leak = await try_read(s["eve"], v)
        shown = v if isinstance(v, str) else repr(v)
        t.record("A2", "Path traversal / alias", "eve", f"OPEN {shown}", out, leak, "blocked")
    out, leak = await try_read(s["bob"], "/projects/../admin/ctf/flag.txt")
    t.record("A2", "Path traversal / alias", "bob", "OPEN /projects/../admin/ctf/flag.txt", out, leak, "blocked")

    # A3: enumeration.
    for user, path in (("eve", "/"), ("eve", "/admin"), ("bob", "/"), ("alice", "/")):
        t.record("A3", "Directory enumeration", user, f"OPENDIR/READDIR {path}",
                 await list_names(s[user], path), False, "info")
    try:
        await s["eve"].stat(FLAG_PATH)
        out = "ATTRS returned"
    except cl.SFTPError as exc:
        out = f"STATUS {CODE.get(exc.code)}"
    t.record("A3", "Directory enumeration", "eve", f"STAT {FLAG_PATH}", out, False, "info")

    # A4: symlinks planted inside the jail. The server has no SYMLINK request, so
    # they simulate a misconfiguration or someone with local access.
    for user, path in (("eve", "/public/link_to_flag"), ("alice", "/public/link_to_flag"),
                       ("eve", "/public/link_out/outside-secret.txt")):
        out, leak = await try_read(s[user], path)
        leak = leak or "outside-secret" in out
        t.record("A4", "Symlink trick", user, f"OPEN+READ {path}", out, leak, "blocked")

    # A5: reused and forged handles.
    _, h = await raw_open(s["alice"], FLAG_PATH, cl.PF_READ)
    out, leak = await raw_read(s["eve"], h)
    t.record("A5", "Handle reuse", "eve", "READ with alice's live handle (other session)", out, leak, "blocked")
    for guess in (b"1", b"2", b"0" * 48):
        out, leak = await raw_read(s["eve"], guess)
        t.record("A5", "Handle reuse", "eve", f"READ with guessed handle {guess[:8]!r}", out, leak, "blocked")
    await s["alice"].close_handle(h)
    out, leak = await raw_read(s["alice"], h)
    t.record("A5", "Handle reuse", "alice", "READ with her own handle after CLOSE", out, leak, "blocked")
    _, h = await raw_open(s["alice"], FLAG_PATH, cl.PF_READ)
    kind, r = await s["alice"].raw_request(cl.WRITE, cl.sstr(h) + cl.u64(0) + cl.sstr(b"pwned"))
    out = f"STATUS {CODE.get(r.u32())}" if kind == cl.STATUS else "?"
    t.record("A5", "Handle reuse", "alice", "WRITE through a read-only handle", out, False, "blocked")
    await s["alice"].close_handle(h)

    # A6: destroy or overwrite the flag.
    for user, flags, label in (("eve", cl.PF_WRITE | cl.PF_TRUNC, "WRITE|TRUNC"),
                               ("eve", cl.PF_READ | cl.PF_TRUNC, "READ|TRUNC (no WRITE)"),
                               ("bob", cl.PF_WRITE | cl.PF_CREAT, "WRITE|CREAT")):
        out, h = await raw_open(s[user], FLAG_PATH, flags)
        if h:
            await s[user].close_handle(h)
        t.record("A6", "Destroy / overwrite flag", user, f"OPEN {FLAG_PATH} {label}", out, False,
                 "blocked" if h is None else "EXPOSED")

    # A7: alice may read the flag, but copying it to a lower level must fail.
    for dest in ("/public/flag_copy.txt", "/projects/flag_copy.txt"):
        out, h = await raw_open(s["alice"], dest, cl.PF_WRITE | cl.PF_CREAT | cl.PF_TRUNC)
        if h:
            await s["alice"].write(h, 0, FLAG_BYTES)
            await s["alice"].close_handle(h)
        t.record("A7", "Write-down exfiltration", "alice", f"OPEN {dest} WRITE|CREAT",
                 out, h is not None, "blocked")

    # A8: swap /public/race.txt between a plain file and a symlink to the flag
    # while eve keeps reading it, to hit the gap between check and use.
    public = t.jail / "public"
    (public / "race.txt").write_text("harmless\n")
    stop = threading.Event()
    swaps = [0]

    def toggler():
        while not stop.is_set():
            try:
                os.symlink("../admin/ctf/flag.txt", public / "race.lnk")
                os.replace(public / "race.lnk", public / "race.txt")
                (public / "race.tmp").write_text("harmless\n")
                os.replace(public / "race.tmp", public / "race.txt")
                swaps[0] += 1
            except OSError:
                pass

    thread = threading.Thread(target=toggler, daemon=True)
    thread.start()
    tally, leaks = {}, 0
    for _ in range(300):
        out, leak = await try_read(s["eve"], "/public/race.txt")
        key = out.split(" - ")[0] if out.startswith("DATA") else out
        key = "DATA (harmless file)" if key.startswith("DATA") and not leak else key
        tally[key] = tally.get(key, 0) + 1
        leaks += leak
    stop.set()
    thread.join()
    summary = "; ".join(f"{k}: {v}" for k, v in sorted(tally.items()))
    t.record("A8", "Symlink-swap race", "eve",
             f"300 reads of /public/race.txt during {swaps[0]} swaps", summary + f"; flag leaks: {leaks}",
             leaks > 0, "blocked")

    for conn, sftp in sess.values():
        sftp.close()
        conn.close()


# Attacks on the naive starter
async def naive_attacks(t: Target):
    conn, sftp, out = await try_login(t, "eve")
    t.record("N0", "Login as another user", "eve", "password auth", out, False, "info")
    if conn:
        conn.close()
    conn, sftp = await t.session("bob")
    out, leak = await try_read(sftp, FLAG_PATH)
    t.record("N1", "Direct read of the flag", "bob", f"OPEN+READ {FLAG_PATH}", out, leak, "blocked")
    out, leak = await try_read(sftp, "/public/../admin/ctf/flag.txt")
    t.record("N2", "Path traversal / alias", "bob", "OPEN /public/../admin/ctf/flag.txt", out, leak, "blocked")
    out, leak = await try_read(sftp, "/../../etc/passwd")
    t.record("N2", "Path traversal / alias", "bob", "OPEN /../../etc/passwd", out, leak, "blocked")
    t.record("N3", "Directory enumeration", "bob", "OPENDIR/READDIR /", await list_names(sftp, "/"), False, "info")
    out, leak = await try_read(sftp, "/public/link_to_flag")
    t.record("N4", "Symlink trick", "bob", "OPEN+READ /public/link_to_flag", out, leak, "blocked")
    out, leak = await try_read(sftp, "/public/link_out/outside-secret.txt")
    t.record("N4", "Symlink trick", "bob", "OPEN+READ /public/link_out/outside-secret.txt",
             out, leak or "DATA" in out, "blocked")
    _, h1 = await raw_open(sftp, "/public/welcome.txt", cl.PF_READ)
    _, h2 = await raw_open(sftp, "/projects/plan.txt", cl.PF_READ)
    t.record("N5", "Handle reuse", "bob", "two OPENs: handle values", f"handles {h1!r}, {h2!r} (sequential)",
             False, "info")
    out, h = await raw_open(sftp, FLAG_PATH, cl.PF_READ | cl.PF_TRUNC)
    if h:
        await sftp.close_handle(h)
    destroyed = not t.flag_intact()
    t.record("N6", "Destroy / overwrite flag", "bob", f"OPEN {FLAG_PATH} READ|TRUNC (no WRITE)",
             out + ("; flag file now EMPTY" if destroyed else ""), destroyed, "blocked")
    sftp.close()
    conn.close()


# Server start-up
def auth_mode(requested: str):
    has_auth = (ROOT / "server" / "auth.py").exists()
    env_pw = {u: os.environ.get(f"CTF_PASSWORD_{u.upper()}") for u in USERS}
    if requested == "real" or (requested == "auto" and has_auth and all(env_pw.values())):
        if not has_auth or not all(env_pw.values()):
            sys.exit("--auth real needs server/auth.py and CTF_PASSWORD_<USER> for every user")
        return "real", env_pw
    return ("one-run" if requested == "one-run" else "ephemeral-scrypt"), {u: secrets.token_urlsafe(12) for u in USERS}


async def run_hardened(work: Path, mode: str, passwords: dict):
    from policy import Policy
    jail = work / "hardened_jail"
    plant(jail)
    plant_links(jail, work / "outside")
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(work / "hardened_key"))
    audit = work / "audit.jsonl"
    policy = Policy(DATA_DIR, audit)
    authorize, inherit = policy.authorize, policy.inherit
    if mode in ("real", "ephemeral-scrypt"):
        from auth import AuthService
        if mode == "real":
            from loader import load_users
            users = load_users(DATA_DIR)
        else:
            sys.path.insert(0, str(ROOT / "tools"))
            from make_users import create_user_record
            users = {u: create_user_record(u, p) for u, p in passwords.items()}
        verify_password = AuthService(users, audit_path=audit).authenticate
    else:
        def verify_password(user, password):
            return user in passwords and secrets.compare_digest(password, passwords[user])
    port = free_port()
    listener = await hardened.serve(verify_password, authorize, inherit, root=jail,
                                    host_key=work / "hardened_key", port=port)
    target = Target("hardened", port, jail, passwords, work / "known_hosts_hardened")
    try:
        await hardened_attacks(target)
    finally:
        listener.close()
        await listener.wait_closed()
    target.flag_ok = target.flag_intact()
    target.audit = audit if audit.exists() else None
    return target


async def run_naive(work: Path):
    base = work / "naive"
    base.mkdir()
    jail = base / "sftp_root"
    plant(jail)
    plant_links(jail, work / "outside_naive")
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(base / "ssh_host_ed25519_key"))
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", 2222)) == 0:
            sys.exit("Port 2222 is busy; the starter server is hard-coded to it. Stop the other server.")
    log = open(base / "starter.log", "w")
    proc = subprocess.Popen([sys.executable, str(ROOT / "ctf" / "naive" / "starter_main.py")],
                            cwd=base, stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", 2222)) == 0:
                    break
            await asyncio.sleep(0.1)
        target = Target("naive", 2222, jail, {"bob": "test"}, work / "known_hosts_naive")
        await naive_attacks(target)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()
    return target


# Evidence
def table(results):
    rows = ["| ID | Attack | User | Request | Server response | Flag exposed | Verdict |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in results:
        req = r["request"].replace("|", "\\|")
        out = r["outcome"].replace("|", "\\|")
        rows.append(f"| {r['id']} | {r['attack']} | {r['user']} | `{req}` | {out} | "
                    f"{'yes' if r['leaked'] else 'no'} | {r['verdict']} |")
    return "\n".join(rows)


def write_evidence(h: Target, n: Target, mode: str):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True).stdout.strip() or "unknown"
    auth_line = ("`server/auth.py` AuthService with temporary salted scrypt records"
                 if mode == "ephemeral-scrypt" else "`server/auth.py` with deployed users.json"
                 if mode == "real" else "explicit one-run password callback (no AuthN coverage)")
    exposed = [r for r in h.results if r["verdict"] == "EXPOSED"]
    audit_lines = []
    if h.audit:
        keep = ("/admin", "/public/link", "/public/flag_copy", "/projects/flag_copy", "/projects/..")
        for line in h.audit.read_text().splitlines():
            rec = json.loads(line)
            if any(k in rec.get("path", "") for k in keep) and (not rec["allowed"] or rec["user"] == "alice"):
                audit_lines.append(line)
        (EVIDENCE / "ctf-audit.jsonl").write_text(h.audit.read_text())
    md = f"""# CTF attack evidence

Generated by `ctf/run_attacks.py` on {time.strftime('%Y-%m-%d %H:%M %Z')}, repo commit `{commit}`.

- Flag: `{FLAG_PATH}` (content `{FLAG}`)
- Hardened target: `server/server.py`; authorization: `server/policy.py` with `data/`; passwords: {auth_line}
- Naive target: unmodified course starter `ctf/naive/starter_main.py` (only account bob/test, no authorization)
- Client: `client/client.py` raw SFTP channel for every request

## Hardened server

Result: {len(exposed)} of {sum(r['verdict'] != 'info' and r['id'] != 'C1' for r in h.results)} attack attempts exposed or changed the flag; flag file intact after the run: {'yes' if h.flag_ok else 'NO'}.

{table(h.results)}

## Naive starter server (same jail, same attacks where possible)

Flag file intact after the run: {'yes' if n.flag_intact() else 'NO (destroyed by N6)'}.

{table(n.results)}

## Audit excerpt (hardened run)

Denied decisions on the flag area, symlinks and exfiltration targets, plus alice's allowed reads.
Full log: `docs/evidence/ctf-audit.jsonl`.

```json
{chr(10).join(audit_lines[:40])}
```
"""
    (EVIDENCE / "ctf-attacks.md").write_text(md)
    return EVIDENCE / "ctf-attacks.md"


async def amain(args):
    mode, passwords = auth_mode(args.auth)
    with tempfile.TemporaryDirectory(prefix="ctf_") as tmp:
        # resolve(): the server refuses a jail behind a symlink (macOS /var -> /private/var).
        work = Path(tmp).resolve()
        for d in ("outside", "outside_naive"):
            (work / d).mkdir()
        h = await run_hardened(work, mode, passwords)
        n = await run_naive(work) if not args.skip_naive else Target("naive", 0, work, {}, work)
        path = write_evidence(h, n, mode)
    bad = [r for r in h.results if r["verdict"] in ("EXPOSED", "UNEXPECTED")]
    print(f"Password check: {mode}")
    print(f"Hardened: {len(bad)} problems; flag intact: {h.flag_ok}")
    print(f"Naive: {sum(r['verdict'] == 'EXPOSED' for r in n.results)} attacks exposed/destroyed the flag")
    print(f"Evidence: {path}")
    return 1 if bad or not h.flag_ok else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--auth", choices=["auto", "real", "one-run"], default="auto")
    parser.add_argument("--skip-naive", action="store_true")
    sys.exit(asyncio.run(amain(parser.parse_args())))


if __name__ == "__main__":
    main()
