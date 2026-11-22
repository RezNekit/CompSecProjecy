# CTF write-up: protecting the flag in our SFTP server

Computer Security group project, stage 1 (SFTP over SSH with DAC, MAC and RBAC).
Client and CTF. Source of this PDF: `docs/CTF_writeup.md`. Evidence: `docs/evidence/`.

## 1. Summary

The flag `FLAG{group01_sftp_wins}` is stored at `/admin/ctf/flag.txt` inside the server's jail, and only alice
(role admin, clearance confidential, file owner) may read it. It sits behind four independent layers: RBAC, MAC,
DAC, and the server's path canonicalization with no-follow file access. With our own client
(`ctf/run_attacks.py`) we made 27 attack attempts in 7 classes, plus some enumeration checks. None of them read or
changed the flag on the hardened server, and alice could still read it. On the unmodified course starter the same
client leaked the flag in 3 different ways and destroyed it once.

The hardened runs (22 November) used the project's `server/server.py` with the project's policy,
`server/policy.py` loaded from `data/`. The password store (`server/auth.py`) is not in the repository yet, so the
runner gave each user a random one-run password; `run_attacks.py` switches to `auth.py` once it exists
(section 8). Authentication is not part of what protects the flag, so this does not change the results.

## 2. Flag design

| Item | Value |
| --- | --- |
| Location | `/admin/ctf/flag.txt` (jail-relative; on disk `server/sftp_root/admin/ctf/flag.txt`) |
| Planted by | `ctf/setup_flag.py`, at deployment time, not committed to git |
| Only legitimate reader | alice: role admin, clearance confidential, owner of the file |
| Decoys | `/public/welcome.txt`, `/projects/plan.txt` |

Users (`data/user_roles.json`, `data/mac_labels.json`, `data/groups.json`): alice (role admin, clearance
confidential, groups admins and staff), bob (analyst, internal, analysts and staff), eve (guest, public, staff).

| Layer | Mechanism | Enforced in | Who it stops on its own |
| --- | --- | --- | --- |
| 1. RBAC | Only role admin has a row covering `/admin` (`admin,/`); analyst and guest rows stop at `/public`, `/demo` and `/projects` | policy gate (`server/policy.py`) | bob, eve |
| 2. MAC | `/admin` labelled confidential; no read up (clearance must be at least the label), no write down | policy gate | bob, eve; also stops alice copying the flag to a lower level |
| 3. DAC | `/admin` alice:admins 0700 (owner only, inherited by everything below it) | policy gate | bob, eve |
| 4. Path handling | Canonicalize before the gate (`safe_join`), deny all links, open every component with `O_NOFOLLOW` at use time (`Jail`) | server path handling (`server/server.py`) | traversal, symlink and link-swap race attempts by anyone, including alice |

Access is granted only when DAC ∧ MAC ∧ RBAC all allow it, and anything not covered is denied. The gate checks
DAC first and reports the first denial, so the audit log names DAC for bob's and eve's reads. Running each
check of `Policy` on its own shows the overlap, since each one denies bob and eve by itself:

| Request | DAC | MAC | RBAC |
| --- | --- | --- | --- |
| bob reads `/admin/ctf/flag.txt` | denied at `/admin/ctf` | no read up | no role grants read |
| eve reads `/admin/ctf/flag.txt` | denied at `/admin/ctf` | no read up | no role grants read |
| alice reads `/admin/ctf/flag.txt` | ok | ok | ok |
| alice writes `/public/flag_copy.txt` | ok | no write down | ok |

If one layer is misconfigured, the other two still keep bob and eve away from the flag. The rows in `data/` that
matter are collected in `ctf/flag_config.py` (`REQUIRED_POLICY`).

## 3. Attack surface

| Surface | Requests | What an attacker controls |
| --- | --- | --- |
| Authentication | SSH password auth | username, password guesses |
| Path names | REALPATH, STAT/LSTAT, OPENDIR, MKDIR, OPEN | any byte string: `..`, backslashes, NUL, invalid UTF-8, case |
| Handles | READ, WRITE, FSTAT, READDIR, CLOSE | handle tokens, including other sessions' or closed ones |
| Open flags | OPEN `pflags` | combinations such as READ+TRUNC |
| Filesystem links | (no SYMLINK request exists) | a link planted by a misconfiguration or local actor |
| Concurrency | any path request | timing between the check and the use |
| Policy itself | all | an insider allowed to read who tries to leak |

## 4. How a naive design exposes the flag

We pointed the same client at the unmodified starter (`ctf/naive/starter_main.py`), using the same jail.

| ID | Attack | Result | Cause in the starter |
| --- | --- | --- | --- |
| N1 | bob reads `/admin/ctf/flag.txt` | flag returned | no authorization call anywhere; one hard-coded account `bob`/`test` (line 365) can read everything |
| N2 | `/public/../admin/ctf/flag.txt` | flag returned | traversal inside the jail is normalised, but nothing checks the result |
| N4 | read `/public/link_to_flag` (symlink to the flag) | flag returned | `safe_join` resolves links with `os.path.realpath` (lines 102-105) and accepts any target inside the jail |
| N6 | OPEN flag with READ\|TRUNC (no WRITE) | file truncated to 0 bytes | `PF_TRUNC` selects mode `w+b` regardless of `PF_WRITE` (lines 302-303) |
| N3 | list `/` | `admin` visible | READDIR returns every entry (line 233) |
| N5 | two OPENs | handles `5`, `6` | sequential handle IDs (line 92) are predictable |

The starter did stop `/../../etc/passwd` and a symlink pointing outside the jail, because `realpath` plus its prefix
check catch escapes from the jail. Within the jail it checks nothing.

## 5. Attack attempts against the hardened server

Every attempt went through the raw SFTP channel in `client/client.py`, which let us send packets a normal client
never would. Full results are in `docs/evidence/ctf-attacks.md`.

| Class | Attempts | Result | Check that stops it |
| --- | --- | --- | --- |
| A1 Direct read | bob and eve open the flag | PERMISSION_DENIED (2/2) | gate: DAC (`/admin` is 0700); MAC and RBAC would each deny as well |
| A2 Traversal and aliases | `/public/../admin/...`, `../../../admin/...`, `/../../etc/passwd`, backslashes, `//` and `./`, `/ADMIN`, `%2e%2e`, NUL byte, invalid UTF-8 | denied or NO_SUCH_FILE (10/10) | `safe_join` rejects NUL, `\`, `:`, invalid UTF-8 and escapes above the root; canonical paths such as `/admin/ctf/flag.txt` then reach the gate and are denied. `%2e%2e` is a literal name, never decoded |
| A3 Enumeration | eve lists `/` and `/admin`, stats the flag; bob and alice list `/` | eve sees only `public`, bob `projects` and `public`, alice all three; `/admin` denied | READDIR authorizes `stat` on each child and omits denied entries (server.py lines 526-537) |
| A4 Symlink trick | read `/public/link_to_flag` as eve and as alice; read through `/public/link_out` (link to a host directory) | PERMISSION_DENIED (3/3) | `safe_join` compares the resolved path with the literal path and rejects any link (lines 131-138); this applies to alice too |
| A5 Handle reuse | eve uses alice's live handle; guessed tokens `1`, `2`, zeros; alice reuses a closed handle; WRITE through a read-only handle | FAILURE / PERMISSION_DENIED (6/6) | handles are random 192-bit tokens kept per session (lines 398-403); closed tokens are deleted; kind and read/write mode are checked on every use (lines 388-392 and 545-549) |
| A6 Destroy the flag | eve WRITE\|TRUNC; eve READ\|TRUNC; bob WRITE\|CREAT | denied (3/3); flag intact | mutation flags require WRITE and the `write` decision before any filesystem call (lines 470-478) |
| A7 Insider exfiltration | alice, who may read the flag, creates `/public/flag_copy.txt` and `/projects/flag_copy.txt` | PERMISSION_DENIED (2/2) | MAC no write down: confidential subject cannot write public or internal objects |
| A8 Symlink-swap race | a thread swaps `/public/race.txt` between a plain file and a link to the flag (439 swaps) while eve reads it 300 times | 0 leaks (209 denied, 91 got the harmless file) | after the gate, `Jail.parent` walks directories with `O_DIRECTORY` + `O_NOFOLLOW` descriptors and opens the leaf with `O_NOFOLLOW` (lines 208-236), so a link swapped in after the check cannot be followed |

## 6. Evidence and how auditing helped

Each authorization decision goes into `audit.jsonl` as one JSON object with `timestamp`, `user`, `op`, `path`,
`allowed` and `reason`. Excerpt from the hardened run (`docs/evidence/ctf-audit.jsonl`, timestamps omitted):

```json
{"user": "bob",   "op": "read",  "path": "/admin/ctf/flag.txt",   "allowed": false, "reason": "DAC: read denied at /admin/ctf"}
{"user": "eve",   "op": "read",  "path": "/admin/ctf/flag.txt",   "allowed": false, "reason": "DAC: read denied at /admin/ctf"}
{"user": "eve",   "op": "stat",  "path": "/admin",                "allowed": false, "reason": "MAC: no read up"}
{"user": "eve",   "op": "list",  "path": "/admin",                "allowed": false, "reason": "DAC: list denied at /admin"}
{"user": "alice", "op": "read",  "path": "/admin/ctf/flag.txt",   "allowed": true,  "reason": "allowed by DAC, MAC and RBAC"}
{"user": "alice", "op": "write", "path": "/public/flag_copy.txt", "allowed": false, "reason": "MAC: no write down"}
```

Filtering the log for denied requests under `/admin` lists eve's attempts in time order:
`jq -c 'select(.allowed==false and (.path|startswith("/admin")))' audit.jsonl`. Her traversal attempt shows up
under its canonical path `/admin/ctf/flag.txt`, because canonicalization runs before the gate.

The `reason` field names the model that denied each request, which made it easy to see that alice's copy was
stopped by MAC while every other user was already stopped by DAC. Because only the first denial is logged, the
per-layer table in section 2 was produced by calling the three checks directly.

An insider leak looks like the A7 records: alice, who is allowed to read the flag, tries to write copies of it to
`/public` and `/projects`, and both writes are logged as denied.

Requests rejected before the gate (symlinks, NUL bytes, escapes above the root, invalid
handles) leave no audit record, because the server raises before it calls `authorize()`. A4, part of A2, A5 and
A8 are therefore visible only in the client's STATUS replies. We recommend that the server write one audit record
for each protocol-level rejection (`allowed: false`, `reason: "path validation"`), so these attacks can be detected too.

## 7. Limitations

- Passwords were random one-run values, not the project's password store, which is not in the repository yet.
- Tested on macOS (Python 3.14, AsyncSSH 2.24.1). The Windows code path (reparse points, case folding) is not
  exercised by these attacks.
- A8 is a probabilistic test. 0 leaks in 300 reads shows the defence holds in practice; it does not prove a leak
  is impossible. The argument for that is the design: the leaf is opened with `O_NOFOLLOW` relative to a
  directory descriptor that was itself opened without following links.
- A privileged local process on the server machine can still read the file directly; the CTF covers the SFTP
  interface only.

## 8. Reproduce

```text
pip install asyncssh
python3 ctf/run_attacks.py            # hardened + naive runs, writes docs/evidence/ctf-attacks.md
python3 ctf/setup_flag.py             # plant the flag in server/sftp_root for a live demo
```

Once `server/auth.py` exists, set `CTF_PASSWORD_ALICE`, `CTF_PASSWORD_BOB` and `CTF_PASSWORD_EVE` and run
`python3 ctf/run_attacks.py --auth real`. The naive run needs port 2222 free.
