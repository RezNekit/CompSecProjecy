# Dream Team 1 - CTF write-up: protecting the flag in our SFTP server

This is the CTF part of our Computer Security group project. We tested whether
a user could get around the access controls in our SFTP server and read or
change the flag. The test output is saved in `docs/evidence/`.

## What we tested

We put `FLAG{group01_sftp_wins}` at `/admin/ctf/flag.txt` inside the server's
jail. Only alice should be able to read it, since she is the owner, has the
admin role and has confidential clearance. We then used our client through
`ctf/run_attacks.py` to try reading or changing it as users who should not have
access. The runner made 27 attack attempts across seven classes, alongside
directory checks and a separate symlink-swap test. None read or changed the
flag on our updated server, and alice could still read it normally. With the
original course starter, we could read the flag in three ways and truncate it
in another attack.

The final run on 22 November used `server/server.py`, the policy in
`server/policy.py` and the configuration in `data/`. It also used
`server/auth.py` with temporary salted scrypt password records. Our earlier
runs used a temporary password callback, so those only checked the protocol
and policy. We describe the later authentication checks at the end.

## Flag design

The flag is created by `ctf/setup_flag.py` when setting up the server. On disk
it is at `server/sftp_root/admin/ctf/flag.txt`; the flag file is not committed to
git. We also have `/public/welcome.txt` and `/projects/plan.txt` as decoys.

There are three users. Alice is an admin with confidential clearance and is in
the admins and staff groups. Bob is an analyst with internal clearance and is
in analysts and staff. Eve is a guest with public clearance and is only in
staff. These settings are in `data/user_roles.json`, `data/mac_labels.json` and
`data/groups.json`.

We protect the flag through DAC, MAC and RBAC. The `/admin` folder belongs to
alice:admins with mode 0700, which keeps bob and eve out through DAC. MAC also
blocks them because `/admin` is confidential, above both of their clearances.
For RBAC, only the admin role has a rule covering `/admin`. MAC also prevents
alice from writing a copy to a folder with a lower label.

Path handling is checked separately in `server/server.py`. Before checking the
policy, `safe_join` cleans the path and rejects links. The `Jail` code uses
`O_NOFOLLOW` when opening each path component, so swapping in a symlink after
the first check should not redirect the operation.

All three policy checks have to allow a request. DAC runs first, so it is the
reason recorded in the log when bob or eve tries to read the flag. We also ran
the checks separately to see what each one would do:

| Request | DAC | MAC | RBAC |
| --- | --- | --- | --- |
| bob reads `/admin/ctf/flag.txt` | denied at `/admin/ctf` | no read up | no role grants read |
| eve reads `/admin/ctf/flag.txt` | denied at `/admin/ctf` | no read up | no role grants read |
| alice reads `/admin/ctf/flag.txt` | ok | ok | ok |
| alice writes `/public/flag_copy.txt` | ok | no write down | ok |

If one layer is misconfigured, the other two still keep bob and eve away from the flag. The rows in `data/` that
matter are collected in `ctf/flag_config.py` (`REQUIRED_POLICY`).

## Ways we tried to get around the checks

We looked at password authentication, path names, file handles and OPEN flags.
The client can send unusual paths, guessed handles or flag combinations such
as READ+TRUNC. We also checked whether alice could copy the flag into a folder
that other users could read.

There is no SFTP SYMLINK request in our server, so the symlink tests assume a
link was already placed on disk by a local user or a setup mistake. For the
race test, a local thread repeatedly swapped a normal file with a link while
the client tried to read it.

## How a naive design exposes the flag

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

## Results on our server

We sent the attempts through the raw SFTP channel in `client/client.py`. This
let us try malformed requests and unusual flag combinations directly. The full
output is in `docs/evidence/ctf-attacks.md`; the table below groups the results.

| Class | Attempts | Result | Check that stops it |
| --- | --- | --- | --- |
| A1 Direct read | bob and eve open the flag | PERMISSION_DENIED (2/2) | gate: DAC (`/admin` is 0700); MAC and RBAC would each deny as well |
| A2 Traversal and aliases | `/public/../admin/...`, `../../../admin/...`, `/../../etc/passwd`, backslashes, `//` and `./`, `/ADMIN`, `%2e%2e`, NUL byte, invalid UTF-8 | denied or NO_SUCH_FILE (10/10) | `safe_join` rejects NUL, `\`, `:`, invalid UTF-8 and escapes above the root; canonical paths such as `/admin/ctf/flag.txt` then reach the gate and are denied. `%2e%2e` is a literal name, never decoded |
| A3 Enumeration | eve lists `/` and `/admin`, stats the flag; bob and alice list `/` | eve sees only `public`, bob `projects` and `public`, alice all three; `/admin` denied | READDIR authorizes `stat` on each child and omits denied entries (server.py lines 526-537) |
| A4 Symlink trick | read `/public/link_to_flag` as eve and as alice; read through `/public/link_out` (link to a host directory) | PERMISSION_DENIED (3/3) | `safe_join` compares the resolved path with the literal path and rejects any link (lines 131-138); this applies to alice too |
| A5 Handle reuse | eve uses alice's live handle; guessed tokens `1`, `2`, zeros; alice reuses a closed handle; WRITE through a read-only handle | FAILURE / PERMISSION_DENIED (6/6) | handles are random 192-bit tokens kept per session (lines 398-403); closed tokens are deleted; kind and read/write mode are checked on every use (lines 388-392 and 545-549) |
| A6 Destroy the flag | eve WRITE\|TRUNC; eve READ\|TRUNC; bob WRITE\|CREAT | denied (3/3); flag intact | mutation flags require WRITE and the `write` decision before any filesystem call (lines 470-478) |
| A7 Insider exfiltration | alice, who may read the flag, creates `/public/flag_copy.txt` and `/projects/flag_copy.txt` | PERMISSION_DENIED (2/2) | MAC no write down: confidential subject cannot write public or internal objects |
| A8 Symlink-swap race | a thread swaps `/public/race.txt` between a plain file and a link to the flag (416 swaps) while eve reads it 300 times | 0 leaks (232 denied, 68 got the harmless file) | after the gate, `Jail.parent` walks directories with `O_DIRECTORY` + `O_NOFOLLOW` descriptors and opens the leaf with `O_NOFOLLOW` (lines 208-236), so a link swapped in after the check cannot be followed |

## What we could see in the audit log

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

The reasons helped us check why an attempt failed. For example, MAC stopped
alice from writing a copy, whereas DAC already stopped bob and eve from
reading the flag. The log only gives the first denial, which is why we called
the checks separately for the table in the flag setup above.

An insider leak looks like the A7 records: alice, who is allowed to read the flag, tries to write copies of it to
`/public` and `/projects`, and both writes are logged as denied.

Requests rejected before the gate (symlinks, NUL bytes, escapes above the root, invalid
handles) leave no audit record, because the server raises before it calls `authorize()`. A4, part of A2, A5 and
A8 are therefore visible only in the client's STATUS replies. We recommend that the server write one audit record
for each protocol-level rejection (`allowed: false`, `reason: "path validation"`), so these attacks can be detected too.

## Limitations

The final attack runs used the real AuthService with temporary salted scrypt
records, so we did not need the deployed passwords. The earlier runs used
one-run password callbacks and did not check the final authentication code.

We ran these attacks on macOS with Python 3.14 and AsyncSSH 2.24.1. This run
does not check the Windows handling of reparse points or case folding. Also,
getting zero leaks in 300 race-test reads is only the result of that run. It
does not prove that every possible race is covered. The use of `O_NOFOLLOW`
and directory descriptors is the main reason we expect link swaps to be
blocked.

The tests cover access through SFTP. Someone with enough local privileges on
the server machine could still read the file directly. Another gap is that
requests rejected before the policy check do not appear in the audit log.

## Running the tests again

```text
pip install asyncssh
python3 ctf/run_attacks.py            # hardened + naive runs, writes docs/evidence/ctf-attacks.md
python3 ctf/setup_flag.py             # plant the flag in server/sftp_root for a live demo
```

To use deployed password records instead of temporary hashes, set `CTF_PASSWORD_ALICE`, `CTF_PASSWORD_BOB` and `CTF_PASSWORD_EVE` and run
`python3 ctf/run_attacks.py --auth real`. The naive run needs port 2222 free.

## Checks after integrating authentication

After WP2 arrived, WP5 connected the attack runner to the real `AuthService`.
The 22 November integration rerun used temporary salted scrypt password records
for alice, bob and eve, real DAC/MAC/RBAC policy and host-verified SSH. Our server
blocked the attacks and the flag was still intact afterwards. The course
starter exposed or destroyed it in four attacks. The current transcript
and audit are in `docs/evidence/ctf-attacks.md` and `ctf-audit.jsonl`.
Earlier one-run-password evidence described above was a protocol/policy fixture;
it did not verify password hashing. The integration rerun and WP5 lockout tests
check authentication as well. The race-test result still has the limits
described above.

We used AI to assist with understanding the assignment, integration and debugging,
client and CTF development, documentation, and creating test cases. We did not
write all the code with AI. See `docs/ai-disclosure.md`.
