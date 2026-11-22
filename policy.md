# Access Control Design

Every file operation on our SFTP server goes through one function,
`authorize(user, op, path)` in `server/policy.py`. It combines three access
control models (DAC, MAC and RBAC), and a request only goes through if all three
allow it. Anything we did not explicitly allow is denied, and every decision is
written to an audit log.

## Operations covered

Before asking the policy, the server turns each SFTP request into one of six
operations:

| SFTP request | Operation |
| --- | --- |
| REALPATH | `realpath` |
| STAT, LSTAT, FSTAT | `stat` |
| OPENDIR, READDIR | `list` |
| OPEN for reading, READ | `read` |
| OPEN with the WRITE flag (alone or with CREAT, TRUNC or APPEND), WRITE | `write` |
| MKDIR | `mkdir` |

Opening a file for both reading and writing needs both `read` and `write`. The
server checks again on every READ, WRITE, FSTAT and READDIR, not just when the file or folder is
opened, and each entry in a directory listing is checked with `stat` and left
out if it is denied. CLOSE needs no check. REMOVE, RENAME and SETSTAT are not
implemented, so clients cannot delete files or change permissions.

Unknown users, unknown operations and malformed paths are refused before any
model runs. If the policy raises an error, the server treats it as a denial.

## Enforcement point

The server takes the username from the SSH session, never from the request. For
every path it first runs `safe_join`, which turns what the client sent into a
clean path inside the jail (`server/sftp_root`), such as `/projects/a.txt`. It
rejects `..` above the root, symlinks, NUL bytes, backslashes and Windows device
names. Only then does it call `authorize`, and only if that allows the request
does it open, list, read,
write or create anything. Files are opened without following symlinks, so a
link swapped in after the check cannot redirect the server.

The policy also refuses any path that is not already clean. This is a second
line of defence: the rules match paths as text, so a path like
`/projects/../admin` would otherwise be judged as if it were inside `/projects`.

## DAC

Each path has an owner, a group and Unix permission bits. Defaults are set per
folder in `data/dac_owners.csv`, and a path without its own line uses the
closest folder above it. Group membership is in `data/groups.json`.

We follow the Unix rule: if you own the path you get the owner bits, otherwise
the group bits if you are in its group, otherwise the "other" bits. The lecture
describes a rule where the most permissive right wins, but the assignment asks
for Unix-style modes, so we use the Unix one.

On a file, r means read and w means write. On a folder, r lets you list it, w
lets you create things in it, and x lets you go inside. You need x on every
folder along the way, so without x on a folder you can neither `ls` it nor
`stat` anything in it.

When someone creates a file or folder, they become its owner, and it takes the
group and mode of the folder it was created in (files lose the x bits). An
existing owner is never replaced, so uploading over someone else's file does not
make it yours.

For example, on a file `alice:analysts 0640`, alice can read and write, bob (in
analysts) can only read, and eve can do neither.

## MAC

We use three levels: public < internal < confidential. In `data/mac_labels.json`
each folder gets a label and each user a clearance, and a path takes the label
of the closest labelled folder above it.

- Reading (`realpath`, `stat`, `list`, `read`) is allowed only if the label is
  at or below your clearance: no read up.
- Writing (`write`, `mkdir`) is allowed only if the label is at or above your
  clearance: no write down.

So bob (internal) can read `/public` and `/projects` but not `/admin`, and alice
(confidential) cannot copy anything into `/projects` or `/public`. Both rules
are tested in `test_mac_internal_reads_public_and_internal_not_confidential`
and `test_mac_confidential_cannot_write_down`.

## RBAC

Users get roles in `data/user_roles.json`, and `data/role_perms.csv` says what
each role may do under a folder. A rule for `/projects` covers everything inside
it, but not `/projects2`. A user can do something if any of their roles allows
it. A row can also name a single user, such as `user:eve`, and a `deny` in any
matching row beats every allow.

| Role | Folder | Allowed |
| --- | --- | --- |
| guest, analyst | `/` | list, stat |
| guest, analyst | `/public` | read, list, stat |
| analyst | `/demo`, `/projects` | read, write, list, stat, mkdir |
| admin | `/` | everything |
| user:eve | `/public/archive` | nothing (deny) |

## Putting them together

The final decision is DAC and MAC and RBAC. If any one of them says no, the
answer is no. They are checked in that order, and the audit log records the
first one that refused.

| | MAC allows | MAC denies |
| --- | --- | --- |
| **DAC allows** | bob writes `/projects/plan.txt`: allowed | alice writes `/projects/plan.txt`: denied (write down) |
| **DAC denies** | bob reads `/public/archive/old.txt`: denied (folder is 0750 admins) | eve reads `/admin/flag.txt`: denied |

No single model can be used to get around the others. alice owns `/projects`,
but MAC still stops her writing there. bob's analyst role lets him read
`/public`, but DAC still keeps him out of `/public/archive`.

## Audit log

Authentication and policy share the synchronized writer in `server/audit.py`.
Every decision is added to `server/audit.jsonl` as one JSON line with the time,
user, operation, path, result and reason. If the log cannot be written, the
request is refused. The client only ever sees "permission denied"; the reason
stays in the log. Paths that `safe_join` rejects, such as `/../etc/passwd` or a
symlink, never reach the policy, so they are refused but not logged.

```json
{"timestamp": "2026-11-21T18:39:06+00:00", "user": "bob", "op": "write", "path": "/projects/plan.txt", "allowed": true, "reason": "allowed by DAC, MAC and RBAC"}
{"timestamp": "2026-11-21T18:39:06+00:00", "user": "alice", "op": "write", "path": "/projects/plan.txt", "allowed": false, "reason": "MAC: no write down"}
```

## Users

| User | Role | Clearance | What they can do |
| --- | --- | --- | --- |
| alice | admin | confidential | read everything, write only in `/admin` |
| bob | analyst | internal | read `/public` (except `/public/archive`), read and write `/projects` and `/demo` |
| eve | guest | public | list `/` and read `/public`, except `/public/archive` |

## Data files and tests

The five files in `data/` are loaded when the server starts, and each one is
logged. If a file is missing or broken, the server refuses to start and
logs what is wrong. Users, roles and labels only change by editing the files and
restarting. One limitation: ownership of files created while the server runs is
kept in memory, so after a restart those files fall back to the owner of
the closest folder listed in `data/dac_owners.csv`.

`pytest -q` runs the complete suite; `tests/test_policy.py` contains 10 policy tests: three for DAC (owner,
group and other; the folder x bit; inheritance), two for MAC, two for RBAC
(analyst versus admin; deny overrides), two for combined decisions and default
deny (including traversal attempts), and one for the audit log.

Startup calls `loader.load_all()` to validate all six static files, constructs
`AuthService`, and calls `policy.init()` before accepting SSH connections.
See README for integrated test results.
