# Access Control Design

We use `authorize(user, op, path)` in `server/policy.py` to check DAC, MAC and
RBAC before allowing a file operation. All three have to agree. If no rule
allows a request, we deny it. Each policy decision is also written to the audit
log so we can see why something was allowed or blocked.

## Requests and checks

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

The server takes the username from the SSH session, never from the request. For
every path it first runs `safe_join`, which turns what the client sent into a
clean path inside the jail (`server/sftp_root`), such as `/projects/a.txt`. It
rejects `..` above the root, symlinks, NUL bytes, backslashes and Windows device
names. Only then does it call `authorize`, and only if that allows the request
does it open, list, read, write or create anything. Files are opened without following symlinks, so a
link swapped in after the check cannot redirect the server.

The policy also refuses paths that are not already clean. We check this again
because the rules match paths as text, so a path like
`/projects/../admin` would otherwise be judged as if it were inside `/projects`.

## DAC

Each path has an owner, a group and Unix permission bits. Defaults are set per
folder in `data/dac_owners.csv`, and a path without its own line uses the
closest folder above it. Group membership is in `data/groups.json`.

For DAC we use Unix-style permissions, as requested in the assignment. The
owner bits apply to the owner, the group bits apply to other users in that
group, and everyone else gets the other bits.

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

## How the rules work together

DAC, MAC and RBAC all have to allow the request. We check them in that order
and record the first refusal in the audit log.

| | MAC allows | MAC denies |
| --- | --- | --- |
| **DAC allows** | bob writes `/projects/plan.txt`: allowed | alice writes `/projects/plan.txt`: denied (write down) |
| **DAC denies** | bob reads `/public/archive/old.txt`: denied (folder is 0750 admins) | eve reads `/admin/flag.txt`: denied |

This matters when the models give different answers. alice owns `/projects`,
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

### User examples

| User | Role | Clearance | What they can do |
| --- | --- | --- | --- |
| alice | admin | confidential | read everything, write only in `/admin` |
| bob | analyst | internal | read `/public` (except `/public/archive`), read and write `/projects` and `/demo` |
| eve | guest | public | list `/` and read `/public`, except `/public/archive` |

## Testing and limitations

The six data files are loaded when the server starts, and each one is
logged. If a file is missing or broken, the server refuses to start and
logs what is wrong. Users, roles and labels only change by editing the files and
restarting. One limitation: ownership of files created while the server runs is
kept in memory, so after a restart those files fall back to the owner of
the closest folder listed in `data/dac_owners.csv`.

We run the full suite with `python -m pytest tests -q`. The 10 tests in
`tests/test_policy.py` focus on the policy. Three check DAC permissions, folder
access and inheritance. Two check MAC, and two check roles and deny overrides
in RBAC. The remaining tests check combined decisions, default denial and
traversal attempts, as well as the audit log.

At startup we load and validate the data, set up authentication and initialize
the policy before accepting connections. The README has the full test results.
