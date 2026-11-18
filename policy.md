# Access Control Design

## Operations covered

This document contains only WP1's two subsections. WP3 supplies the DAC, MAC,
RBAC, composition, auditing and inheritance design; WP2 supplies authentication,
static-data loading and audit storage. These packages are not present yet.

| SFTP v3 request | Gate operation | Behaviour |
| --- | --- | --- |
| INIT | None | Negotiate VERSION(3); no user filesystem access |
| REALPATH | `realpath` | Return a canonical jail-relative POSIX name |
| STAT / LSTAT | `stat` | Return ATTRS; all symlinks/reparse points are denied |
| FSTAT | `stat` | Authorize the file handle's saved path, then use its descriptor |
| OPENDIR / READDIR | `list` | Authorize the directory on open and each batch |
| READDIR entry metadata | `stat` | Authorize each child; omit denied children |
| MKDIR | `mkdir` | Create exactly one directory, then apply WP3 inheritance |
| OPEN read-only / READ | `read` | Authorize on open and each read |
| OPEN write / WRITE | `write` | Authorize on open and each write |
| OPEN read-write | `write` AND `read` | Both decisions must allow before opening |
| CLOSE | None | Release an already-owned handle, even if policy now denies |

`WRITE`, `CREAT`, `TRUNC` and `APPEND` flags require write access. A mutation
flag without `WRITE` is rejected before any filesystem operation; `EXCL`
requires `CREAT`. Create uses an atomic exclusive attempt, falling back to an
existing file only when `EXCL` was not requested. Truncation happens only after
authorization and checking the opened object is a regular file. Append seeks to
the end for every WRITE. Client attributes never override policy ownership,
permissions or labels. Requests with unsupported types, malformed fields,
invalid handles or invalid flags return generic FAILURE(4). Denials return
PERMISSION_DENIED(3), missing paths NO_SUCH_FILE(2), exhausted reads/directories
EOF(1), and successful mutations/CLOSE OK(0). No exception text or OS paths are
sent to clients. REALPATH can return an authorized, nonexistent canonical name
with empty attributes; this supports uploads to new filenames.

REMOVE, RENAME, SETSTAT, FSETSTAT, READLINK and SYMLINK are not implemented.
Limits: 256 KiB packet body, 64 KiB per READ, 128 handles per session, and
64 visible entries per READDIR reply. Handles use random 192-bit identifiers,
are private to one session, record path/kind/read-write mode, and are closed on
CLOSE, EOF or disconnect. Closed or foreign handles cannot be reused.

## Enforcement point

The server obtains the authenticated username from the AsyncSSH channel.
For pathname requests it runs `safe_join(jail, path)` and then
`authorize(user, op, canonical_posix_path) -> (bool, reason)` before accessing
user data. WP1 follows the task-division contract's jail-relative POSIX path
argument (for example `/projects/a.txt`); WP3 can derive the OS path from its
configured jail root. The screenshot's `full_path` terminology does not mean
that OS paths should appear in SFTP replies or policy resource prefixes.

`safe_join` rejects invalid UTF-8, NUL, traversal above the root, backslashes,
drive/ADS syntax, Windows device names and ambiguous names. It uses
`os.path.commonpath` to check containment and rejects resolved aliases.
On Windows, existing components use their on-disk casing in the policy path,
so changing the spelling of an existing protected path cannot bypass its rule.
The only pre-gate filesystem inspection is canonicalization itself. After the
gate, guarded traversal checks components again: POSIX uses directory
descriptors and `O_NOFOLLOW`; Windows pins ancestor directories against deletion
or renaming and opens file leaves using `OPEN_REPARSE_POINT`, checks the actual
opened object, and refuses every reparse point. Symlinks within the jail are
also intentionally denied. LSTAT consequently denies links rather than exposing
their metadata. Each gate approval covers the guarded primitive sequence for
that operation (including descriptor validation, seek/read/write and rollback).
READDIR's own iterator and each child's metadata have separate checks.
FSTAT/READ/WRITE reauthorize the handle's saved path on every request and use
the already-open descriptor, not a new path-based open. CLOSE/disconnect cleanup
must remain possible without another authorization decision.

No missing or broken policy hook grants access: only `(True, str)` allows.
Unknown operations fail without performing an operation. WP3's gate owns
allow/deny auditing and must log before returning; audit failures must raise and
thus deny access. Invalid framing/paths rejected before a canonical resource
exists are protocol validation failures, not fabricated policy decisions.
WP2/WP3 must agree how to audit those separately if desired.

Integration hooks (proposed because no `docs/interfaces.md` exists):

- WP2: `auth.verify_password(username, password) -> bool`, optionally async.
  WP2 initializes and validates its static dataset before serving, and owns
  hashing, rate limits, lockout and authentication audit. Exceptions deny login.
- WP3: `policy.authorize(user, op, path) -> (bool, str)`, synchronous, with
  audit inside the gate. No built-in permissive fallback exists.
- WP3: `policy.inherit(user, path, kind) -> None`, synchronous, where `kind` is
  `file` or `dir`. Called only for a newly created object, before returning a
  handle or success. It must atomically register owner/group/mode/label, use
  secure filesystem operations if needed, and fail closed on missing metadata.
  An exception makes the server close/remove the newly created object and
  return FAILURE. Existing files never get their ownership reset by `CREAT`.
- `serve(verify_password, authorize, inherit, root=..., host_key=...,
  host=..., port=...)` accepts configured hooks for integration and isolated
  testing. The executable imports the hooks and refuses startup if absent.
  WP2's loader initialization must be connected when its interface is available.

The jail is server-owned: untrusted local processes must not modify its
contents, inject hard links or move opened directories. POSIX directory
descriptors prevent symlink substitution but do not stop an independently
privileged local process moving an already-open directory outside the jail.
The server exposes no link, rename or removal commands. Windows and POSIX
implementations need independent platform verification; Windows has been the
available execution environment for this work.

The persistent key is `server/ssh_host_ed25519_key`; the runtime jail is
`server/sftp_root`, both anchored to `Path(__file__).parent`. Generate a fresh
key once with `ssh-keygen -t ed25519 -N "" -f server/ssh_host_ed25519_key`.
Never distribute the starter private key or a newly generated private key.
Clients must trust/verify the new public fingerprint (WP4 owns this).

Protocol references: [SFTP v3 draft](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
and [AsyncSSH API](https://asyncssh.readthedocs.io/en/latest/api.html).
AsyncSSH supplies SSH transport, password-authentication exchange and channels;
`server/server.py` implements the SFTP packets itself.
