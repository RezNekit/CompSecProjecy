# WP1 server verification - 12 November 2026

Scope: Person 1 only. Windows, Python 3.12, AsyncSSH 2.24.1,
OpenSSH_for_Windows_9.5p2 (LibreSSL 3.8.2). These results do not establish
Linux/macOS compatibility or validate the missing WP2/WP3 implementations.

## Fixture and host verification

The production server's `serve()` entry point ran on loopback with an ephemeral
port and a temporary empty jail. The fixture supplied an ephemeral password,
an allow-all authorization callback and a no-op inheritance callback. The
password was passed to OpenSSH through a temporary askpass process and never
printed. Every gate call received the authenticated username `wp1`.
No stub authentication, allow-all mode or credentials were added to the server.

The client used `StrictHostKeyChecking=yes` and a temporary `known_hosts` file
containing the new server public key; host verification was not disabled.
The command was:

```text
sftp -oBatchMode=no -oPreferredAuthentications=password -oPubkeyAuthentication=no
     -oStrictHostKeyChecking=yes -oUserKnownHostsFile=<fixture-known-hosts>
     -oGlobalKnownHostsFile=NUL -P <ephemeral-port> wp1@127.0.0.1
```

## OpenSSH transcript

Local temporary paths below are shortened to `<fixture>`; output otherwise
reflects the observed run. The stderr `Invalid command.` belongs to `stat .`.

```text
OpenSSH exit: 0
Connected to 127.0.0.1.
sftp> pwd
Remote working directory: /
sftp> ls -l
sftp> mkdir demo
sftp> put "<fixture>/upload.bin" /demo/upload.bin
Uploading <fixture>/upload.bin to /demo/upload.bin
sftp> ls -l /demo
-rw-rw-rw-   1        0        0     393225 Nov 12 12:35 upload.bin
sftp> stat .
Invalid command.
sftp> get /demo/upload.bin "<fixture>/download.bin"
Fetching /demo/upload.bin to <fixture>/download.bin
sftp> quit

SHA256 upload/download: 42596af449ee2632c0edea421703b523c4296890a4a783bb7fea746e930b35f7
Bytes: 393225
Gate operations: list, mkdir, read, realpath, stat, write
```

The uploaded and downloaded byte strings were compared directly and matched.
The payload contains all byte values and is larger than one READ or WRITE
chunk. The displayed Windows mode is OS metadata under the no-op inheritance
fixture; it is not evidence of WP3's DAC implementation.

The screenshot and task division request an OpenSSH `stat .` command, but this
installed OpenSSH CLI does not implement that command. This is a CLI limitation,
not a server STATUS failure. To verify the exact required operation, an
additional password-authenticated, host-verified AsyncSSH connection opened the
raw `sftp` subsystem (without the built-in SFTP client) and exchanged:

```text
INIT(version=3)                       -> VERSION(3)
STAT(request_id=1001, path=".")       -> ATTRS(request_id=1001)
Result: PASS
```

## Focused server checks

Temporary development checks were run independently of WP5's future test suite:

```text
python -m pytest tmp/check_wp1.py -q -p no:cacheprovider --basetemp=tmp/check-run-4
.....................................                                    [100%]
37 passed in 0.38s
```

Coverage includes all twelve requests, binary data, FSTAT, canonical REALPATH,
fragmented/coalesced framing, malformed attributes and request IDs, packet/read
caps, unknown messages, 64-entry directory pagination, denied-entry filtering,
handle limits/modes/invalid tokens/closed tokens/disconnect cleanup, generic
STATUS errors, missing parents, exclusive creation, authorized truncation,
rejection of read-only truncation, append semantics, oversized offsets,
creation-only inheritance and rollback on inheritance failure, gate exceptions,
reauthorization of handles, password callback delegation, traversal/UTF-8/NUL/
DOS/ADS restrictions, Windows case normalization and junction escape rejection.
The junction check also bypasses the initial canonicalization to verify the
guarded filesystem traversal independently rejects the reparse point.

The regenerated Ed25519 key loads successfully and persists between starts.
The known starter key was removed; private keys and temporary verification
artifacts are ignored by `.gitignore`. Existing jail contents were preserved
when moved under `server/sftp_root`.

## Integration boundary

WP2's `auth.py`/loader/audit and WP3's `policy.py` are absent. Normal startup
must fail closed until those hooks are integrated. The injection contract and
operation mapping are in the two WP1 sections of `policy.md`. Real salted
authentication, lockout, DAC/MAC/RBAC, policy audit records and owner/label/mode
inheritance cannot be claimed verified by these stub-based runs. No WP2-WP5
deliverables were implemented. The task-division deadline also differs from
the screenshot deadline; neither is used to change the technical scope.
