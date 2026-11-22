# WP1 server verification - 12 November 2026

These are the earlier WP1 results from Person 1, using Windows, Python 3.12,
AsyncSSH 2.24.1 and OpenSSH_for_Windows_9.5p2 (LibreSSL 3.8.2). At this point
WP2 and WP3 had not been integrated, so this run only checked the server part.
It did not check Linux or macOS compatibility.

## Test setup

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

The downloaded file matched the upload byte for byte. We used a file with all
byte values, large enough to need several READ and WRITE requests. The mode
shown by Windows came from the OS metadata with the test inheritance callback;
it did not tell us whether WP3's DAC rules worked.

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

## Other server checks

We also ran temporary checks during development, before the WP5 test suite:

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

## What was still missing at the time

At the time of this run, WP2's `auth.py`, loader and audit code and WP3's
`policy.py` were still missing. Normal startup had to refuse connections until
these were integrated. The injection contract and
operation mapping are in the two WP1 sections of `policy.md`. Because we used test callbacks, this run did not verify salted password
authentication, lockout, DAC/MAC/RBAC, policy audit records or owner, label and
mode inheritance. No WP2-WP5
deliverables were implemented. The task-division deadline also differs from
the screenshot deadline; neither is used to change the technical scope.
