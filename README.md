# SFTP over SSH: DAC, MAC and RBAC

A raw SFTP v3 server and client using AsyncSSH for SSH transport. File-protocol
packets, authorization and authentication are implemented in this repository.

## Install and run

Python 3.12 is the CI baseline. On macOS/Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python tools/make_users.py
ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key
.venv/bin/python ctf/setup_flag.py
.venv/bin/python server/server.py
```

On Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python tools/make_users.py
ssh-keygen -t ed25519 -f server/ssh_host_ed25519_key
.venv\Scripts\python ctf/setup_flag.py
.venv\Scripts\python server/server.py
```

For the Windows host-key prompt, leave the passphrase empty. Generate the key
once and preserve it locally; it is excluded from Git and the submission.
`make_users.py` prompts privately for passwords and confirms them. Do not commit
plaintext passwords. The shipped users.json contains valid salted scrypt hashes
of discarded random passwords, so **set local passwords before logging in**.
Running the tool without arguments updates alice, bob and eve to match the policy.

Startup logs each loaded data filename and entry count, then
`SFTP listening on 127.0.0.1:2222`. Missing/malformed data or a missing/invalid
Ed25519 key causes a readable error and exit status 1.

In another terminal (use the Windows interpreter path on Windows):

```sh
.venv/bin/python client/client.py --host 127.0.0.1 --port 2222 --username bob
```

Verify the displayed fingerprint against your server key before accepting TOFU.
Use `ssh-keygen -lf server/ssh_host_ed25519_key.pub` to inspect it. A saved key
mismatch aborts the client. Commands:

```text
pwd
ls /
mkdir /projects/demo
put README.md /projects/demo/README.md
stat /projects/demo/README.md
get /projects/demo/README.md README.copy.md
quit
```

`pwd` prints `/`; upload/download should preserve the bytes. The CLI also offers
`cd`, help and clear permission/missing-file errors. OpenSSH interoperability:
`sftp -P 2222 bob@127.0.0.1`. Some OpenSSH versions have no `stat` CLI command;
our raw protocol tests exercise STAT, LSTAT and FSTAT directly.

## Users and Access Control Design

| User | Role | Clearance | Intended access |
| --- | --- | --- | --- |
| alice | admin | confidential | Read all areas; write only confidential /admin (no write down). |
| bob | analyst | internal | Read public; read/write /projects and /demo; no /admin access. |
| eve | guest | public | Read /public and list root; explicit denial on /public/archive. |

See [policy.md](policy.md) for operation mapping, DAC modes and directory execute
bits, inheritance, MAC no-read-up/no-write-down, RBAC matrix, composition and audit.
Data is static and loaded at startup. Change configuration on disk and restart.
Six files are loaded: users.json, user_roles.json, role_perms.csv, mac_labels.json,
dac_owners.csv and groups.json. The loader validates cross-references and exposes
read-only data. Authorization requires DAC AND MAC AND RBAC and defaults to deny.
All auth and policy records use `timestamp,user,op,path,allowed,reason`, with
optional `model,session` fields, in `server/audit.jsonl` by default. No password
text is logged. JSONL escaping prevents newlines from forging records. Failure
to write a decision prevents access.

Password verification uses salted scrypt and constant-time comparison; unknown
users incur a dummy hash. Five failures within 300 seconds lock that username
for 300 seconds; failed checks delay 0.25 seconds. Successful login clears its
failure history. Lockout state is in memory and resets on restart. Password
hashing and delays run outside the SSH event loop.

## Tests, CTF and submission

```sh
.venv/bin/python -m pytest -q
.venv/bin/python ctf/run_attacks.py
.venv/bin/python tools/check_submission.py
```

The attack runner uses temporary salted scrypt records by default and runs only
against local temporary servers/jails. Its naive baseline uses the public course
starter credential as an intentionally vulnerable fixture, never as a production
credential. Port 2222 must be free for that baseline. It updates the CTF evidence.
The flag is `FLAG{group01_sftp_wins}` at `/admin/ctf/flag.txt`; confirm the group
number before submission. See [CTF_writeup.pdf](CTF_writeup.pdf), its
[Markdown source](docs/CTF_writeup.md), and [client notes](docs/client-ctf.md).

| Platform | Observed result |
| --- | --- |
| macOS ARM64, Python 3.14, AsyncSSH 2.24.1 | 48 tests passed locally; full startup, client and lockout included. |
| Windows, Python 3.12 | CI configured; see the latest GitHub Actions result. No teammate-run result claimed. |
| Linux, Python 3.12 | CI configured; see the latest GitHub Actions result. No teammate-run result claimed. |

CI runs the same suite on all three OSes. Symlink tests require OS permission;
on Windows that may need Developer Mode. A skipped symlink test is reported
separately and is not evidence of Windows symlink enforcement.

[WP5 evidence](docs/evidence/wp5-results.md) records scope, integration fixes and
release checks. [AI-use disclosure](docs/ai-disclosure.md) describes assistance.
After review and committing the complete tree:

```sh
.venv/bin/python tools/check_submission.py --zip output/submission.zip
```

The packager checks the committed tree in a fresh local clone, reruns tests,
excludes keys/runtime data and adds an SHA-256 manifest. It never uploads to the
course portal. Open and inspect the final zip before submitting.

## Known limitations

- REMOVE, RENAME and SETSTAT are unsupported. No runtime user/role editing.
- Runtime ownership inheritance is in memory; restart falls back to prefix defaults.
- Paths rejected by safe_join before authorization do not produce a policy audit
  entry. Valid paths denied by policy do. CTF evidence includes both cases.
- MAC metadata reads can prevent browsing a high-labelled path through the CLI;
  raw low-clearance read attempts are still rejected at the gate.
- Server binds loopback only. Local users who can modify the jail/configuration
  are outside the remote SFTP threat model. Windows junction race coverage is
  described in the earlier WP1 evidence, not newly established by macOS tests.
- The course brief and task division list different deadlines; verify the course
  deadline. Team review, individual AI confirmations and course upload remain
  human actions.
