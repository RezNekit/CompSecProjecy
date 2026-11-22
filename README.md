# Dream Team 1 - SFTP project

For this project we built an SFTP client and server with DAC, MAC and RBAC access
control. AsyncSSH handles the SSH connection. We wrote the SFTP packet handling
and the authentication and authorization logic in the repository.

## Running it

We use Python 3.12 in CI. On macOS or Linux, run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python tools/make_users.py
ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key
.venv/bin/python ctf/setup_flag.py
.venv/bin/python server/server.py
```

On Windows PowerShell, use:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python tools/make_users.py
ssh-keygen -t ed25519 -f server/ssh_host_ed25519_key
.venv\Scripts\python ctf/setup_flag.py
.venv\Scripts\python server/server.py
```

Leave the Windows key passphrase empty when prompted. The host key only needs
to be generated once. Keep it locally; it should not be committed or submitted.

The password script asks you to set passwords for alice, bob and eve. Run it
before trying to log in: the hashes already in users.json were made from random
passwords that were not saved. Passwords are entered privately and only salted
scrypt hashes go into the file.

When the server starts, it logs the loaded data files and then prints
`SFTP listening on 127.0.0.1:2222`. If a data file is missing or invalid, or the
host key cannot be loaded, it prints an error and stops.

Open another terminal and start the client. On Windows, replace the interpreter
path with `.venv\Scripts\python`.

```sh
.venv/bin/python client/client.py --host 127.0.0.1 --port 2222 --username bob
```

On the first connection, compare the fingerprint with
`ssh-keygen -lf server/ssh_host_ed25519_key.pub` before accepting it. The client
saves the trusted key and refuses a later connection if that key changes.

For example, bob can run:

```text
pwd
ls /
mkdir /projects/demo
put README.md /projects/demo/README.md
stat /projects/demo/README.md
get /projects/demo/README.md README.copy.md
quit
```

`pwd` starts at `/`. The downloaded copy should have the same bytes as the
upload. The client also supports `cd` and `help`. You can connect with OpenSSH
using `sftp -P 2222 bob@127.0.0.1`, although some versions do not offer a `stat`
command in their CLI. Our tests send STAT, LSTAT and FSTAT packets directly.

## Users and permissions

| User | Role | Clearance | Access |
| --- | --- | --- | --- |
| alice | admin | confidential | Can read all areas, but can only write in /admin because of no write down. |
| bob | analyst | internal | Can read /public and read/write /projects and /demo. Cannot access /admin. |
| eve | guest | public | Can list root and read /public, except /public/archive. |

The full access-control design is in [policy.md](policy.md). A request needs
permission from all three models. Users and permissions come from the six files
in `data/`; changes take effect after restarting the server. The loader checks
the files and their references before the server accepts connections.

Five failed logins within five minutes lock that username for five minutes.
Failed checks also have a 0.25 second delay. A successful login clears the
failure count. The lockout is held in memory, so restarting clears it. Unknown
usernames still go through a dummy scrypt calculation.

Authentication and policy decisions are written to `server/audit.jsonl`, with
the timestamp, user, operation, path, result and reason. Passwords are not logged.
If a decision cannot be logged, access is refused.

## Tests and CTF

```sh
.venv/bin/python -m pytest tests -q
.venv/bin/python ctf/run_attacks.py
```

We ran the 48 tests locally on macOS ARM64 with Python 3.14 and AsyncSSH
2.24.1, and they all passed. They also passed with Python 3.12 on Windows,
macOS and Linux in
[CI run 45042041446](https://github.com/RezNekit/CompSecProjecy/actions/runs/45042041446),
on commit fef526b. The results for those three systems came from CI; each
member did not run them separately.
Windows symlink tests need permission to create links, which can require
Developer Mode.

The CTF flag is `FLAG{group01_sftp_wins}`, stored at `/admin/ctf/flag.txt` for
Dream Team 1. The attack script starts temporary local servers and uses temporary
salted password hashes. It also tests the original starter, which needs port
2222 to be free. Its public bob/test credential is only used for that vulnerable
comparison. The results are in [CTF_writeup.pdf](CTF_writeup.pdf), with the
[editable report](docs/CTF_writeup.md) and [client notes](docs/client-ctf.md) in docs.

To make the submission zip after committing the files, run:

```sh
.venv/bin/python tools/check_submission.py --zip output/submission.zip
```

This checks a fresh checkout, runs the tests and creates a zip with file hashes.
It leaves out untracked files, including the local host key and runtime log.
The zip still needs to be checked and uploaded to the course portal manually.
To rebuild the CTF PDF, install `requirements-docs.txt` and run
`python tools/build_ctf_pdf.py`.

There are still a few things we have not implemented. REMOVE, RENAME and
SETSTAT are missing, and changing users requires a server restart. Ownership of newly created
files is kept in memory and falls back to the configured defaults after a restart.
Requests rejected during path validation do not reach the policy audit log.
The server only listens on loopback, and this project does not protect against
someone who already has local access to edit the jail or configuration.

Our AI-use statement is in [docs/ai-disclosure.md](docs/ai-disclosure.md).
