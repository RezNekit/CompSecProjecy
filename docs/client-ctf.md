# Client and CTF

## Client

Requires Python 3.10+ and `pip install asyncssh`. Works on Windows, macOS and Linux.

```text
python3 client/client.py --host 127.0.0.1 --port 2222 --username bob
```

| Command | SFTP requests |
| --- | --- |
| `pwd` | REALPATH at start-up, then the stored path |
| `cd <path>` | REALPATH + STAT |
| `ls [path]` | OPENDIR, READDIR until EOF, CLOSE |
| `mkdir <path>` | MKDIR |
| `stat <path>` | STAT |
| `get <rpath> [lpath]` | OPEN(read), READ in 32 KiB chunks until EOF, CLOSE |
| `put <lpath> [rpath]` | OPEN(write, create, truncate), WRITE in 32 KiB chunks, CLOSE |
| `quit` / `exit` | closes the channel and connection |

The host key is trusted on first use. On the first connection the client shows the server's Ed25519 SHA256
fingerprint and asks yes/no, then saves the key in `client/known_hosts` (ignored by git). If the server later
offers a different key, the client prints a warning and exits with code 2. To use a pre-provisioned file
instead, pass `--known-hosts FILE`.

The password is read with `getpass`, so it is never echoed or logged. `SFTP_PASSWORD` can be set, but only for
scripted demos.

STATUS codes are shown as messages (`permission denied`, `no such file or directory`, ...) and the prompt
keeps running. A failed download leaves no partial file behind.

`--batch FILE` runs commands from a file; `docs/evidence/client-demo.md` was made this way. The client
opens the `sftp` subsystem and builds each SFTP v3 packet itself instead of using AsyncSSH's built-in SFTP
client.

Known limitations: one request in flight at a time (no pipelining), no `rm`/`rename` (the server does not
implement them), no recursive transfers.

## CTF

```text
python3 ctf/setup_flag.py      # plant FLAG{group01_sftp_wins} at /admin/ctf/flag.txt in server/sftp_root
python3 ctf/run_attacks.py     # run all attacks on the hardened and the naive server, write docs/evidence/
```

Flag design, protections, attacks and evidence: `CTF_writeup.pdf` (source `docs/CTF_writeup.md`).
Attack results and audit log: `docs/evidence/ctf-attacks.md`, `docs/evidence/ctf-audit.jsonl`.
Policy entries in `data/` that protect the flag: `ctf/flag_config.py`.

## Tests

```text
python3 -m pytest tests/test_client.py -q
```
