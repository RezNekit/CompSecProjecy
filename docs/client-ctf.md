# Client and CTF notes

The client opens the SSH `sftp` subsystem and builds SFTP v3 packets itself. It
does not use AsyncSSH's built-in SFTP client. Install the dependencies from the
README, start the server, then connect with:

```sh
python3 client/client.py --host 127.0.0.1 --port 2222 --username bob
```

The commands are `pwd`, `cd`, `ls`, `mkdir`, `stat`, `get`, `put` and `quit`.
`ls` reads directory entries until EOF. Uploads and downloads use 32 KiB chunks,
and file handles are closed afterwards. The client sends one request at a time,
so it does not support pipelining. Recursive transfers, remove and rename are
also not implemented.

On the first connection, the client shows the server's Ed25519 fingerprint and
asks whether to trust it. Accepted keys go in `client/known_hosts`. If the key
changes later, the client stops with exit code 2. You can also supply an existing
file with `--known-hosts FILE`.

Passwords are entered through `getpass`, so they are not displayed. There is
also an `SFTP_PASSWORD` environment variable for scripted demos. Errors such as
permission denied or a missing file are printed without ending the prompt. A
failed download does not leave a partial file behind.

For scripted commands, use `--batch FILE`. This was used for the transcript in
`docs/evidence/client-demo.md`. The client tests can be run separately with:

```sh
python3 -m pytest tests/test_client.py -q
```

For the CTF we used `python3 ctf/setup_flag.py` to put the flag at
`/admin/ctf/flag.txt` inside the jail. We tested both our updated server and the
original starter with `python3 ctf/run_attacks.py`, which uses temporary jails
for the runs.
The flag and its expected policy entries are described in `ctf/flag_config.py`.
The report is in `docs/CTF_writeup.md`, and the attack results and audit log are
in `docs/evidence/ctf-attacks.md` and `docs/evidence/ctf-audit.jsonl`.
