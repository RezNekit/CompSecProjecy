# WP5 verification and handoff

Observed locally on 22 November 2026: macOS ARM64, Python 3.14,
AsyncSSH 2.24.1, pytest 9.2.0. Command: `.venv/bin/python -m pytest -q`.
Result: **19 passed**. Windows/Linux results are pending CI execution.

## Coverage

- Ten isolated policy tests: Unix owner/group/other, directory execute semantics,
  inheritance, MAC read-up/write-down, role union, prefix boundaries, per-user
  deny precedence, composition, default deny and complete allow/deny audit records.
- Six raw SFTP tests (including three traversal parameters) use a temporary jail,
  ephemeral Ed25519 key, pinned known_hosts, a free loopback port, real SSH and
  the actual Policy instance. They cover all twelve required request types,
  binary chunked round-trip and EOF, directory EOF, invalid/closed handles,
  unknown requests, read-handle writes, traversal and symlink rejection.
- Three integration checks cover the module-level policy hooks, malformed/missing
  policy data and clean startup refusal while authentication is absent.

The SSH fixture uses an ephemeral password callback, not WP2 password hashing.
It does not establish production authentication, lockout, or client CLI correctness.
No AsyncSSH SFTP implementation is used in these tests.

## Defect fixed

`server/policy.py` exposed authorize/inherit functions which did not delegate to
`current`; both returned None. This denied every server request and failed to
register creation ownership. Delegation is restored and covered by regression test.
Import no longer eagerly initializes policy data; call `policy.init()` explicitly
at startup before using the hooks. WP2 startup must wire this initialization.

## Blocking team work

| Owner | Blocker / required validation |
| --- | --- |
| Person 2 | Supply auth.py, loader.py, audit.py, users.json and README. Wire policy.init at startup. Then add tests for correct/wrong/unknown passwords, N-failure lockout, recovery, no passwords in logs, loader cross-references and startup loading messages. |
| Person 3 | Review policy-hook fix and integration startup. Runtime ownership is currently in memory; document/resolve persistence requirements. |
| Person 4 | Supply client/client.py and CTF_writeup.pdf; run client and attack evidence against real authentication and policy. |
| All members | Confirm AI disclosure, review required files and run tests on Windows/macOS/Linux. |
| Person 5 | Finish AuthN/loader tests against Person 2's agreed interfaces, review CI results, then fresh-clone test and package the committed tree. |

No final submission zip has been produced: the deliverables above are absent.
The original brief says 18 November; the task division says 22 November.
Confirm the actual course deadline independently; this report does not resolve it.

## Run and package

```sh
python3 -m venv .venv
# Windows: .venv\Scripts\python instead of .venv/bin/python
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
.venv/bin/python tools/check_submission.py
# After all team deliverables are present, reviewed, and committed:
.venv/bin/python tools/check_submission.py --zip output/submission.zip
```

The checker requires tracked deliverables and a clean working tree for packaging,
rejects tracked host keys/runtime logs and recognized private-key headers, and
runs tests before building. It cannot prove absence of every plaintext credential;
review generated users.json (salted hashes only), source and documentation manually.
Run again in a fresh clone, extract the archive and verify it before uploading.
GitHub issues, PR review, teammate confirmations and course upload were not performed.
