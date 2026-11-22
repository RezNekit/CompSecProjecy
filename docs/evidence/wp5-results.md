# WP5 verification and release record

22 November 2026, macOS ARM64, Python 3.14, AsyncSSH 2.24.1, pytest 9.2.0.
Command: `.venv/bin/python -m pytest -q`. **48 passed, zero skipped** locally.

## Verified coverage

- DAC owner/group/other, directory execute semantics and creation inheritance.
- MAC public/internal/confidential reads, no read up and no write down.
- RBAC role union, admin role addition, prefix boundaries and per-user deny.
- Composite denial, default deny, traversal and complete allow/deny audit records.
- Correct/wrong/unknown password verification using real salted scrypt, dummy
  hashing, lockout threshold, expiry, rolling failure window and successful reset.
- All six static files: missing/malformed data, cross-references, known levels,
  scrypt parameters, immutable loaded data and startup load messages.
- Audit control-character injection, password absence in logs and fail-closed
  authorization when the audit destination is unwritable.
- All twelve required SFTP requests over actual host-verified SSH and raw packets,
  request IDs, binary chunked transfer, file/directory EOF, FSTAT, unknown packets,
  closed handles, invalid handle modes, traversal and symlinks.
- Client command round-trips, working directory, graceful errors and changed-key
  rejection. WP4 client tests use explicit auth/policy stubs; WP5 full-stack tests
  separately use real authentication, loader and policy.
- Real server entry point launched from a different working directory, temporary
  data/jail/key/audit, free port, three users, every required client command,
  denial by actual policy and five failed SSH logins followed by account lockout.

## CTF and report

Final integration attack run: real AuthService with ephemeral salted scrypt
records, actual policy and raw client. **0 of 27 hardened attack attempts
exposed/changed the flag; flag intact.** The naive baseline exposed/destroyed it
in four cases. See ctf-attacks.md and ctf-audit.jsonl. The timed race is a
probabilistic check, not a proof. CTF_writeup.pdf was rendered from the team's
Markdown report and all four pages visually inspected.

## Integration and release

WP2 branch abaa9c9 was integrated after the existing WP1/WP3 and merged WP4 work.
[Integration review](wp5-integration-review.md) lists defects and regression
coverage. README contains local setup, user powers, lockout policy, limitations,
OS result status and links to design/CTF/disclosure.

`.github/workflows/tests.yml` runs Python 3.12 on Windows/macOS/Linux. Actual
remote results must be read from GitHub Actions; configuration alone is not a
pass. Local macOS results above do not establish teammate Windows/Linux runs.

`tools/check_submission.py --zip output/submission.zip` requires a clean,
committed tree, checks required tracked files, scans private-key signatures and
runtime data, validates credential fields, tests a fresh clone, creates a zip
and verifies every file against its SHA-256 manifest. The final run is recorded
in output/release-verification.txt alongside the archive (runtime output).

## Human handoff

- Review all submitted code and reports; the automated review is not a second
  student's PR approval.
- Confirm the inherited group01 flag identifier and each member's AI disclosure.
- Team members should run tests on their own OS and append their observed result
  to README; CI results are recorded separately.
- Upload the verified archive to the course portal and confirm the downloaded
  submission opens. No course upload has been performed by this tooling.

The brief says 18 November; the task division says 22 November. Confirm the
actual course deadline. No credentials, private host key or live runtime audit
log belong in the archive. The CTF audit under docs/evidence is generated
synthetic attack evidence and is deliberately included.
