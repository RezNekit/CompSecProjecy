# WP5 integration review

Merged locally in dependency order: WP1 transport and WP3 policy on main, WP4
client/CTF already merged through PR #1, then origin/wp2-auth (abaa9c9).

Defects found and fixed during WP5 acceptance testing:

| Owner area | Finding | Fix / regression evidence |
| --- | --- | --- |
| WP3 | Module-level policy hooks returned None. | Delegate to current instance; public-hook test. |
| WP2 | Auth read `password hash`, while generator writes `password_hash`. | Match agreed schema; real password tests. |
| WP2 | Failure-delay/lockout code was unreachable after successful return. | Move failed-attempt handling outside success branch; unit expiry/window tests and five-failure SSH test. |
| WP2 | Loader had keys()/set/row-iteration/type errors and returned loader functions rather than loaded data. | Correct validation/iteration, expose load_all, validate all six files and cross-references; loader acceptance suite. |
| WP2/WP1 | Server startup never constructed AuthService or initialized policy. | Wire real services and data; production subprocess fixture runs from another CWD. |
| WP2/WP3 | Auth and policy had different audit locations/schemas. | Shared synchronized writer, timestamp schema and configurable path; log/audit tests. |
| WP1 | Synchronous scrypt and failure delays blocked the SSH event loop. | Offload synchronous password callbacks with asyncio.to_thread. |
| WP2/WP3 | /demo RBAC allowed writes but DAC inherited a non-writable root. | Add explicit /demo DAC template. |
| WP4 integration | Attack runner called low-level hash verifier as a two-argument auth hook. | Construct AuthService; use ephemeral salted hashes by default, rerun attacks. |

These findings are resolved in this integration change. No GitHub issues were
opened for already-fixed defects. This review does not substitute for a second
team member's PR approval. Remaining human checks: confirm group number, read
code/reports, confirm each member's AI use, and upload/verify the course submission.
