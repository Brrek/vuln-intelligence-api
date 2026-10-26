# Threat model and security limitations

## Assets and trust boundaries

Protected material includes optional scanner credentials, asset inventory, vulnerability evidence, report contents, and ingestion audit history. The demo assumes a trusted local operator and workstation. Scanner/API responses and query parameters are untrusted. Local configuration and the SQLite file are trusted inputs under the operator's filesystem permissions. This application is not intended to serve untrusted clients over a network.

| Threat | Implemented controls | Residual risk |
|---|---|---|
| Credentials leaked through errors or logs | Environment-only keys, SecretStr configuration, sanitized provider errors, no raw validation inputs in responses, structured completion logs, HTTPX INFO logging disabled by CLI | Process environment and debugger access remain privileged; user-written integrations could log secrets |
| SQL injection | Static SQL, bound values, malicious-filter regression test, read-only API connections | A user who can modify the database or code is already within the trusted boundary |
| SSRF or credential forwarding | Explicit live gate, fixed HTTPS origin allowlist, redirects disabled, no caller-supplied API target | DNS/TLS infrastructure and the upstream domains are trusted; no network egress firewall is installed |
| Unbounded retries or huge feeds | Timeout, retry, response-byte, polling, chunk, and record caps | No total run deadline; slow responses and many unique CVEs can still consume time and memory |
| Misleading priority from failed enrichment | Nullable intelligence, per-source provenance, stale-data warnings, incomplete-run status, transparent factors | Missing factors contribute zero; manual review is essential; the model is not validated |
| Inconsistent or duplicate evidence | Stable IDs, timestamp-aware merge, atomic transactions, foreign keys, idempotency and rollback tests | No remediation lifecycle, distributed coordination, or upstream completeness proof |
| Untrusted strings in reports | HTML and Markdown table/code escaping; no raw provider bodies persisted in errors | JSON remains untrusted when embedded in other applications; consumers must escape for their rendering context |
| Exposure of vulnerability inventory | Loopback-only CLI server, no mutation API, ignored local data/reports, restrictive new-file setup | No authentication, encryption at rest, TLS service, or tenant authorization; localhost is not a strong isolation boundary |
| Dependency or CI compromise | Locked dependencies with hashes, commit-pinned actions, read-only CI token, Ruff/Bandit/tests | Static analysis does not prove security; no dependency vulnerability scanner or signed release process is included |

## Deployment boundaries

Do not expose this demo directly to the internet, use it for production asset inventories without additional controls, or interpret an absent/low score as evidence that an asset is safe. Before enterprise adaptation, add authentication and authorization, inventory scoping, ingestion coordination, feed validation policy, remediation state management, operational monitoring, backup/restore testing, dependency maintenance, and an independently evaluated risk model.

Use `umask 077`, a private directory, and a dedicated least-privileged account for live data. SQLite WAL/SHM files and exports can contain the same sensitive data as the database. The code does not encrypt files, manage secrets, rotate keys, or validate that a workstation is secure. Review reports before sharing them.

Tests and sample assets are synthetic. The Tenable adapter retrieves findings from an authorized account; this tool performs no scanning, exploitation, or remediation actions against assets. External feeds are never queried by default or by CI tests.
