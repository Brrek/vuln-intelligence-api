# Verification record

Executed on October 26, 2026 against the implemented application and packaged synthetic fixtures. These are measured results, not performance claims.

| Check | Observed result |
|---|---|
| Pytest on CPython 3.12.15 | 86 passed |
| Pytest on CPython 3.13.16 | 86 passed |
| pytest-cov, branch measurement enabled | 100.00% combined coverage; 686 statements and 138 branches, none missed |
| Coverage gate | 85% enforced in pytest configuration |
| Ruff lint and formatting | Passed |
| Bandit scan of `src` | Passed, no findings, no per-line suppressions |
| Wheel build | Passed; both offline JSON fixtures included |
| Default ingestion | 8 accepted observations, 1 duplicate, 7 persisted findings, 4 assets, 5 vulnerabilities |
| Repeated ingestion | Finding IDs/count/content unchanged for the same date; additional audit run recorded |
| Synthetic intelligence | 3 finding-level KEV matches, 2 findings with intentionally unavailable intelligence |
| Reproducible reports | JSON and Markdown byte-identical across repeated generation; committed JSON also compared to actual output by a test |
| Real HTTP smoke test on 127.0.0.1:8765 | Health, finding list/detail, filters, vulnerabilities, priorities, ingestion status, stats, OpenAPI all returned 200 |
| Real HTTP invalid input / write request | 422 / 405 as expected |

All tests block outbound socket connections. Live Tenable, CISA, and FIRST adapters were exercised using HTTPX MockTransport; **no live provider compatibility claim is made**. Dependency installation and GitHub publication require network access, while the synthetic application does not.

The installed Starlette test client emits one deprecation warning about its HTTPX compatibility layer. The tests pass; the warning is not suppressed. This project deliberately continues to use the requested HTTPX stack. Coverage is a measure of exercised code, not proof that all possible behaviors or security issues have been tested.

The example report was generated from a fresh SQLite database after one ingestion using assessment date **2026-01-15**. Audit records use real execution timestamps; reports omit those timestamps and random run IDs to retain reproducibility.
