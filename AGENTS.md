# Repository instructions

- Preserve existing work and history. Keep this an offline-first Python 3.12+ portfolio demonstration.
- Application code is under `src/vuln_intelligence`; tests use synthetic data and HTTPX MockTransport.
- Never enable real network access in tests or commit credentials, real asset data, databases, or live reports.
- Default CLI operation must remain offline; API analysis endpoints must remain read-only.
- Preserve explicit unknown enrichment values and source/freshness metadata. Do not silently replace live intelligence with synthetic values.
- Keep stable finding identities and transactional/idempotent ingestion behavior. Test any changes to these contracts.
- Run `uv run ruff check src tests`, `uv run ruff format --check src tests`, `uv run bandit -r src -q`, and `uv run pytest` before delivering a change.
- Keep the 85% coverage gate. Regenerate example reports through the application from a fresh database when fixtures, scoring, or report schemas change; do not hand-edit generated examples.
- Document limitations honestly. Do not claim production readiness, validated enterprise risk scoring, live provider verification, or unmeasured performance.
