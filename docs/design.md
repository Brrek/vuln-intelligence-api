# Technical design decisions

## Data boundaries and identifiers

`Scanner.records()` yields normalized dictionaries; Pydantic is the ingestion trust boundary. The synthetic scanner slices a packaged fixture into pages. The optional Tenable adapter creates an export, polls for completion, and retrieves sorted unique chunk IDs. Normalization expands a plugin's CVE list into one observation per CVE, converts timestamps to UTC dates, normalizes transport protocol, and applies explicitly provided asset context. Non-CVE plugins retain a `tenable-plugin-<id>` identity. Missing CVSS is `null`, with severity `unknown`.

A finding UUID5 is derived from `(scanner source, asset ID, vulnerability ID, port, protocol)`. It is a stable lookup identifier, not an access-control token. Duplicate plugin evidence for the same CVE/asset/endpoint collapses into one finding. Different ports remain distinct. Earliest first-seen is retained; newer observations supersede older ones. Equal-day conflicts keep higher CVSS; exact ties accept the incoming metadata, enabling asset context updates. UTC date precision intentionally loses sub-day ordering.

## Persistence and publication

SQLite schema version 1 contains `assets`, `vulnerabilities`, `findings`, `enrichment`, and `ingestion_runs`, with foreign keys and filter/sort indexes. `init` creates version 1 from an empty database; setup is idempotent and refuses future schema versions. There is no invented legacy migration chain. Future schema changes must add explicit, tested migrations.

A run first commits a `running` audit record. It stages up to 100,000 normalized observations in memory. Invalid rows are counted and omitted. A scanner transport or export failure prevents partial scanner publication. The write phase uses `BEGIN IMMEDIATE`; inventory, finding snapshots, enrichment, priorities, and final run status commit together. Errors roll back this phase and persist a failed run separately. A process killed mid-run may leave a `running` audit record; inspect it and retry rather than assuming completion.

Updates refresh shared asset/vulnerability metadata across stored findings, enrich retained findings, and recompute priorities for the requested date. A backdated run cannot regress a stored assessment. Finding data is idempotent; ingestion audit records deliberately are not. Absence in a later snapshot never implies successful remediation. Asset IDs are expected to be stable within the deployment; use separate databases when combining unrelated inventories.

SQLite WAL permits concurrent readers; API connections use URI `mode=ro`, `query_only`, and explicit read transactions. Multi-query API pages therefore use a consistent snapshot. The single writer may hold its transaction during enrichment. This deliberately simple design is suitable for a bounded demonstration, not high-throughput concurrent ingestion. Schedule only one ingestion at a time. Pagination is offset-based; separate page requests can observe different ingestion snapshots.

## Enrichment semantics and freshness

KEV is `true`, `false`, or unknown (`null`). A failed catalog retrieval cannot produce `false`. EPSS is a validated probability in [0,1]; missing data is `null`, never an invented zero. KEV catalog date and EPSS score date are retained independently, together with source and retrieval/assessment date. Live feed dates older than seven days produce warnings; future-dated live data is rejected. This tool does not establish that seven days is an appropriate enterprise freshness policy.

Live KEV is fetched once and EPSS once per unique CVE per ingestion instance. One-CVE requests remain within FIRST's query-size and pagination limits. Failure results are cached only for that instance; the next run retries. Scanner and intelligence choices are explicit. Synthetic data is the offline fallback mode, not a silent replacement for failed live evidence. The Tenable CLI path requires live intelligence to prevent accidental scoring of real assets with synthetic probabilities.

## Scoring contract

For configured nonnegative weights totaling 100:

| Factor | Normalization | Default weight |
|---|---|---:|
| CVSS | score / 10; missing contributes 0 | 30 |
| KEV | true = 1; false/unknown = 0 | 25 |
| EPSS | probability; missing contributes 0 | 15 |
| Asset criticality | ordinal value 1–5 / 5 | 15 |
| Environment | production 1, staging 0.5, development 0.2, unknown 0.5 | 10 |
| Age | min(days since first seen / 90, 1) | 5 |

Contributions round to four decimal places; their sum rounds to two and is capped at 100. Each result stores model version, date, actual weights, contributions, and explanations. Unknown inputs are disclosed because zero contribution can under-prioritize them. CVSS and EPSS can be correlated, asset criticality is subjective, and the weighting is uncalibrated. This is neither a breach probability nor expected financial loss. Asset exposure sums scores for a simple ordering, with no probabilistic interpretation.

## Network behavior

HTTPX verifies TLS. Only fixed HTTPS origins `cloud.tenable.com`, `www.cisa.gov`, and `api.first.org` are allowed; redirects and ambient proxy credentials are disabled by the CLI. Requests have a 5-second connect and 15-second operation timeout, a 16 MB decoded-response cap, and three attempts by default (configurable in code, at most five). GET retries cover network failures, 429, 500, 502, 503, and 504. Backoff is exponential and capped at 30 seconds; numeric and HTTP-date Retry-After are supported and clamped. The demo does not implement fleet-scale jitter or a global rate limiter.

Export creation is a POST. Only an explicit 429 is retried; network ambiguity and server errors are not automatically replayed to avoid duplicate export jobs. Polling is bounded to 30 attempts by default and chunks to 1,000; these can reject a legitimate large export. Response byte caps and socket timeouts are not a total wall-clock deadline. Tenable jobs are not automatically canceled on a local timeout.

## References used for adapters

- [Tenable export request](https://developer.tenable.com/reference/exports-vulns-request-export)
- [Tenable export status](https://developer.tenable.com/reference/exports-vulns-export-status)
- [Tenable chunk download](https://developer.tenable.com/reference/exports-vulns-download-chunk)
- [FIRST EPSS API](https://api.first.org/epss/)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

These references inform the adapter contracts; mocked tests do not establish live compatibility with a particular account, permissions, or future upstream changes.
