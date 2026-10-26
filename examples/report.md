# Vulnerability intelligence report

As of: 2026-01-15

Demonstration prioritization only; not a validated enterprise risk standard.

## Most urgent findings

| Vulnerability | Asset | Severity | Score | KEV | EPSS |
|---|---|---|---:|---|---:|
| CVE-2021-44228 | payments-prod | critical | 99.55 | True | 0.97 |
| CVE-2023-34362 | portal-prod | critical | 94.67 | True | 0.94 |
| CVE-2021-44228 | build-staging | critical | 84.33 | True | 0.97 |
| CVE-2022-0778 | payments-prod | high | 51.8 | False | 0.12 |
| CVE-2022-0778 | lab-dev | high | 29.58 | False | 0.12 |
| demo-plugin-100 | build-staging | medium | 28.62 | None | None |
| demo-plugin-200 | lab-dev | unknown | 5.17 | None | None |

## Asset exposure

Sum of demonstration scores; not loss expectancy.

- payments-prod: 2 findings; total 151.35; highest 99.55.
- build-staging: 2 findings; total 112.95; highest 84.33.
- portal-prod: 1 findings; total 94.67; highest 94.67.
- lab-dev: 2 findings; total 34.75; highest 29.58.

## KEV matches

- 419a7ecf-615a-5a93-8a33-2160448a6cf8
- 6599aec0-ae0c-59cd-94bf-6519510089aa
- 5457f4da-f2f0-53c4-a308-ab302c72398e

## Remediation recommendations

- 419a7ecf-615a-5a93-8a33-2160448a6cf8: Upgrade the affected Log4j dependency to a vendor-supported fixed version; verify the deployed artifact.
- 6599aec0-ae0c-59cd-94bf-6519510089aa: Apply vendor security updates, review indicators of compromise, and verify the affected service.
- 5457f4da-f2f0-53c4-a308-ab302c72398e: Upgrade the affected Log4j dependency to a vendor-supported fixed version; verify the deployed artifact.
- 8cae77b0-3272-5349-92da-9d8e4c7b68cb: Update the affected TLS library and rebuild dependent services.
- 27867efd-e7aa-55d1-ba3a-797d61ce07ca: Update the affected TLS library and rebuild dependent services.
- 50ed5fef-4c14-5268-aef5-51a72701139d: Configure the missing response header and verify application behavior.
- 0d3084be-f36e-57fd-9ba9-587fd55fd93e: Manually verify the finding and obtain a severity assessment.

## Freshness and provenance

- 419a7ecf-615a-5a93-8a33-2160448a6cf8: last seen 2026-01-15; observation age 0 days; KEV synthetic (2026-01-15); EPSS synthetic (2026-01-15).
- 6599aec0-ae0c-59cd-94bf-6519510089aa: last seen 2026-01-15; observation age 0 days; KEV synthetic (2026-01-15); EPSS synthetic (2026-01-15).
- 5457f4da-f2f0-53c4-a308-ab302c72398e: last seen 2026-01-15; observation age 0 days; KEV synthetic (2026-01-15); EPSS synthetic (2026-01-15).
- 8cae77b0-3272-5349-92da-9d8e4c7b68cb: last seen 2026-01-15; observation age 0 days; KEV synthetic (2026-01-15); EPSS synthetic (2026-01-15).
- 27867efd-e7aa-55d1-ba3a-797d61ce07ca: last seen 2026-01-15; observation age 0 days; KEV synthetic (2026-01-15); EPSS synthetic (2026-01-15).
- 50ed5fef-4c14-5268-aef5-51a72701139d: last seen 2026-01-15; observation age 0 days; KEV synthetic (None); EPSS synthetic (None).
  - No synthetic intelligence for this vulnerability.
- 0d3084be-f36e-57fd-9ba9-587fd55fd93e: last seen 2026-01-15; observation age 0 days; KEV synthetic (None); EPSS synthetic (None).
  - No synthetic intelligence for this vulnerability.

## Ingestion errors and incomplete enrichment

Runs: 1; failed: 0; rejected records: 0.

Incomplete findings: 2.
