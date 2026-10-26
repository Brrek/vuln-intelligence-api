# Security policy

This portfolio demonstration is not a production service. The current `main` branch is maintained on a best-effort basis; no support SLA or fixed remediation timeline is promised.

For a suspected vulnerability, use GitHub's **Report a vulnerability** option in this repository's Security tab if available. If private reporting is unavailable, contact the maintainer through the contact channel listed on their GitHub profile before sharing sensitive reproduction details. Do not put credentials, real asset names, or exploitable private information in a public issue. Ordinary non-sensitive defects may be reported as issues.

Include the affected commit/version, a minimal synthetic reproduction, expected and actual behavior, and potential impact. Do not run tests against systems you do not own or have permission to assess.

The API is read-only but unauthenticated. The CLI binds it to localhost; maintain that boundary. Live integrations require explicit opt-in and process-environment credentials. Databases and reports may contain sensitive inventory if you enable live ingestion. See the [threat model](docs/threat-model.md) for implemented controls and limitations.
