# Security policy

## Report privately

Use this repository's [private vulnerability reporting form](https://github.com/Prank1004/cyble-anomali-threatstream/security/advisories/new). If it is unavailable, contact the repository owner through an existing private channel to arrange secure disclosure. Do not place vulnerability details, credentials, tenant identifiers, personal data, or real Cyble alert records in a public issue.

Include the affected commit/version, a description of the impact, and a minimal synthetic reproduction. Avoid proprietary SDK code and vendor-only documentation. This community project does not promise a vendor support SLA or a fixed response time.

## Data and credential handling

- Inject Cyble and ThreatStream credentials from the runtime secret store. Keep secrets out of source, command-line arguments, committed environment files, logs, reports, and screenshots.
- Keep the feed private and review ThreatStream access and downstream sharing separately from the connector's TLP marking.
- Treat Cyble content as untrusted. The connector sanitizes known sensitive keys and patterns, validates supported observable types, and does not fetch remote images from alert content.
- Pattern-based redaction cannot prove arbitrary source text is free of personal data. Review newly enabled service schemas, especially credential and leak services.
- Maintain TLS verification and trusted CA configuration. Keep one active runner per feed to protect checkpoint consistency.

If a credential is exposed, revoke or rotate it through the issuing service and review where it was used. Removing a public Git commit or log does not invalidate a credential.

## Supported code

The exact SDK 2.8.1 environment includes pinned Requests and Pillow versions with published advisories. Remote-image fetching is disabled, and no direct call to the affected Requests extraction utility was found in the connector or inspected SDK. These observations do not clear the dependency findings. Anomali's supported remediation and staging acceptance remain required; see [dependency review](docs/anomali-handoff.md#dependency-review).

Security fixes target the latest maintained repository version. The Anomali Feed SDK has its own license, release lifecycle, and support channel. See [validation](docs/validation.md) for the runtime versions and checks actually exercised by this project.
