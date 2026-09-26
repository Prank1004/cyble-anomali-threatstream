# Security policy

## Report privately

Use this repository's [private vulnerability reporting form](https://github.com/Prank1004/cyble-anomali-threatstream/security/advisories/new). If it is unavailable, contact the repository owner through an existing private channel to arrange secure disclosure. Do not place vulnerability details, credentials, tenant identifiers, personal data, or real Cyble alert records in a public issue.

Include the affected commit/version, a description of the impact, and a minimal synthetic reproduction. Avoid proprietary SDK code and vendor-only documentation. This community project does not promise a vendor support SLA or a fixed response time.

## Data and credential handling

- Inject Cyble and ThreatStream authentication credentials from the runtime secret store. Never add these connector authentication secrets to source, command-line arguments, committed environment files, logs, report bodies, or screenshots.
- Keep the feed private and review ThreatStream access and downstream sharing separately from the connector's TLP marking.
- `CYBLE_CONTENT_MODE=full` intentionally retains all source alert values in the private bulletin body, including exposed passwords, tokens, personal data, and raw text. These are source exposure records, distinct from credentials used to authenticate the connector. Keep real alert content out of logs, public issues, fixtures, and screenshots.
- Treat Cyble content as untrusted data. Native Indicator and summary mapping use a sanitized derivative in both modes. The connector does not execute source text or download remote images, binary attachments, or linked content.
- Optional `CYBLE_CONTENT_MODE=redacted` applies known field/pattern redaction and raw-text omission. Pattern-based redaction cannot prove arbitrary source text is free of personal data.
- A content-mode change replays only the configured lookback. Switching to redacted mode does not erase earlier full-content bulletins, audit history, exports, or backups; use tenant retention controls for those records.
- Maintain TLS verification and trusted CA configuration. Keep one active runner per feed to protect checkpoint consistency.

If a connector authentication credential is exposed, revoke or rotate it through the issuing service and review where it was used. Removing a public Git commit or log does not invalidate a credential. Handle credentials found in source breach records through the affected organization's incident-response process.

## Supported code

The exact SDK 2.8.1 environment includes pinned Requests and Pillow versions with published advisories. Remote-image fetching is disabled, and no direct call to the affected Requests extraction utility was found in the connector or inspected SDK. These observations do not clear the dependency findings. Anomali's supported remediation and staging acceptance remain required; see [dependency review](docs/anomali-handoff.md#dependency-review).

Security fixes target the latest maintained repository version. The Anomali Feed SDK has its own license, release lifecycle, and support channel. See [validation](docs/validation.md) for the runtime versions and checks actually exercised by this project.
