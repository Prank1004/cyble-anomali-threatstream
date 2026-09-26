# Changelog

## 0.5.0 — 2026-09-26

- Default to `CYBLE_CONTENT_MODE=full`, preserving every returned source field and value in the private bulletin body, including exposed credentials, personal data, raw text, and original JSON-encoded strings.
- Keep native Indicator and summary mapping on a sanitized derivative; retained contextual values are not automatically classified as malicious Indicators.
- Retain the prior sanitization policy through optional `CYBLE_CONTENT_MODE=redacted`.
- Require `CYBLE_WITH_DATA_MESSAGE=true` in full mode; fail oversized or over-deep records without truncation.
- Replay the configured initial lookback after content-mode changes so recent bulletins can be updated using stable source identities. Older history still requires a planned replay.
- Document source-content retention, private access expectations, attachment boundaries, and vendor acceptance checks. Runtime authentication secrets and real source payloads remain excluded from public material and logs.

## 0.4.1 — 2026-09-26

- Final QA: enforce nested service-bucket pagination metadata and reject ambiguous ID-bearing response wrappers.
- Redact quoted credential assignments embedded in text while preserving valid hash values containing card-like digit sequences.
- Bound the SDK CSV upload's connect/read wait through a scoped adapter and add actual SDK transport regression checks.
- Document cooperative run limits, the required external process timeout, and POSIX runtime support.
- Add the Anomali engineering handoff, including open vendor dependency advisories and staging acceptance decisions.

## 0.4.0 — 2026-09-25

### Ingestion reliability

- Discover all explicitly alert-enabled service slugs with `CYBLE_SERVICES=all`.
- Preserve status changes, including false positives, in reports. Suppress new native indicators for false-positive records.
- Keep independent service/date checkpoints and fixed pending windows. Save completed windows while failed services remain retryable.
- Split unfinished high-volume windows and protect each local feed run with a process lock.
- Reject malformed, ambiguous, partial, repeated, and inconsistent API pages.
- Check SDK warnings, errors, return shape, and accepted report IDs before advancing a checkpoint.

### Mapping and data handling

- Preserve structured nested Cyble fields and arrays; reject oversized records without truncating them.
- Apply sanitization before every report, context, and IOC mapping path; protect encoded credential parameters in URLs.
- Map IOC arrays, preserve URL path case, prefer observed IOC timestamps, fall back from null user severity, and apply TLP to native indicators.
- Preserve value/type pairing in sparse and nested wildcard arrays; validate configured paths before polling.
- Disable SDK remote-image downloads and isolate its constructor logging/CLI side effects.

### Repository and validation

- Add offline regression tests and optional contract tests against the exact proprietary SDK 2.8.1.
- Add GitHub Actions CI, issue forms, operator documentation, validation evidence, and official vendor logo links.
- Add `--version` and a bounded, read-only `--dry-run` mapping check.

See [validation](docs/validation.md) for measured coverage and remaining deployment checks, and [deployment](docs/deployment.md) for the checkpoint migration from 0.3.0.

## 0.3.0 — 2026-09-25

- Preserve sanitized structured alert payloads in private ThreatStream report bodies.
- Add report-size protection and expand mapping documentation.

## 0.2.0 — 2026-09-25

- Initial public connector using Cyble Alerts API v2 and Anomali Feed SDK 2.8.1.
