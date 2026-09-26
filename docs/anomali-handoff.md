# Anomali engineering handoff

**Candidate:** v0.5.0, 2026-09-26. **Purpose:** vendor technical review and staging acceptance. Production acceptance remains open.

## Integration contract

| Area | Implemented behavior |
|---|---|
| Source | Cyble Vision Alerts API v2 over verified HTTPS; token and company scope injected at runtime |
| Execution | Scheduled Python process on a POSIX host; one active runner per ThreatStream feed |
| Destination | Private `tipreport` bulletins plus supported related Indicators through Feed SDK 2.8.1 |
| Full alert context | Every returned alert field and value preserved in the private bulletin JSON body by default, including source credentials, personal data, and raw text; arbitrary fields do not become native ThreatStream attributes |
| Data policy | `CYBLE_CONTENT_MODE=full` by default; optional `redacted` retains the previous policy. Summary and native IOC mapping remain sanitized. Runtime authentication secrets are never added to reports or logs |
| Files and links | Returned attachment metadata and URLs preserved; no binary attachment, image, or linked-content downloads |
| Incremental state | Independent creation/update cursors and fixed pending windows in feed configuration; progress saved only after report acceptance; content-mode changes trigger a bounded lookback replay |
| Delivery limits | Replay may repeat updates; native IOC processing is asynchronous; offset pagination is not a frozen source snapshot |

The licensed SDK and tenant credentials must be provisioned separately. Public fixtures are synthetic. Deployment instructions, field destinations, and recovery behavior are in [deployment](deployment.md), [mapping](api-mapping.md), and [operations](operations.md).

## Changes in this candidate

- Preserve original keys, types, strings, nulls, arrays, and objects from every returned alert in the private body in full mode. JSON-encoded source strings remain strings.
- Retain exposed passwords, tokens, personal data, internal IPs, and raw source text as alert context. They are not automatically classified as malicious native Indicators.
- Require detailed source responses (`CYBLE_WITH_DATA_MESSAGE=true`) in full mode, and reject oversized or over-deep records instead of truncating them.
- Replay the configured initial lookback after a content-mode change, using stable alert identity to update recent bulletins. Older history requires a planned replay.
- Keep authentication secrets and source content out of public fixtures, logs, and GitHub material. Only synthetic examples belong in this repository.

### Retained v0.4.1 QA protections

- Validate pagination metadata inside supported service buckets so a short page cannot silently finish a declared incomplete result.
- Reject ambiguous response envelopes whose wrapper IDs could conceal nested alerts.
- Redact quoted credential assignments embedded in descriptive text and preserve valid hashes containing card-like digit sequences.
- Add a finite timeout to the exact SDK's CSV upload through a scoped compatibility adapter; keep SDK failures from advancing the checkpoint.
- Clarify that the connector's time budget is cooperative and requires a runner-enforced wall-clock timeout.

See the [validation record](validation.md) and the release's GitHub Actions checks for test evidence. Local compatibility tests use the exact licensed SDK; public CI omits that proprietary dependency.

## Dependency review

The installed-environment `pip-audit` snapshot from 2026-09-25 examined **22 packages**. The proprietary SDK could not be matched to a public advisory catalogue. After deduplicating advisory IDs, the snapshot reported **14 advisories across two dependencies** pinned exactly by SDK 2.8.1. This is an open dependency review, not a clean security scan.

| SDK pin | Audit result | Connector exposure review | Requested action |
|---|---|---|---|
| `requests==2.32.5` | One advisory, CVE-2026-25645; patched in 2.33.0 | No direct use of `extract_zipped_paths()` found in connector or inspected SDK. The maintainer says standard Requests usage is unaffected. | Anomali to confirm the supported patched dependency set and deployment exposure |
| `pillow==12.2.0` | 13 distinct advisory IDs; audit lists 12.3.0 as the fix | Connector disables SDK body-image retrieval; no image attachments are ingested by this connector. This reduces the identified input path, without proving all SDK/runtime paths unreachable. | Anomali to provide or approve a compatible SDK dependency update |

Primary references: [Requests advisory](https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2) and [Pillow maintainer advisories](https://github.com/python-pillow/Pillow/security/advisories), including the [image memory-mapping advisory](https://github.com/python-pillow/Pillow/security/advisories/GHSA-62p4-gmf7-7g93).

Do not force-install newer versions over the SDK's exact pins and call that a validated remediation. Re-run compatibility, dependency, and tenant acceptance checks against the vendor-supported package set. The current candidate preserves the supplied SDK contract so Anomali can reproduce the review.

## Decisions requested from Anomali

1. **SDK and dependency support:** Confirm SDK 2.8.1 support for the target runner, provide a patched dependency set, and review the adapter that bypasses constructor CLI/logging side effects and bounds the CSV upload timeout.
2. **Destination contract:** Confirm `tipreport` support, native iTypes and TLP values, maximum bulletin body size, report identity/update behavior, asynchronous IOC processing, and hosted cache effects on refreshed Indicator attributes. Verify that the stored private bulletin JSON preserves the full source values and types, and that tenant access, indexing, export, audit, and retention controls suit this content.
3. **Runner and acceptance:** Confirm feed-configuration update permissions, durable state semantics, singleton scheduling, external process termination, private temporary CSV storage/cleanup on failed uploads, and staging acceptance evidence for initial ingest, repeat ingest, source updates, and interrupted-run recovery.

Cyble should separately confirm subscriptions and response shapes for the required services. `all` covers alert-capable services accessible through Alerts API v2; separate product APIs and fields absent from responses are outside this connector's collection scope. Live detail samples were inspected for `iocs` and `new_vulnerability`; the bounded `suspicious_domains` probe returned an error. Catalogue discovery is not evidence that every service is entitled or fully mapped to native observables.

## Staging acceptance record

Complete this privately with the vendors; never post tenant values or real alert content in a public issue.

| Check | Current status |
|---|---|
| Exact-SDK offline construction, serialization, and transport contracts | Covered by local contract tests |
| Public Python 3.10/3.11 regression checks | See GitHub Actions for the candidate commit |
| Known nonempty alert delivered to the target private feed | Pending |
| Bulletin body, classification, TLP, relationships, and native IOC completion verified | Pending |
| Full source values/types, sensitive-field retention, and private reader/export controls verified | Pending |
| Content-mode change updates recent bulletins through bounded replay | Pending |
| Replay, updated alert, false-positive handling, and SDK cache behavior verified | Pending |
| Interrupted window resumes and repeated scheduled cycles succeed | Pending |
| Vendor-approved dependency remediation accepted | Pending |

No Anomali certification, vendor endorsement, or production deployment is claimed by this repository.
