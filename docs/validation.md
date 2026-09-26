# Validation record

## Release scope

Version **0.4.1** is an integration preview, reviewed on **2026-09-26**. Implementation checks and an offline contract run against the supplied Anomali Feed SDK establish the behavior described below. A live ThreatStream tenant, ingestion credentials, and running schedule were not available for end-to-end acceptance. The [Anomali handoff](anomali-handoff.md) records open vendor decisions, including dependency advisories.

The current public result is available in [GitHub Actions](https://github.com/Prank1004/cyble-anomali-threatstream/actions/workflows/ci.yml). Public CI runs on Python 3.10 and 3.11 and skips the licensed SDK contract checks. The private local validation environment uses Python 3.11.15 and the exact vendor-provided `anomali_feedsdk` **2.8.1** wheel.

The local release check passed **96 tests**, including **12 real-SDK contracts**, with no skips. Compilation, CLI help/version, Git whitespace checks, and installed dependency compatibility also passed. Public CI can run the remaining **84 tests** without distributing the proprietary SDK. Dependency advisory findings remain open and are recorded in the handoff.

## What was exercised

| Area | Evidence |
|---|---|
| Cyble HTTP contract | Offline fixtures cover recognized envelopes, service discovery, pagination consistency, retries, authentication errors, and malformed/partial responses |
| Field preservation | Synthetic nested objects, arrays, Unicode, long values, JSON-encoded data, nulls, unknown fields, and report size/depth limits |
| Native mapping | IP/domain/URL/hash extraction, private-address exclusions, source timestamp precedence, severity, TLP, and false-positive behavior |
| Custom paths | Sparse and nested wildcard arrays retain value/type alignment; invalid paths fail explicitly |
| Data handling | Known secret fields, embedded credentials, encoded query parameters, long values, JSON strings, and Markdown fence handling |
| SDK models | Actual Report and Indicator objects, private bulletin serialization, supported types, timestamps, and stable versus changed report hashes |
| SDK startup and logging | Constructor wrapper handling, preserved CLI/logging behavior, remote image fetching disabled, and sanitized failure handling |
| SDK CSV transport | Actual SDK upload uses finite connect/read timeouts; a simulated read timeout rejects the batch even after the report ID was accepted |
| Destination acceptance guard | Mocked report acceptance, cached reports, missing accepted IDs, malformed results, and SDK warnings/errors |
| Continuous polling | Independent service streams, creation/update windows, failure recovery, repeated pages, page limits, checkpoint write errors, and local process locking |
| Source preview | Dry-run remains read-only with respect to ThreatStream and checkpoints |

All fixtures committed to the repository are synthetic. Network access is blocked in the real-SDK contract tests. No proprietary SDK source or wheel, vendor-only API guide, credentials, tenant identifiers, or real alert payloads are distributed.

Reproduce the offline checks after installing the public requirements, optionally with the licensed SDK in your private environment:

```bash
python -m unittest discover -s tests -v
python -m compileall -q source tests
python source/cyble_anomali_feed.py --help
python source/cyble_anomali_feed.py --version
```

## Bounded Cyble API inspection

Read-only Cyble MCP calls inspected the service catalogue and at most one detailed alert per selected service from a bounded 30-day interval ending **2026-09-25 16:06:59 UTC**. Only schema names and result status were used for this record; source values were not saved.

| Probe | Observed result | Limit |
|---|---|---|
| Service catalogue | 52 service entries, each explicitly marked `allowAlerts=true` | Catalogue membership does not establish access to every alert service |
| `iocs` | One alert returned; nested IOC, type, source, timestamps, risk/confidence, and behavior fields inspected | One sample does not cover all IOC schemas or values |
| `new_vulnerability` | One alert returned; CVE and nested data fields inspected | One sample does not establish all vulnerability detail variants |
| `suspicious_domains` | Error envelope returned | No usable detail sample; live mapping coverage remains unconfirmed |

These were MCP-mediated source reads, not a live execution of this connector's HTTP client. They do not establish successful ThreatStream delivery, service-wide completeness, or current access to all 52 services. The response wrapper can support cached results; freshness was not independently established.

## Remaining tenant acceptance

Use the [deployment acceptance steps](deployment.md#tenant-acceptance) before production rollout:

- Verify a nonempty private bulletin and its native Indicators in the target ThreatStream tenant after asynchronous ingestion completes.
- Confirm repeated ingestion, updated source fields, relationships, and SDK cache behavior.
- Exercise the alert services covered by your subscription, especially schemas not sampled above.
- Confirm the destination accepts your largest sanitized reports and applies the intended access controls.
- Verify failure/restart recovery and several scheduled cycles with one active runner per feed.
- Obtain Anomali's approved remediation for the SDK's pinned dependency advisories; dependency compatibility does not establish security clearance.

Arbitrary Cyble fields are retained as sanitized bulletin JSON; they are not all native ThreatStream attributes. Recognized sensitive values are redacted and unstructured source content is omitted. Pattern-based sanitization is not a proof that arbitrary source content contains no personal data.

Cyble offset pagination can change during a poll. Fixed windows, settling, overlap, and replay reduce the risk, but exactly-once delivery and zero-loss snapshots are not established. SDK report acceptance also does not prove final asynchronous IOC processing. See [operations](operations.md) for recovery and these limits.
