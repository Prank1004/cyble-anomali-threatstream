# Deployment

This connector runs as a scheduled Anomali Feed SDK process. Each invocation polls a bounded Cyble time window and writes private ThreatStream bulletins with associated Indicators. Full source content is retained in the private bulletin body by default, including exposed credentials and personal data returned by Cyble. Your feed runner owns its schedule, authentication secrets, and process lifecycle.

## Prerequisites

| Requirement | What to provision |
|---|---|
| Runtime | POSIX host (Linux or macOS), Python 3.10 or 3.11, and the vendor-provided `anomali_feedsdk` 2.8.1 wheel |
| Cyble | Alerts API v2 access, API token, company UUID, and the required alert service subscriptions |
| ThreatStream | A provisioned private feed, API endpoint, feed ID/name, and API account with report/observable ingestion and feed-configuration update permissions |
| Network | Verified outbound HTTPS to `bifrost.cyble.ai` and your ThreatStream API endpoint |
| Scheduling | One active feed process at a time, with a working directory, absolute executable path, and an external process timeout |

The proprietary SDK wheel and Cyble API guide are not part of this repository. Obtain them through the vendors. Keep tenant data and SDK internals outside your checkout.

Before production, resolve the SDK dependency advisory review with Anomali; see the [handoff](anomali-handoff.md#dependency-review). The supplied wheel pins Requests and Pillow versions with published advisories. Installing newer versions over those exact pins creates an unsupported dependency combination and does not complete vendor acceptance.

## Install

Install a reviewed release or commit in a dedicated environment:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install /secure/path/anomali_feedsdk-2.8.1-py3-none-any.whl
.venv/bin/python -m pip install -r requirements.txt
```

The wheel filename is an example; use your authorized vendor distribution. Do not upload the wheel into GitHub Actions or commit it to the repository. The Python version used by your runner must match the installed environment.

## Configure

Inject credentials from the feed runtime's secret store. The entry point reads environment variables, not `.env` files automatically. [`.env.example`](../.env.example) is a configuration reference and contains no credentials.

### Required settings

| Setting | Meaning |
|---|---|
| `CYBLE_API_TOKEN` | Cyble Bearer token, supplied only through the environment/secret store |
| `CYBLE_COMPANY_UUID` | Company scope used in alert query bodies |
| `CYBLE_SERVICES` | `all` to discover alert-capable services, or explicit comma-separated service slugs |
| `TS_USERNAME` / `TS_API_KEY` | ThreatStream API credentials |
| `TS_API_URL` | API base URL for your ThreatStream deployment |
| `TS_FEED_ID` / `TS_FEED_NAME` | Existing feed identity in ThreatStream |

`CYBLE_SERVICES=all` selects catalogue entries where `allowAlerts` is exactly `true`; it is the setting in `.env.example`. It covers alert-capable services exposed by Alerts API v2 within your accessible scope. It does not add separate Cyble product APIs. Catalogue presence is not proof of entitlement. A service that rejects your token must be investigated; it is not treated as an empty feed. Choose an explicit list when your subscription or rollout scope covers a subset.

### Ingestion settings

| Setting | Default | Purpose |
|---|---|---|
| `CYBLE_CONTENT_MODE` | `full` | Preserve complete source alert values in the private body; `redacted` retains the prior sanitization policy |
| `CYBLE_INITIAL_LOOKBACK_HOURS` | `24` | Initial history for a new service and bounded replay after changing content mode |
| `CYBLE_PAGE_SIZE` | `200` | Page size; maximum 200 with detailed payloads, 2,000 for metadata-only queries in redacted mode |
| `CYBLE_MAX_PAGES_PER_SERVICE` | `100` | Page guard for each service/date window |
| `CYBLE_WINDOW_MINUTES` | `60` | Maximum forward cursor step, from 1 to 1,440 minutes; queried span also includes overlap |
| `CYBLE_OVERLAP_SECONDS` | `300` | Replays boundary records; must be smaller than the configured window |
| `CYBLE_SETTLE_SECONDS` | `60` | Keeps polling end behind current time for stability; 0 to 3,600 seconds |
| `CYBLE_SYNC_UPDATED_ALERTS` | `true` | Polls `updated_at` to ingest changes to existing alerts |
| `CYBLE_WITH_DATA_MESSAGE` | `true` | Requests service details; must remain `true` in full mode |
| `CYBLE_THREAT_TYPE` | `malware` | ThreatStream Indicator classification; review its meaning for your services |
| `CYBLE_TLP` | `amber` | Report and Indicator marking: `amber`, `green`, `red`, or `white` |
| `CYBLE_FIELD_MAP_PATH` | Bundled example | Custom mapping file with defaults and per-service overrides |
| `CYBLE_MAX_RUN_MINUTES` | `20` | Cooperative run budget, checked between pages; does not interrupt an active SDK call |
| `CYBLE_MAX_REPORT_BYTES` | `4194304` | Maximum serialized alert JSON size; excess fails the window without truncating |
| `CYBLE_LOCK_DIR` | Private user temp directory | Optional private directory for the POSIX process lock |
| `TS_BATCH_SIZE` | `1000` | Feed SDK batch size |
| `LOG_LEVEL` | `INFO` | Connector logging level; SDK payload logging remains suppressed |

Set a lookback appropriate to your alert volume. Large backfills require multiple scheduled runs and enough API quota. Full mode rejects `CYBLE_WITH_DATA_MESSAGE=false`; metadata-only requests cannot preserve complete service detail. Optional redacted mode permits reduced-detail queries, with that collection limit made explicit.

Source exposure credentials are data intentionally retained in the private bulletin body in full mode. Connector authentication credentials belong only in the runtime secret store. Keep both source data and authentication secrets out of logs, public GitHub material, support screenshots, and test fixtures. Full mode does not download binary attachments or linked files; it retains their metadata and URLs when returned in the alert.

Preview the configuration's source access and mapping with `--dry-run`. It fetches at most one alert per selected service and constructs SDK models locally, without calling ThreatStream ingestion or writing checkpoints. It still needs Cyble access and the installed SDK. An empty preview does not establish the mapping for that service.

## Schedule continuous ingestion

Use the Anomali feed runner's supported deployment and scheduling process for your tenant. The scheduled command is:

```bash
/absolute/path/to/connector/.venv/bin/python /absolute/path/to/connector/source/cyble_anomali_feed.py
```

Choose a cadence that fits your API quota and normal processing time; five minutes is an example, not an API guarantee. Arrange exactly one active runner for each feed across all hosts. The POSIX lock coordinates processes on one host only. Treat nonzero exit status as an operational failure and surface it in your runner's monitoring.

Configure the runner to terminate a process that exceeds its wall-clock limit, including a bounded grace period before forced termination. `CYBLE_MAX_RUN_MINUTES` is a cooperative budget: SDK retries, sleeps, and in-flight requests may run beyond it. The adapter supplies a 5-second connect timeout and 120-second read timeout to the SDK's CSV upload, but HTTP timeouts are not total process deadlines. An interrupted window is replayed from its saved state on the next run. Confirm this lifecycle in Anomali's supported runner.

Do not copy a credential-bearing command into scheduler arguments. Inject credentials as secrets. Feed visibility is private; access and downstream distribution still follow your ThreatStream tenant policies.

Give the runner a private temporary directory (`TMPDIR`, owned by its service account with mode `0700`) and a cleanup policy after terminated runs. The SDK writes temporary IOC CSV files and may leave them behind after an upload exception. Keep this directory outside the repository, preserve files needed by active runs, and confirm the hosted runner's equivalent with Anomali.

## Tenant acceptance

Perform the following in a private staging feed before broad service rollout:

1. Use `--list-services` with the Cyble credentials to inspect the catalogue.
2. Start with a service and time window known to contain an alert. A zero-record run alone does not validate ingestion.
3. Run `--dry-run`, then an ingestion cycle. Verify the corresponding private bulletin in ThreatStream: identity, timestamps, original field values and types in full mode (or expected redactions in redacted mode), and native Indicators after asynchronous ingestion completes. Check access controls using the intended reader accounts.
4. Repeat the cycle and inspect replay behavior, checkpoint progress, and whether the hosted SDK cache permits refreshed attributes.
5. Change an alert status through your normal Cyble workflow and confirm an updated bulletin arrives. For false positives, check that no new Indicators are created; existing indicator disposition remains an analyst/tenant decision.
6. Confirm a failed or interrupted run retries its incomplete service window without advancing that window's cursor.
7. Enable the schedule and observe several successful runs, then expand to the required service set.

The repository's offline checks and SDK contract checks do not replace these tenant checks. Current evidence is recorded in [validation](validation.md).

## Upgrade and rollback

Pause scheduling and wait for the active process to finish. Record the deployed commit, preserve the feed configuration through your approved administrative process, and install the new code/dependencies in a separate runtime directory. Keep credentials and saved checkpoints outside source control.

Version 0.5.0 defaults to `CYBLE_CONTENT_MODE=full`. Set `CYBLE_CONTENT_MODE=redacted` explicitly to keep the previous output policy. The state records the selected content mode; changing modes schedules a bounded replay of `CYBLE_INITIAL_LOOKBACK_HOURS` (24 hours by default). Recent alerts are ingested again using their existing stable identities so the private bulletin body can be updated. This does not restore the full source content for every older bulletin automatically. Plan a separate historical replay for records outside the selected lookback, and verify actual update behavior in the tenant.

Progress remains under `cyble_state_v1`, with a hash of the source scope, per-service creation/update cursors, and pending fixed windows. Existing pre-v0.5 state represents the redacted policy. A newly enabled service starts from its own configured lookback. The v0.3 global watermarks are not reused; upgrading from that format also starts from the configured lookback. Use a separate ThreatStream feed for another Cyble tenant; a source-scope mismatch is rejected.

Switching back to redacted mode changes subsequent and replayed bulletin bodies. It does not erase historical content from platform audit records, exports, backups, or reports outside the replay interval; manage those through ThreatStream's retention controls.

Deploy the new runtime path, resume scheduling, and check the first cycle plus cursor progress. Consult [operations](operations.md) before changing cursor values or replaying history. Restoring an older binary is not sufficient when its checkpoint format differs; restore a compatible feed configuration or use a separately provisioned staging feed. Replaying previously ingested windows can repeat report updates, so verify tenant deduplication behavior.
