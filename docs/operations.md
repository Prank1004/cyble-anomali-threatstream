# Operations and recovery

## Monitor each scheduled run

Track process exit status, processed page/alert counts, elapsed time, and checkpoint age. A successful empty Cyble query is different from a failed query. Authentication, permissions, schema, timeout, and rate-limit failures need investigation even when no alerts were ingested.

The connector logs service names and aggregate counts. It suppresses SDK payload logs and does not emit source bodies, Indicator values, or credentials. Preserve that behavior in runner wrappers and monitoring integrations.

Check both creation and update polling. Creation polling collects new alerts; update polling carries changes to older alert records. Disabling `CYBLE_SYNC_UPDATED_ALERTS` deliberately stops that second path.

## Checkpoints and replay

The feed configuration's `cyble_state_v1` namespace stores a source-scope hash, the content mode, per-service creation/update cursors, and pending fixed windows. A service/date window advances only after all pages have completed, accepted report IDs have been checked, and the checkpoint write succeeds. Completed windows of other services retain their progress if a later window fails.

`CYBLE_WINDOW_MINUTES` caps forward cursor progress at 60 minutes by default. The query also includes the overlap before the cursor, so the default total span is 65 minutes. `CYBLE_SETTLE_SECONDS` holds its end 60 seconds behind the current time to reduce changes at the boundary. A page/time guard halves the forward span down to a minimum of 60 seconds while retaining overlap, allowing the next run to retry a smaller range without moving the incomplete cursor forward.

Cyble uses offset pagination; a fixed end time does not freeze the result set while alerts change. Settling and overlap reduce this risk but cannot guarantee a snapshot or zero omissions during concurrent updates. Reconcile a known historical interval during tenant acceptance. If the overlap alone exceeds the page budget, shrinking the forward window cannot resolve it; increase the page/runtime budget or adjust overlap after reviewing the affected interval.

Overlap intentionally re-reads recent records. Stable Cyble alert identity supports replay through the SDK, but exactly-once delivery is not claimed. Network failures can occur after a request reaches ThreatStream and before confirmation. Native IOC CSV ingestion is asynchronous, and the hosted SDK cache can suppress refreshed attributes; accepted report IDs do not prove final indicator updates. Verify repeated reports, relationships, and refreshed fields in your tenant.

A process lock helps prevent competing workers in the same execution environment. Configure singleton scheduling as well; a local lock alone cannot coordinate independent hosts or containers. Keep a feed owned by one active runner.

Enforce a wall-clock process timeout in the runner. The connector's time budget is checked between pages and cannot preempt SDK retries or an active request. If the runner kills a stalled process, the operating system releases its local lock; the next run replays the saved pending window.

Do not delete or move a cursor forward to clear an error. First resolve the API, mapping, size, or ingestion problem, then rerun. A manual forward jump can omit alerts. Historical replay should use a backed-up configuration and a documented time range, ideally in a separate feed.

## Full source content and mode changes

`CYBLE_CONTENT_MODE=full` keeps all returned source fields and values in the private bulletin body, including exposed passwords, tokens, personal data, internal IPs, and raw text. Native Indicators and summary fields use a sanitized derivative. The connector does not log full bodies, add its own authentication credentials to reports, or download files referenced in an alert.

Changing content mode triggers a replay of the configured initial lookback. Check the first saved state and corresponding updated bulletins before relying on the new representation. Older bulletins outside that interval remain as previously ingested until a planned historical replay reaches them. A switch to redacted mode does not remove full content already present in ThreatStream audit history, exports, or backups.

## Troubleshooting

| Symptom | Check | Recovery |
|---|---|---|
| Missing required configuration | Runtime secret/environment names, feed ID/name, API base URL | Correct the runner configuration and retry |
| Cyble HTTP 401/403 | Token validity, company scope, subscription to the requested service | Resolve access or use the intended explicit service list |
| Cyble HTTP 429 | API quota and overlapping schedules | Allow retry delay; reduce cadence or history size |
| Cyble 5xx or timeout | Cyble availability, DNS, TLS trust, proxy and firewall | Retry; preserve the incomplete checkpoint |
| Unknown alert response shape | Requested service and schema drift | Reproduce with synthetic field structure and add a parser/mapping change |
| Page or runtime guard reached | Backfill size, page size, service count, window span | Reduce the requested window or allocate a suitable runtime/page budget |
| Source-scope mismatch | Cyble tenant/company scope differs from the saved state | Use a separate ThreatStream feed for the new source scope |
| Oversized/deep alert rejected | `CYBLE_MAX_REPORT_BYTES`, response structure, required data detail | Review the record privately; adjust the supported limit or service scope |
| SDK warning/error or missing accepted report ID | ThreatStream permissions, supported models/iTypes, tenant limits | Resolve the ingestion rejection and replay the incomplete window |
| Feed checkpoint update fails | Permission to update feed configuration and endpoint reachability | Restore permission/connectivity; repeat ingestion may be replayed |
| Run already active | Scheduler overlap or a second runner for the same feed | Let the active process finish; enforce one runner |
| Invalid overlap/window settings | `CYBLE_OVERLAP_SECONDS` is not smaller than `CYBLE_WINDOW_MINUTES` | Reduce overlap or increase the window |
| Bulletin exists but no Indicators | Source has no supported IOC values, false-positive status, excluded values, or unfamiliar IOC paths | Inspect the private bulletin fields and add an explicit mapping only for an appropriate native IOC |
| A source-body field shows a redaction/omission marker | Configured content mode, older bulletin outside the replay interval, or marker already present at source | Confirm full mode and replay coverage; summary fields and native IOC extraction remain sanitized |
| Full mode rejects configuration | `CYBLE_WITH_DATA_MESSAGE=false` or an unsupported content-mode value | Use `CYBLE_WITH_DATA_MESSAGE=true` and content mode `full` or `redacted` |
| README logo is unavailable | Vendor-hosted image URL or GitHub's image proxy | Update the original vendor URL in README and `assets/README.md` |

Do not disable TLS verification as a workaround. For a corporate proxy, configure the runtime's trusted CA chain and authorized proxy environment.

## Mapping additions

Field preservation and observable extraction are separate. All fields returned in an alert already appear in full-mode private bulletin JSON; optional redacted mode applies its documented omissions and redactions. Add rules to `CYBLE_FIELD_MAP_PATH` only when a legitimate IOC uses a path the generic extractor does not recognize, or when you want a selected safe summary field.

Document each rule with its service slug, a synthetic input, the expected native Indicator type, and excluded examples. A monitored company domain, victim IP, reference URL, or hosting address is not automatically a malicious IOC. Review contextual fields before converting them into native indicators and review `CYBLE_THREAT_TYPE` for the feed's purpose.

## Safe support evidence

A useful issue includes the connector version/commit, Python and SDK versions, service slug, HTTP status or sanitized error category, configured limits, and a small synthetic response with the same structure. Exclude tokens, tenant IDs, personal data, live alert content, SDK source, and vendor-only documents. Report suspected vulnerabilities privately using [SECURITY.md](../SECURITY.md).
