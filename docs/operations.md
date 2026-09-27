# Operations and recovery

## Monitor ingestion

For `--daemon`, watch the `CYBLE_STATUS_FILE` heartbeat rather than exit status: stale `updated_at`, a stalled `last_success_at`, or nonzero `last_cycle.failed_streams`/`backed_off_streams` need attention. For scheduled runs, track exit status. In both modes, each cycle logs one `Cycle finished` line with window, alert, quarantine, failure, backoff, and backlog counts. A successful empty Cyble query is different from a failed query. Authentication, permissions, schema, timeout, and rate-limit failures need investigation even when no alerts were ingested.

The connector logs service names and aggregate counts. It suppresses SDK payload logs and does not emit source bodies, Indicator values, or credentials. Preserve that behavior in runner wrappers and monitoring integrations.

Check all three streams. Creation polling collects new alerts; update polling carries changes to older alert records; the delayed `created_at_reconcile` re-read collects alerts that became searchable after their creation window was read. Disabling `CYBLE_SYNC_UPDATED_ALERTS` or setting `CYBLE_RECONCILE_LAG_HOURS=0` deliberately stops those paths.

## Checkpoints and replay

The feed configuration's `cyble_state_v1` namespace stores a source-scope hash, the content mode, per-service creation/update/reconcile cursors, and pending fixed windows. A window advances only after all its pages have been ingested and accepted report IDs have been checked. Completed windows are saved once per round; a crash before that save replays them (repeat updates), never skips them. Other services keep their progress when one window fails.

`CYBLE_WINDOW_MINUTES` caps forward cursor progress at 60 minutes by default. The query also includes the overlap before the cursor, so the default total span is 62 minutes. `CYBLE_SETTLE_SECONDS` holds its end 15 seconds behind the current time. A page limit, or a window still running at `CYBLE_MAX_RUN_MINUTES`, halves the forward span down to a minimum of 60 seconds while retaining overlap. The next attempt retries a smaller range without moving the incomplete cursor forward; only a window that cannot shrink further counts as a failure.

Cyble uses offset pagination, and a fixed end time does not freeze the result set while alerts change. Each page therefore re-reads the last 10 rows of the previous one (a quarter of the page for small pages) and discards repeats. That absorbs up to 9 rows leaving the window between two requests. If none of the re-read rows come back, more rows moved than the overlap covers: the window is deferred and replayed instead of completed with a gap. Paging stops only when the source returns no new rows, so a server-side cap below `CYBLE_PAGE_SIZE` or misleading pagination metadata cannot end a window early. Each window that returned data costs one extra request to confirm the end. If the overlap alone exceeds the page budget, shrinking the forward window cannot resolve it; increase the page/runtime budget or reduce overlap.

The delayed re-read handles alerts whose `created_at` is earlier than when they became searchable. It re-reads each settled creation window once, in whole windows, `CYBLE_RECONCILE_LAG_HOURS` later. Alerts already accepted with identical content are not sent again. An alert delayed by more than the lag is outside this protection; reconcile a known historical interval during tenant acceptance.

Overlap intentionally re-reads recent records. Stable Cyble alert identity supports replay through the SDK, but exactly-once delivery is not claimed. Network failures can occur after a request reaches ThreatStream and before confirmation. Native IOC CSV ingestion is asynchronous, and the hosted SDK cache can suppress refreshed attributes; accepted report IDs do not prove final indicator updates. Verify repeated reports, relationships, and refreshed fields in your tenant.

A process lock helps prevent competing workers in the same execution environment. Configure singleton scheduling as well; a local lock alone cannot coordinate independent hosts or containers. Keep a feed owned by one active runner.

For scheduled runs, enforce a wall-clock process timeout in the runner. For `--daemon`, give the supervisor a stop timeout. The connector checks its budgets and stop requests between pages and cannot preempt SDK retries or an active request. If a stalled process is killed, the operating system releases its local lock and the next start replays unfinished windows.

## Quarantined alerts

An alert that cannot become a bulletin is quarantined so its service keeps moving. This covers no usable ID, non-JSON values, nesting beyond 256 levels (`invalid-alert`), rejection by the SDK Report model (`sdk-model-rejected`), or ThreatStream rejecting that one report when it is resent alone after its page's batch failed (`ingest-rejected`). The window completes, and a content-free entry (service, stream, alert ID or `sha256:` content digest, reason, time) is kept under `cyble_quarantine_v1`. That list holds the most recent 200 entries, and each quarantine is logged at ERROR. Two cases are treated as systemic SDK or tenant problems rather than bad alerts: at least three alerts failing SDK validation when that is most of those attempted in a window, and three reports in a row rejected when resent individually. In either case the window fails and is retried instead of being quarantined.

A quarantined alert is not in ThreatStream. Investigate the reason, fix the mapping or schema handling, and replay the affected interval in a staging feed or through a planned historical replay.

Alerts larger than `CYBLE_MAX_REPORT_BYTES` are not quarantined. The bulletin is created with its source JSON shortened, tagged `cyble_source_truncated`, and native Indicators are still extracted from the complete alert.

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
| `Window split` warning | Dense window reached the page or runtime limit | None normally; the next attempt covers a smaller range. Persistent failures at the minimum span need a larger page/runtime budget |
| `Window deferred` warning | Rows shifted beyond the page overlap during paging | None normally; the window is replayed next cycle. Frequent deferrals mean heavy concurrent updates in that service |
| `Alert quarantined` error | Alert without a usable ID, non-JSON content, or SDK model rejection | See [quarantined alerts](#quarantined-alerts) |
| `backed_off_streams` above zero | A service failed and is waiting up to 15 minutes before retrying | Inspect that service's `Stream failed` log line |
| High Cyble request rate or HTTP 429 | Service count × active streams per poll interval | Raise `CYBLE_POLL_INTERVAL_SECONDS`, use an explicit service list, or agree a higher quota |
| Source-scope mismatch | Cyble tenant/company scope differs from the saved state | Use a separate ThreatStream feed for the new source scope |
| `cyble_source_truncated` tag on a bulletin | Source JSON larger than `CYBLE_MAX_REPORT_BYTES` | Retrieve the full record from Cyble by alert ID; raise the limit only within the tenant's accepted bulletin size |
| SDK warning/error or missing accepted report ID | ThreatStream permissions, supported models/iTypes, tenant limits | Resolve the ingestion rejection and replay the incomplete window |
| Feed checkpoint update fails | Permission to update feed configuration and endpoint reachability | Restore permission/connectivity; repeat ingestion may be replayed |
| Run already active | Scheduler overlap, a scheduled run beside a daemon, or a second runner for the same feed | Keep one daemon or one schedule per feed |
| Invalid overlap/window settings | `CYBLE_OVERLAP_SECONDS` is not smaller than `CYBLE_WINDOW_MINUTES` | Reduce overlap or increase the window |
| Bulletin exists but no Indicators | Service not in `CYBLE_INDICATOR_SERVICES`, no supported IOC values, false-positive status, excluded values, or unfamiliar IOC paths | Inspect the private bulletin fields; add the service or an explicit per-service rule only for values that are malicious |
| A source-body field shows a redaction/omission marker | Configured content mode, older bulletin outside the replay interval, or marker already present at source | Confirm full mode and replay coverage; summary fields and native IOC extraction remain sanitized |
| Full mode rejects configuration | `CYBLE_WITH_DATA_MESSAGE=false` or an unsupported content-mode value | Use `CYBLE_WITH_DATA_MESSAGE=true` and content mode `full` or `redacted` |
| README logo is unavailable | Vendor-hosted image URL or GitHub's image proxy | Update the original vendor URL in README and `assets/README.md` |

Do not disable TLS verification as a workaround. For a corporate proxy, configure the runtime's trusted CA chain and authorized proxy environment.

## Mapping additions

Field preservation and observable extraction are separate. All fields returned in an alert already appear in full-mode private bulletin JSON; optional redacted mode applies its documented omissions and redactions. Generic IOC scanning and the field map's `default` rules apply only to `CYBLE_INDICATOR_SERVICES`. A `services.<slug>` rule applies to its service regardless, so use one to extract a specific malicious field from, for example, a brand-monitoring service. Add rules to `CYBLE_FIELD_MAP_PATH` only when a legitimate IOC uses a path the generic extractor does not recognize, or when you want a selected safe summary field.

Document each rule with its service slug, a synthetic input, the expected native Indicator type, and excluded examples. A monitored company domain, victim IP, reference URL, or hosting address is not automatically a malicious IOC. Review contextual fields before converting them into native indicators and review `CYBLE_THREAT_TYPE` for the feed's purpose.

## Safe support evidence

A useful issue includes the connector version/commit, Python and SDK versions, service slug, HTTP status or sanitized error category, configured limits, and a small synthetic response with the same structure. Exclude tokens, tenant IDs, personal data, live alert content, SDK source, and vendor-only documents. Report suspected vulnerabilities privately using [SECURITY.md](../SECURITY.md).
