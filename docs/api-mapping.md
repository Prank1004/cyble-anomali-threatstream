# Cyble Alerts API v2 → ThreatStream mapping

The connector preserves each Cyble alert's complete JSON content in a private bulletin by default and extracts supported observables into native ThreatStream Indicators. Arbitrary service fields remain available under their original keys and types in the bulletin body; they do not create new native ThreatStream schema fields.

## Evidence and scope

The supplied Cyble API guide documents Alerts API v2 request filters and service discovery, but omits representative successful alert responses. Read-only Cyble MCP probes on 2026-09-25 observed 52 catalogue entries and inspected `iocs` and `new_vulnerability` records. No tenant values or raw records are retained here. Catalogue presence does not establish entitlement or successful ingestion for every service.

Generic source-field preservation applies to each configured service. `CYBLE_SERVICES=all` discovers accessible alert-capable services exposed by Alerts API v2. This does not cover separate Cyble product APIs, inaccessible subscriptions, or content absent from the API response. Service-specific IOC extraction still depends on field shape and meaning. See [validation](validation.md) for checks completed against synthetic data, the real SDK, and live services.

## API requests

| Purpose | Method and path | Behavior |
|---|---|---|
| Discover services | `GET /ar-apollo-v2/api/v2/y/services` | `--list-services` and `CYBLE_SERVICES=all` discovery |
| Search alerts | `POST /ar-apollo-v2/api/v2/y/alerts` | One service per request; fixed time window and offset pagination |

The API root is `https://bifrost.cyble.ai`. The token is sent in the Bearer authorization header, and `companyUuid` scopes each search. TLS is verified and redirects are disabled. The client includes JSON headers and the Cyble portal Referer.

Illustrative request, containing no tenant values:

```json
{
  "companyUuid": "<configured-company-uuid>",
  "filters": {
    "created_at": {
      "gte": "<UTC-ISO8601-start>",
      "lte": "<UTC-ISO8601-end>"
    },
    "service": ["<one-service-slug>"]
  },
  "orderBy": [{"created_at": "desc"}],
  "skip": 0,
  "take": 200,
  "withDataMessage": true
}
```

Updated-alert polling replaces `created_at` with `updated_at` in both the filter and ordering. Confirm update behavior for the selected services during tenant acceptance. The default page size is 200; detailed queries are capped at 200 by the connector. `CYBLE_WITH_DATA_MESSAGE=true` is required in full mode. Metadata-only queries allow up to 2,000 records per page when using redacted mode.

No alert-status exclusion is sent. False-positive records remain available to update bulletin status, with new observable extraction suppressed for those records.

## Accepted response envelopes

The client handles a single record, a record list inside a supported envelope, and service-keyed buckets such as `data.iocs[]`. Recognized envelope names include `data`, `alerts`, `items`, `results`, `records`, and `rows`. It verifies record shape and service consistency, and rejects application errors, ambiguous containers, malformed rows, and explicitly incomplete or inconsistent pagination metadata.

An unrecognized schema is an error, not an empty result. The incomplete window's checkpoint must not advance. The parsing flexibility is implementation coverage; it is not a claim that every envelope has been observed from Cyble.

Recognized pagination totals must be nonnegative JSON integers, and continuation flags must be JSON booleans. Nulls, strings, and other malformed values fail explicitly, including within service buckets and metadata wrappers. Wrapper request IDs must not replace the identities of nested alert records.

## Field destinations

| Cyble field/content | ThreatStream mapping |
|---|---|
| `id`, `uuid`, `alertId`, `alert_id`, or `alert_uuid` | Bulletin identity and `original_source_id` |
| `service` | Bulletin context and service tag |
| `status` | Bulletin status context; false positives create no new Indicators |
| `severity`, `user_severity` | Context and severity tag; supported values map to Indicator severity |
| `created_at`, `updated_at` | Bulletin source timestamps |
| `first_seen`, `first_seen_on`, `last_seen`, `last_seen_on` | Observable source timestamps when available |
| `ioc`, `data.ioc`, common IOC-shaped keys, or configured paths | Native Indicators after validation and exclusion checks |
| `data.ioc_type` and related type fields | Observable type hints, subject to final SDK validation |
| `cve`, risk/confidence labels, behavior tags, references, and all other fields | Original values and types under original field names in full-mode bulletin JSON |
| Structured objects and arrays, including empty containers and nulls | Preserved in full-mode bulletin JSON |
| JSON-encoded `data` / `payload` / `dataMessage` and other strings | Preserved as the original strings in full mode; no decoding changes the source representation |
| Exposed passwords, tokens, usernames, emails, personal data, internal IPs, and raw text | Preserved in the private bulletin body in full mode |
| Attachment metadata and URLs | Preserved when present in the source alert; no linked content or binary attachment is fetched |

Reports use `Report(threat_model_type="tipreport")`, private visibility, and amber TLP by default. Native Indicators are associated through the Feed SDK. The default threat type is `malware`; configure it to match your feed's semantics. A syntactically valid domain or URL is not proof of maliciousness.

Cyble confidence and risk labels are not converted to an Anomali confidence score because the scales are not established as equivalent. CVEs remain in bulletin context; this connector does not create a separate native vulnerability object for every CVE.

## Observed service details

### `iocs`

A live record under `data.iocs[]` included standard alert fields and an IOC. Its nested `data` object included `ioc`, `ioc_type`, `hosting_ip`, `first_seen`, `last_seen`, `risk_rating`, `confident_rating`, `behaviour_tags`, `ioc_attack_name`, and `reference_link`.

The bundled field map includes IOC paths and hosting IP extraction. Hosting addresses, victim assets, and reference URLs require contextual review before downstream blocking decisions. The entire source record is retained in the private bulletin body in full mode.

### `new_vulnerability`

A live record under `data.new_vulnerability[]` included standard alert fields and `cve`. Its nested `data.data` was an opaque string. Full mode preserves that string exactly, as it does every other string. Redacted mode expands a data string only when it parses as a JSON object or array; otherwise it uses an omission marker.

## Custom extraction rules

Set `CYBLE_FIELD_MAP_PATH` to a JSON file. The bundled [example](../config/field-map.example.json) provides common paths. Defaults apply to all services; a `services` entry adds rules for a particular slug.

```json
{
  "default": {
    "ioc_rules": [
      {"value_path": "data.indicators[*].value", "type_path": "data.indicators[*].type"}
    ]
  },
  "services": {
    "example_service": {
      "ioc_rules": [
        {"value_path": "data.confirmed_malicious_url", "type": "url"}
      ],
      "context_paths": [
        {"path": "data.category_label", "label": "Category"}
      ]
    }
  }
}
```

`example_service` and its fields are illustrative. Use actual service slugs and paths established from the corresponding response. Dotted paths and `[*]` array expansion are supported. `context_paths` adds safe summary text; it is not needed to retain the corresponding structured JSON field.

Wildcard value and type paths pair by their original array index tuples, including nested arrays. Missing fields cannot shift a type onto another value. Wildcard paths must have the same wildcard depth; a type path without wildcards supplies a shared scalar type. Unsupported syntax fails before polling.

Native Indicator extraction and summary mapping read a sanitized derivative in both content modes. An explicit rule cannot promote passwords, email addresses, session tokens, or raw source text into native malicious Indicators. These source values remain available in the full-mode private JSON body.

## Content modes

`CYBLE_CONTENT_MODE=full` is the default. The private body preserves every field in the returned alert record, including original keys, arrays, scalar types, nulls, raw text, exposed credentials, personal data, and strings containing encoded JSON. JSON formatting and escaping may differ from the HTTP bytes, but the field values and types are preserved. This retention applies to source alert content; runtime credentials used to authenticate the connector are never injected into the record.

`CYBLE_CONTENT_MODE=redacted` retains the v0.4.1 policy: known sensitive field names and common sensitive patterns are redacted; unstructured content/message/body/paste fields and opaque data strings are omitted. Nested object and array structure remains visible; scalar values under a sensitive parent are redacted. Ordinary descriptive text is retained after common pattern redaction. Pattern-based redaction cannot guarantee detection of every personal-data pattern.

In both modes, public IPs, domains, HTTP/HTTPS URLs, and supported file hashes may become native Indicators after validation. Non-public IPs, email addresses, credential values, and excluded types remain contextual content. The native extraction path does not classify every retained source value as malicious.

## Data handling limits

JSON larger than `CYBLE_MAX_REPORT_BYTES`, or nesting beyond 32 levels, fails the window without silent truncation. Full mode rejects `CYBLE_WITH_DATA_MESSAGE=false` because it would request reduced detail. The connector can preserve only fields returned by the selected API and subscription; it cannot reconstruct omitted data.

SDK remote-image fetching is disabled. Attachment metadata and URLs returned in the alert remain in its JSON body, but images, binary attachments, and external linked content are not downloaded. Source content is treated as data and is not executed. Keep bulletin access and downstream distribution aligned with the feed's private-content policy.

A content-mode change starts a replay of the configured initial lookback using stable alert identities. Recent existing bulletins can receive the new body representation. Records outside that interval require a separately planned historical replay; switching modes does not automatically rewrite every previously ingested bulletin.

The connector is read-only against Cyble. It never modifies alert status or comments. Cyble IoCs V4 is a separate lookup API and is not used as an alert-feed source. False-positive handling does not automatically delete or revoke previously ingested/shared Indicators; review their disposition in ThreatStream.
