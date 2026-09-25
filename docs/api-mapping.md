# Cyble Alerts API v2 → ThreatStream Feed mapping

This document records the request and field mapping used by the connector. The supplied Cyble API guide covers Alerts API v2 request filters and service discovery, but does not include a representative successful `POST /alerts` response. A read-only Cyble MCP probe was used on 2026-09-25 to inspect one `iocs` record and one `new_vulnerability` record; all values were redacted before review.

## Cyble API operations

| Purpose | Method and path | Connector behavior |
|---|---|---|
| List entitled services | `GET /ar-apollo-v2/api/v2/y/services` | Optional `--list-services` discovery helper |
| Search alert records | `POST /ar-apollo-v2/api/v2/y/alerts` | Scheduled polling, one configured service per request, fixed date window, page offsets |

The connector sends the company UUID in the request body, as required by the live Alerts API endpoint, and sends the API token only in `Authorization: Bearer ...`. It uses JSON headers, `Referer: https://cyble.ai/`, verified TLS, and disabled redirects.

Each search body has this shape:

```json
{
  "companyUuid": "<configured-company-uuid>",
  "filters": {
    "created_at": {
      "gte": "<UTC-ISO8601-start>",
      "lte": "<UTC-ISO8601-end>"
    },
    "service": ["<one-allowlisted-service>"]
  },
  "excludes": {"status": ["FALSE_POSITIVE"]},
  "orderBy": [{"created_at": "desc"}],
  "skip": 0,
  "take": 200,
  "withDataMessage": true
}
```

Updated-alert polling uses the same structure with `updated_at` in the date filter and orderBy. Live API probes confirmed updated-time filters work. Cyble documents a maximum `take` of 2,000; detailed payload queries use a default page size of 200.

## Observed response shape: iocs

The live `iocs` service response was service-keyed: `data.iocs[]`. One item included standard alert fields (`id`, `service`, `status`, `severity`, `user_severity`, `created_at`, `updated_at`) and an IOC field. With data messages enabled, the item also included a nested `data` object with fields such as `ioc`, `ioc_type`, `hosting_ip`, `first_seen`, `last_seen`, `risk_rating`, `confident_rating`, `behaviour_tags`, `ioc_attack_name`, and `reference_link`.

The field map extracts `ioc`, `data.ioc`, `data.hosting_ip`, and common `indicators[*].value` / `observables[*].value` patterns. It retains risk/confidence labels and safe context in the bulletin; it does not map risk rating to Anomali source confidence.

## Observed response shape: new_vulnerability

One live item under `data.new_vulnerability[]` included standard alert fields and a `cve` field. Its nested `data.data` value was an opaque string. The connector keeps the CVE in the bulletin context and parses nested `data` strings only when they are valid JSON, extracting only IOC-shaped keys. It does not copy the opaque value verbatim.

## Anomali representation

| Cyble data | Anomali Feed SDK object |
|---|---|
| One alert | Private `Report(threat_model_type="tipreport")` |
| Cyble ID | Stable report name and `original_source_id` |
| Recognized IOC values | `Indicator` instances, attached as `related_indicators` |
| Alert status, severity, timestamps, approved context | Report body and tags |
| Cyble severity LOW/MEDIUM/HIGH | Indicator severity where supported; no severity inference from risk ratings |
| Cyble confidence/risk labels | Preserved as text context only; no score conversion |
| Cyble first/last-seen timestamps | Indicator source timestamps when available |

The Feed SDK creates/updates the report and associates its indicators. Feed visibility is private, TLP defaults to amber, and feed configuration watermarks are written only after a full poll window completes.

## Service-specific mapping

Cyble alert payloads differ across services. The connector recursively recognizes common IOC-shaped keys and supports explicit JSON paths in `config/field-map.example.json`. Use one service per API query, as recommended by Cyble for service-specific filters. Add only fields seen in the live response, and do not map free-text descriptions or personal/credential content into the report.

The connector does not call Cyble alert update or comment endpoints. It does not use the Cyble IoCs V4 lookup API as a feed source; that API accepts supplied IOCs for lookup and is distinct from the Alerts API.
