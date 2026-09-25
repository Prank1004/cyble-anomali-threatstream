"""Scheduled Cyble Vision Alerts API v2 to Anomali ThreatStream feed."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import requests

from cyble_client import CybleAPIError, CybleClient


VERSION = "0.2.0"
LOGGER = logging.getLogger("cyble_anomali_feed")
SAFE_CONTEXT_KEYS = {
    "risk_score",
    "risk_rating",
    "confidence_rating",
    "confident_rating",
    "target_countries",
    "target_regions",
    "target_industries",
    "related_malware",
    "related_threat_actors",
    "behaviour_tags",
    "behavior_tags",
    "ioc_attack_name",
    "reference_link",
    "hosting_ip",
    "sources",
    "category",
    "severity",
    "user_severity",
    "status",
    "created_at",
    "updated_at",
    "first_seen",
    "last_seen",
    "first_seen_on",
    "last_seen_on",
    "ioc_type",
    "cve",
}
IOC_KEY_HINTS = {
    "ioc", "iocs", "indicator", "indicators", "observable", "observables",
    "ip", "ipv4", "ipv6", "ip_address", "ipaddress", "domain", "domain_name",
    "hostname", "url", "uri", "md5", "sha1", "sha256", "sha512", "file_hash",
    "filehash", "hash", "hosting_ip",
}
TYPE_KEYS = {"type", "ioc_type", "indicator_type", "observable_type", "itype", "kind"}
NORMALIZED_TYPE_KEYS = {re.sub(r"[^a-z0-9]", "", key) for key in TYPE_KEYS}
EXCLUDED_KEYS = {
    "email", "email_address", "username", "user_name", "password", "passwd", "secret",
    "token", "cookie", "session", "credential", "credentials", "ssn", "social_security",
    "credit_card", "card_number", "phone", "phone_number", "firstname", "lastname",
    "first_name", "last_name", "full_name", "raw_data",
}
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
SECRET_RE = re.compile(r"(?i)(?:password|passwd|secret|api[_ -]?key|access[_ -]?token)\s*[:=]")
VALID_TLP = {"amber", "green", "red", "white"}
FORBIDDEN_CONTEXT_PATHS = {"description", "content", "message", "payload", "raw", "body", "text"}


class IncompletePoll(RuntimeError):
    """Raised when the full polling window was not processed and must be retried."""


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        result = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer.") from None
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return result


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false.")


def _iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _configured_services() -> list[str]:
    values = [part.strip() for part in os.environ.get("CYBLE_SERVICES", "").split(",") if part.strip()]
    if not values:
        raise ValueError("CYBLE_SERVICES must explicitly list the Cyble alert services to ingest.")
    return list(dict.fromkeys(values))


def _safe_tag(value: Any) -> str | None:
    text = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value).strip()).strip("_-").lower()
    if not text:
        return None
    return text[:48]


def _clean_scalar(value: Any, limit: int = 500) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return str(value)
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text or EMAIL_RE.search(text) or SECRET_RE.search(text):
        return None
    return text[:limit]


def _alert_identifier(alert: dict[str, Any]) -> str:
    for key in ("id", "uuid", "alertId", "alert_id", "alert_uuid"):
        value = alert.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            candidate = str(value).strip()
            if re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", candidate):
                return candidate
    digest = hashlib.sha256(
        json.dumps(alert, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()[:20]
    return f"unidentified-{digest}"


def _parse_ioc_type(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    if normalized in {"email", "emailaddress", "mail", "credential"}:
        return "excluded"
    if normalized in {"ip", "ipv4", "ipv6", "ipaddress", "malip"}:
        return "ip"
    if normalized in {"domain", "domainname", "hostname", "fqdn", "maliciousdomain", "maldomain"}:
        return "domain"
    if normalized in {"url", "uri", "malurl"}:
        return "url"
    if normalized in {"md5", "sha1", "sha256", "sha512", "filehash", "hash"}:
        return "hash"
    return None


def _is_acceptable_candidate(value: Any, type_hint: str | None) -> str | None:
    if type_hint == "excluded" or not isinstance(value, (str, int)):
        return None
    candidate = str(value).strip().strip("\"'<>[](){};, ")
    if not candidate or len(candidate) > 4096 or EMAIL_RE.search(candidate) or SECRET_RE.search(candidate):
        return None
    try:
        address = ipaddress.ip_address(candidate)
        if not address.is_global:
            return None
        return str(address)
    except ValueError:
        pass
    if candidate.lower() in {"localhost", "localhost.localdomain"} or candidate.endswith(".local"):
        return None
    if candidate.lower().startswith(("http://", "https://")):
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            return None
        if parsed.username or parsed.password or not parsed.hostname:
            return None
    # SDK Indicator validation below is authoritative for the supported iType.
    return candidate


def _walk_semantic_iocs(node: Any, Indicator: Any, threat_type: str, severity: str | None,
                        source_created: str | None, source_modified: str | None,
                        tags: list[str], explicit_candidates: list[tuple[Any, str | None]] | None = None) -> list[Any]:
    """Extract only values under IOC-shaped keys; never scrape arbitrary prose."""
    candidates: list[tuple[Any, str | None]] = list(explicit_candidates or [])

    def visit(value: Any, key_context: str | None = None, inherited_type: str | None = None) -> None:
        if isinstance(value, dict):
            local_type = inherited_type
            for key, child in value.items():
                normalized_type_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if normalized_type_key in NORMALIZED_TYPE_KEYS:
                    candidate_type = _parse_ioc_type(child)
                    if candidate_type:
                        local_type = candidate_type
            for key, child in value.items():
                normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if str(key).lower() in EXCLUDED_KEYS or normalized_key in {"emailaddress", "creditcard", "password"}:
                    continue
                key_type = _parse_ioc_type(str(key))
                is_ioc_key = key_type is not None or normalized_key in NORMALIZED_IOC_KEYS
                type_hint = key_type or local_type
                if isinstance(child, (str, int)) and (is_ioc_key or (normalized_key == "value" and local_type is not None)):
                    candidates.append((child, type_hint))
                else:
                    visit(child, str(key), type_hint if is_ioc_key else local_type)
        elif isinstance(value, list):
            for child in value:
                visit(child, key_context, inherited_type)
        elif isinstance(value, str) and key_context and key_context.lower() in {"data", "data_message", "datamessage"}:
            # Some services encode structured alert data as JSON text. Parse JSON only;
            # only IOC-shaped keys are extracted and the original text is never copied.
            try:
                decoded = json.loads(value)
            except (ValueError, json.JSONDecodeError):
                return
            visit(decoded, key_context, inherited_type)

    visit(node)
    output: list[Any] = []
    seen: set[tuple[str, str | None]] = set()
    for value, type_hint in candidates:
        candidate = _is_acceptable_candidate(value, type_hint)
        if candidate is None or type_hint == "excluded":
            continue
        key = (candidate.lower(), type_hint)
        if key in seen:
            continue
        seen.add(key)
        indicator = Indicator(
            value=candidate,
            threat_type=threat_type,
            severity=severity,
            source_created=source_created,
            source_modified=source_modified,
            tags=tags,
        )
        if getattr(indicator, "observable", None) is not None and getattr(indicator, "itype", None):
            output.append(indicator)
    return output


NORMALIZED_IOC_KEYS = {re.sub(r"[^a-z0-9]", "", key) for key in IOC_KEY_HINTS}


def _json_path_values(root: Any, path: str) -> list[Any]:
    """Resolve a small documented JSONPath subset: dotted keys and [*] array expansion."""
    expression = path.strip()
    if expression.startswith("$."):
        expression = expression[2:]
    elif expression == "$":
        return [root]
    current = [root]
    for token in expression.split("."):
        next_values: list[Any] = []
        wildcard = token.endswith("[*]")
        key = token[:-3] if wildcard else token
        for item in current:
            if not isinstance(item, dict):
                continue
            child = item.get(key)
            if wildcard:
                if isinstance(child, list):
                    next_values.extend(child)
                elif child is not None:
                    next_values.append(child)
            elif child is not None:
                next_values.append(child)
        current = next_values
    return current


def _explicit_ioc_candidates(alert: dict[str, Any], service: str, field_map: dict[str, Any]) -> list[tuple[Any, str | None]]:
    defaults = field_map.get("default", {}) if isinstance(field_map.get("default", {}), dict) else {}
    services = field_map.get("services", {}) if isinstance(field_map.get("services", {}), dict) else {}
    override = services.get(service, {}) if isinstance(services.get(service, {}), dict) else {}
    rules = list(defaults.get("ioc_rules", [])) + list(override.get("ioc_rules", []))
    output: list[tuple[Any, str | None]] = []
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("value_path"), str):
            continue
        values = _json_path_values(alert, rule["value_path"])
        type_values = _json_path_values(alert, rule["type_path"]) if isinstance(rule.get("type_path"), str) else []
        fixed_type = _parse_ioc_type(rule.get("type"))
        for index, value in enumerate(values):
            hint = fixed_type
            if index < len(type_values):
                hint = _parse_ioc_type(type_values[index]) or hint
            elif len(type_values) == 1:
                hint = _parse_ioc_type(type_values[0]) or hint
            output.append((value, hint))
    return output


def _configured_context(alert: dict[str, Any], service: str, field_map: dict[str, Any]) -> list[tuple[str, str]]:
    defaults = field_map.get("default", {}) if isinstance(field_map.get("default", {}), dict) else {}
    services = field_map.get("services", {}) if isinstance(field_map.get("services", {}), dict) else {}
    override = services.get(service, {}) if isinstance(services.get(service, {}), dict) else {}
    rules = list(defaults.get("context_paths", [])) + list(override.get("context_paths", []))
    output: list[tuple[str, str]] = []
    forbidden = {re.sub(r"[^a-z0-9]", "", key) for key in EXCLUDED_KEYS}
    forbidden.update(FORBIDDEN_CONTEXT_PATHS)
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("path"), str):
            continue
        path = rule["path"]
        normalized_path = re.sub(r"[^a-z0-9]", "", path.lower())
        if any(key and key in normalized_path for key in forbidden):
            continue
        label = _clean_scalar(rule.get("label"), 80)
        if not label:
            continue
        values = _json_path_values(alert, path)
        if len(values) == 1 and isinstance(values[0], list):
            values = values[0]
        cleaned = [_clean_scalar(value, 200) for value in values]
        rendered = ", ".join(value for value in cleaned if value)
        if rendered:
            output.append((label, rendered[:600]))
    return output


def _find_nested_timestamp(node: Any, keys: set[str]) -> str | None:
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).lower() in keys and isinstance(value, str) and value.strip() and len(value) <= 64:
                return value.strip()
        for value in node.values():
            found = _find_nested_timestamp(value, keys)
            if found:
                return found
    elif isinstance(node, list):
        for value in node:
            found = _find_nested_timestamp(value, keys)
            if found:
                return found
    return None


def _load_field_map() -> dict[str, Any]:
    configured = os.environ.get("CYBLE_FIELD_MAP_PATH")
    path = Path(configured) if configured else Path(__file__).resolve().parents[1] / "config" / "field-map.example.json"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"default": {}, "services": {}}
    except (OSError, ValueError, json.JSONDecodeError):
        raise ValueError("CYBLE_FIELD_MAP_PATH must point to a readable JSON field map.") from None
    if not isinstance(parsed, dict):
        raise ValueError("The Cyble field map must be a JSON object.")
    return parsed


def _severity(value: Any) -> str | None:
    text = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    return {
        "very-high": "very-high",
        "critical": "very-high",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "very-low": "low",
        "informational": "low",
        "info": "low",
    }.get(text)


def _safe_context(alert: dict[str, Any], service: str, field_map: dict[str, Any]) -> list[tuple[str, str]]:
    fields: dict[str, str] = {}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_name = str(key).lower()
                if key_name in SAFE_CONTEXT_KEYS:
                    values = child if isinstance(child, list) else [child]
                    cleaned = [_clean_scalar(item, 160) for item in values]
                    rendered = ", ".join(item for item in cleaned if item)
                    if rendered:
                        fields.setdefault(key_name, rendered[:500])
                if key_name not in EXCLUDED_KEYS:
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(alert)
    configured = _configured_context(alert, service, field_map)
    for label, value in configured:
        fields.setdefault(label, value)
    return sorted(fields.items())


def _timestamp(alert: dict[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        value = alert.get(key)
        if isinstance(value, str) and value.strip() and len(value) <= 64:
            return value.strip()
    return None


def _map_alert(alert: dict[str, Any], service: str, Indicator: Any, Report: Any,
               threat_type: str, tlp: str, field_map: dict[str, Any]) -> Any:
    alert_id = _alert_identifier(alert)
    actual_service = str(alert.get("service") or service)
    status = _clean_scalar(alert.get("status"), 80)
    severity_value = alert.get("user_severity", alert.get("severity"))
    raw_severity = _clean_scalar(severity_value, 80)
    mapped_severity = _severity(raw_severity)
    alert_created = _timestamp(alert, ("created_at", "createdAt"))
    alert_updated = _timestamp(alert, ("updated_at", "updatedAt"))
    source_created = _find_nested_timestamp(alert, {"first_seen", "first_seen_on"}) or alert_created
    source_modified = _find_nested_timestamp(alert, {"last_seen", "last_seen_on"}) or alert_updated
    service_tag = _safe_tag(actual_service) or "unknown"
    tags = ["cyble_vision", f"cyble_service_{service_tag}"]
    severity_tag = _safe_tag(raw_severity) if raw_severity else None
    if severity_tag:
        tags.append(f"cyble_severity_{severity_tag}")

    indicators = _walk_semantic_iocs(
        alert,
        Indicator=Indicator,
        threat_type=threat_type,
        severity=mapped_severity,
        source_created=source_created,
        source_modified=source_modified,
        tags=tags,
        explicit_candidates=_explicit_ioc_candidates(alert, service, field_map),
    )
    context = _safe_context(alert, service, field_map)
    summary = [
        f"Cyble Vision alert ID: {alert_id}",
        f"Service: {actual_service}",
    ]
    if status:
        summary.append(f"Status: {status}")
    if raw_severity:
        summary.append(f"Cyble severity: {raw_severity}")
    if alert_created:
        summary.append(f"Alert created: {alert_created}")
    if alert_updated:
        summary.append(f"Alert updated: {alert_updated}")
    if context:
        summary.append("Safe context fields:")
        summary.extend(f"- {key}: {value}" for key, value in context)
    summary.append(f"Validated observables associated: {len(indicators)}")
    summary.append("Raw alert payload and personal data are not copied into this report.")

    return Report(
        name=f"Cyble Vision alert {alert_id}",
        threat_model_type="tipreport",
        related_indicators=indicators,
        description="\n".join(summary),
        tags=tags,
        is_public=False,
        original_source="Cyble Vision",
        original_source_id=alert_id,
        tlp=tlp,
        source_created=alert_created,
        source_modified=alert_updated,
        body_content_type="markdown",
    )


def _proxies_from_environment() -> dict[str, str] | None:
    proxies = {}
    for scheme, name in (("http", "HTTP_PROXY"), ("https", "HTTPS_PROXY")):
        if os.environ.get(name):
            proxies[scheme] = os.environ[name]
    return proxies or None


def _new_feed() -> Any:
    try:
        from anomali_feedsdk.feed import Feed
    except ImportError:
        raise RuntimeError(
            "Anomali Feed SDK 2.8.1 is required. Install the vendor-provided wheel outside this repository."
        ) from None
    return Feed(
        username=os.environ.get("TS_USERNAME"),
        api_key=os.environ.get("TS_API_KEY"),
        api_url=os.environ.get("TS_API_URL"),
        feed_id=os.environ.get("TS_FEED_ID"),
        feed_name=os.environ.get("TS_FEED_NAME"),
        classification="private",
        allow_update=False,
        requests_verify_ssl=True,
        batch_size=_env_int("TS_BATCH_SIZE", 1000, 1, 5000),
    )


def _save_feed_config(feed: Any) -> None:
    """Persist the Cyble watermark using the documented ThreatStream feed API."""
    url = f"{feed.ts_url}feed/{feed.feed_id}/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"apikey {feed.creds['username']}:{feed.creds['api_key']}",
    }
    try:
        response = requests.patch(
            url,
            headers=headers,
            json={"config": feed.feed_config},
            timeout=30,
            allow_redirects=False,
            verify=True,
            proxies=feed.proxies,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"ThreatStream feed checkpoint update failed ({type(exc).__name__}).") from None
    if not response.ok:
        raise RuntimeError(f"ThreatStream feed checkpoint update failed (HTTP {response.status_code}).")


class _SDKFailureCapture(logging.Handler):
    """Capture SDK errors without allowing vendor log messages to reveal values."""

    def __init__(self) -> None:
        super().__init__(level=logging.ERROR)
        self.failed = False

    def emit(self, record: logging.LogRecord) -> None:
        self.failed = True


def _ingest_reports(feed: Any, reports: list[Any]) -> None:
    sdk_logger = logging.getLogger("anomali_feedsdk")
    capture = _SDKFailureCapture()
    sdk_logger.addHandler(capture)
    try:
        feed.ingest_reports(reports)
    finally:
        sdk_logger.removeHandler(capture)
    if capture.failed:
        raise RuntimeError("The Anomali Feed SDK reported an ingestion error; the Cyble checkpoint was not advanced.")


def _initial_start(now: datetime) -> datetime:
    hours = _env_int("CYBLE_INITIAL_LOOKBACK_HOURS", 24, 1, 24 * 365)
    return now - timedelta(hours=hours)


def run_poll() -> None:
    sdk_logger = logging.getLogger("anomali_feedsdk")
    sdk_logger.setLevel(logging.ERROR)
    sdk_logger.propagate = False
    services = _configured_services()
    page_size = _env_int("CYBLE_PAGE_SIZE", 200, 1, 2000)
    max_pages = _env_int("CYBLE_MAX_PAGES_PER_SERVICE", 100, 1, 10000)
    overlap_seconds = _env_int("CYBLE_OVERLAP_SECONDS", 300, 0, 86400)
    max_run_minutes = _env_int("CYBLE_MAX_RUN_MINUTES", 20, 1, 24 * 60)
    with_data_message = _env_bool("CYBLE_WITH_DATA_MESSAGE", True)
    sync_updated_alerts = _env_bool("CYBLE_SYNC_UPDATED_ALERTS", True)
    if with_data_message and page_size > 200:
        raise ValueError("Keep CYBLE_PAGE_SIZE at 200 or less when CYBLE_WITH_DATA_MESSAGE=true.")
    threat_type = os.environ.get("CYBLE_THREAT_TYPE", "malware").strip().lower()
    tlp = os.environ.get("CYBLE_TLP", "amber").strip().lower()
    if tlp not in VALID_TLP:
        raise ValueError("CYBLE_TLP must be one of amber, green, red, or white.")
    if not threat_type:
        raise ValueError("CYBLE_THREAT_TYPE cannot be empty.")

    started = time.monotonic()
    deadline = started + (max_run_minutes * 60)
    now = datetime.now(timezone.utc)
    feed = _new_feed()
    previous_created = feed.feed_config.get("cyble_last_created_poll_time", feed.feed_config.get("cyble_last_poll_time"))
    previous_updated = feed.feed_config.get("cyble_last_updated_poll_time", previous_created)

    def previous_cursor(previous: Any) -> datetime:
        if isinstance(previous, str) and previous.strip():
            try:
                cursor_value = datetime.fromisoformat(previous.replace("Z", "+00:00"))
                if cursor_value.tzinfo is None:
                    cursor_value = cursor_value.replace(tzinfo=timezone.utc)
                return cursor_value.astimezone(timezone.utc)
            except ValueError:
                raise RuntimeError("Stored Cyble checkpoint is invalid; no data was ingested.") from None
        return _initial_start(now)

    created_cursor = previous_cursor(previous_created)
    updated_cursor = previous_cursor(previous_updated)
    poll_fields = [("created_at", created_cursor)]
    if sync_updated_alerts:
        poll_fields.append(("updated_at", updated_cursor))

    client = CybleClient(
        api_key=os.environ.get("CYBLE_API_TOKEN", ""),
        company_uuid=os.environ.get("CYBLE_COMPANY_UUID"),
        proxies=_proxies_from_environment(),
    )
    try:
        from anomali_feedsdk.models import Indicator, Report
    except ImportError:
        raise RuntimeError("Anomali Feed SDK models are unavailable; install the vendor-provided wheel.") from None
    field_map = _load_field_map()

    total_alerts = 0
    total_observables = 0
    for date_field, date_cursor in poll_fields:
        start_text = _iso_utc(date_cursor - timedelta(seconds=overlap_seconds))
        end_text = _iso_utc(now)
        for service in services:
            skip = 0
            page_number = 0
            while True:
                if time.monotonic() >= deadline:
                    raise IncompletePoll("Run time budget reached; checkpoint was not advanced. Retry the same time window.")
                if page_number >= max_pages:
                    raise IncompletePoll(
                        f"Page limit reached for service {service}; checkpoint was not advanced. Raise CYBLE_MAX_PAGES_PER_SERVICE."
                    )
                alerts = client.fetch_page(
                    services=[service],
                    start=start_text,
                    end=end_text,
                    skip=skip,
                    take=page_size,
                    with_data_message=with_data_message,
                    date_field=date_field,
                )
                if not alerts:
                    break
                reports = [
                    _map_alert(alert, service, Indicator, Report, threat_type, tlp, field_map)
                    for alert in alerts
                    if isinstance(alert, dict)
                ]
                if reports:
                    _ingest_reports(feed, reports)
                    total_observables += sum(len(report.related_indicators or []) for report in reports)
                total_alerts += len(alerts)
                page_number += 1
                skip += len(alerts)
                LOGGER.info(
                    "Processed Cyble alert page service=%s date_field=%s page=%d alerts=%d",
                    _safe_tag(service), date_field, page_number, len(alerts),
                )
                if len(alerts) < page_size:
                    break

    if time.monotonic() >= deadline:
        raise IncompletePoll("Run time budget reached before checkpoint commit; retry the same time window.")
    feed.feed_config["cyble_last_created_poll_time"] = _iso_utc(now)
    if sync_updated_alerts:
        feed.feed_config["cyble_last_updated_poll_time"] = _iso_utc(now)
    feed.feed_config.pop("cyble_last_poll_time", None)
    feed.feed_config["cyble_connector_version"] = VERSION
    _save_feed_config(feed)
    LOGGER.info(
        "Poll complete services=%d alerts=%d validated_observables=%d created_cursor=%s updated_sync=%s",
        len(services), total_alerts, total_observables, _iso_utc(now), sync_updated_alerts,
    )


def list_services() -> None:
    client = CybleClient(
        api_key=os.environ.get("CYBLE_API_TOKEN", ""),
        company_uuid=os.environ.get("CYBLE_COMPANY_UUID"),
        proxies=_proxies_from_environment(),
    )
    for service in client.get_services():
        print(f"{service['name']}\t{service['display_name']}")


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(message)s")
    # The SDK can log request parameters at DEBUG. Keep its loggers quiet to prevent credential exposure.
    sdk_logger = logging.getLogger("anomali_feedsdk")
    sdk_logger.setLevel(logging.ERROR)
    sdk_logger.propagate = False
    parser = argparse.ArgumentParser(description="Scheduled Cyble Vision Alerts API v2 feed for Anomali ThreatStream.")
    parser.add_argument("--list-services", action="store_true", help="List Cyble alert services available to the API token, then exit.")
    args = parser.parse_args()
    try:
        if args.list_services:
            list_services()
        else:
            run_poll()
        return 0
    except (ValueError, RuntimeError, CybleAPIError) as exc:
        LOGGER.error("Connector run failed: %s", exc)
        return 1
    except Exception as exc:
        LOGGER.error("Connector run failed (%s). Check SDK and feed configuration.", type(exc).__name__)
        return 1


if __name__ == "__main__":
    sys.exit(main())
