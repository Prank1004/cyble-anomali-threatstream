"""Cyble field preservation, redaction, and Anomali model mapping."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_MAX_REPORT_BYTES = 4 * 1024 * 1024
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
    "filehash", "hash", "hosting_ip", "ips", "domains", "urls", "hashes", "ip_addresses",
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
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|token|authorization|cookie)\b"
    r"[\"']?\s*(?::|=|\bis\b)\s*(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;&]+)"
)
AUTH_VALUE_RE = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)
URL_USERINFO_RE = re.compile(r"(?i)(https?://)[^/\s@]+@")
URL_TEXT_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# A digit run inside a hexadecimal hash is not a payment-card value. Keep
# standalone candidates bounded by non-alphanumeric characters.
CARD_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d[ -]?){12,18}\d(?![A-Za-z0-9])")
SENSITIVE_FIELD_PARTS = {
    "password", "passwd", "secret", "credential", "authorization", "accesstoken", "refreshtoken",
    "apikey", "privatekey", "cookie", "socialsecurity", "creditcard", "cardnumber", "paymentcard",
}
SENSITIVE_FIELD_NAMES = {
    "token", "tokens", "jwt", "session", "sessionid", "sessiontoken", "email", "emailaddress",
    "contactemail", "phone", "phonenumber", "mobile", "mobilenumber", "telephone", "ssn",
    "bankaccount", "accountnumber", "username", "firstname", "lastname", "fullname", "dateofbirth",
    "birthdate", "dob", "personname", "assignee", "assigneeid", "assignedto", "createdby", "updatedby",
    "cvv", "cvv2", "cvc", "pan", "accesskey", "clientsecret", "clientkey",
}
UNSTRUCTURED_DATA_FIELD_NAMES = {
    "content", "message", "body", "rawtext", "pastecontent", "raw", "rawdata", "text",
}
VALID_TLP = {"amber", "green", "red", "white"}
FORBIDDEN_CONTEXT_PATHS = {"description", "content", "message", "payload", "raw", "body", "text"}


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


def _passes_luhn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _redact_text(value: str) -> str:
    text = PRIVATE_KEY_RE.sub("<redacted-private-key>", value)
    text = URL_TEXT_RE.sub(lambda match: _redact_url_query(match.group()), text)
    text = URL_USERINFO_RE.sub(r"\1<redacted-userinfo>@", text)
    text = AUTH_VALUE_RE.sub("<redacted-authorization>", text)
    text = EMAIL_RE.sub("<redacted-email>", text)
    text = SSN_RE.sub("<redacted-ssn>", text)
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    text = CARD_CANDIDATE_RE.sub(
        lambda match: "<redacted-payment-card>" if _passes_luhn(match.group(0)) else match.group(0),
        text,
    )
    return text


def _redact_url_query(value: str) -> str:
    try:
        parsed = urlsplit(value)
        def redact_part(part: str) -> str:
            pairs = parse_qsl(part, keep_blank_values=True)
            changed = False
            safe_pairs = []
            for name, item in pairs:
                normalized = re.sub(r"[^a-z0-9]", "", name.lower())
                if _sensitive_key(name) or normalized in {
                    "key", "auth", "sig", "signature", "xamzsignature", "xamzcredential",
                    "xamzsecuritytoken", "awsaccesskeyid", "xgoogsignature", "xgoogcredential",
                }:
                    item = "redacted-sensitive-value"
                    changed = True
                safe_pairs.append((name, item))
            return urlencode(safe_pairs) if changed else part
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                           redact_part(parsed.query), redact_part(parsed.fragment)))
    except ValueError:
        return "<omitted:invalid-url>"


def _sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized in SENSITIVE_FIELD_NAMES or any(part in normalized for part in SENSITIVE_FIELD_PARTS)


def _sanitize_alert_fields(value: Any, key: str = "", depth: int = 0, sensitive: bool = False,
                           *, analysis_only: bool = False) -> Any:
    """Keep the Cyble field structure while redacting sensitive values."""
    if depth > 32:
        if analysis_only:
            # The full source object has already passed its own depth check.
            # JSON encoded inside a source string can expand more deeply only
            # in this derivative; retain that exact string in the source body.
            return "<omitted:analysis-depth>"
        raise ValueError("Cyble alert nesting exceeds the supported depth; no report was truncated and the checkpoint will not advance.")
    normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
    sensitive = sensitive or _sensitive_key(key)
    if isinstance(value, dict):
        result = {}
        for child_key, child in value.items():
            # The full-content route uses this copy only for analysis. Keeping
            # its keys avoids collisions between distinct sensitive source
            # names; unknown keys are never emitted by the summary mapper.
            safe_key = str(child_key) if analysis_only else _redact_text(str(child_key))
            if safe_key in result:
                raise ValueError("Redacted Cyble field names collide; the record cannot be preserved safely.")
            result[safe_key] = _sanitize_alert_fields(
                child, str(child_key), depth + 1, sensitive, analysis_only=analysis_only)
        return result
    if isinstance(value, list):
        return [_sanitize_alert_fields(child, key, depth + 1, sensitive, analysis_only=analysis_only)
                for child in value]
    if sensitive and value is not None:
        return "<redacted:sensitive-field>"
    if isinstance(value, str):
        if value.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(value)
            except (ValueError, RecursionError):
                pass
            else:
                if isinstance(parsed, (dict, list)):
                    return _sanitize_alert_fields(parsed, key, depth + 1, analysis_only=analysis_only)
        if normalized_key in UNSTRUCTURED_DATA_FIELD_NAMES:
            try:
                parsed = json.loads(value)
            except (ValueError, RecursionError):
                return "<omitted:unstructured-content>"
            if isinstance(parsed, (dict, list)):
                return _sanitize_alert_fields(parsed, key, depth + 1, analysis_only=analysis_only)
            return "<omitted:unstructured-content>"
        if normalized_key in {"data", "payload", "datamessage"}:
            try:
                parsed = json.loads(value)
            except (ValueError, RecursionError):
                return "<omitted:unstructured-data-string>"
            if isinstance(parsed, (dict, list)):
                return _sanitize_alert_fields(parsed, key, depth + 1, analysis_only=analysis_only)
            return "<omitted:unstructured-data-string>"
        return _redact_text(value)
    return value


def _validate_source_json(value: Any, depth: int = 0) -> None:
    """Reject non-JSON inputs and excessive nesting without changing source values."""
    if depth > 32:
        raise ValueError("Cyble alert nesting exceeds the supported depth; no report was truncated and the checkpoint will not advance.")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("Cyble source JSON must contain string field names.")
            _validate_source_json(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_source_json(child, depth + 1)
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ValueError("Cyble source contains a value unsupported by JSON.")


def _serialize_alert_fields(alert: dict[str, Any], max_bytes: int, *, content_mode: str = "redacted") -> str:
    """Serialize source JSON in the selected mode, rejecting oversize records."""
    if content_mode not in {"full", "redacted"}:
        raise ValueError("Cyble content mode must be 'full' or 'redacted'.")
    if content_mode == "full":
        _validate_source_json(alert)
        payload = alert
    else:
        payload = _sanitize_alert_fields(alert)
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    # Keep arbitrary Cyble strings from terminating the Markdown code fence. The
    # replacement remains valid JSON and decodes to the original backtick value.
    serialized = serialized.replace("`", r"\u0060")
    if len(serialized.encode("utf-8")) > max_bytes:
        raise ValueError(
            "A Cyble alert exceeds CYBLE_MAX_REPORT_BYTES; no report was truncated and the checkpoint will not advance."
        )
    return serialized


def _alert_identifier(alert: dict[str, Any]) -> str:
    for key in ("id", "uuid", "alertId", "alert_id", "alert_uuid"):
        value = alert.get(key)
        if not isinstance(value, bool) and isinstance(value, (str, int)) and str(value).strip():
            candidate = str(value).strip()
            if re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", candidate):
                return candidate
    raise ValueError("Cyble alert is missing a usable stable ID; its checkpoint was not advanced.")


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
    if type_hint == "excluded" or not isinstance(value, str):
        return None
    candidate = str(value).strip().strip("\"'<>[](){};, ")
    if not candidate or len(candidate) > 4096 or "redacted" in candidate or "omitted:" in candidate:
        return None
    if EMAIL_RE.search(candidate) or SECRET_RE.search(candidate) or _redact_text(candidate) != candidate:
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
        try:
            if not ipaddress.ip_address(parsed.hostname).is_global:
                return None
        except ValueError:
            if parsed.hostname.lower() == "localhost" or parsed.hostname.lower().endswith(".local"):
                return None
    # SDK Indicator validation below is authoritative for the supported iType.
    return candidate


def _walk_semantic_iocs(node: Any, Indicator: Any, threat_type: str, severity: str | None,
                        source_created: str | None, source_modified: str | None,
                        tags: list[str], explicit_candidates: list[tuple[Any, str | None]] | None = None,
                        tlp: str = "amber") -> list[Any]:
    """Extract only values under IOC-shaped keys; never scrape arbitrary prose."""
    candidates = []

    def visit(value: Any, key_context: str | None = None, inherited_type: str | None = None,
              first_seen: str | None = source_created, last_seen: str | None = source_modified,
              depth: int = 0, timestamp_rank: int = 0) -> None:
        if isinstance(value, dict):
            local_type = inherited_type
            local_first = _timestamp(value, ("first_seen", "first_seen_on"))
            local_last = _timestamp(value, ("last_seen", "last_seen_on"))
            if local_first or local_last:
                timestamp_rank = depth + 1
            first_seen = local_first or first_seen
            last_seen = local_last or last_seen
            for key, child in value.items():
                normalized_type_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if normalized_type_key in NORMALIZED_TYPE_KEYS:
                    candidate_type = _parse_ioc_type(child)
                    if candidate_type:
                        local_type = candidate_type
            for key, child in value.items():
                normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if _sensitive_key(str(key)) or str(key).lower() in EXCLUDED_KEYS:
                    continue
                key_type = _parse_ioc_type(str(key))
                is_ioc_key = key_type is not None or normalized_key in NORMALIZED_IOC_KEYS
                type_hint = key_type or local_type
                if isinstance(child, (str, int)) and (is_ioc_key or (normalized_key == "value" and local_type is not None)):
                    candidates.append((child, type_hint, first_seen, last_seen, timestamp_rank))
                else:
                    visit(child, str(key), type_hint if is_ioc_key else local_type, first_seen, last_seen, depth + 1, timestamp_rank)
        elif isinstance(value, list):
            for child in value:
                visit(child, key_context, inherited_type, first_seen, last_seen, depth + 1, timestamp_rank)
        elif isinstance(value, str) and key_context and re.sub(r"[^a-z0-9]", "", key_context.lower()) in NORMALIZED_IOC_KEYS:
            candidates.append((value, inherited_type, first_seen, last_seen, timestamp_rank))
        elif isinstance(value, str) and key_context and key_context.lower() in {"data", "data_message", "datamessage"}:
            # Some services encode structured alert data as JSON text. Parse JSON only;
            # only IOC-shaped keys are extracted and the original text is never copied.
            try:
                decoded = json.loads(value)
            except (ValueError, json.JSONDecodeError):
                return
            visit(decoded, key_context, inherited_type, first_seen, last_seen, depth + 1, timestamp_rank)

    visit(node)
    candidates.extend((value, hint, source_created, source_modified, 0) for value, hint in (explicit_candidates or []))
    output: list[Any] = []
    seen: set[str] = set()
    for value, type_hint, first_seen, last_seen, _ in sorted(candidates, key=lambda candidate: candidate[4], reverse=True):
        candidate = _is_acceptable_candidate(value, type_hint)
        if candidate is None or type_hint == "excluded":
            continue
        # Domain/IP/hash values are insensitive to case; URL path/query may not be.
        key = candidate if candidate.lower().startswith(("http://", "https://")) else candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        indicator = Indicator(
            value=candidate,
            threat_type=threat_type,
            severity=severity,
            source_created=first_seen,
            source_modified=last_seen,
            tags=tags,
            tlp=tlp,
        )
        if getattr(indicator, "observable", None) is not None and getattr(indicator, "itype", None):
            output.append(indicator)
    return output


NORMALIZED_IOC_KEYS = {re.sub(r"[^a-z0-9]", "", key) for key in IOC_KEY_HINTS}


def _json_path_tokens(path: str) -> list[tuple[str, int]]:
    """Parse dotted keys and [*] wildcards; reject unsupported path syntax."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("Cyble field-map paths must be nonempty strings.")
    expression = path.strip()
    if expression == "$":
        return []
    if expression.startswith("$."):
        expression = expression[2:]
    tokens = []
    for token in expression.split("."):
        match = re.fullmatch(r"([^.[\]$\s]+)((?:\[\*\])*)", token)
        if match is None:
            raise ValueError("Cyble field-map paths support dotted keys and [*] array wildcards only.")
        tokens.append((match.group(1), len(match.group(2)) // 3))
    return tokens


def _json_path_entries(root: Any, tokens: list[tuple[str, int]]) -> list[tuple[tuple[int, ...], Any]]:
    """Retain each wildcard index so missing fields cannot shift sibling types."""
    current: list[tuple[tuple[int, ...], Any]] = [((), root)]
    for key, expansions in tokens:
        selected = [(indices, item[key]) for indices, item in current
                    if isinstance(item, dict) and key in item and item[key] is not None]
        for _ in range(expansions):
            expanded = []
            for indices, value in selected:
                if not isinstance(value, list):
                    raise ValueError("A Cyble field-map [*] wildcard encountered a non-array value.")
                expanded.extend((indices + (index,), item) for index, item in enumerate(value))
            selected = expanded
        current = selected
    return current


def _json_path_values(root: Any, path: str) -> list[Any]:
    """Resolve the documented JSONPath subset, preserving array traversal order."""
    return [value for _, value in _json_path_entries(root, _json_path_tokens(path))]


def _explicit_ioc_candidates(alert: dict[str, Any], service: str, field_map: dict[str, Any]) -> list[tuple[Any, str | None]]:
    defaults = field_map.get("default", {}) if isinstance(field_map.get("default", {}), dict) else {}
    services = field_map.get("services", {}) if isinstance(field_map.get("services", {}), dict) else {}
    override = services.get(service, {}) if isinstance(services.get(service, {}), dict) else {}
    default_rules, service_rules = defaults.get("ioc_rules", []), override.get("ioc_rules", [])
    if not isinstance(default_rules, list) or not isinstance(service_rules, list):
        raise ValueError("Cyble field-map IOC rules must be JSON arrays.")
    rules = default_rules + service_rules
    output: list[tuple[Any, str | None]] = []
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("value_path"), str):
            raise ValueError("Each Cyble IOC mapping rule must contain a value_path string.")
        value_tokens = _json_path_tokens(rule["value_path"])
        type_tokens = _json_path_tokens(rule["type_path"]) if "type_path" in rule else None
        value_depth = sum(expansions for _, expansions in value_tokens)
        type_depth = sum(expansions for _, expansions in type_tokens) if type_tokens is not None else 0
        if type_depth and type_depth != value_depth:
            raise ValueError("Cyble wildcard value_path and type_path must have the same number of [*] expansions.")
        values = _json_path_entries(alert, value_tokens)
        type_values = dict(_json_path_entries(alert, type_tokens)) if type_tokens is not None else {}
        fixed_type = _parse_ioc_type(rule.get("type"))
        for indices, value in values:
            # A non-wildcard type path intentionally applies one type to every
            # value. Wildcard type paths match only the same array index tuple.
            matched_type = type_values.get(indices if type_depth else ())
            hint = _parse_ioc_type(matched_type) or fixed_type
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
        raise ValueError("The configured Cyble field map does not exist.") from None
    except (OSError, ValueError, json.JSONDecodeError):
        raise ValueError("CYBLE_FIELD_MAP_PATH must point to a readable JSON field map.") from None
    if not isinstance(parsed, dict):
        raise ValueError("The Cyble field map must be a JSON object.")
    if not isinstance(parsed.get("default", {}), dict) or not isinstance(parsed.get("services", {}), dict):
        raise ValueError("Cyble field-map default and services entries must be JSON objects.")
    for section in [parsed.get("default", {}), *parsed.get("services", {}).values()]:
        if not isinstance(section, dict):
            raise ValueError("Each Cyble service field map must be a JSON object.")
        for collection, required in (("ioc_rules", "value_path"), ("context_paths", "path")):
            rules = section.get(collection, [])
            if not isinstance(rules, list) or any(
                not isinstance(rule, dict) or not isinstance(rule.get(required), str) or not rule[required].strip()
                for rule in rules
            ):
                raise ValueError("Cyble field-map rules must contain nonempty JSON paths.")
            for rule in rules:
                _json_path_tokens(rule[required])
                if collection == "ioc_rules" and "type_path" in rule:
                    value_depth = sum(depth for _, depth in _json_path_tokens(rule["value_path"]))
                    type_depth = sum(depth for _, depth in _json_path_tokens(rule["type_path"]))
                    if type_depth and type_depth != value_depth:
                        raise ValueError("Cyble wildcard value_path and type_path must have the same number of [*] expansions.")
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
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            except ValueError:
                continue
    return None


def _map_alert(alert: dict[str, Any], service: str, Indicator: Any, Report: Any,
               threat_type: str, tlp: str, field_map: dict[str, Any],
               max_report_bytes: int = DEFAULT_MAX_REPORT_BYTES,
               content_mode: str = "redacted") -> Any:
    if content_mode not in {"full", "redacted"}:
        raise ValueError("Cyble content mode must be 'full' or 'redacted'.")
    # Preserve the full original object only in the private bulletin's fenced
    # source JSON. Native observables, summaries, tags, and custom mappings all
    # receive a separate sanitized derivative in either mode.
    serialized_alert = (_serialize_alert_fields(alert, max_report_bytes, content_mode="full")
                        if content_mode == "full" else None)
    # A legitimate numeric source ID can resemble a payment-card number. Its
    # separately validated identity must remain stable in full-content mode.
    source_id = _alert_identifier(alert) if content_mode == "full" else None
    alert = _sanitize_alert_fields(alert, analysis_only=content_mode == "full")
    alert_id = source_id or _alert_identifier(alert)
    actual_service = str(alert.get("service") or service)
    if actual_service != service or not re.fullmatch(r"[a-z0-9_\-]+", actual_service):
        raise ValueError("Cyble alert service does not match the requested service.")
    status = _clean_scalar(alert.get("status"), 80)
    severity_value = alert.get("user_severity") or alert.get("severity")
    raw_severity = _clean_scalar(severity_value, 80)
    # Unrecognized prose remains in the fenced source JSON, never executable
    # Markdown in the human-readable summary.
    if status and not re.fullmatch(r"[A-Z_]{1,64}", status):
        status = None
    if raw_severity and not re.fullmatch(r"[A-Za-z_ -]{1,40}", raw_severity):
        raw_severity = None
    mapped_severity = _severity(raw_severity)
    alert_created = _timestamp(alert, ("created_at", "createdAt"))
    alert_updated = _timestamp(alert, ("updated_at", "updatedAt"))
    source_created = _timestamp(alert, ("first_seen", "first_seen_on")) or alert_created
    source_modified = _timestamp(alert, ("last_seen", "last_seen_on")) or alert_updated
    service_tag = _safe_tag(actual_service) or "unknown"
    tags = ["cyble_vision", f"cyble_service_{service_tag}"]
    severity_tag = _safe_tag(raw_severity) if raw_severity else None
    if severity_tag:
        tags.append(f"cyble_severity_{severity_tag}")
    if status:
        tags.append(f"cyble_status_{_safe_tag(status)}")

    indicators = _walk_semantic_iocs(
        alert,
        Indicator=Indicator,
        threat_type=threat_type,
        severity=mapped_severity,
        source_created=source_created,
        source_modified=source_modified,
        tags=tags,
        explicit_candidates=_explicit_ioc_candidates(alert, service, field_map),
        tlp=tlp,
    ) if status != "FALSE_POSITIVE" else []
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
        summary.append("Configured context mappings:")
        for key, value in context:
            context_json = json.dumps({key: value}, ensure_ascii=False).replace("`", r"\u0060")
            summary.append(f"- `{context_json}`")
    summary.append(f"Validated observables associated: {len(indicators)}")
    if content_mode == "full":
        summary.append("The complete Cyble source alert is retained below, including sensitive values and raw content.")
        source_label = "Complete Cyble source alert (private):"
    else:
        summary.append(
            "The complete structured Cyble alert is included below. Sensitive values are redacted; "
            "unstructured content fields are omitted."
        )
        source_label = "Sanitized Cyble alert fields:"
        serialized_alert = _serialize_alert_fields(alert, max_report_bytes)
    summary.extend(("", source_label, "```json", serialized_alert, "```"))

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
