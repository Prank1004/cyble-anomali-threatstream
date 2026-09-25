"""Read-only client for Cyble Vision Alerts API v2."""

from __future__ import annotations

import json
import re
import time
from typing import Any

import requests


API_ROOT = "https://bifrost.cyble.ai/ar-apollo-v2/api/v2/y"
ALERTS_PATH = "/alerts"
SERVICES_PATH = "/services"
MAX_TAKE = 2000
MAX_DETAIL_TAKE = 200
ALERT_CONTAINERS = ("alerts", "items", "results", "records", "rows")
ALERT_ID_FIELDS = ("id", "uuid", "alertId", "alert_id", "alert_uuid")


class CybleAPIError(RuntimeError):
    """Sanitized Cyble error; response bodies and credentials are never included."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _looks_like_alert(value: dict[str, Any]) -> bool:
    # A status/message wrapper is not an alert. A stable ID or a service plus
    # a creation timestamp distinguishes records from response metadata.
    return any(isinstance(value.get(key), (str, int)) and not isinstance(value[key], bool)
               and value[key] != "" for key in ALERT_ID_FIELDS) or (
        "service" in value and any(key in value for key in ("created_at", "createdAt"))
    )


def _check_envelope(value: dict[str, Any]) -> None:
    """Reject application errors and partial pages without exposing body values."""
    if value.get("success") is False or value.get("error") or value.get("errors"):
        raise CybleAPIError("Cyble API returned an unsuccessful response.")
    if any(value.get(key) is True for key in ("truncated", "partial", "isPartial", "isTruncated")):
        raise CybleAPIError("Cyble API returned a partial response; the checkpoint must not advance.")


def _extract_alert_rows(payload: dict[str, Any], services: list[str]) -> list[dict[str, Any]]:
    """Find alert records in documented/common envelopes; reject unknown schemas."""
    def visit(value: Any, depth: int = 0) -> list[dict[str, Any]]:
        if depth > 8:
            raise CybleAPIError("Cyble Alerts API envelope nesting exceeds the supported limit.")
        if isinstance(value, list):
            if all(isinstance(item, dict) and _looks_like_alert(item) for item in value):
                return value
            raise CybleAPIError("Cyble Alerts API returned malformed alert records.")
        if not isinstance(value, dict):
            raise CybleAPIError("Cyble Alerts API returned an unsupported alert container.")
        _check_envelope(value)
        if _looks_like_alert(value):
            return [value]
        buckets = [service for service in dict.fromkeys(services) if service in value]
        containers = [key for key in ("data", *ALERT_CONTAINERS) if key in value]
        if buckets:
            if containers or len(buckets) != len(set(services)):
                raise CybleAPIError("Cyble Alerts API returned incomplete or ambiguous service buckets.")
            rows = []
            for service in buckets:
                for row in visit(value[service], depth + 1):
                    if row.get("service") not in (None, "", service):
                        raise CybleAPIError("Cyble Alerts API returned a conflicting service label.")
                    rows.append(dict(row, service=service))
            return rows
        if len(containers) != 1:
            raise CybleAPIError("Cyble Alerts API response shape is ambiguous or unrecognized; no poll checkpoint was saved.")
        return visit(value[containers[0]], depth + 1)

    return visit(payload)


def _check_page_metadata(payload: dict[str, Any], skip: int, take: int, count: int) -> None:
    """Do not let a short, explicitly incomplete page finish a polling window."""
    if count > take:
        raise CybleAPIError("Cyble Alerts API returned more rows than the requested page size.")

    def visit(value: Any, depth: int = 0) -> None:
        if not isinstance(value, dict) or depth > 8 or _looks_like_alert(value):
            return
        _check_envelope(value)
        for key in ("total", "total_count", "totalCount", "total_records", "totalRecords"):
            total = value.get(key)
            if isinstance(total, int) and not isinstance(total, bool):
                if total < skip + count or (count < take and total > skip + count):
                    raise CybleAPIError("Cyble Alerts API pagination metadata is inconsistent; the checkpoint must not advance.")
        if count < take and any(value.get(key) is True for key in ("has_more", "hasMore", "hasNextPage", "next")):
            raise CybleAPIError("Cyble Alerts API returned a short page with more data; the checkpoint must not advance.")
        for key in ("data", "meta", "pagination", *ALERT_CONTAINERS):
            visit(value.get(key), depth + 1)

    visit(payload)


def _check_service_completeness(payload: dict[str, Any], count: int) -> None:
    """Service discovery has no documented pagination; fail if a list is partial."""
    def visit(value: Any, depth: int = 0) -> None:
        if not isinstance(value, dict) or depth > 8:
            return
        _check_envelope(value)
        if any(value.get(key) is True for key in ("has_more", "hasMore", "hasNextPage", "next")):
            raise CybleAPIError("Cyble service discovery returned a partial list.")
        for key in ("total", "total_count", "totalCount", "total_records", "totalRecords"):
            total = value.get(key)
            if isinstance(total, int) and not isinstance(total, bool) and total != count:
                raise CybleAPIError("Cyble service discovery returned inconsistent counts.")
        for key in ("data", "meta", "pagination"):
            visit(value.get(key), depth + 1)

    visit(payload)


class CybleClient:
    """Read-only Cyble API client with bounded retries and verified TLS."""

    def __init__(
        self,
        api_key: str,
        company_uuid: str | None = None,
        session: requests.Session | None = None,
        timeout: tuple[float, float] = (5.0, 60.0),
        retries: int = 3,
        proxies: dict[str, str] | None = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("CYBLE_API_TOKEN is required.")
        self._api_key = api_key.strip()
        self._company_uuid = company_uuid.strip() if company_uuid and company_uuid.strip() else None
        self._session = session or requests.Session()
        self._timeout = timeout
        self._retries = max(0, min(retries, 5))
        self._proxies = proxies

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Referer": "https://cyble.ai/",
            "User-Agent": "cyble-anomali-threatstream-feed/0.4.0",
        }
        retryable = {429, 500, 502, 503, 504}
        url = API_ROOT + path
        for attempt in range(self._retries + 1):
            try:
                response = self._session.request(
                    method,
                    url,
                    headers=headers,
                    json=body,
                    timeout=self._timeout,
                    allow_redirects=False,
                    verify=True,
                    proxies=self._proxies,
                )
            except requests.RequestException as exc:
                if attempt < self._retries:
                    time.sleep(min(2**attempt, 12))
                    continue
                raise CybleAPIError(f"Cyble API network request failed ({type(exc).__name__}).") from None

            if response.status_code in retryable and attempt < self._retries:
                retry_after = response.headers.get("Retry-After", "")
                delay = int(retry_after) if retry_after.isdigit() else min(2**attempt, 12)
                time.sleep(min(max(delay, 1), 30))
                continue
            if response.status_code == 401:
                raise CybleAPIError("Cyble rejected the API token (HTTP 401).", 401)
            if response.status_code == 403:
                raise CybleAPIError("Cyble denied access (HTTP 403); check API permissions and company scope.", 403)
            if response.status_code == 400:
                raise CybleAPIError("Cyble rejected the request (HTTP 400); check the service and date filters.", 400)
            if response.status_code == 429:
                raise CybleAPIError("Cyble rate limit reached (HTTP 429).", 429)
            if response.status_code >= 500:
                raise CybleAPIError(f"Cyble returned a server error (HTTP {response.status_code}).", response.status_code)
            if 300 <= response.status_code < 400:
                raise CybleAPIError(f"Cyble returned an unexpected redirect (HTTP {response.status_code}).", response.status_code)
            if not response.ok:
                raise CybleAPIError(f"Cyble request failed (HTTP {response.status_code}).", response.status_code)
            try:
                return response.json()
            except (ValueError, json.JSONDecodeError):
                raise CybleAPIError("Cyble returned a non-JSON response.", response.status_code) from None
        raise CybleAPIError("Cyble request failed after retries.")

    def get_services(self) -> list[dict[str, Any]]:
        """Return service slugs plus alert eligibility (None means unspecified)."""
        payload = self._request("GET", SERVICES_PATH)
        if not isinstance(payload, dict):
            raise CybleAPIError("Cyble services response has an unsupported shape.")
        _check_envelope(payload)
        data = payload.get("data")
        if isinstance(data, dict):
            _check_envelope(data)
            if "services" in data and "items" in data:
                raise CybleAPIError("Cyble services response contains ambiguous service containers.")
            data = data.get("services", data.get("items"))
        if not isinstance(data, list):
            raise CybleAPIError("Cyble services response has an unsupported shape.")
        _check_service_completeness(payload, len(data))
        services: list[dict[str, Any]] = []
        seen = set()
        for item in data:
            if isinstance(item, str):
                name, display_name, allow_alerts = item, item, None
            elif isinstance(item, dict) and item.get("name"):
                name = item["name"]
                display_name = item.get("displayName", name)
                allow_alerts = item.get("allowAlerts", item.get("allow_alerts"))
                if allow_alerts is not None and not isinstance(allow_alerts, bool):
                    raise CybleAPIError("Cyble services response contains an invalid alert eligibility value.")
            else:
                raise CybleAPIError("Cyble services response contains an invalid service record.")
            if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", name):
                raise CybleAPIError("Cyble services response contains an invalid service name.")
            if name in seen:
                raise CybleAPIError("Cyble services response contains duplicate service names.")
            seen.add(name)
            services.append({"name": name, "display_name": str(display_name), "allow_alerts": allow_alerts})
        return services

    def fetch_page(
        self,
        services: list[str],
        start: str,
        end: str,
        skip: int,
        take: int,
        with_data_message: bool,
        date_field: str = "created_at",
    ) -> list[dict[str, Any]]:
        """Fetch one offset-paginated page of alerts for an explicit service allowlist."""
        if not services:
            raise ValueError("Configure at least one Cyble service in CYBLE_SERVICES.")
        if any(not isinstance(service, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", service)
               for service in services):
            raise ValueError("CYBLE_SERVICES must contain concrete Cyble service slugs.")
        if not self._company_uuid:
            raise ValueError("CYBLE_COMPANY_UUID is required by the live Alerts API endpoint.")
        if not isinstance(take, int) or isinstance(take, bool) or not 1 <= take <= MAX_TAKE:
            raise ValueError(f"CYBLE_PAGE_SIZE must be between 1 and {MAX_TAKE}.")
        if not isinstance(skip, int) or isinstance(skip, bool) or skip < 0:
            raise ValueError("Cyble page offset must be a nonnegative integer.")
        if not isinstance(with_data_message, bool):
            raise ValueError("with_data_message must be a boolean.")
        if with_data_message and take > MAX_DETAIL_TAKE:
            raise ValueError(f"CYBLE_PAGE_SIZE must not exceed {MAX_DETAIL_TAKE} with data messages enabled.")
        if date_field not in {"created_at", "updated_at"}:
            raise ValueError("date_field must be created_at or updated_at.")
        body: dict[str, Any] = {
            "filters": {date_field: {"gte": start, "lte": end}, "service": services},
            "orderBy": [{date_field: "desc"}],
            "skip": skip,
            "take": take,
            "withDataMessage": with_data_message,
        }
        body["companyUuid"] = self._company_uuid
        payload = self._request("POST", ALERTS_PATH, body)
        if not isinstance(payload, dict):
            raise CybleAPIError("Cyble Alerts API returned an unsupported JSON shape.")
        rows = _extract_alert_rows(payload, services)
        for row in rows:
            service = row.get("service")
            if service not in (None, "") and service not in services:
                raise CybleAPIError("Cyble Alerts API returned an unexpected service.")
            if service in (None, "") and len(set(services)) != 1:
                raise CybleAPIError("Cyble Alerts API returned a record without an unambiguous service.")
        _check_page_metadata(payload, skip, take, len(rows))
        return rows
