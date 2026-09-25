"""Read-only client for Cyble Vision Alerts API v2."""

from __future__ import annotations

import json
import time
from typing import Any

import requests


API_ROOT = "https://bifrost.cyble.ai/ar-apollo-v2/api/v2/y"
ALERTS_PATH = "/alerts"
SERVICES_PATH = "/services"
MAX_TAKE = 2000
ALERT_CONTAINERS = ("alerts", "items", "results", "records", "rows")
ALERT_ID_FIELDS = ("id", "uuid", "alertId", "alert_id", "alert_uuid")


class CybleAPIError(RuntimeError):
    """Sanitized Cyble error; response bodies and credentials are never included."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _looks_like_alert(value: dict[str, Any]) -> bool:
    if any(value.get(key) not in (None, "") for key in ALERT_ID_FIELDS):
        return True
    return any(key in value for key in ("service", "status", "severity", "created_at", "createdAt"))


def _extract_alert_rows(payload: dict[str, Any], services: list[str]) -> list[dict[str, Any]]:
    """Find alert records in documented/common envelopes; reject unknown schemas."""
    if payload.get("success") is False or payload.get("error"):
        raise CybleAPIError("Cyble Alerts API returned an unsuccessful response.")

    def visit(value: Any, depth: int = 0) -> list[dict[str, Any]] | None:
        if depth > 8:
            return None
        if isinstance(value, list):
            if not value:
                return []
            if all(isinstance(item, dict) and _looks_like_alert(item) for item in value):
                return value
            return None
        if not isinstance(value, dict):
            return None
        for key in ALERT_CONTAINERS:
            if key in value:
                found = visit(value[key], depth + 1)
                if found is not None:
                    return found
        for service in services:
            if service in value:
                found = visit(value[service], depth + 1)
                if found is not None:
                    return found
        if _looks_like_alert(value):
            return [value]
        for key, child in value.items():
            if key.lower() in {"pagination", "meta", "count", "total_count", "success"}:
                continue
            found = visit(child, depth + 1)
            if found is not None:
                return found
        return None

    root = payload.get("data", payload.get("alerts", payload.get("results", payload)))
    rows = visit(root)
    if rows is None:
        raise CybleAPIError("Cyble Alerts API response shape is not recognized; no poll checkpoint was saved.")
    return rows


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
            "User-Agent": "cyble-anomali-threatstream-feed/0.3.0",
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

    def get_services(self) -> list[dict[str, str]]:
        """Return services available to the configured API token."""
        payload = self._request("GET", SERVICES_PATH)
        if not isinstance(payload, dict) or payload.get("success") is False:
            raise CybleAPIError("Cyble services response has an unsupported shape.")
        data = payload.get("data")
        if isinstance(data, dict):
            data = data.get("services", data.get("items"))
        if not isinstance(data, list):
            raise CybleAPIError("Cyble services response has an unsupported shape.")
        services = []
        for item in data:
            if isinstance(item, str):
                services.append({"name": item, "display_name": item})
            elif isinstance(item, dict) and item.get("name"):
                name = str(item["name"])
                services.append({"name": name, "display_name": str(item.get("displayName", name))})
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
        if not self._company_uuid:
            raise ValueError("CYBLE_COMPANY_UUID is required by the live Alerts API endpoint.")
        if not 1 <= take <= MAX_TAKE:
            raise ValueError(f"CYBLE_PAGE_SIZE must be between 1 and {MAX_TAKE}.")
        if date_field not in {"created_at", "updated_at"}:
            raise ValueError("date_field must be created_at or updated_at.")
        body: dict[str, Any] = {
            "filters": {date_field: {"gte": start, "lte": end}, "service": services},
            "excludes": {"status": ["FALSE_POSITIVE"]},
            "orderBy": [{date_field: "desc"}],
            "skip": skip,
            "take": take,
            "withDataMessage": with_data_message,
        }
        body["companyUuid"] = self._company_uuid
        payload = self._request("POST", ALERTS_PATH, body)
        if not isinstance(payload, dict):
            raise CybleAPIError("Cyble Alerts API returned an unsupported JSON shape.")
        return _extract_alert_rows(payload, services)
