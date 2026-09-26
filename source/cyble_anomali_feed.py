"""Scheduled Cyble Vision Alerts API v2 to Anomali ThreatStream feed."""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from cyble_client import CybleAPIError, CybleClient
from cyble_mapping import DEFAULT_MAX_REPORT_BYTES, VALID_TLP, _alert_identifier, _load_field_map, _map_alert, _safe_tag
from cyble_sdk import construct_sdk, ingest_reports as _ingest_reports, quiet_sdk_logger, require_sdk, sdk_models
from cyble_state import CheckpointState, poll_lock

VERSION = "0.4.1"
LOGGER = logging.getLogger("cyble_anomali_feed")


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


def _configured_services(client: Any = None) -> list[str]:
    values = [part.strip() for part in os.environ.get("CYBLE_SERVICES", "").split(",") if part.strip()]
    if not values:
        raise ValueError("CYBLE_SERVICES must explicitly list the Cyble alert services to ingest.")
    if values in (["all"], ["*"]):
        if client is None:
            raise ValueError("Cyble service discovery requires an initialized API client.")
        services = [item["name"] for item in client.get_services() if item.get("allow_alerts") is True]
        if not services:
            raise ValueError("Cyble did not explicitly mark any discovered services as alert-enabled.")
        return sorted(set(services))
    if any(not re.fullmatch(r"[a-z0-9_\-]+", value) or value == "all" for value in values):
        raise ValueError("CYBLE_SERVICES must be all, *, or comma-separated service slugs.")
    return list(dict.fromkeys(values))


def _proxies_from_environment() -> dict[str, str] | None:
    proxies = {}
    for scheme, name in (("http", "HTTP_PROXY"), ("https", "HTTPS_PROXY")):
        if os.environ.get(name):
            proxies[scheme] = os.environ[name]
    return proxies or None


def _new_feed() -> Any:
    require_sdk()
    for name in ("TS_USERNAME", "TS_API_KEY", "TS_API_URL", "TS_FEED_ID", "TS_FEED_NAME"):
        if not os.environ.get(name, "").strip():
            raise ValueError(f"{name} is required.")
    parsed_url = urlsplit(os.environ["TS_API_URL"])
    if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment:
        raise ValueError("TS_API_URL must be an HTTPS API endpoint without embedded credentials, query, or fragment.")
    try:
        from anomali_feedsdk.feed import Feed
    except ImportError:
        raise RuntimeError(
            "Anomali Feed SDK 2.8.1 is required. Install the vendor-provided wheel outside this repository."
        ) from None
    feed = construct_sdk(Feed,
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
    if not isinstance(getattr(feed, "feed_config", None), dict):
        raise RuntimeError("Anomali did not return a usable feed configuration.")
    feed.feed_config["tm_body_skip_fetching_images"] = True
    return feed


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
    if response.status_code not in {200, 201, 204}:
        raise RuntimeError(f"ThreatStream feed checkpoint update failed (HTTP {response.status_code}).")
    if response.content:
        try:
            payload = response.json()
        except ValueError:
            raise RuntimeError("ThreatStream checkpoint response was not valid JSON.") from None
        if isinstance(payload, dict) and (payload.get("success") is False or payload.get("error")):
            raise RuntimeError("ThreatStream rejected the feed checkpoint update.")


def _initial_start(now: datetime) -> datetime:
    hours = _env_int("CYBLE_INITIAL_LOOKBACK_HOURS", 24, 1, 24 * 365)
    return now - timedelta(hours=hours)


def _settings() -> dict[str, Any]:
    settings = {
        "page_size": _env_int("CYBLE_PAGE_SIZE", 200, 1, 2000),
        "max_pages": _env_int("CYBLE_MAX_PAGES_PER_SERVICE", 100, 1, 10000),
        "overlap": _env_int("CYBLE_OVERLAP_SECONDS", 300, 0, 86400),
        "window": _env_int("CYBLE_WINDOW_MINUTES", 60, 1, 1440) * 60,
        "settle": _env_int("CYBLE_SETTLE_SECONDS", 60, 0, 3600),
        "run_minutes": _env_int("CYBLE_MAX_RUN_MINUTES", 20, 1, 1440),
        "max_report_bytes": _env_int("CYBLE_MAX_REPORT_BYTES", DEFAULT_MAX_REPORT_BYTES, 1024, 20 * 1024 * 1024),
        "with_data": _env_bool("CYBLE_WITH_DATA_MESSAGE", True),
        "sync_updated": _env_bool("CYBLE_SYNC_UPDATED_ALERTS", True),
        "threat_type": os.environ.get("CYBLE_THREAT_TYPE", "malware").strip().lower(),
        "tlp": os.environ.get("CYBLE_TLP", "amber").strip().lower(),
    }
    if settings["with_data"] and settings["page_size"] > 200:
        raise ValueError("Keep CYBLE_PAGE_SIZE at 200 or less when CYBLE_WITH_DATA_MESSAGE=true.")
    if settings["overlap"] >= settings["window"]:
        raise ValueError("CYBLE_OVERLAP_SECONDS must be smaller than CYBLE_WINDOW_MINUTES.")
    if settings["tlp"] not in VALID_TLP:
        raise ValueError("CYBLE_TLP must be one of amber, green, red, or white.")
    if not settings["threat_type"]:
        raise ValueError("CYBLE_THREAT_TYPE cannot be empty.")
    return settings


def _client() -> CybleClient:
    return CybleClient(
        api_key=os.environ.get("CYBLE_API_TOKEN", ""),
        company_uuid=os.environ.get("CYBLE_COMPANY_UUID"),
        proxies=_proxies_from_environment(),
    )


def _poll_window(client: Any, feed: Any, service: str, date_field: str,
                 start: str, end: str, settings: dict[str, Any], deadline: float,
                 Indicator: Any, Report: Any, field_map: dict[str, Any]) -> tuple[int, int]:
    skip = total_indicators = 0
    seen_ids: set[str] = set()
    for page in range(settings["max_pages"]):
        if time.monotonic() >= deadline:
            raise IncompletePoll("Run time budget reached; unfinished windows remain pending.")
        alerts = client.fetch_page(
            services=[service], start=start, end=end, skip=skip,
            take=settings["page_size"], with_data_message=settings["with_data"], date_field=date_field,
        )
        if not alerts:
            return skip, total_indicators
        page_ids = [_alert_identifier(alert) for alert in alerts]
        if len(set(page_ids)) != len(page_ids) or seen_ids.intersection(page_ids):
            raise IncompletePoll("Cyble repeated an alert across pages; the window will be replayed.")
        seen_ids.update(page_ids)
        reports = [
            _map_alert(alert, service, Indicator, Report, settings["threat_type"], settings["tlp"],
                       field_map, settings["max_report_bytes"])
            for alert in alerts
        ]
        if time.monotonic() >= deadline:
            raise IncompletePoll("Run time budget reached before upload; the window remains pending.")
        _ingest_reports(feed, reports)
        skip += len(alerts)
        total_indicators += sum(len(report.related_indicators or []) for report in reports)
        LOGGER.info("Page accepted service=%s date_field=%s page=%d alerts=%d",
                    _safe_tag(service), date_field, page + 1, len(alerts))
        if len(alerts) < settings["page_size"]:
            return skip, total_indicators
    raise IncompletePoll("Page limit reached; the unfinished window will be split and retried.")


def run_poll() -> None:
    quiet_sdk_logger()
    settings = _settings()
    client = _client()
    company_uuid = os.environ.get("CYBLE_COMPANY_UUID", "").strip()
    if not company_uuid:
        raise ValueError("CYBLE_COMPANY_UUID is required.")
    services = _configured_services(client)
    lock_identity = os.environ.get("TS_API_URL", "") + ":" + os.environ.get("TS_FEED_ID", "")
    with poll_lock(lock_identity):
        deadline = time.monotonic() + settings["run_minutes"] * 60
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings["settle"])
        feed = _new_feed()
        feed.feed_config["cyble_connector_version"] = VERSION
        state = CheckpointState(
            feed.feed_config, hashlib.sha256(company_uuid.encode("utf-8")).hexdigest(),
            _initial_start(cutoff), settings["window"], settings["overlap"],
        )
        Indicator, Report = sdk_models()
        field_map = _load_field_map()
        fields = ["created_at", "updated_at"] if settings["sync_updated"] else ["created_at"]
        streams = [(service, field) for service in services for field in fields]
        failed: set[tuple[str, str]] = set()
        completed_windows = total_alerts = total_indicators = 0
        while True:
            active = [stream for stream in streams if stream not in failed and state.cursor(*stream) < cutoff]
            if not active:
                break
            # One bounded window per stream per round prevents a busy service from
            # consuming the entire backfill while other services never advance.
            for service, date_field in sorted(active, key=lambda stream: (state.cursor(*stream), stream)):
                if time.monotonic() >= deadline:
                    raise IncompletePoll("Run time budget reached; completed windows were saved and unfinished streams will resume.")
                bounds = state.window(service, date_field, cutoff)
                if bounds is None:
                    continue
                start, end = bounds
                _save_feed_config(feed)  # Persist the fixed window before requesting any pages.
                try:
                    alerts, indicators = _poll_window(
                        client, feed, service, date_field, start, end, settings, deadline,
                        Indicator, Report, field_map,
                    )
                except (CybleAPIError, ValueError, RuntimeError) as exc:
                    if isinstance(exc, IncompletePoll) and state.shrink_window(service, date_field):
                        _save_feed_config(feed)
                    failed.add((service, date_field))
                    LOGGER.error("Stream failed service=%s date_field=%s reason=%s", _safe_tag(service), date_field, exc)
                    continue
                state.complete(service, date_field, end)
                _save_feed_config(feed)  # An SDK failure never reaches this checkpoint advancement.
                completed_windows += 1
                total_alerts += alerts
                total_indicators += indicators
        LOGGER.info("Poll finished services=%d completed_windows=%d alerts=%d mapped_observables=%d failed_streams=%d",
                    len(services), completed_windows, total_alerts, total_indicators, len(failed))
        if failed:
            raise IncompletePoll("Some Cyble streams remain pending; successful service windows were saved for the next scheduled run.")


def dry_run() -> None:
    """Validate one recent source record per configured service without any TS write."""
    settings = _settings()
    client = _client()
    services = _configured_services(client)
    Indicator, Report = sdk_models()
    field_map = _load_field_map()
    end = datetime.now(timezone.utc) - timedelta(seconds=settings["settle"])
    start = _initial_start(end)
    failed = 0
    for service in services:
        try:
            alerts = client.fetch_page(
                services=[service], start=_iso_utc(start), end=_iso_utc(end), skip=0, take=1,
                with_data_message=settings["with_data"], date_field="created_at",
            )
            reports = [_map_alert(alert, service, Indicator, Report, settings["threat_type"], settings["tlp"],
                                  field_map, settings["max_report_bytes"]) for alert in alerts]
            if any(getattr(report, "threatmodel", None) is None for report in reports):
                raise RuntimeError("SDK report validation failed.")
            LOGGER.info("Dry run service=%s sampled_alerts=%d mapped_observables=%d", _safe_tag(service),
                        len(alerts), sum(len(report.related_indicators or []) for report in reports))
        except (CybleAPIError, ValueError, RuntimeError) as exc:
            failed += 1
            LOGGER.error("Dry run failed service=%s reason=%s", _safe_tag(service), exc)
    if failed:
        raise RuntimeError("Dry run encountered service errors; inspect the sanitized status messages.")


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
    quiet_sdk_logger()
    parser = argparse.ArgumentParser(description="Scheduled Cyble Vision Alerts API v2 feed for Anomali ThreatStream.")
    parser.add_argument("--list-services", action="store_true", help="List Cyble alert services available to the API token, then exit.")
    parser.add_argument("--dry-run", action="store_true", help="Map one recent alert per configured service without writing to ThreatStream.")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    try:
        if args.list_services:
            list_services()
        elif args.dry_run:
            dry_run()
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
