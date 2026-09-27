"""Continuous Cyble Vision Alerts API v2 to Anomali ThreatStream feed."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import signal
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from cyble_client import CybleAPIError, CybleClient
from cyble_mapping import DEFAULT_MAX_REPORT_BYTES, VALID_TLP, _alert_identifier, _load_field_map, _map_alert, _safe_tag
from cyble_sdk import construct_sdk, ingest_reports as _ingest_reports, quiet_sdk_logger, require_sdk, sdk_models
from cyble_state import STATE_KEY, CheckpointState, poll_lock
from cyble_version import VERSION

LOGGER = logging.getLogger("cyble_anomali_feed")
# Set by SIGTERM/SIGINT. Work stops between pages; unfinished windows resume.
STOP = threading.Event()

RECONCILE_STREAM = "created_at_reconcile"
QUERY_FIELDS = {"created_at": "created_at", "updated_at": "updated_at", RECONCILE_STREAM: "created_at"}
# Rows re-read at each page boundary so records that shift up between offset
# requests are still collected.
PAGE_OVERLAP_ROWS = 10
QUARANTINE_KEY = "cyble_quarantine_v1"
QUARANTINE_LIMIT = 200
RECENT_ALERT_LIMIT = 50_000
DISCOVERY_REFRESH_SECONDS = 3600
MAX_BACKOFF_SECONDS = 900
SLUG_RE = re.compile(r"[a-z0-9_\-]+")


class IncompletePoll(RuntimeError):
    """The window was not fully processed; it stays pending and is retried."""


class WindowTooLarge(IncompletePoll):
    """The page or time limit was reached inside one window; split and retry it."""


class SourceDrift(IncompletePoll):
    """Offset results shifted further than the page overlap; replay the window."""


class StopRequested(Exception):
    """A shutdown signal arrived; unfinished windows stay pending."""


@dataclass
class WindowStats:
    alerts: int = 0
    indicators: int = 0
    unchanged: int = 0
    quarantined: int = 0


@dataclass
class CycleResult:
    completed_windows: int = 0
    alerts: int = 0
    indicators: int = 0
    unchanged: int = 0
    quarantined: int = 0
    failed_streams: int = 0
    deferred_streams: int = 0
    backed_off_streams: int = 0
    backlog: bool = False
    stopped: bool = False


class RecentAlerts:
    """Skip re-sending alerts whose content was already accepted.

    Window overlap, page overlap, the updated_at stream, and the delayed
    re-read all fetch the same alert more than once. Only an accepted report
    is remembered, so a skip never hides an alert ThreatStream has not taken.
    """

    def __init__(self, limit: int = RECENT_ALERT_LIMIT) -> None:
        self._limit = limit
        self._items: OrderedDict[tuple[str, str], str] = OrderedDict()

    @staticmethod
    def digest(alert: Any) -> str | None:
        try:
            encoded = json.dumps(alert, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return None
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def unchanged(self, key: tuple[str, str], digest: str | None) -> bool:
        if digest is None or self._items.get(key) != digest:
            return False
        self._items.move_to_end(key)
        return True

    def remember(self, key: tuple[str, str], digest: str | None) -> None:
        if digest is None:
            return
        self._items[key] = digest
        self._items.move_to_end(key)
        while len(self._items) > self._limit:
            self._items.popitem(last=False)


class StreamHealth:
    """Per-stream failure backoff and turn order, kept across daemon cycles."""

    def __init__(self) -> None:
        self._failures: dict[tuple[str, str], tuple[int, float]] = {}
        self._attempted: dict[tuple[str, str], float] = {}

    def waiting(self, key: tuple[str, str], now: float) -> bool:
        return self._failures.get(key, (0, 0.0))[1] > now

    def attempted(self, key: tuple[str, str]) -> None:
        self._attempted[key] = time.monotonic()

    def failed(self, key: tuple[str, str], interval: int) -> None:
        """Back off a repeatedly failing stream so it cannot flood logs or quotas."""
        count = self._failures.get(key, (0, 0.0))[0] + 1
        self._failures[key] = (count, time.monotonic() + min(interval * 2 ** min(count - 1, 10), MAX_BACKOFF_SECONDS))

    def succeeded(self, key: tuple[str, str]) -> None:
        self._failures.pop(key, None)

    def turn_order(self, key: tuple[str, str], cursor: datetime) -> tuple[float, float, tuple[str, str]]:
        # Least recently attempted first, so a cycle that runs out of budget
        # cannot keep serving the same streams while others never get a turn.
        # Among equals, the stream closest to real time goes first.
        return self._attempted.get(key, float("-inf")), -cursor.timestamp(), key


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


def _discovers_services() -> bool:
    return os.environ.get("CYBLE_SERVICES", "").strip() in {"all", "*"}


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
    if any(not SLUG_RE.fullmatch(value) or value == "all" for value in values):
        raise ValueError("CYBLE_SERVICES must be all, *, or comma-separated service slugs.")
    return list(dict.fromkeys(values))


def _indicator_services() -> frozenset[str] | None:
    """Services scanned for generic IOC keys; None means every service."""
    raw = os.environ.get("CYBLE_INDICATOR_SERVICES", "").strip().lower() or "iocs"
    if raw in {"all", "*"}:
        return None
    if raw == "none":
        return frozenset()
    values = [part.strip() for part in raw.split(",") if part.strip()]
    if not values or any(not SLUG_RE.fullmatch(value) for value in values):
        raise ValueError("CYBLE_INDICATOR_SERVICES must be all, none, or comma-separated service slugs.")
    return frozenset(values)


def _generic_iocs(settings: dict[str, Any], service: str) -> bool:
    return settings["indicator_services"] is None or service in settings["indicator_services"]


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
        # SDK semantics are unverified in a tenant; see docs/anomali-handoff.md.
        allow_update=_env_bool("TS_ALLOW_UPDATE", False),
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
        "overlap": _env_int("CYBLE_OVERLAP_SECONDS", 120, 0, 86400),
        "window": _env_int("CYBLE_WINDOW_MINUTES", 60, 1, 1440) * 60,
        "settle": _env_int("CYBLE_SETTLE_SECONDS", 15, 0, 3600),
        "run_minutes": _env_int("CYBLE_MAX_RUN_MINUTES", 20, 1, 1440),
        "poll_interval": _env_int("CYBLE_POLL_INTERVAL_SECONDS", 60, 5, 3600),
        "reconcile_lag": _env_int("CYBLE_RECONCILE_LAG_HOURS", 24, 0, 168) * 3600,
        "max_report_bytes": _env_int("CYBLE_MAX_REPORT_BYTES", DEFAULT_MAX_REPORT_BYTES, 1024, 20 * 1024 * 1024),
        "with_data": _env_bool("CYBLE_WITH_DATA_MESSAGE", True),
        "sync_updated": _env_bool("CYBLE_SYNC_UPDATED_ALERTS", True),
        "threat_type": os.environ.get("CYBLE_THREAT_TYPE", "malware").strip().lower(),
        "tlp": os.environ.get("CYBLE_TLP", "amber").strip().lower(),
        "content_mode": os.environ.get("CYBLE_CONTENT_MODE", "full").strip().lower(),
        "indicator_services": _indicator_services(),
    }
    if settings["content_mode"] not in {"full", "redacted"}:
        raise ValueError("CYBLE_CONTENT_MODE must be full or redacted.")
    if settings["content_mode"] == "full" and not settings["with_data"]:
        raise ValueError("Full content ingestion requires CYBLE_WITH_DATA_MESSAGE=true.")
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


def _company_scope() -> str:
    company_uuid = os.environ.get("CYBLE_COMPANY_UUID", "").strip()
    if not company_uuid:
        raise ValueError("CYBLE_COMPANY_UUID is required.")
    return hashlib.sha256(company_uuid.encode("utf-8")).hexdigest()


def _lock_identity() -> str:
    return os.environ.get("TS_API_URL", "") + ":" + os.environ.get("TS_FEED_ID", "")


def _page_identity(alert: dict[str, Any]) -> str:
    """Stable alert ID, or a content digest for an alert that lacks one."""
    try:
        return _alert_identifier(alert)
    except ValueError:
        digest = RecentAlerts.digest(alert) or hashlib.sha256(repr(alert).encode("utf-8", "replace")).hexdigest()
        return "sha256:" + digest


def _quarantine(config: dict[str, Any], service: str, stream: str, identity: str, reason: str) -> None:
    """Keep a bounded, content-free record of alerts that could not become bulletins."""
    entries = config.get(QUARANTINE_KEY)
    entries = [entry for entry in entries if isinstance(entry, dict)] if isinstance(entries, list) else []
    entries = [entry for entry in entries if (entry.get("service"), entry.get("alert")) != (service, identity)]
    entries.append({"service": service, "stream": stream, "alert": identity, "reason": reason,
                    "at": _iso_utc(datetime.now(timezone.utc))})
    config[QUARANTINE_KEY] = entries[-QUARANTINE_LIMIT:]


def _deliver(feed: Any, accepted: list[tuple[tuple[str, str], str | None, Any]]) -> tuple[list, list]:
    """Ingest a page of reports; isolate one the destination rejects.

    If the batch fails, reports are retried one at a time and a rejected one is
    set aside for quarantine. Three rejections in a row mean ThreatStream is
    failing, not the data, so the window fails instead of being quarantined.
    """
    try:
        _ingest_reports(feed, [report for _, _, report in accepted])
        return accepted, []
    except RuntimeError:
        if len(accepted) == 1:
            raise
    delivered, undeliverable, streak = [], [], 0
    for item in accepted:
        try:
            _ingest_reports(feed, [item[2]])
        except RuntimeError:
            streak += 1
            if streak >= 3 or len(undeliverable) + 1 == len(accepted):
                raise RuntimeError("Anomali rejected reports individually as well; the window was not advanced.") from None
            undeliverable.append(item)
            continue
        streak = 0
        delivered.append(item)
    return delivered, undeliverable


def _poll_window(client: Any, feed: Any, service: str, stream: str, start: str, end: str,
                 settings: dict[str, Any], hard_deadline: float, models: tuple[Any, Any],
                 field_map: dict[str, Any], recent: RecentAlerts) -> WindowStats:
    """Ingest one fixed window, paging with overlapping offsets.

    Offset pages are not a snapshot: a record leaving the window mid-read
    shifts later rows up. Each page therefore re-reads the previous page's last
    rows. If none of them come back, more rows moved than the overlap covers
    and the window is replayed rather than completed with a gap. Paging ends
    only when the source returns no new rows, so a server-side page cap or
    misleading pagination metadata cannot end a window early.
    """
    Indicator, Report = models
    take = settings["page_size"]
    overlap = min(PAGE_OVERLAP_ROWS, take // 4)
    generic = _generic_iocs(settings, service)
    stats = WindowStats()
    seen: set[str] = set()
    previous: list[str] | None = None
    expect_overlap = False
    skip = attempted = sdk_failures = 0
    for page in range(settings["max_pages"]):
        if STOP.is_set():
            raise StopRequested()
        if time.monotonic() >= hard_deadline:
            raise WindowTooLarge("Run time limit reached inside a window; it will be split and retried.")
        alerts = client.fetch_page(
            services=[service], start=start, end=end, skip=skip, take=take,
            with_data_message=settings["with_data"], date_field=QUERY_FIELDS[stream],
        )
        ids = [_page_identity(alert) for alert in alerts]
        if len(set(ids)) != len(ids):
            raise IncompletePoll("Cyble repeated an alert within one page; the window will be replayed.")
        if expect_overlap and seen.isdisjoint(ids):
            raise SourceDrift("Cyble results shifted beyond the page overlap; the window will be replayed.")
        if not alerts:
            return stats
        if ids == previous:
            raise IncompletePoll("Cyble returned the same page for a new offset; the window will be replayed.")
        fresh = [(identity, alert) for identity, alert in zip(ids, alerts) if identity not in seen]
        seen.update(ids)
        accepted: list[tuple[tuple[str, str], str | None, Any]] = []
        rejected: list[tuple[str, str]] = []
        for identity, alert in fresh:
            key = (service, identity)
            digest = RecentAlerts.digest(alert)
            if recent.unchanged(key, digest):
                stats.unchanged += 1
                continue
            attempted += 1
            try:
                report = _map_alert(alert, service, Indicator, Report, settings["threat_type"], settings["tlp"],
                                    field_map, settings["max_report_bytes"], content_mode=settings["content_mode"],
                                    generic_iocs=generic)
            except (ValueError, TypeError):
                rejected.append((identity, "invalid-alert"))
                continue
            except RuntimeError:
                sdk_failures += 1
                rejected.append((identity, "sdk-model-rejected"))
                continue
            if not getattr(report, "report_id", None) or getattr(report, "threatmodel", None) is None:
                # The ingestion boundary rejects a whole batch for one of these.
                sdk_failures += 1
                rejected.append((identity, "sdk-model-rejected"))
                continue
            accepted.append((key, digest, report))
        # A broken SDK or tenant rejects everything. Do not quarantine a whole
        # window and advance past it; one poison alert is quarantined instead.
        if sdk_failures >= 3 and sdk_failures * 2 > attempted:
            raise IncompletePoll("Most alerts in this window failed SDK model validation; the window was not advanced.")
        if accepted:
            accepted, undeliverable = _deliver(feed, accepted)
            rejected.extend((key[1], "ingest-rejected") for key, _, _ in undeliverable)
            for key, digest, _ in accepted:
                recent.remember(key, digest)
            stats.alerts += len(accepted)
            stats.indicators += sum(len(report.related_indicators or []) for _, _, report in accepted)
        for identity, reason in rejected:
            _quarantine(feed.feed_config, service, stream, identity, reason)
            LOGGER.error("Alert quarantined service=%s stream=%s alert=%s reason=%s",
                         _safe_tag(service), stream, identity, reason)
        stats.quarantined += len(rejected)
        if accepted:
            LOGGER.info("Page accepted service=%s stream=%s page=%d alerts=%d",
                        _safe_tag(service), stream, page + 1, len(accepted))
        if not fresh and len(alerts) < take:
            return stats
        expect_overlap = bool(fresh) and overlap > 0 and len(alerts) > overlap
        skip += len(alerts) - overlap if expect_overlap else len(alerts)
        previous = ids
    raise WindowTooLarge("Page limit reached; the unfinished window will be split and retried.")


def _stream_due(state: CheckpointState, service: str, stream: str, cutoffs: dict[str, datetime],
                window_seconds: int) -> bool:
    cutoff = cutoffs[stream]
    pending_end = state.pending_end(service, stream)
    if pending_end is not None:
        return pending_end <= cutoff
    cursor = state.cursor(service, stream)
    if stream == RECONCILE_STREAM:
        # Settled history is re-read in whole windows, not on every cycle.
        return (cutoff - cursor).total_seconds() >= window_seconds
    return cursor < cutoff


def _run_cycle(client: Any, services: list[str], settings: dict[str, Any], models: tuple[Any, Any],
               field_map: dict[str, Any], recent: RecentAlerts, health: StreamHealth,
               soft_deadline: float, hard_deadline: float) -> CycleResult:
    """Bring every stream up to the current cutoff, one window per stream per round.

    New windows start only before soft_deadline; a window already in progress
    may run until hard_deadline. Completed windows are saved once per round.
    """
    result = CycleResult()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings["settle"])
    cutoffs = {"created_at": cutoff, "updated_at": cutoff,
               RECONCILE_STREAM: cutoff - timedelta(seconds=settings["reconcile_lag"])}
    feed = _new_feed()
    feed.feed_config["cyble_connector_version"] = VERSION
    existing_state = STATE_KEY in feed.feed_config
    state = CheckpointState(feed.feed_config, _company_scope(), _initial_start(cutoff),
                            settings["window"], settings["overlap"])
    # State from before 0.5.0 carries no mode and represents the redacted policy.
    previous_mode = feed.feed_config.get("cyble_content_mode", "redacted" if existing_state else settings["content_mode"])
    if previous_mode not in {"full", "redacted"}:
        raise ValueError("Saved Cyble content mode is invalid; review feed configuration.")
    if previous_mode != settings["content_mode"]:
        state.rewind(_initial_start(cutoff))
        LOGGER.warning("Content mode changed from %s to %s; replaying the configured lookback with stable report "
                       "identities.", previous_mode, settings["content_mode"])
    feed.feed_config["cyble_content_mode"] = settings["content_mode"]
    kinds = ["created_at"]
    if settings["sync_updated"]:
        kinds.append("updated_at")
    if settings["reconcile_lag"]:
        kinds.append(RECONCILE_STREAM)
    streams = [(service, kind) for service in services for kind in kinds]
    # Streams still waiting out a failure backoff are reported, not hidden.
    started = time.monotonic()
    result.backed_off_streams = sum(1 for key in streams if health.waiting(key, started))
    done: set[tuple[str, str]] = set()
    while not (result.backlog or result.stopped):
        now = time.monotonic()
        active = [key for key in streams if key not in done and not health.waiting(key, now)
                  and _stream_due(state, *key, cutoffs, settings["window"])]
        if not active:
            break
        # One window per stream per round, so a busy service cannot hold the
        # cycle while others wait.
        active.sort(key=lambda key: health.turn_order(key, state.cursor(*key)))
        for service, stream in active:
            key = (service, stream)
            if STOP.is_set():
                result.stopped = True
                break
            if time.monotonic() >= soft_deadline:
                result.backlog = True
                break
            health.attempted(key)
            try:
                bounds = state.window(service, stream, cutoffs[stream])
                if bounds is None:
                    done.add(key)
                    continue
                start, end = bounds
                stats = _poll_window(client, feed, service, stream, start, end, settings, hard_deadline,
                                     models, field_map, recent)
            except StopRequested:
                result.stopped = True
                break
            except SourceDrift as exc:
                done.add(key)
                result.deferred_streams += 1
                LOGGER.warning("Window deferred service=%s stream=%s reason=%s", _safe_tag(service), stream, exc)
                continue
            except WindowTooLarge as exc:
                done.add(key)
                if state.shrink_window(service, stream):
                    result.deferred_streams += 1
                    LOGGER.warning("Window split service=%s stream=%s reason=%s", _safe_tag(service), stream, exc)
                    continue
                health.failed(key, settings["poll_interval"])
                result.failed_streams += 1
                LOGGER.error("Stream failed service=%s stream=%s reason=%s (window is already at its minimum span)",
                             _safe_tag(service), stream, exc)
                continue
            except (CybleAPIError, ValueError, RuntimeError) as exc:
                done.add(key)
                health.failed(key, settings["poll_interval"])
                result.failed_streams += 1
                LOGGER.error("Stream failed service=%s stream=%s reason=%s", _safe_tag(service), stream, exc)
                continue
            state.complete(service, stream, end)
            health.succeeded(key)
            result.completed_windows += 1
            result.alerts += stats.alerts
            result.indicators += stats.indicators
            result.unchanged += stats.unchanged
            result.quarantined += stats.quarantined
        # Saved only after ingestion: a crash before this point replays windows
        # (duplicate updates), never skips them.
        _save_feed_config(feed)
    level = logging.WARNING if result.failed_streams or result.backed_off_streams else logging.INFO
    LOGGER.log(level, "Cycle finished services=%d completed_windows=%d alerts=%d unchanged=%d mapped_observables=%d "
               "quarantined=%d failed_streams=%d backed_off_streams=%d deferred_streams=%d backlog=%s",
               len(services), result.completed_windows, result.alerts, result.unchanged, result.indicators,
               result.quarantined, result.failed_streams, result.backed_off_streams, result.deferred_streams,
               result.backlog)
    return result


def _healthy(result: CycleResult) -> bool:
    return not (result.failed_streams or result.backed_off_streams)


def _write_status(result: CycleResult | None, errors: int, last_success: datetime | None, started: float) -> None:
    """Write an optional heartbeat file for external monitoring."""
    path = os.environ.get("CYBLE_STATUS_FILE", "").strip()
    if not path:
        return
    status = {
        "version": VERSION,
        "updated_at": _iso_utc(datetime.now(timezone.utc)),
        "last_success_at": _iso_utc(last_success) if last_success else None,
        "consecutive_cycle_errors": errors,
        "cycle_seconds": round(time.monotonic() - started, 3),
        "last_cycle": asdict(result) if result else None,
    }
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".cyble-status-", dir=os.path.dirname(os.path.abspath(path)))
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(status, handle)
        os.replace(temporary, path)
    except OSError:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
        LOGGER.warning("Could not write CYBLE_STATUS_FILE.")


def run_poll() -> None:
    """Run one bounded ingestion cycle, for scheduler-driven deployments."""
    quiet_sdk_logger()
    settings = _settings()
    client = _client()
    _company_scope()
    services = _configured_services(client)
    models, field_map = sdk_models(), _load_field_map()
    with poll_lock(_lock_identity()):
        started = time.monotonic()
        deadline = started + settings["run_minutes"] * 60
        result = _run_cycle(client, services, settings, models, field_map, RecentAlerts(), StreamHealth(),
                            deadline, deadline)
    _write_status(result, 0, datetime.now(timezone.utc) if _healthy(result) else None, started)
    if result.failed_streams:
        raise IncompletePoll("Some Cyble streams remain pending; completed windows were saved for the next run.")


def run_daemon() -> None:
    """Poll continuously for near-real-time ingestion until SIGTERM or SIGINT."""
    quiet_sdk_logger()
    settings = _settings()
    client = _client()
    _company_scope()
    services = _configured_services(client)
    models, field_map = sdk_models(), _load_field_map()
    recent, health = RecentAlerts(), StreamHealth()
    # Starting new windows stops after this budget so a large backfill is
    # spread over short cycles in which every stream takes a turn.
    cycle_budget = min(settings["run_minutes"] * 60, max(60, 2 * settings["poll_interval"]))
    discovered_at = time.monotonic()
    errors = 0
    last_success: datetime | None = None
    with poll_lock(_lock_identity()):
        LOGGER.info("Continuous ingestion started services=%d interval_seconds=%d",
                    len(services), settings["poll_interval"])
        while not STOP.is_set():
            started = time.monotonic()
            if _discovers_services() and started - discovered_at >= DISCOVERY_REFRESH_SECONDS:
                try:
                    services = _configured_services(client)
                    discovered_at = started
                except (CybleAPIError, ValueError) as exc:
                    LOGGER.error("Service discovery refresh failed; keeping the previous list: %s", exc)
            result = None
            try:
                result = _run_cycle(client, services, settings, models, field_map, recent, health,
                                    started + cycle_budget, started + settings["run_minutes"] * 60)
                errors = 0
                if _healthy(result):
                    last_success = datetime.now(timezone.utc)
            except (CybleAPIError, ValueError, RuntimeError) as exc:
                errors += 1
                LOGGER.error("Ingestion cycle failed consecutive=%d reason=%s", errors, exc)
            except Exception as exc:  # Keep a long-running feed alive; never log a payload.
                errors += 1
                LOGGER.error("Ingestion cycle failed consecutive=%d (%s)", errors, type(exc).__name__)
            _write_status(result, errors, last_success, started)
            if STOP.is_set():
                break
            if errors:
                delay = min(settings["poll_interval"] * 2 ** min(errors - 1, 10), MAX_BACKOFF_SECONDS)
            elif result is not None and result.backlog:
                delay = 0.0
            else:
                delay = max(0.0, settings["poll_interval"] - (time.monotonic() - started))
            STOP.wait(delay)
    LOGGER.info("Continuous ingestion stopped; unfinished windows resume on restart.")


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
                                  field_map, settings["max_report_bytes"], content_mode=settings["content_mode"],
                                  generic_iocs=_generic_iocs(settings, service)) for alert in alerts]
            if any(getattr(report, "threatmodel", None) is None for report in reports):
                raise RuntimeError("SDK report validation failed.")
            LOGGER.info("Dry run service=%s sampled_alerts=%d mapped_observables=%d", _safe_tag(service),
                        len(alerts), sum(len(report.related_indicators or []) for report in reports))
        except (CybleAPIError, ValueError, TypeError, RuntimeError) as exc:
            failed += 1
            LOGGER.error("Dry run failed service=%s reason=%s", _safe_tag(service), exc)
    if failed:
        raise RuntimeError("Dry run encountered service errors; inspect the sanitized status messages.")


def list_services() -> None:
    for service in _client().get_services():
        print(f"{service['name']}\t{service['display_name']}")


def _install_signal_handlers() -> None:
    def request_stop(signum: int, frame: Any) -> None:
        STOP.set()

    for name in ("SIGTERM", "SIGINT"):
        signal.signal(getattr(signal, name), request_stop)


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(message)s")
    # The SDK can log request parameters at DEBUG. Keep its loggers quiet to prevent credential exposure.
    quiet_sdk_logger()
    parser = argparse.ArgumentParser(description="Cyble Vision Alerts API v2 feed for Anomali ThreatStream.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--daemon", action="store_true",
                      help="Run continuously, polling every CYBLE_POLL_INTERVAL_SECONDS until SIGTERM/SIGINT.")
    mode.add_argument("--list-services", action="store_true", help="List Cyble alert services available to the API token, then exit.")
    mode.add_argument("--dry-run", action="store_true", help="Map one recent alert per configured service without writing to ThreatStream.")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    _install_signal_handlers()
    try:
        if args.list_services:
            list_services()
        elif args.dry_run:
            dry_run()
        elif args.daemon:
            run_daemon()
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
