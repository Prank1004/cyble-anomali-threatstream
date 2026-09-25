"""Durable bounded poll windows and a local single-writer lock.

The caller saves feed configuration after opening a window and after completing
it. This module deliberately performs no HTTP requests or checkpoint writes.
"""

from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator


STATE_KEY = "cyble_state_v1"
DATE_FIELDS = {"created_at", "updated_at"}
UTC = timezone.utc


def _utc_datetime(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("Cyble checkpoint dates must be timezone-aware UTC datetimes.")
    return value.astimezone(UTC)


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40 or "T" not in value:
        raise ValueError("Cyble checkpoint contains an invalid UTC timestamp.")
    try:
        return _utc_datetime(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (ValueError, OverflowError):
        raise ValueError("Cyble checkpoint contains an invalid UTC timestamp.") from None


def _iso(value: datetime) -> str:
    return _utc_datetime(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_service(service: Any) -> None:
    if not isinstance(service, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", service):
        raise ValueError("Cyble checkpoint service must be a concrete service slug.")


class CheckpointState:
    """Keep independent created/updated cursors and restartable service windows."""

    def __init__(
        self,
        config: dict[str, Any],
        scope: str,
        initial_start: datetime,
        window_seconds: int,
        overlap_seconds: int,
    ) -> None:
        if not isinstance(config, dict):
            raise ValueError("Cyble feed configuration must be an object.")
        if not isinstance(scope, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", scope):
            raise ValueError("Cyble checkpoint requires an opaque scope identifier.")
        for value, minimum in ((window_seconds, 1), (overlap_seconds, 0)):
            if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= 366 * 86400:
                raise ValueError("Cyble checkpoint window and overlap must be bounded integer seconds.")
        self._initial_start = _utc_datetime(initial_start)
        now = datetime.now(UTC)
        if self._initial_start > now:
            raise ValueError("Cyble initial checkpoint is in the future.")
        self._window = timedelta(seconds=window_seconds)
        self._overlap = timedelta(seconds=overlap_seconds)
        try:
            self._initial_start - self._overlap
        except OverflowError:
            raise ValueError("Cyble checkpoint overlap exceeds the supported date range.") from None
        if STATE_KEY in config:
            state = copy.deepcopy(config[STATE_KEY])
            self._validate_state(state, scope, now)
        else:
            state = {"version": 1, "scope": scope, "streams": {}}
        self._state = state
        config[STATE_KEY] = state

    @staticmethod
    def _validate_state(state: Any, scope: str, now: datetime) -> None:
        if not isinstance(state, dict) or type(state.get("version")) is not int or state["version"] != 1:
            raise ValueError("Cyble checkpoint state version is unsupported or invalid.")
        if state.get("scope") != scope:
            raise ValueError("Cyble checkpoint scope changed; use a separate feed or explicitly reset its state.")
        if not isinstance(state.get("streams"), dict):
            raise ValueError("Cyble checkpoint streams must be an object.")
        for service, fields in state["streams"].items():
            _validate_service(service)
            if not isinstance(fields, dict) or any(field not in DATE_FIELDS for field in fields):
                raise ValueError("Cyble checkpoint contains an invalid date-field stream.")
            for stream in fields.values():
                if not isinstance(stream, dict) or set(stream) - {"cursor", "pending"}:
                    raise ValueError("Cyble checkpoint stream has an invalid shape.")
                cursor = _parse_timestamp(stream.get("cursor"))
                if cursor > now:
                    raise ValueError("Cyble checkpoint cursor is in the future.")
                if "pending" in stream:
                    pending = stream["pending"]
                    if not isinstance(pending, dict) or set(pending) != {"start", "end"}:
                        raise ValueError("Cyble pending window has an invalid shape.")
                    start = _parse_timestamp(pending["start"])
                    end = _parse_timestamp(pending["end"])
                    if not start <= cursor < end <= now:
                        raise ValueError("Cyble pending window dates are inconsistent or in the future.")
                    if end - cursor > timedelta(days=366) or cursor - start > timedelta(days=366):
                        raise ValueError("Cyble pending window exceeds the supported bounds.")

    def _stream(self, service: str, date_field: str) -> dict[str, Any]:
        _validate_service(service)
        if date_field not in DATE_FIELDS:
            raise ValueError("Cyble checkpoint date field must be created_at or updated_at.")
        fields = self._state["streams"].setdefault(service, {})
        return fields.setdefault(date_field, {"cursor": _iso(self._initial_start)})

    def cursor(self, service: str, date_field: str) -> datetime:
        """Return the independent UTC cursor, initializing new services safely."""
        value = _parse_timestamp(self._stream(service, date_field)["cursor"])
        if value > datetime.now(UTC):
            raise ValueError("Cyble checkpoint cursor is in the future.")
        return value

    def window(self, service: str, date_field: str, now: datetime) -> tuple[str, str] | None:
        """Create a bounded pending window or replay its exact saved bounds."""
        now = _utc_datetime(now)
        if now > datetime.now(UTC):
            raise ValueError("Cyble poll cutoff is in the future.")
        stream = self._stream(service, date_field)
        cursor = self.cursor(service, date_field)
        if cursor > now:
            raise ValueError("Cyble checkpoint cursor is after the current poll cutoff.")
        if "pending" in stream:
            pending = stream["pending"]
            if _parse_timestamp(pending["end"]) > now:
                raise ValueError("Cyble pending window is after the current poll cutoff.")
            return pending["start"], pending["end"]
        if cursor == now:
            return None
        try:
            start = cursor - self._overlap
            end = min(cursor + self._window, now)
        except OverflowError:
            raise ValueError("Cyble checkpoint window exceeds the supported date range.") from None
        stream["pending"] = {"start": _iso(start), "end": _iso(end)}
        return stream["pending"]["start"], stream["pending"]["end"]

    def complete(self, service: str, date_field: str, end_iso: str) -> None:
        """Advance only the exact pending window the caller finished ingesting."""
        stream = self._stream(service, date_field)
        pending = stream.get("pending")
        if not isinstance(pending, dict) or _parse_timestamp(end_iso) != _parse_timestamp(pending["end"]):
            raise ValueError("Cyble checkpoint completion does not match its pending window.")
        if _parse_timestamp(end_iso) > datetime.now(UTC):
            raise ValueError("Cyble checkpoint completion is in the future.")
        stream["cursor"] = pending["end"]
        del stream["pending"]

    def shrink_window(self, service: str, date_field: str, min_seconds: int = 60) -> bool:
        """Split an unfinished high-volume window without advancing its cursor."""
        if not isinstance(min_seconds, int) or isinstance(min_seconds, bool) or not 1 <= min_seconds <= 366 * 86400:
            raise ValueError("Cyble minimum split window must be bounded integer seconds.")
        stream = self._stream(service, date_field)
        pending = stream.get("pending")
        if pending is None:
            return False
        cursor = self.cursor(service, date_field)
        end = _parse_timestamp(pending["end"])
        span = end - cursor
        minimum = timedelta(seconds=min_seconds)
        if span <= minimum:
            return False
        pending["end"] = _iso(cursor + max(span / 2, minimum))
        return True


@contextmanager
def poll_lock(identity: str, directory: str | None = None) -> Iterator[None]:
    """Hold a private POSIX lock for the whole poll; never unlink its inode."""
    if not isinstance(identity, str) or not identity:
        raise ValueError("A connector identity is required for the poll lock.")
    directory = directory or os.environ.get("CYBLE_LOCK_DIR") or os.path.join(
        tempfile.gettempdir(), f"cyble-anomali-locks-{os.getuid()}"
    )
    lock_name = hashlib.sha256(identity.encode("utf-8")).hexdigest() + ".lock"
    directory_fd = lock_fd = None
    try:
        try:
            os.mkdir(directory, mode=0o700)
        except FileExistsError:
            pass
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        directory_stat = os.fstat(directory_fd)
        if directory_stat.st_uid != os.getuid() or stat.S_IMODE(directory_stat.st_mode) & 0o077:
            raise OSError(errno.EACCES, "Unsafe lock directory")
        lock_fd = os.open(
            lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=directory_fd,
        )
        lock_stat = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != os.getuid() or lock_stat.st_nlink != 1:
            raise OSError(errno.EACCES, "Unsafe lock file")
        os.fchmod(lock_fd, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise RuntimeError("Another connector poll is already running for this feed.") from None
            raise
    except (OSError, RuntimeError) as exc:
        if lock_fd is not None:
            os.close(lock_fd)
        if directory_fd is not None:
            os.close(directory_fd)
        if isinstance(exc, RuntimeError):
            raise
        raise RuntimeError("Cannot acquire the connector poll lock; check lock directory ownership and permissions.") from None
    os.close(directory_fd)
    try:
        yield
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
