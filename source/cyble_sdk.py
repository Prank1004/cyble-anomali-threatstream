"""Small compatibility boundary for the proprietary Anomali Feed SDK 2.8.1."""

from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from importlib.metadata import PackageNotFoundError, version
from threading import RLock
from typing import Any


SDK_UPLOAD_TIMEOUT = (5, 120)
_SDK_TRANSPORT_LOCK = RLock()


class _UploadRequestsProxy:
    """Delegate requests attributes while bounding the SDK's direct CSV POST."""

    def __init__(self, transport: Any) -> None:
        self._transport = transport

    def __getattr__(self, name: str) -> Any:
        return getattr(self._transport, name)

    def post(self, *args: Any, **kwargs: Any) -> Any:
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = SDK_UPLOAD_TIMEOUT
        return self._transport.post(*args, **kwargs)


@contextmanager
def _bounded_sdk_upload():
    """Temporarily scope the SDK 2.8.1 upload workaround to its Feed module.

    That version supplies timeouts to its HTTP helper but omits one on its
    direct CSV requests.post call. Preserve its transport/exception contract;
    never replace global requests functions or requests.Session. These are
    connect/read inactivity limits, not an absolute ingestion deadline.
    """
    with _SDK_TRANSPORT_LOCK:
        module = sys.modules.get("anomali_feedsdk.feed")
        if module is None:
            # Allows dependency-free adapter tests; a real Feed has already
            # imported this module before reaching the ingestion boundary.
            yield
            return
        original = module.requests
        module.requests = _UploadRequestsProxy(original)
        try:
            yield
        finally:
            module.requests = original


class SDKFailureCapture(logging.Handler):
    """Remember SDK failure severity without retaining or emitting its messages."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.failed = False

    def emit(self, record: logging.LogRecord) -> None:
        self.failed = True


def quiet_sdk_logger() -> logging.Logger:
    # The SDK may authenticate with query parameters. HTTP debug/retry logs must
    # not expose those URLs even when the connector's own LOG_LEVEL is DEBUG.
    for name in ("urllib3", "requests"):
        network_logger = logging.getLogger(name)
        network_logger.handlers = [logging.NullHandler()]
        network_logger.propagate = False
    logger = logging.getLogger("anomali_feedsdk")
    for name, child in logging.Logger.manager.loggerDict.items():
        if name == "anomali_feedsdk" or name.startswith("anomali_feedsdk."):
            if not isinstance(child, logging.Logger):
                continue
            child.disabled = False
            for handler in list(child.handlers):
                if not isinstance(handler, (logging.NullHandler, SDKFailureCapture)):
                    child.removeHandler(handler)
            if child is not logger:
                child.propagate = True
                child.setLevel(logging.NOTSET)
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    # A handler also prevents Python's lastResort handler from printing vendor
    # errors during initialization, before an ingestion capture is installed.
    if not any(isinstance(handler, logging.NullHandler) for handler in logger.handlers):
        logger.addHandler(logging.NullHandler())
    return logger


def require_sdk() -> None:
    quiet_sdk_logger()
    try:
        installed = version("anomali-feedsdk")
    except PackageNotFoundError:
        raise RuntimeError("Install the vendor-provided Anomali Feed SDK 2.8.1 wheel in the feed runtime.") from None
    if installed != "2.8.1":
        raise RuntimeError("This connector requires the validated Anomali Feed SDK version 2.8.1.")


def construct_sdk(model: Any, *, strict: bool = True, **kwargs: Any) -> Any:
    """Use the actual SDK constructor without its CLI/global-logging decorator.

    In 2.8.1 the configure_logging decorator parses process arguments and replaces
    root log handlers on every Feed, Report, and Indicator construction. Calling
    its functools.wraps entry point preserves constructor behavior while keeping
    connector logging private and leaving the host's CLI untouched.
    """
    constructor = getattr(model.__init__, "__wrapped__", None)
    if constructor is None:
        raise RuntimeError("The Anomali SDK constructor contract has changed.")
    logger = quiet_sdk_logger()
    capture = SDKFailureCapture()
    logger.addHandler(capture)
    try:
        instance = model.__new__(model)
        constructor(instance, **kwargs)
    except Exception:
        raise RuntimeError("Anomali SDK initialization or model validation failed; no SDK payload was logged.") from None
    finally:
        logger.removeHandler(capture)
    if strict and capture.failed:
        raise RuntimeError("Anomali SDK initialization or model validation reported a warning/error.")
    return instance


def sdk_models() -> tuple[Any, Any]:
    require_sdk()
    from anomali_feedsdk.models import Indicator, Report

    def indicator(**kwargs: Any) -> Any:
        return construct_sdk(Indicator, strict=False, **kwargs)

    def report(**kwargs: Any) -> Any:
        return construct_sdk(Report, **kwargs)

    return indicator, report


def ingest_reports(feed: Any, reports: list[Any]) -> tuple[int, int]:
    """Accept an SDK batch only when every report has a persisted platform ID."""
    if not reports:
        return 0, 0
    unique = {}
    for report in reports:
        report_id = getattr(report, "report_id", None)
        if not report_id or getattr(report, "threatmodel", None) is None:
            raise RuntimeError("Anomali rejected a mapped report before ingestion; its checkpoint was not advanced.")
        unique[report_id] = report
    logger = quiet_sdk_logger()
    capture = SDKFailureCapture()
    logger.addHandler(capture)
    try:
        with _bounded_sdk_upload():
            result = feed.ingest_reports(list(unique.values()))
    except Exception:
        raise RuntimeError("Anomali report ingestion failed; its checkpoint was not advanced.") from None
    finally:
        logger.removeHandler(capture)
    if capture.failed:
        raise RuntimeError("Anomali reported an ingestion warning/error; its checkpoint was not advanced.")
    if not isinstance(result, tuple) or len(result) != 2 or any(type(n) is not int or n < 0 for n in result):
        raise RuntimeError("Anomali returned an unrecognized ingestion result; its checkpoint was not advanced.")
    accepted = getattr(feed, "processed_threat_models", {})
    if not isinstance(accepted, dict) or any(
        type(accepted.get(report_id)) is not int or accepted[report_id] <= 0 for report_id in unique
    ):
        raise RuntimeError("Anomali did not accept every report; its checkpoint was not advanced.")
    # A zero count can mean the SDK accepted an unchanged cached report. The
    # processed IDs above establish report acceptance; IOC processing is async.
    return result
