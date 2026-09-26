"""Optional contracts against the licensed Anomali Feed SDK, without network I/O.

Install the vendor-provided 2.8.1 wheel to run these checks. Public CI skips this
module's tests when that proprietary dependency is unavailable. The fixtures are
invented; public resolver addresses are used only to exercise SDK IP validation.
"""

from copy import deepcopy
from contextlib import ExitStack
from datetime import datetime
from importlib import metadata, util
from inspect import Parameter, signature
import json
import logging
import os
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile, TemporaryDirectory
import unittest
from unittest.mock import Mock, patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))

SDK_AVAILABLE = util.find_spec("anomali_feedsdk") is not None
if SDK_AVAILABLE:
    # Importing a licensed SDK must never turn an offline contract check into a
    # network operation. An installed but broken SDK is an error, not a skip.
    with patch("socket.socket.connect", side_effect=AssertionError("Network disabled in SDK contracts")):
        from anomali_feedsdk.models import Indicator, Report
        from anomali_feedsdk.feed import Feed
        from cyble_anomali_feed import _map_alert, _new_feed
        from cyble_sdk import SDK_UPLOAD_TIMEOUT, construct_sdk, ingest_reports, sdk_models


def synthetic_alert():
    return {
        "id": "synthetic-contract-alert-001",
        "service": "iocs",
        "status": "unreviewed",
        "severity": "critical",
        "created_at": "2026-01-02T03:04:05Z",
        "updated_at": "2026-01-03T04:05:06Z",
        "data": {
            "first_seen": "2026-01-01T01:02:03Z",
            "last_seen": "2026-01-03T02:03:04Z",
            "domain": "example.com",
            "ip": "9.9.9.9",
            "sha256": "a" * 64,
            "url": "https://example.com/synthetic",
            "vendor_extension": {"number": 7, "enabled": False, "empty": [], "nullable": None},
        },
    }


@unittest.skipUnless(SDK_AVAILABLE, "Install the licensed anomali_feedsdk 2.8.1 wheel for SDK contracts")
class AnomaliSDKContractTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket.connect", "socket.create_connection", "requests.sessions.Session.request"):
            guard = patch(target, side_effect=AssertionError("Network disabled in SDK contracts"))
            guard.start()
            self.addCleanup(guard.stop)

    def map_alert(self, alert=None, tlp="amber"):
        indicator_factory, report_factory = sdk_models()
        alert = synthetic_alert() if alert is None else alert
        return _map_alert(
            alert, alert["service"], indicator_factory, report_factory, "malware", tlp, {},
        )

    def feed_boundary(self):
        """Mock only remote responses and SDK host caches, retaining real Feed."""
        stack = ExitStack()
        self.addCleanup(stack.close)
        responses = [Mock(), Mock()]
        responses[0].json.return_value = {"name": "synthetic", "organization": {"id": 7},
                                         "config": {"sentinel": "keep"}}
        responses[1].json.return_value = {"objects": [{"id": 11}]}
        transport = stack.enter_context(patch("anomali_feedsdk.feed.make_request_to_ts", side_effect=responses))
        stack.enter_context(patch("anomali_feedsdk.feed.memcached", False))
        stack.enter_context(patch("anomali_feedsdk.feed.os.path.exists", return_value=False))
        stack.enter_context(patch.object(sys, "argv", ["sdk-contract-tests", "--arbitrary-option", "-v"]))
        logging_config = stack.enter_context(patch("anomali_feedsdk.utils.helpers.dictConfig"))
        # These four defaults are captured by the SDK at import time. Keep the
        # caller's proxy/sharing configuration out of an offline synthetic test.
        constructor = Feed.__init__.__wrapped__
        defaults = tuple(None if name in {"trustedcircles", "workgroups", "http_proxy", "https_proxy"}
                         else parameter.default for name, parameter in signature(constructor).parameters.items()
                         if parameter.default is not Parameter.empty)
        stack.enter_context(patch.object(constructor, "__defaults__", defaults))
        return transport, logging_config

    def assert_feed_contract(self, feed, transport, logging_config, root_state):
        self.assertIsInstance(feed, Feed)
        self.assertEqual(feed.feed_id, 123)
        self.assertEqual(feed.organization_id, 7)
        self.assertEqual(feed.user_id, 11)
        self.assertEqual(feed.classification, "private")
        self.assertIs(feed.requests_verify_ssl, True)
        self.assertIs(feed.allow_update, False)
        self.assertEqual(feed.feed_config["sentinel"], "keep")
        self.assertEqual(feed.processed_threat_models, {})
        self.assertIsNone(feed.memcached_client)
        self.assertIsNone(feed.cachefile)
        self.assertIsNone(feed.model_db)
        self.assertEqual([call.args[0] for call in transport.call_args_list],
                         ["https://example.invalid/v1/feed/123/", "https://example.invalid/v1/user/"])
        for call in transport.call_args_list:
            self.assertEqual(call.kwargs["method"], "get")
            self.assertIs(call.kwargs["verify_ssl"], True)
        logging_config.assert_not_called()
        root = logging.getLogger()
        self.assertEqual((root.level, root.handlers, [handler.formatter for handler in root.handlers]), root_state)

    def test_uses_the_supplied_sdk_version(self):
        self.assertEqual(metadata.version("anomali-feedsdk"), "2.8.1")

    def test_real_feed_constructor_loads_config_without_network_or_host_caches(self):
        transport, logging_config = self.feed_boundary()
        root = logging.getLogger()
        root_state = root.level, list(root.handlers), [handler.formatter for handler in root.handlers]
        feed = construct_sdk(Feed, username="synthetic-user", api_key="synthetic-placeholder",
                             api_url="https://example.invalid", feed_id="123", feed_name="synthetic",
                             classification="private", requests_verify_ssl=True, allow_update=False,
                             trustedcircles=None, workgroups=None, http_proxy=None, https_proxy=None)
        self.assert_feed_contract(feed, transport, logging_config, root_state)

    def test_new_feed_preserves_remote_config_and_disables_remote_image_fetching(self):
        transport, logging_config = self.feed_boundary()
        root = logging.getLogger()
        root_state = root.level, list(root.handlers), [handler.formatter for handler in root.handlers]
        with patch.dict(os.environ, {
            "TS_USERNAME": "synthetic-user", "TS_API_KEY": "synthetic-placeholder",
            "TS_API_URL": "https://example.invalid", "TS_FEED_ID": "123", "TS_FEED_NAME": "synthetic",
        }, clear=True):
            feed = _new_feed()
        self.assert_feed_contract(feed, transport, logging_config, root_state)
        self.assertIs(feed.feed_config["tm_body_skip_fetching_images"], True)

    def upload_boundary(self):
        transport, _ = self.feed_boundary()
        feed = construct_sdk(Feed, username="synthetic-user", api_key="synthetic-placeholder",
                             api_url="https://example.invalid", feed_id="123", feed_name="synthetic",
                             classification="private", requests_verify_ssl=True, allow_update=False,
                             trustedcircles=None, workgroups=None, http_proxy=None, https_proxy=None)
        feed.feed_config["tm_body_skip_fetching_images"] = True
        feed.throttling_enabled = False
        feed.throttle_max_minute_ingestions = False
        feed.threat_model_throttling_sleep_time = 0
        feed.tm_batch_upload_interval_ms = 0
        lookup = Mock(status_code=200, content=b"{}", reason="OK", url="https://example.invalid/v1/tipreport/")
        lookup.json.return_value = {"objects": []}
        created = Mock(status_code=201, content=b"{}", reason="Created", url="https://example.invalid/v1/tipreport/")
        created.json.return_value = {"id": 77}
        transport.side_effect = [lookup, created]
        report = self.map_alert({"id": "synthetic-upload", "service": "iocs", "data": {"domain": "example.com"}})
        return feed, report

    def test_real_sdk_csv_upload_receives_finite_timeout_and_preserves_sdk_module(self):
        import requests
        import anomali_feedsdk.feed as feed_module
        original_requests = feed_module.requests
        feed, report = self.upload_boundary()
        accepted = Mock(status_code=201, content=b"{}", reason="Created", url="https://example.invalid/v1/csvfile/")
        accepted.json.return_value = {}
        with TemporaryDirectory() as directory, \
                patch("anomali_feedsdk.feed.NamedTemporaryFile", side_effect=lambda **kwargs: NamedTemporaryFile(dir=directory, **kwargs)), \
                patch.object(requests, "post", return_value=accepted) as upload:
            self.assertEqual(ingest_reports(feed, [report]), (1, 1))
        upload.assert_called_once()
        self.assertEqual(upload.call_args.kwargs["timeout"], SDK_UPLOAD_TIMEOUT)
        self.assertIs(upload.call_args.kwargs["verify"], True)
        self.assertIs(feed_module.requests, original_requests)
        self.assertEqual(feed.processed_threat_models[report.report_id], 77)

    def test_real_sdk_csv_timeout_rejects_batch_despite_accepted_report_id(self):
        import requests
        import anomali_feedsdk.feed as feed_module
        original_requests = feed_module.requests
        feed, report = self.upload_boundary()
        with TemporaryDirectory() as directory, \
                patch("anomali_feedsdk.feed.NamedTemporaryFile", side_effect=lambda **kwargs: NamedTemporaryFile(dir=directory, **kwargs)), \
                patch.object(requests, "post", side_effect=requests.ReadTimeout("SYNTHETIC_PRIVATE_VALUE")) as upload:
            with self.assertRaises(RuntimeError) as raised:
                ingest_reports(feed, [report])
        self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", str(raised.exception))
        self.assertIn("checkpoint was not advanced", str(raised.exception))
        self.assertEqual(upload.call_args.kwargs["timeout"], SDK_UPLOAD_TIMEOUT)
        self.assertEqual(feed.processed_threat_models[report.report_id], 77)
        self.assertIs(feed_module.requests, original_requests)

    def test_sdk_adapter_does_not_parse_cli_or_reconfigure_logging(self):
        with TemporaryDirectory() as directory:
            logfile = Path(directory) / "unexpected-sdk.log"
            with patch.object(sys, "argv", ["sdk-contract-tests", "-v"]), \
                    patch.dict(os.environ, {"LOG_FILE": str(logfile)}), \
                    patch("anomali_feedsdk.utils.helpers.dictConfig") as configure_logging:
                report = self.map_alert()
            self.assertIsInstance(report, Report)
            configure_logging.assert_not_called()
            self.assertFalse(logfile.exists())

    def test_real_report_serializes_markdown_private_tlp_and_timestamps(self):
        alert = synthetic_alert()
        report = self.map_alert(alert)
        self.assertIsInstance(report, Report)
        self.assertIsNotNone(report.threatmodel)
        self.assertTrue(report.report_id)

        payload = report.threatmodel.to_ts_json()
        self.assertEqual(report.threat_model_type, "tipreport")
        self.assertEqual(payload["body"], report.description)
        self.assertIn("```json\n", payload["body"])
        self.assertEqual(payload["body_content_type"], "markdown")
        self.assertIs(payload["is_public"], False)
        self.assertEqual(payload["tlp"], "amber")
        self.assertTrue(str(payload["original_source_id"]).endswith(alert["id"]))
        for key in ("source_created", "source_modified"):
            self.assertIsNotNone(payload[key])
            # SDK 2.8.1 normalizes UTC timestamps without the trailing Z.
            expected = alert["created_at" if key == "source_created" else "updated_at"]
            self.assertEqual(datetime.fromisoformat(payload[key]).replace(tzinfo=None),
                             datetime.fromisoformat(expected.replace("Z", "+00:00")).replace(tzinfo=None))

    def test_real_indicators_recognize_domain_ip_hash_and_url(self):
        report = self.map_alert()
        indicators = {indicator.value: indicator for indicator in report.related_indicators}
        expected = {"example.com", "9.9.9.9", "a" * 64, "https://example.com/synthetic"}
        self.assertEqual(set(indicators), expected)
        for value, indicator in indicators.items():
            with self.subTest(value=value):
                self.assertIsInstance(indicator, Indicator)
                self.assertIsNotNone(indicator.observable)
                self.assertTrue(indicator.itype)
                self.assertEqual(indicator.severity, "very-high")
                self.assertEqual(indicator.source_created[:19], "2026-01-01T01:02:03")
                self.assertEqual(indicator.source_modified[:19], "2026-01-03T02:03:04")
        self.assertIn("domain", indicators["example.com"].itype)
        self.assertIn("ip", indicators["9.9.9.9"].itype)
        self.assertIn("url", indicators["https://example.com/synthetic"].itype)

    def test_unchanged_reports_have_equal_sdk_hashes(self):
        first = self.map_alert()
        replay = self.map_alert(deepcopy(synthetic_alert()))
        self.assertEqual(first.name, replay.name)
        self.assertEqual(first.report_id, replay.report_id)

    def test_changed_alert_keeps_report_name_and_changes_sdk_hash(self):
        alert = synthetic_alert()
        first = self.map_alert(alert)
        changed = deepcopy(alert)
        changed["data"]["vendor_extension"]["number"] = 8
        update = self.map_alert(changed)
        self.assertEqual(first.name, update.name)
        self.assertEqual(first.original_source_id, update.original_source_id)
        self.assertNotEqual(first.report_id, update.report_id)

    def test_structured_fields_survive_real_sdk_serialization_and_secrets_do_not(self):
        alert = synthetic_alert()
        alert["data"]["vendor_extension"]["note"] = "Unicode: café; code fence: ```"
        alert["data"]["credential"] = {"password": "synthetic-value-that-must-be-redacted"}
        report = self.map_alert(alert)
        body = report.threatmodel.to_ts_json()["body"]
        self.assertNotIn("synthetic-value-that-must-be-redacted", body)
        self.assertEqual(body.count("```"), 2)
        fields = json.loads(body.split("```json\n", 1)[1].split("\n```", 1)[0])
        expected = deepcopy(alert)
        expected["data"]["credential"]["password"] = "<redacted:sensitive-field>"
        self.assertEqual(fields, expected)

    def test_alert_without_observables_still_forms_a_real_report(self):
        alert = {"id": "synthetic-no-observables", "service": "new_vulnerability",
                 "data": {"cve": "CVE-2099-1000001", "score": 5.2}}
        report = self.map_alert(alert)
        self.assertIsNotNone(report.threatmodel)
        self.assertTrue(report.report_id)
        self.assertFalse(report.related_indicators)
        self.assertIn("CVE-2099-1000001", report.threatmodel.to_ts_json()["body"])


if __name__ == "__main__":
    unittest.main()
