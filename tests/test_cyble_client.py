"""Cyble HTTP boundary regressions using synthetic records; no live API access."""

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))

from cyble_client import CybleAPIError, CybleClient, _extract_alert_rows


def response(payload, status=200, headers=None):
    result = Mock()
    result.status_code = status
    result.ok = 200 <= status < 400
    result.headers = headers or {}
    result.json.return_value = payload
    return result


class AlertEnvelopeTests(unittest.TestCase):
    def test_preserves_every_requested_service_bucket(self):
        payload = {"success": True, "data": {
            "iocs": [{"id": "synthetic-ioc", "data": {"ioc": "example.invalid"}}],
            "github": [{"id": "synthetic-github"}],
        }}
        rows = _extract_alert_rows(payload, ["iocs", "github"])
        self.assertEqual([row["id"] for row in rows], ["synthetic-ioc", "synthetic-github"])
        self.assertEqual([row["service"] for row in rows], ["iocs", "github"])
        self.assertNotIn("service", payload["data"]["iocs"][0])

    def test_accepts_explicit_empty_data_and_service_lists(self):
        for payload in ({"data": []}, {"data": {"iocs": []}}, {"data": {"alerts": []}}):
            with self.subTest(payload=payload):
                self.assertEqual(_extract_alert_rows(payload, ["iocs"]), [])

    def test_rejects_empty_arbitrary_nested_lists(self):
        for payload in ({"data": {"warnings": []}}, {"data": {}}, {"data": None},
                        {"data": {"count": 0}}, {"data": {"error": "synthetic", "items": []}}):
            with self.subTest(payload=payload), self.assertRaises(CybleAPIError):
                _extract_alert_rows(payload, ["iocs"])

    def test_rejects_incomplete_or_ambiguous_envelopes(self):
        for payload, services in (
            ({"data": {"iocs": []}}, ["iocs", "github"]),
            ({"data": {"iocs": [], "alerts": []}}, ["iocs"]),
            ({"data": [], "alerts": [{"id": "synthetic"}]}, ["iocs"]),
            ({"data": {"iocs": [{"id": "synthetic", "service": "github"}]}}, ["iocs"]),
            ({"data": [{"status": "success", "message": "metadata only"}]}, ["iocs"]),
            ({"data": [{"id": "synthetic"}, "malformed-row"]}, ["iocs"]),
            ({"id": "synthetic", "service": "iocs", "data": {"items": [{"id": "nested"}]}}, ["iocs"]),
        ):
            with self.subTest(payload=payload), self.assertRaises(CybleAPIError):
                _extract_alert_rows(payload, services)

    def test_accepts_nested_common_envelope(self):
        payload = {"success": True, "data": {"results": {"rows": [{"id": "synthetic"}]}}}
        self.assertEqual(_extract_alert_rows(payload, ["iocs"]), [{"id": "synthetic"}])

    def test_wrapper_id_does_not_replace_nested_alert_records(self):
        record = {"id": "synthetic-alert", "service": "iocs", "data": {"ioc": "example.invalid"}}
        for nested in (record, [record], {"items": [record]}, {"iocs": {"items": [record]}}):
            with self.subTest(nested=nested):
                rows = _extract_alert_rows({"id": "synthetic-request", "data": nested}, ["iocs"])
                self.assertEqual(rows, [record])
        self.assertEqual(_extract_alert_rows({"id": "synthetic-request", "data": []}, ["iocs"]), [])

    def test_real_alert_preserves_structured_data_and_its_own_id(self):
        record = {"id": "synthetic-alert", "service": "iocs", "created_at": "2026-01-01T00:00:00Z",
                  "data": {"items": [{"id": "nested-source-id", "total": 100}]}}
        self.assertEqual(_extract_alert_rows({"data": [record]}, ["iocs"]), [record])

    def test_rejects_errors_and_partial_responses(self):
        for extra in ({"success": False}, {"error": "synthetic"}, {"errors": ["synthetic"]},
                      {"truncated": True}, {"partial": True}):
            with self.subTest(extra=extra), self.assertRaises(CybleAPIError):
                _extract_alert_rows({"data": [], **extra}, ["iocs"])


class CybleClientTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock(spec=requests.Session)
        self.client = CybleClient("synthetic-test-token", "synthetic-company", session=self.session, retries=1)

    def fetch(self, payload, **changes):
        self.session.request.return_value = response(payload)
        args = dict(services=["iocs"], start="2026-01-01T00:00:00Z", end="2026-01-02T00:00:00Z",
                    skip=0, take=2, with_data_message=True, date_field="updated_at")
        args.update(changes)
        return self.client.fetch_page(**args)

    def test_request_uses_documented_filters_verified_tls_and_all_statuses(self):
        rows = self.fetch({"data": {"iocs": [{"id": "synthetic"}]}})
        self.assertEqual(rows[0]["id"], "synthetic")
        method, url = self.session.request.call_args.args
        kwargs = self.session.request.call_args.kwargs
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/alerts"))
        self.assertEqual(kwargs["json"]["companyUuid"], "synthetic-company")
        self.assertEqual(kwargs["json"]["filters"]["service"], ["iocs"])
        self.assertEqual(kwargs["json"]["orderBy"], [{"updated_at": "desc"}])
        self.assertNotIn("excludes", kwargs["json"])
        self.assertNotIn("countOnly", kwargs["json"])
        self.assertTrue(kwargs["verify"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["headers"]["User-Agent"].endswith("/0.5.0"))

    def test_single_service_payload_preserves_missing_empty_and_null_service_fields(self):
        for fields in ({}, {"service": ""}, {"service": None}, {"service": "iocs"}):
            original = {"id": "synthetic-source", **fields, "data": {"source_key": "unchanged"}}
            with self.subTest(fields=fields):
                self.assertEqual(self.fetch({"data": {"iocs": [original]}}), [original])

    def test_rejects_short_page_that_claims_more_data(self):
        for metadata in ({"total": 3}, {"hasMore": True}, {"next": True}, {"partial": True}):
            with self.subTest(metadata=metadata), self.assertRaises(CybleAPIError):
                self.fetch({"data": [{"id": "synthetic"}], "meta": metadata})

    def test_rejects_incomplete_metadata_inside_service_buckets(self):
        for metadata in ({"total": 100}, {"hasMore": True}, {"pagination": {"total": 100}}):
            for request_id in ({}, {"id": "synthetic-request"}):
                payload = {**request_id, "data": {"iocs": {"items": [{"id": "synthetic"}], **metadata}}}
                with self.subTest(payload=payload), self.assertRaises(CybleAPIError):
                    self.fetch(payload)

    def test_rejects_malformed_recognized_pagination_metadata(self):
        cases = [(key, bad) for key in ('total', 'total_count', 'totalCount', 'total_records', 'totalRecords')
                 for bad in ('100', '', None, True, 1.0, -1, [], {})]
        cases += [(key, bad) for key in ('has_more', 'hasMore', 'hasNextPage', 'next')
                  for bad in ('true', 'false', None, 1, 0, [], {})]
        for key, bad in cases:
            for records in ([], [{'id': 'synthetic'}]):
                for payload in (
                    {'data': records, 'meta': {key: bad}},
                    {'data': records, 'pagination': {'id': 'synthetic-request', key: bad}},
                    {'data': {'iocs': {'items': records, key: bad}}},
                ):
                    with self.subTest(key=key, bad=bad, payload=payload), self.assertRaises(CybleAPIError):
                        self.fetch(payload)

    def test_accepts_well_typed_empty_final_pagination_metadata(self):
        payload = {'data': {'iocs': {'items': [], 'total': 0, 'has_more': False, 'next': False}}}
        self.assertEqual(self.fetch(payload), [])

    def test_service_bucket_metadata_uses_each_buckets_record_count(self):
        payload = {"data": {
            "iocs": {"items": [{"id": "synthetic-one"}], "total": 1},
            "github": {"items": [{"id": "synthetic-two"}], "total": 1},
        }}
        self.assertEqual(len(self.fetch(payload, services=["iocs", "github"])), 2)
        payload["data"]["iocs"]["total"] = 100
        with self.assertRaises(CybleAPIError):
            self.fetch(payload, services=["iocs", "github"])

    def test_final_service_page_and_actual_alert_metadata_are_preserved(self):
        record = {"id": "synthetic", "service": "iocs", "created_at": "2026-01-01T00:00:00Z",
                  "data": {"items": [{"total": 100}]}}
        payload = {"data": {"iocs": {"items": [record], "meta": {"total": 3}}}}
        self.assertEqual(self.fetch(payload, skip=2), [record])

    def test_rejects_more_rows_than_requested_and_inconsistent_totals(self):
        for payload in (
            {"data": [{"id": "one"}, {"id": "two"}, {"id": "three"}]},
            {"data": [{"id": "one"}], "pagination": {"total": 0}},
        ):
            with self.subTest(payload=payload), self.assertRaises(CybleAPIError):
                self.fetch(payload)

    def test_accepts_final_short_page_with_consistent_metadata(self):
        self.assertEqual(len(self.fetch({"data": [{"id": "synthetic"}], "meta": {"total": 3}}, skip=2)), 1)

    def test_rejects_cross_service_rows_and_unattributed_multiservice_records(self):
        with self.assertRaises(CybleAPIError):
            self.fetch({"data": [{"id": "synthetic", "service": "github"}]})
        with self.assertRaises(CybleAPIError):
            self.fetch({"data": [{"id": "synthetic"}]}, services=["iocs", "github"])

    def test_rejects_invalid_pagination_before_network_access(self):
        for changes in ({"skip": -1}, {"skip": True}, {"take": True}, {"take": 0},
                        {"take": 201}, {"take": 2001, "with_data_message": False},
                        {"with_data_message": "true"}, {"services": ["all"] , "date_field": "bad"},
                        {"services": ["*"]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.fetch({"data": []}, **changes)
        self.session.request.assert_not_called()

    @patch("cyble_client.time.sleep")
    def test_retries_rate_limits_with_bounded_retry_after(self, sleep):
        self.session.request.side_effect = [response({}, 429, {"Retry-After": "999"}), response({"data": []})]
        result = self.client._request("GET", "/services")
        self.assertEqual(result, {"data": []})
        self.assertEqual(self.session.request.call_count, 2)
        sleep.assert_called_once_with(30)

    @patch("cyble_client.time.sleep")
    def test_network_error_does_not_expose_exception_details(self, sleep):
        self.session.request.side_effect = requests.ConnectionError("synthetic-secret-must-not-appear")
        with self.assertRaises(CybleAPIError) as raised:
            self.client._request("GET", "/services")
        self.assertNotIn("synthetic-secret", str(raised.exception))
        self.assertEqual(self.session.request.call_count, 2)

    def test_auth_errors_are_not_retried_or_leaked(self):
        self.session.request.return_value = response({"error": "synthetic-sensitive-body"}, 403)
        with self.assertRaises(CybleAPIError) as raised:
            self.client._request("GET", "/services")
        self.assertEqual(raised.exception.status_code, 403)
        self.assertNotIn("synthetic-sensitive-body", str(raised.exception))
        self.session.request.assert_called_once()

    def test_redirect_and_nonjson_responses_fail_closed(self):
        self.session.request.return_value = response({}, 302)
        with self.assertRaises(CybleAPIError):
            self.client._request("GET", "/services")
        self.session.request.return_value = response({})
        self.session.request.return_value.json.side_effect = ValueError("sensitive body")
        with self.assertRaises(CybleAPIError) as raised:
            self.client._request("GET", "/services")
        self.assertNotIn("sensitive body", str(raised.exception))

    def test_service_discovery_preserves_alert_eligibility(self):
        self.session.request.return_value = response({"success": True, "data": [
            {"name": "iocs", "displayName": "IOCs", "allowAlerts": True},
            {"name": "lookup", "allowAlerts": False},
            {"name": "github"},
        ]})
        services = self.client.get_services()
        self.assertEqual([item["allow_alerts"] for item in services], [True, False, None])
        self.assertEqual(services[0]["display_name"], "IOCs")

    def test_service_discovery_rejects_invalid_or_partial_catalogs(self):
        for payload in (
            {"data": [{"name": "iocs", "allowAlerts": "false"}]},
            {"data": [{"name": "iocs"}, {"name": "iocs"}]},
            {"data": [{"displayName": "Missing slug"}]},
            {"data": ["iocs"], "meta": {"total": 3}},
            {"data": ["iocs"], "pagination": {"hasMore": True}},
            {"data": [], "error": "synthetic failure"},
        ):
            with self.subTest(payload=payload), self.assertRaises(CybleAPIError):
                self.session.request.return_value = response(payload)
                self.client.get_services()


if __name__ == "__main__":
    unittest.main()
