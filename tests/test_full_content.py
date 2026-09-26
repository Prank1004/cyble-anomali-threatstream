"""Synthetic checks for exact private source content and sanitized derived fields."""

from copy import deepcopy
from importlib import util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))

from cyble_mapping import _map_alert


def indicator(**kwargs):
    return SimpleNamespace(**kwargs, observable=kwargs["value"], itype="test")


def report(**kwargs):
    return SimpleNamespace(**kwargs)


def mapped(alert, **kwargs):
    return _map_alert(alert, "iocs", indicator, report, "malware", "amber", {},
                      content_mode="full", **kwargs)


def source_body(model):
    return json.loads(model.description.split("```json\n", 1)[1].split("\n```", 1)[0])


class FullContentTests(unittest.TestCase):
    def test_exact_source_types_values_and_json_strings_round_trip(self):
        alert = {
            "id": "synthetic-full-1", "service": "iocs", "severity": "HIGH",
            "number": 9007199254740993, "fraction": 1.25, "enabled": False,
            "empty": None, "empty_array": [], "empty_object": {},
            "unknown_extension": [{"label": "مرحبا 🔎", "nested": [0, True, None, ["value"]]}],
            "data": '{"token":"SYNTHETIC_SOURCE_TOKEN","enabled":false}',
            "raw_text": "Unparsed source line\r\nAnother line\t: value",
            "password": "SYNTHETIC_SOURCE_PASSWORD", "token": None,
        }
        result = mapped(alert)
        self.assertEqual(source_body(result), alert)
        self.assertIsInstance(source_body(result)["data"], str)
        self.assertIs(source_body(result)["enabled"], False)
        self.assertIsNone(source_body(result)["token"])
        self.assertFalse(result.is_public)
        self.assertEqual(result.tlp, "amber")

    def test_source_credentials_and_raw_text_stay_out_of_derived_fields(self):
        password = "SYNTHETIC_PRIVATE_PASSWORD"
        token = "SYNTHETIC_PRIVATE_TOKEN"
        alert = {
            "id": "synthetic-full-1", "service": "iocs",
            "password": password, "data": {"access_token": token, "domain": "example.invalid"},
            "content": "person@example.invalid:" + password,
            "message": "Authorization: Bearer " + token,
            "description": "password=" + password,
            "reference_link": "https://example.invalid/?access_token=" + token,
            "credentials": {"domain": "credential.example.invalid", "url": "https://example.invalid/?token=" + token},
        }
        result = mapped(alert)
        self.assertEqual(source_body(result), alert)
        summary = result.description.split("```json\n", 1)[0]
        for sensitive in (password, token, "person@example.invalid", "credential.example.invalid"):
            self.assertNotIn(sensitive, summary)
            self.assertNotIn(sensitive, json.dumps(result.tags))
            self.assertNotIn(sensitive, json.dumps([vars(item) for item in result.related_indicators]))
        self.assertEqual([item.value for item in result.related_indicators], ["example.invalid"])

    def test_custom_mapping_cannot_copy_credentials_to_context_or_indicators(self):
        alert = {"id": "synthetic-full-1", "service": "iocs",
                 "credentials": {"domain": "credential.example.invalid"},
                 "api_key": "SYNTHETIC_PRIVATE_TOKEN"}
        field_map = {"default": {
            "ioc_rules": [{"value_path": "credentials.domain", "type": "domain"}],
            "context_paths": [{"path": "api_key", "label": "Custom"}],
        }}
        result = _map_alert(alert, "iocs", indicator, report, "malware", "amber", field_map,
                            content_mode="full")
        self.assertEqual(source_body(result), alert)
        self.assertEqual(result.related_indicators, [])
        self.assertNotIn("SYNTHETIC_PRIVATE_TOKEN", result.description.split("```json\n", 1)[0])

    def test_distinct_sensitive_field_names_do_not_collide_in_full_mode(self):
        alert = {"id": "synthetic-full-1", "service": "iocs", "accounts": {
            "one@example.invalid": {"password": "SYNTHETIC_PASSWORD_ONE"},
            "two@example.invalid": {"password": "SYNTHETIC_PASSWORD_TWO"},
        }}
        result = mapped(alert)
        self.assertEqual(source_body(result), alert)
        self.assertNotIn("one@example.invalid", result.description.split("```json\n", 1)[0])
        self.assertNotIn("two@example.invalid", result.description.split("```json\n", 1)[0])

    def test_code_fence_and_html_in_keys_and_values_remain_inert_json(self):
        alert = {"id": "synthetic-full-1", "service": "iocs",
                 "```\n<script>synthetic</script>": "```json\n![image](https://example.invalid/x)\n```",
                 "raw": "<img src='https://example.invalid/synthetic'>"}
        result = mapped(alert)
        self.assertEqual(result.description.count("```"), 2)
        self.assertEqual(source_body(result), alert)

    def test_input_is_not_mutated(self):
        alert = {"id": "synthetic-full-1", "service": "iocs",
                 "data": [{"password": "SYNTHETIC_PASSWORD", "raw": "source"}],
                 "encoded": '{"domain":"example.invalid"}'}
        original = deepcopy(alert)
        mapped(alert)
        self.assertEqual(alert, original)

    def test_false_positive_preserves_full_source_without_new_indicators(self):
        alert = {"id": "synthetic-full-1", "service": "iocs", "status": "FALSE_POSITIVE",
                 "domain": "example.invalid", "password": "SYNTHETIC_PASSWORD"}
        result = mapped(alert)
        self.assertEqual(source_body(result), alert)
        self.assertEqual(result.related_indicators, [])

    def test_default_redacted_mode_retains_legacy_behavior(self):
        alert = {"id": "synthetic-full-1", "service": "iocs",
                 "password": "SYNTHETIC_PASSWORD", "content": "SYNTHETIC_RAW_TEXT"}
        result = _map_alert(alert, "iocs", indicator, report, "malware", "amber", {})
        self.assertNotIn("SYNTHETIC_PASSWORD", result.description)
        self.assertNotIn("SYNTHETIC_RAW_TEXT", result.description)
        self.assertEqual(source_body(result)["password"], "<redacted:sensitive-field>")

    def test_source_sensitive_value_changes_change_body(self):
        first = {"id": "synthetic-full-1", "service": "iocs", "password": "SYNTHETIC_OLD"}
        second = {**first, "password": "SYNTHETIC_NEW"}
        self.assertNotEqual(mapped(first).description, mapped(second).description)

    def test_full_mode_preserves_valid_numeric_identity_even_when_it_resembles_a_card(self):
        alert = {"id": "4111111111111111", "service": "iocs", "password": "SYNTHETIC_VALUE"}
        result = mapped(alert)
        self.assertEqual(result.original_source_id, alert["id"])
        self.assertEqual(source_body(result), alert)

    def test_invalid_content_mode_is_rejected(self):
        alert = {"id": "synthetic-full-1", "service": "iocs"}
        for mode in ("", "FULL", "retain", None):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                _map_alert(alert, "iocs", indicator, report, "malware", "amber", {}, content_mode=mode)

    def test_oversize_and_excessive_nesting_fail_without_truncation(self):
        with self.assertRaises(ValueError):
            mapped({"id": "synthetic-full-1", "service": "iocs", "password": "x" * 2048}, max_report_bytes=1024)
        nested = {"end": True}
        for _ in range(35):
            nested = {"next": nested}
        with self.assertRaises(ValueError):
            mapped({"id": "synthetic-full-1", "service": "iocs", "data": nested})

    def test_non_json_numbers_types_and_keys_are_rejected(self):
        for value in (float("nan"), float("inf"), -float("inf"), (1, 2), {1: "ambiguous key"}):
            with self.subTest(value=repr(value)), self.assertRaises((ValueError, TypeError)):
                mapped({"id": "synthetic-full-1", "service": "iocs", "value": value})

    def test_deep_json_encoded_string_is_preserved_without_expanding_source(self):
        nested = {"domain": "example.invalid"}
        for _ in range(40):
            nested = {"next": nested}
        alert = {"id": "synthetic-full-1", "service": "iocs", "data": json.dumps(nested)}
        result = mapped(alert)
        self.assertEqual(source_body(result), alert)
        self.assertEqual(result.related_indicators, [])

    def test_unparseable_json_text_is_preserved_verbatim(self):
        alert = {"id": "synthetic-full-1", "service": "iocs", "data": "[" * 1500 + "]" * 1500}
        self.assertEqual(source_body(mapped(alert)), alert)

    @unittest.skipUnless(util.find_spec("anomali_feedsdk") is not None,
                         "Install the licensed anomali_feedsdk 2.8.1 wheel for SDK contracts")
    def test_real_sdk_hash_tracks_sensitive_source_changes(self):
        with patch("socket.socket.connect", side_effect=AssertionError("Network disabled")), \
                patch("requests.sessions.Session.request", side_effect=AssertionError("Network disabled")):
            from cyble_sdk import sdk_models
            sdk_indicator, sdk_report = sdk_models()
            original = {"id": "synthetic-full-1", "service": "iocs", "password": "SYNTHETIC_OLD"}
            first = _map_alert(original, "iocs", sdk_indicator, sdk_report, "malware", "amber", {}, content_mode="full")
            changed = _map_alert({**original, "password": "SYNTHETIC_NEW"}, "iocs", sdk_indicator, sdk_report,
                                 "malware", "amber", {}, content_mode="full")
        self.assertNotEqual(first.report_id, changed.report_id)
        self.assertEqual(source_body(first), original)
        payload = first.threatmodel.to_ts_json()
        self.assertEqual(payload["body"], first.description)
        self.assertIs(payload["is_public"], False)
        self.assertEqual(payload["tlp"], "amber")


if __name__ == "__main__":
    unittest.main()
