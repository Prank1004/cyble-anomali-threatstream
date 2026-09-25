"""Synthetic regressions for field loss, redaction, and observable metadata."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'source'))
from cyble_mapping import _map_alert, _sanitize_alert_fields, _serialize_alert_fields, _load_field_map


def indicator(**kwargs):
    return SimpleNamespace(**kwargs, observable=kwargs['value'], itype='test')


def report(**kwargs):
    return SimpleNamespace(**kwargs, report_id=kwargs['original_source_id'], threatmodel=object())


def mapped(alert, field_map=None, **kwargs):
    return _map_alert(alert, 'iocs', indicator, report, 'malware', 'amber', field_map or {}, **kwargs)


def body(model):
    return json.loads(model.description.split('```json\n', 1)[1].split('\n```', 1)[0])


class MappingTests(unittest.TestCase):
    def test_retains_unknown_nested_fields_arrays_and_large_strings(self):
        alert = {'id': 'synthetic-1', 'service': 'iocs', 'new_vendor_field': {
            'items': [{'value': i, 'flag': False, 'empty': None} for i in range(2100)],
            'label': 'a' * 51000,
        }}
        self.assertEqual(body(mapped(alert)), alert)

    def test_redacts_every_sensitive_output_path_and_retains_nested_keys(self):
        secret = 'SYNTHETIC_PRIVATE_VALUE'
        alert = {'id': 'synthetic-1', 'service': 'iocs', 'api_key': secret,
                 'token': secret, 'credentials': {'account': secret, 'details': {'password': secret}},
                 'dataMessage': json.dumps({'email': 'someone@example.invalid', 'data': {'token': secret}}),
                 'reference_link': 'https://example.invalid/?api%5Fkey=' + secret,
                 'url': 'https://user:' + secret + '@example.invalid/?access_key=' + secret,
                 'description': 'Authorization: Bearer ' + secret,
                 'mobile_apps': {'package': 'org.example.synthetic'}}
        rules = {'default': {'ioc_rules': [{'value_path': 'credentials.account', 'type': 'domain'}],
                             'context_paths': [{'path': 'reference_link', 'label': 'Reference'}]}}
        model = mapped(alert, rules)
        self.assertNotIn(secret, model.description)
        self.assertNotIn('someone@example.invalid', model.description)
        self.assertEqual(model.related_indicators, [])
        payload = body(model)
        self.assertEqual(set(payload['credentials']), {'account', 'details'})
        self.assertIn('password', payload['credentials']['details'])
        self.assertEqual(payload['mobile_apps']['package'], 'org.example.synthetic')

    def test_redacts_encoded_signed_url_parameters(self):
        for key in ('api%5Fkey', 'access_key', 'X-Amz-Signature', 'X-Amz-Credential', 'sig', 'token'):
            with self.subTest(key=key):
                model = mapped({'id': 'synthetic-1', 'service': 'iocs',
                                'url': 'https://example.invalid/?' + key + '=SYNTHETIC_PRIVATE_VALUE'})
                self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', model.description)
                self.assertEqual(model.related_indicators, [])

    def test_long_assigned_secrets_and_json_strings_are_redacted(self):
        value = 'SYNTHETIC_' * 100
        safe = _sanitize_alert_fields({'description': 'password=' + value,
                                       'other': json.dumps({'api_key': value})})
        self.assertNotIn('SYNTHETIC_', json.dumps(safe))
        self.assertIsInstance(safe['other'], dict)

    def test_full_mapping_escapes_markdown_fences_without_losing_values(self):
        alert = {'id': 'synthetic-1', 'service': 'iocs', 'label': '```json\nhello```'}
        result = mapped(alert)
        self.assertEqual(result.description.count('```'), 2)
        self.assertEqual(body(result), alert)

    def test_arrays_urls_case_and_private_addresses(self):
        alert = {'id': 'synthetic-1', 'service': 'iocs', 'domains': ['example.invalid'],
                 'ips': ['1.1.1.1', '10.1.2.3'],
                 'urls': ['https://example.invalid/A', 'https://example.invalid/a',
                          'http://127.0.0.1/a', 'http://localhost/a']}
        result = mapped(alert)
        values = {item.value for item in result.related_indicators}
        self.assertEqual(values, {'example.invalid', '1.1.1.1', 'https://example.invalid/A', 'https://example.invalid/a'})
        self.assertTrue(all(item.tlp == 'amber' for item in result.related_indicators))

    def test_observed_ioc_timestamps_win_over_alert_times_and_explicit_paths(self):
        alert = {'id': 'synthetic-1', 'service': 'iocs', 'ioc': 'example.invalid',
                 'created_at': '2026-09-20T00:00:00Z', 'updated_at': '2026-09-21T00:00:00Z',
                 'user_severity': None, 'severity': 'HIGH',
                 'data': {'ioc': 'example.invalid', 'first_seen': '2026-08-01T00:00:00Z',
                          'last_seen': '2026-09-19T00:00:00Z'}}
        result = mapped(alert, _load_field_map())
        self.assertEqual(len(result.related_indicators), 1)
        observed = result.related_indicators[0]
        self.assertEqual(observed.source_created, '2026-08-01T00:00:00Z')
        self.assertEqual(observed.source_modified, '2026-09-19T00:00:00Z')
        self.assertEqual(observed.severity, 'high')

    def test_per_indicator_observation_times_do_not_leak_to_siblings(self):
        data = [{'value': 'a.example.invalid', 'type': 'domain', 'first_seen': '2026-01-01T00:00:00Z'},
                {'value': 'b.example.invalid', 'type': 'domain', 'first_seen': '2026-02-01T00:00:00Z'}]
        result = mapped({'id': 'synthetic-1', 'service': 'iocs', 'observables': data})
        self.assertEqual({i.value: i.source_created for i in result.related_indicators},
                         {'a.example.invalid': '2026-01-01T00:00:00Z', 'b.example.invalid': '2026-02-01T00:00:00Z'})

    def test_false_positive_record_is_kept_without_new_indicators(self):
        result = mapped({'id': 'synthetic-1', 'service': 'iocs', 'status': 'FALSE_POSITIVE', 'ioc': 'example.invalid'})
        self.assertEqual(result.related_indicators, [])
        self.assertEqual(body(result)['status'], 'FALSE_POSITIVE')
        self.assertIn('cyble_status_false_positive', result.tags)

    def test_rejects_missing_boolean_id_and_mismatched_service(self):
        for alert in ({'service': 'iocs'}, {'id': True, 'service': 'iocs'}, {'id': 'one', 'service': 'github'}):
            with self.subTest(alert=alert), self.assertRaises(ValueError):
                mapped(alert)

    def test_oversize_and_excessive_nesting_fail_without_truncation(self):
        with self.assertRaises(ValueError):
            _serialize_alert_fields({'label': 'x' * 1100}, 1024)
        nested = {'end': True}
        for _ in range(35):
            nested = {'next': nested}
        with self.assertRaises(ValueError):
            _sanitize_alert_fields(nested)

    def test_explicit_missing_or_malformed_field_map_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'map.json'
            with patch.dict(os.environ, {'CYBLE_FIELD_MAP_PATH': str(path)}), self.assertRaises(ValueError):
                _load_field_map()
            path.write_text('{"default":{"ioc_rules":[{}]}}')
            with patch.dict(os.environ, {'CYBLE_FIELD_MAP_PATH': str(path)}), self.assertRaises(ValueError):
                _load_field_map()

    def test_invalid_custom_paths_fail_before_any_alert_is_fetched(self):
        examples = [
            {'default': {'context_paths': [{'path': 'data..label'}]}},
            {'default': {'ioc_rules': [{'value_path': 'items[0].value'}]}},
            {'default': {'ioc_rules': [{'value_path': 'items[*].value', 'type_path': 42}]}},
            {'services': {'iocs': {'ioc_rules': [
                {'value_path': 'items[*].value', 'type_path': 'groups[*].items[*].type'}]}}},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'map.json'
            for config in examples:
                path.write_text(json.dumps(config))
                with self.subTest(config=config), patch.dict(os.environ, {'CYBLE_FIELD_MAP_PATH': str(path)}), self.assertRaises(ValueError):
                    _load_field_map()


if __name__ == '__main__':
    unittest.main()
