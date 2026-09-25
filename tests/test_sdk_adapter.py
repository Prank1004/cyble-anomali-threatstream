"""Failure acceptance and logging isolation at the SDK boundary; no network."""
import io
import logging
import sys
import unittest
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'source'))
from cyble_sdk import construct_sdk, ingest_reports, quiet_sdk_logger


def item(report_id='synthetic-report'):
    return SimpleNamespace(report_id=report_id, threatmodel=object())


class AdapterTests(unittest.TestCase):
    def test_constructor_bypasses_cli_logging_decorator_only(self):
        def decorator(function):
            @wraps(function)
            def forbidden(*args, **kwargs):
                raise AssertionError('logging decorator must not run')
            return forbidden
        class Model:
            @decorator
            def __init__(self, value):
                self.value = value
        model = construct_sdk(Model, value=42)
        self.assertIsInstance(model, Model)
        self.assertEqual(model.value, 42)

    def test_constructor_exception_never_exposes_payload(self):
        def constructor(self):
            raise ValueError('SYNTHETIC_PRIVATE_VALUE')
        class Model:
            @wraps(constructor)
            def __init__(self):
                pass
        with self.assertRaises(RuntimeError) as raised:
            construct_sdk(Model)
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', str(raised.exception))

    def test_cached_reports_with_zero_counts_are_accepted(self):
        feed = SimpleNamespace(ingest_reports=Mock(return_value=(0, 0)), processed_threat_models={'synthetic-report': 5})
        self.assertEqual(ingest_reports(feed, [item(), item()]), (0, 0))
        self.assertEqual(len(feed.ingest_reports.call_args.args[0]), 1)

    def test_missing_or_nonpositive_acceptance_id_rejects_successful_counts(self):
        for result in ({}, {'synthetic-report': 0}, {'synthetic-report': True}):
            feed = SimpleNamespace(ingest_reports=Mock(return_value=(1, 1)), processed_threat_models=result)
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                ingest_reports(feed, [item()])

    def test_warning_is_failure_and_raw_message_cannot_reach_old_handlers(self):
        output = io.StringIO()
        logger = logging.getLogger('anomali_feedsdk.feed')
        logger.addHandler(logging.StreamHandler(output))
        def upload(reports):
            logger.warning('SYNTHETIC_PRIVATE_VALUE')
            return 1, 1
        feed = SimpleNamespace(ingest_reports=upload, processed_threat_models={'synthetic-report': 5})
        with self.assertRaises(RuntimeError):
            ingest_reports(feed, [item()])
        self.assertEqual(output.getvalue(), '')

    def test_bad_return_and_invalid_report_are_rejected(self):
        for value in (None, [1, 1], (True, 1), (-1, 1)):
            feed = SimpleNamespace(ingest_reports=Mock(return_value=value), processed_threat_models={'synthetic-report': 5})
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                ingest_reports(feed, [item()])
        with self.assertRaises(RuntimeError):
            ingest_reports(Mock(), [SimpleNamespace(report_id='x', threatmodel=None)])


if __name__ == '__main__':
    unittest.main()
