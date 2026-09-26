"""Integrated polling state/failure tests with fake source and destination APIs."""
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'source'))
import cyble_anomali_feed as runner
from cyble_client import CybleAPIError


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)


def indicator(**kwargs):
    return SimpleNamespace(**kwargs, observable=kwargs['value'], itype='test')


def report(**kwargs):
    return SimpleNamespace(**kwargs, report_id=kwargs['original_source_id'], threatmodel=object())


class FakeFeed:
    def __init__(self):
        self.feed_config = {'unrelated_setting': 'preserved'}
        self.processed_threat_models = {}
        self.calls = []

    def ingest_reports(self, reports):
        self.calls.append(reports)
        for model in reports:
            self.processed_threat_models[model.report_id] = 123
        return len(reports), sum(len(model.related_indicators) for model in reports)


class PollingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        env = {'CYBLE_SERVICES': 'iocs,github', 'CYBLE_API_TOKEN': 'synthetic-token',
               'CYBLE_COMPANY_UUID': 'synthetic-company', 'CYBLE_INITIAL_LOOKBACK_HOURS': '1',
               'CYBLE_PAGE_SIZE': '2', 'CYBLE_MAX_PAGES_PER_SERVICE': '3', 'CYBLE_SYNC_UPDATED_ALERTS': 'false',
               'CYBLE_SETTLE_SECONDS': '0', 'CYBLE_WINDOW_MINUTES': '60', 'CYBLE_OVERLAP_SECONDS': '300',
               'CYBLE_LOCK_DIR': self.directory.name, 'TS_API_URL': 'https://example.invalid', 'TS_FEED_ID': 'synthetic-feed'}
        self.env = patch.dict(os.environ, env, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = Mock()
        self.feed = FakeFeed()
        self.snapshots = []
        self.patches = [patch.object(runner, '_client', return_value=self.client),
                        patch.object(runner, '_new_feed', return_value=self.feed),
                        patch.object(runner, 'sdk_models', return_value=(indicator, report)),
                        patch.object(runner, 'datetime', FixedDatetime),
                        patch.object(runner, '_save_feed_config', side_effect=lambda f: self.snapshots.append(copy.deepcopy(f.feed_config)))]
        for mocked in self.patches:
            mocked.start()
            self.addCleanup(mocked.stop)

    def test_failed_service_stays_pending_other_service_completes_and_restart_replays(self):
        calls = []
        def fetch(**kwargs):
            calls.append(kwargs)
            service = kwargs['services'][0]
            if service == 'iocs':
                raise CybleAPIError('Synthetic service failure')
            return [{'id': 'synthetic-github', 'service': 'github'}]
        self.client.fetch_page.side_effect = fetch
        with self.assertLogs(runner.LOGGER, 'ERROR'), self.assertRaises(runner.IncompletePoll):
            runner.run_poll()
        saved = self.snapshots[-1]
        streams = saved['cyble_state_v1']['streams']
        self.assertIn('pending', streams['iocs']['created_at'])
        self.assertNotIn('pending', streams['github']['created_at'])
        self.assertEqual(streams['github']['created_at']['cursor'], '2026-09-25T12:00:00.000000Z')
        self.assertEqual(saved['unrelated_setting'], 'preserved')
        pending = copy.deepcopy(streams['iocs']['created_at']['pending'])
        self.client.fetch_page.side_effect = lambda **kw: []
        runner.run_poll()
        last_query = self.client.fetch_page.call_args.kwargs
        self.assertEqual((last_query['start'], last_query['end']), (pending['start'], pending['end']))
        self.assertNotIn('pending', self.snapshots[-1]['cyble_state_v1']['streams']['iocs']['created_at'])

    def test_failed_destination_does_not_advance_any_affected_cursor(self):
        self.client.fetch_page.side_effect = lambda **kw: [{'id': 'synthetic-' + kw['services'][0], 'service': kw['services'][0]}]
        self.feed.ingest_reports = Mock(side_effect=RuntimeError('SYNTHETIC_PRIVATE_VALUE'))
        with self.assertLogs(runner.LOGGER, 'ERROR') as logs, self.assertRaises(runner.IncompletePoll):
            runner.run_poll()
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', '\n'.join(logs.output))
        for fields in self.snapshots[-1]['cyble_state_v1']['streams'].values():
            self.assertEqual(fields['created_at']['cursor'], '2026-09-25T11:00:00.000000Z')
            self.assertIn('pending', fields['created_at'])

    def test_page_limit_splits_pending_window_without_advancing(self):
        os.environ['CYBLE_SERVICES'] = 'iocs'
        os.environ['CYBLE_MAX_PAGES_PER_SERVICE'] = '1'
        self.client.fetch_page.return_value = [{'id': 'synthetic-1', 'service': 'iocs'}, {'id': 'synthetic-2', 'service': 'iocs'}]
        with self.assertLogs(runner.LOGGER, 'ERROR'), self.assertRaises(runner.IncompletePoll):
            runner.run_poll()
        stream = self.snapshots[-1]['cyble_state_v1']['streams']['iocs']['created_at']
        self.assertEqual(stream['cursor'], '2026-09-25T11:00:00.000000Z')
        self.assertEqual(stream['pending']['end'], '2026-09-25T11:30:00.000000Z')
        self.assertEqual(len(self.feed.calls), 1)

    def test_repeated_pages_fail_and_keep_window_pending(self):
        os.environ['CYBLE_SERVICES'] = 'iocs'
        self.client.fetch_page.return_value = [{'id': 'synthetic-1', 'service': 'iocs'}, {'id': 'synthetic-2', 'service': 'iocs'}]
        with self.assertLogs(runner.LOGGER, 'ERROR'), self.assertRaises(runner.IncompletePoll):
            runner.run_poll()
        self.assertEqual(len(self.feed.calls), 1)
        self.assertIn('pending', self.snapshots[-1]['cyble_state_v1']['streams']['iocs']['created_at'])

    def test_all_mode_selects_only_explicitly_alert_enabled_services(self):
        os.environ['CYBLE_SERVICES'] = 'all'
        self.client.get_services.return_value = [
            {'name': 'yes', 'allow_alerts': True}, {'name': 'no', 'allow_alerts': False}, {'name': 'unknown', 'allow_alerts': None}]
        self.assertEqual(runner._configured_services(self.client), ['yes'])

    def test_dry_run_never_initializes_destination_or_writes_checkpoints(self):
        self.client.fetch_page.side_effect = lambda **kw: [{'id': 'synthetic-' + kw['services'][0], 'service': kw['services'][0]}]
        with patch.object(runner, '_new_feed') as destination, patch.object(runner.requests, 'patch') as network_write:
            runner.dry_run()
        destination.assert_not_called()
        network_write.assert_not_called()
        self.assertEqual(self.snapshots, [])
        self.assertTrue(all(call.kwargs['take'] == 1 for call in self.client.fetch_page.call_args_list))

    def test_full_content_is_default_private_and_never_written_to_logs(self):
        os.environ['CYBLE_SERVICES'] = 'iocs'
        alert = {'id': 'synthetic-full', 'service': 'iocs', 'password': 'SYNTHETIC_EXPOSED_PASSWORD',
                 'content': 'unstructured source text', 'email': 'synthetic@example.invalid'}
        self.client.fetch_page.return_value = [alert]
        with self.assertLogs(runner.LOGGER, 'INFO') as logs:
            runner.run_poll()
        model = self.feed.calls[0][0]
        payload = json.loads(model.description.split('```json\n', 1)[1].split('\n```', 1)[0])
        self.assertEqual(payload, alert)
        self.assertFalse(model.is_public)
        self.assertNotIn('SYNTHETIC_EXPOSED_PASSWORD', '\n'.join(logs.output))
        self.assertEqual(self.snapshots[-1]['cyble_content_mode'], 'full')

    def test_mode_change_replays_lookback_once(self):
        os.environ['CYBLE_SERVICES'] = 'iocs'
        os.environ['CYBLE_CONTENT_MODE'] = 'redacted'
        self.client.fetch_page.return_value = []
        runner.run_poll()
        self.client.fetch_page.reset_mock()
        runner.run_poll()
        self.client.fetch_page.assert_not_called()
        os.environ['CYBLE_CONTENT_MODE'] = 'full'
        runner.run_poll()
        self.assertEqual(self.client.fetch_page.call_count, 1)
        self.assertEqual(self.client.fetch_page.call_args.kwargs['start'], '2026-09-25T10:55:00.000000Z')
        self.client.fetch_page.reset_mock()
        runner.run_poll()
        self.client.fetch_page.assert_not_called()

    def test_full_mode_rejects_disabled_details_and_invalid_mode(self):
        for config in ({'CYBLE_WITH_DATA_MESSAGE': 'false'}, {'CYBLE_CONTENT_MODE': 'unknown'}):
            with self.subTest(config=config), patch.dict(os.environ, config), self.assertRaises(ValueError):
                runner._settings()
        with patch.dict(os.environ, {'CYBLE_WITH_DATA_MESSAGE': 'false', 'CYBLE_CONTENT_MODE': 'redacted'}):
            self.assertFalse(runner._settings()['with_data'])


class CheckpointHTTPTests(unittest.TestCase):
    def setUp(self):
        self.feed = SimpleNamespace(ts_url='https://example.invalid/api/v1/', feed_id='synthetic-feed',
                                    creds={'username': 'synthetic-user', 'api_key': 'synthetic-token'},
                                    feed_config={'cyble_state_v1': {}}, proxies=None)

    def test_redirect_async_acceptance_and_error_body_do_not_count_as_saved(self):
        for status, payload in ((302, {}), (202, {}), (200, {'success': False}), (200, {'error': 'synthetic'})):
            response = Mock(status_code=status, content=b'{}')
            response.json.return_value = payload
            with self.subTest(status=status), patch.object(runner.requests, 'patch', return_value=response), self.assertRaises(RuntimeError):
                runner._save_feed_config(self.feed)

    def test_checkpoint_transport_is_tls_verified_and_sanitizes_exceptions(self):
        with patch.object(runner.requests, 'patch', side_effect=requests.RequestException('SYNTHETIC_PRIVATE_VALUE')) as request:
            with self.assertRaises(RuntimeError) as raised:
                runner._save_feed_config(self.feed)
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', str(raised.exception))
        self.assertTrue(request.call_args.kwargs['verify'])
        self.assertFalse(request.call_args.kwargs['allow_redirects'])


if __name__ == '__main__':
    unittest.main()
