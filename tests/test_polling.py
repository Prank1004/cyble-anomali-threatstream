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


def paged(rows):
    """A source that honors offset pagination, like the real Alerts API."""
    return lambda **kw: [dict(row) for row in rows[kw['skip']:kw['skip'] + kw['take']]]


class FakeSource:
    """Mutable ordered result set; `before` can change it before a given request."""

    def __init__(self, rows, cap=None, before=None):
        self.rows, self.cap, self.before, self.calls = list(rows), cap, before or {}, []

    def __call__(self, **kw):
        self.calls.append(kw)
        if len(self.calls) in self.before:
            self.before[len(self.calls)](self)
        take = min(kw['take'], self.cap or kw['take'])
        return [dict(row) for row in self.rows[kw['skip']:kw['skip'] + take]]


def alerts(count, service='iocs'):
    return [{'id': f'synthetic-{index}', 'service': service} for index in range(1, count + 1)]


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
            return paged([{'id': 'synthetic-github', 'service': 'github'}])(**kwargs)
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

    def test_page_limit_splits_pending_window_without_advancing_or_failing(self):
        os.environ['CYBLE_SERVICES'] = 'iocs'
        os.environ['CYBLE_MAX_PAGES_PER_SERVICE'] = '1'
        self.client.fetch_page.side_effect = paged(alerts(4))
        with self.assertLogs(runner.LOGGER, 'WARNING') as logs:
            runner.run_poll()
        self.assertTrue(any('Window split' in line for line in logs.output))
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
        self.client.fetch_page.side_effect = paged([alert])
        with self.assertLogs(runner.LOGGER, 'INFO') as logs:
            runner.run_poll()
        self.assertFalse(any('Content mode changed' in line for line in logs.output))
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
        with self.assertLogs(runner.LOGGER, 'WARNING') as logs:
            runner.run_poll()
        self.assertTrue(any('Content mode changed from redacted to full' in line for line in logs.output))
        self.assertEqual(self.client.fetch_page.call_count, 1)
        self.assertEqual(self.client.fetch_page.call_args.kwargs['start'], '2026-09-25T10:55:00.000000Z')
        self.client.fetch_page.reset_mock()
        runner.run_poll()
        self.client.fetch_page.assert_not_called()

    def use_source(self, source, page_size=8):
        os.environ.update({'CYBLE_SERVICES': 'iocs', 'CYBLE_PAGE_SIZE': str(page_size),
                           'CYBLE_MAX_PAGES_PER_SERVICE': '10'})
        self.client.fetch_page.side_effect = source
        return source

    def ingested(self):
        return [model.original_source_id for call in self.feed.calls for model in call]

    def created_stream(self):
        return self.snapshots[-1]['cyble_state_v1']['streams']['iocs']['created_at']

    def test_overlapping_pages_keep_rows_that_shift_up_between_requests(self):
        # Page size 8 re-reads 2 rows. Removing one row after page 1 shifts every
        # later row up; plain offsets would skip synthetic-9.
        source = self.use_source(FakeSource(alerts(10), before={2: lambda s: s.rows.pop(1)}))
        runner.run_poll()
        self.assertEqual(sorted(self.ingested()), sorted(f'synthetic-{i}' for i in range(1, 11)))
        self.assertEqual([call['skip'] for call in source.calls], [0, 6, 7])
        self.assertNotIn('pending', self.created_stream())

    def test_shift_beyond_overlap_replays_the_window_instead_of_completing_it(self):
        self.use_source(FakeSource(alerts(10), before={2: lambda s: s.rows.__delitem__(slice(1, 4))}))
        with self.assertLogs(runner.LOGGER, 'WARNING') as logs:
            runner.run_poll()
        self.assertTrue(any('Window deferred' in line for line in logs.output))
        self.assertEqual(self.created_stream()['cursor'], '2026-09-25T11:00:00.000000Z')
        self.assertIn('pending', self.created_stream())

    def test_server_page_cap_and_misleading_short_pages_do_not_end_a_window(self):
        self.use_source(FakeSource(alerts(7), cap=5))
        runner.run_poll()
        self.assertEqual(sorted(self.ingested()), sorted(f'synthetic-{i}' for i in range(1, 8)))
        self.assertNotIn('pending', self.created_stream())

    def test_poison_alert_is_quarantined_and_the_stream_keeps_moving(self):
        rows = [{'id': 'synthetic-1', 'service': 'iocs'}, {'service': 'iocs', 'label': 'no usable id'},
                {'id': 'bad id with spaces', 'service': 'iocs'}, {'id': 'synthetic-2', 'service': 'iocs'}]
        self.use_source(FakeSource(rows))
        with self.assertLogs(runner.LOGGER, 'ERROR') as logs:
            runner.run_poll()
        self.assertEqual(self.ingested(), ['synthetic-1', 'synthetic-2'])
        self.assertNotIn('pending', self.created_stream())
        quarantine = self.snapshots[-1]['cyble_quarantine_v1']
        self.assertEqual([entry['reason'] for entry in quarantine], ['invalid-alert', 'invalid-alert'])
        self.assertTrue(all(entry['alert'].startswith('sha256:') for entry in quarantine))
        self.assertNotIn('no usable id', json.dumps(quarantine) + '\n'.join(logs.output))

    def test_destination_rejection_of_one_report_is_isolated_and_quarantined(self):
        self.use_source(FakeSource(alerts(4)))
        real_ingest = self.feed.ingest_reports
        def ingest(reports):
            if any(model.report_id == 'synthetic-3' for model in reports):
                raise ValueError('synthetic destination rejection')
            return real_ingest(reports)
        self.feed.ingest_reports = ingest
        with self.assertLogs(runner.LOGGER, 'ERROR'):
            runner.run_poll()
        self.assertEqual(sorted(set(self.ingested())), ['synthetic-1', 'synthetic-2', 'synthetic-4'])
        self.assertEqual([(entry['alert'], entry['reason']) for entry in self.snapshots[-1]['cyble_quarantine_v1']],
                         [('synthetic-3', 'ingest-rejected')])
        self.assertNotIn('pending', self.created_stream())

    def test_destination_outage_fails_the_window_instead_of_quarantining(self):
        self.use_source(FakeSource(alerts(4)))
        self.feed.ingest_reports = Mock(side_effect=ValueError('synthetic outage'))
        with self.assertLogs(runner.LOGGER, 'ERROR'), self.assertRaises(runner.IncompletePoll):
            runner.run_poll()
        self.assertNotIn('cyble_quarantine_v1', self.snapshots[-1])
        self.assertIn('pending', self.created_stream())
        self.assertEqual(self.feed.ingest_reports.call_count, 4)

    def test_widespread_sdk_rejection_is_a_failure_not_a_mass_quarantine(self):
        self.use_source(FakeSource(alerts(4)))
        with patch.object(runner, 'sdk_models', return_value=(indicator, Mock(side_effect=RuntimeError('sdk')))):
            with self.assertLogs(runner.LOGGER, 'ERROR'), self.assertRaises(runner.IncompletePoll):
                runner.run_poll()
        self.assertNotIn('cyble_quarantine_v1', self.snapshots[-1])
        self.assertIn('pending', self.created_stream())

    def test_unchanged_alerts_seen_by_several_streams_are_sent_once(self):
        os.environ['CYBLE_SYNC_UPDATED_ALERTS'] = 'true'
        self.use_source(paged([{'id': 'synthetic-1', 'service': 'iocs', 'status': 'OPEN'}]))
        runner.run_poll()
        self.assertEqual(self.ingested(), ['synthetic-1'])

    def test_changed_alert_content_is_sent_again(self):
        os.environ['CYBLE_SYNC_UPDATED_ALERTS'] = 'true'
        def fetch(**kw):
            status = 'OPEN' if kw['date_field'] == 'created_at' else 'CLOSED'
            return paged([{'id': 'synthetic-1', 'service': 'iocs', 'status': status}])(**kw)
        self.use_source(fetch)
        runner.run_poll()
        self.assertEqual(self.ingested(), ['synthetic-1', 'synthetic-1'])

    def test_generic_indicators_only_for_indicator_services_by_default(self):
        os.environ['CYBLE_SERVICES'] = 'iocs,github'
        self.client.fetch_page.side_effect = lambda **kw: paged([
            {'id': 'synthetic-' + kw['services'][0], 'service': kw['services'][0], 'domain': 'example.com'}])(**kw)
        runner.run_poll()
        counts = {model.original_source_id: len(model.related_indicators) for call in self.feed.calls for model in call}
        self.assertEqual(counts, {'synthetic-iocs': 1, 'synthetic-github': 0})
        os.environ['CYBLE_INDICATOR_SERVICES'] = 'bad slug'
        with self.assertRaises(ValueError):
            runner._settings()

    def test_delayed_reread_covers_settled_history_in_whole_windows(self):
        os.environ.update({'CYBLE_RECONCILE_LAG_HOURS': '1', 'CYBLE_INITIAL_LOOKBACK_HOURS': '3'})
        source = self.use_source(FakeSource([]))
        runner.run_poll()
        streams = self.snapshots[-1]['cyble_state_v1']['streams']['iocs']
        self.assertEqual(streams['created_at']['cursor'], '2026-09-25T12:00:00.000000Z')
        self.assertEqual(streams['created_at_reconcile']['cursor'], '2026-09-25T11:00:00.000000Z')
        self.assertEqual(len(source.calls), 5)
        self.assertTrue(all(call['date_field'] == 'created_at' for call in source.calls))

    def test_stop_signal_leaves_the_window_pending_without_failing(self):
        self.addCleanup(runner.STOP.clear)
        self.use_source(FakeSource(alerts(10), before={1: lambda s: runner.STOP.set()}))
        runner.run_poll()
        self.assertEqual(len(self.ingested()), 8)
        self.assertIn('pending', self.created_stream())

    def test_budget_limited_cycles_rotate_through_every_stream(self):
        # Each cycle has budget for one window. Every service is behind, so a
        # "most caught-up first" order would serve github forever.
        os.environ['CYBLE_INITIAL_LOOKBACK_HOURS'] = '3'
        clock = [1000.0]
        def fetch(**kw):
            clock[0] += 100
            return []
        self.client.fetch_page.side_effect = fetch
        settings, health = runner._settings(), runner.StreamHealth()
        with patch.object(runner, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
            for _ in range(3):
                result = runner._run_cycle(self.client, ['github', 'iocs', 'other'], settings, (indicator, report),
                                           {}, runner.RecentAlerts(), health, clock[0] + 50, float('inf'))
                self.assertTrue(result.backlog)
        served = [call.kwargs['services'][0] for call in self.client.fetch_page.call_args_list]
        self.assertEqual(served, ['github', 'iocs', 'other'])

    def test_daemon_runs_cycles_writes_status_and_stops_cleanly(self):
        self.addCleanup(runner.STOP.clear)
        status_path = Path(self.directory.name) / 'status.json'
        os.environ['CYBLE_STATUS_FILE'] = str(status_path)
        self.use_source(paged(alerts(2)))
        with patch.object(runner.STOP, 'wait', side_effect=lambda delay: runner.STOP.set()) as wait:
            runner.run_daemon()
        status = json.loads(status_path.read_text())
        self.assertEqual(status['consecutive_cycle_errors'], 0)
        self.assertEqual(status['last_cycle']['alerts'], 2)
        self.assertIsNotNone(status['last_success_at'])
        self.assertLessEqual(wait.call_args.args[0], 60)
        self.assertEqual(self.ingested(), ['synthetic-1', 'synthetic-2'])

    def test_daemon_backs_off_a_failing_service_and_keeps_reporting_it(self):
        self.addCleanup(runner.STOP.clear)
        status_path = Path(self.directory.name) / 'status.json'
        os.environ['CYBLE_STATUS_FILE'] = str(status_path)
        self.use_source(Mock(side_effect=CybleAPIError('Synthetic service failure')))
        waits = []
        def wait(delay):
            waits.append(delay)
            if len(waits) == 2:
                runner.STOP.set()
        with patch.object(runner.STOP, 'wait', side_effect=wait), self.assertLogs(runner.LOGGER, 'WARNING'):
            runner.run_daemon()
        self.assertEqual(self.client.fetch_page.call_count, 1)
        status = json.loads(status_path.read_text())
        self.assertEqual((status['last_cycle']['failed_streams'], status['last_cycle']['backed_off_streams']), (0, 1))
        self.assertIsNone(status['last_success_at'])

    def test_daemon_survives_a_failed_cycle_and_backs_off(self):
        self.addCleanup(runner.STOP.clear)
        status_path = Path(self.directory.name) / 'status.json'
        os.environ.update({'CYBLE_STATUS_FILE': str(status_path), 'CYBLE_POLL_INTERVAL_SECONDS': '30'})
        with patch.object(runner, '_new_feed', side_effect=RuntimeError('ThreatStream unavailable')), \
                patch.object(runner.STOP, 'wait', side_effect=lambda delay: runner.STOP.set()) as wait, \
                self.assertLogs(runner.LOGGER, 'ERROR'):
            runner.run_daemon()
        self.assertEqual(json.loads(status_path.read_text())['consecutive_cycle_errors'], 1)
        self.assertEqual(wait.call_args.args[0], 30)

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
