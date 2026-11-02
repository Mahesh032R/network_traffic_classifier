"""Synthetic traffic, local temporary databases and mocked OS counters only."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import queue
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.activity import ActivityMonitor, AlertEngine
from src.history import DEFAULTS, HistoryStore, fingerprint
from src.telemetry import CounterRate, flow_direction, resolve_adapter
from src.capture import CaptureSession
from src.capture_worker import process_flow


def flow(**changes):
    return {'src_ip': '192.0.2.10', 'dst_ip': '198.51.100.2', 'src_port': 50000, 'dst_port': 443,
            'src2dst_bytes': 100, 'dst2src_bytes': 300, 'bidirectional_bytes': 400,
            'bidirectional_packets': 4, 'protocol': 6, 'Detected Service': 'Fixture Service',
            'Process Name': 'fixture.exe', 'Process Executable': r'C:\Fixtures\fixture.exe',
            'Process Evidence': 'Exact connected socket and capture-time overlap',
            'Detected Hostname': 'fixture.example', 'Identification Status': 'Hostname evidence',
            'Upload Bytes': 100, 'Download Bytes': 300, 'Remote IP': '198.51.100.2',
            **changes}


class DirectionAndCounterTests(unittest.TestCase):
    def test_counter_rates_are_interval_averages(self):
        rate = CounterRate()
        self.assertIsNone(rate.sample(100, 200, 1, 1000))
        result = rate.sample(2_000_100, 1_000_200, 3, 1002)
        self.assertEqual((result['download_mbps'], result['upload_mbps']), (8, 4))
        self.assertEqual((result['download'], result['upload'], result['seconds']), (2_000_000, 1_000_000, 2))

    def test_reset_does_not_create_spike_or_negative_rate(self):
        rate = CounterRate()
        rate.sample(10000, 10000, 1, 1)
        self.assertIsNone(rate.sample(1, 2, 2, 2))
        self.assertEqual(rate.sample(101, 202, 3, 3)['download'], 100)

    def test_zero_elapsed_has_no_rate_but_zero_traffic_is_valid(self):
        rate = CounterRate()
        rate.sample(10, 20, 1, 1)
        self.assertIsNone(rate.sample(10, 20, 1, 1))
        self.assertEqual(rate.sample(10, 20, 2, 2)['download_mbps'], 0)

    def test_ipv4_direction_and_reversed_endpoints(self):
        self.assertEqual(flow_direction(flow(), ['192.0.2.10']), (100, 300, '198.51.100.2'))
        self.assertEqual(flow_direction(flow(), ['198.51.100.2']), (300, 100, '192.0.2.10'))

    def test_ipv6_and_mapped_ipv4_direction(self):
        self.assertEqual(flow_direction(flow(src_ip='2001:db8::1%4', dst_ip='2001:db8::2'), ['2001:db8::1']),
                         (100, 300, '2001:db8::2'))
        self.assertEqual(flow_direction(flow(src_ip='::ffff:192.0.2.10'), ['192.0.2.10']),
                         (100, 300, '198.51.100.2'))

    def test_unknown_loopback_both_local_and_bad_counters_are_unassigned(self):
        cases = [(flow(), []), (flow(), ['192.0.2.10', '198.51.100.2']),
                 (flow(src_ip='127.0.0.1', dst_ip='127.0.0.2'), ['127.0.0.1']),
                 (flow(src_ip='invalid'), ['192.0.2.10']),
                 (flow(src2dst_bytes=-1), ['192.0.2.10']),
                 (flow(src2dst_bytes=101), ['192.0.2.10'])]
        for row, local in cases:
            with self.subTest(row=row):
                self.assertEqual(flow_direction(row, local), (None, None, None))

    def test_worker_direction_does_not_require_a_process_guess(self):
        row = process_flow(SimpleNamespace(**flow()), local_addresses=['192.0.2.10'])
        self.assertEqual((row['Upload Bytes'], row['Download Bytes']), (100, 300))
        self.assertEqual(row['Process Name'], 'Unknown Process')

    def test_adapter_requires_exact_guid_not_friendly_description(self):
        guid = '00000000-0000-0000-0000-000000000001'
        inventory = [{'Name': 'Fixture adapter', 'InterfaceGuid': guid}]
        addresses = {'Fixture adapter': [SimpleNamespace(address='192.0.2.10')]}
        self.assertEqual(resolve_adapter('\\Device\\NPF_{' + guid + '}', inventory=inventory, addresses=addresses),
                         ('Fixture adapter', ['192.0.2.10']))
        self.assertIsNone(resolve_adapter('Fixture adapter', inventory=inventory, addresses=addresses))
        self.assertIsNone(resolve_adapter('\\Device\\NPF_{' + guid + '}', inventory=[], addresses=addresses))
        self.assertIsNone(resolve_adapter('\\Device\\NPF_{' + guid + '}', inventory='invalid', addresses=addresses))


class ActivityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1_800_000_000.0
        self.clock = lambda: self.now
        self.path = Path(self.temp.name) / 'activity.sqlite3'
        self.monitor = ActivityMonitor(self.path, clock=self.clock, monotonic=self.clock, background=False)
        self.addCleanup(self.monitor.close)

    def test_flow_deduplication_survives_recorder_restart(self):
        self.monitor.on_flow('fixture:1', flow())
        self.monitor.on_flow('fixture:1', flow())
        restarted = ActivityMonitor(self.path, clock=self.clock, background=False)
        restarted.on_flow('fixture:1', flow())
        rows = restarted.store.query('flows', self.now - 1, self.now + 1)
        self.assertEqual((len(rows), rows[0]['bytes'], rows[0]['count']), (1, 400, 1))

    def test_default_history_contains_no_endpoints_processes_or_paths(self):
        self.monitor.on_flow('fixture:1', flow())
        rows = self.monitor.store.query('flows', self.now - 1, self.now + 1)
        self.assertEqual((rows[0]['service'], rows[0]['process']), ('', ''))
        for p in self.path.parent.glob('*'):
            data = p.read_bytes()
            for private in (b'192.0.2.10', b'198.51.100.2', b'fixture.example', b'C:\\Fixtures', b'fixture.exe'):
                self.assertNotIn(private, data)

    def test_opt_in_names_persist_basename_and_no_executable_path(self):
        self.monitor.configure(self.monitor.config | {'names': True})
        self.monitor.on_flow('fixture:1', flow(**{'Process Name': r'C:\Fixtures\fixture.exe'}))
        restarted = ActivityMonitor(self.path, clock=self.clock, background=False)
        row = restarted.store.query('flows', self.now - 1, self.now + 1)[0]
        self.assertEqual((row['service'], row['process']), ('Fixture Service', 'fixture.exe'))

    def test_history_opt_out_retains_only_bounded_memory(self):
        self.monitor.configure(self.monitor.config | {'enabled': False})
        self.monitor.on_flow('fixture:1', flow())
        self.assertEqual(self.monitor.store.query('flows', self.now - 1, self.now + 1), [])
        self.assertEqual(len(self.monitor.flows), 1)
        self.assertEqual(self.monitor.store.alerts(), [])

    def test_new_alerts_are_deduplicated_across_restart(self):
        self.monitor.on_flow('fixture:1', flow())
        self.monitor.on_flow('fixture:2', flow())
        self.assertEqual({r['kind'] for r in self.monitor.alerts()}, {'New service', 'New process'})
        restarted = ActivityMonitor(self.path, clock=self.clock, background=False)
        restarted.on_flow('fixture:3', flow())
        self.assertEqual(len(restarted.alerts()), 2)

    def test_unknown_service_and_unreliable_process_never_create_identity_alerts(self):
        self.monitor.on_flow('fixture:1', flow(**{'Detected Service': 'Unknown', 'Process Evidence': 'No exact socket match'}))
        self.assertEqual(self.monitor.alerts(), [])

    def test_mbps_threshold_cooldown_and_restart(self):
        engine = self.monitor.engine
        engine.sample({'download_mbps': 19.9, 'upload_mbps': 0})
        self.assertEqual(self.monitor.alerts(), [])
        engine.sample({'download_mbps': 20, 'upload_mbps': 0})
        engine.sample({'download_mbps': 40, 'upload_mbps': 0})
        self.assertEqual(len(self.monitor.alerts()), 1)
        self.now += 30
        restarted = ActivityMonitor(self.path, clock=self.clock, background=False)
        restarted.engine.sample({'download_mbps': 40, 'upload_mbps': 0})
        self.assertEqual(len(restarted.alerts()), 1)
        self.now += 31
        restarted.engine.sample({'download_mbps': 40, 'upload_mbps': 0})
        self.assertEqual(len(restarted.alerts()), 2)

    def test_completed_flow_usage_threshold_uses_rolling_window(self):
        self.monitor.configure(self.monitor.config | {'usage_mb': .01})
        for i in range(3):
            self.monitor.on_flow(str(i), flow(bidirectional_bytes=4000))
        self.assertEqual(len([r for r in self.monitor.alerts() if r['kind'] == 'High flow usage']), 1)
        self.now += 61
        self.monitor.on_flow('new-window', flow())
        self.assertEqual(len(self.monitor.engine.usage), 1)

    def test_busy_flow_window_preserves_bytes_without_unbounded_event_memory(self):
        engine = self.monitor.engine
        engine.config = engine.config | {'new_service': False, 'new_process': False, 'usage_mb': 1.00005}
        row = {'service': 'Unknown', 'process': 'Unknown Process', 'bytes': 100}
        for _ in range(10001):
            engine.flow({}, row)
        self.assertEqual(len(engine.usage), 1)
        self.assertEqual(sum(value for _, value in engine.usage), 1_000_100)
        self.assertEqual(self.monitor.alerts()[0]['kind'], 'High flow usage')

    def test_repeated_destination_count_window_and_no_endpoint_in_alert(self):
        self.monitor.configure(self.monitor.config | {'repeated': True, 'connection_count': 2,
                                                       'destination_key': fingerprint('fixture.example')})
        self.monitor.on_flow('1', flow())
        self.now += 61
        self.monitor.on_flow('2', flow())
        self.assertFalse(any(r['kind'] == 'Repeated connections' for r in self.monitor.alerts()))
        self.monitor.on_flow('3', flow())
        matches = [r for r in self.monitor.alerts() if r['kind'] == 'Repeated connections']
        self.assertEqual(len(matches), 1)
        self.assertNotIn('fixture.example', json.dumps(matches))

    def test_dns_only_lookup_does_not_count_as_destination_connection(self):
        self.monitor.configure(self.monitor.config | {'repeated': True, 'connection_count': 2,
                                                       'destination_key': fingerprint('fixture.example')})
        for i in range(3):
            self.monitor.on_flow(str(i), flow(dst_port=53, **{'Remote IP': None, 'Identification Status': 'Lookup only'}))
        self.assertEqual(len(self.monitor.engine.connections), 0)

    def test_blocking_state_baseline_changes_recovery_and_disabled_alerts(self):
        entries = [{'target': 'fixture.example'}]
        state = {'value': 'active'}
        lookup = lambda _: {'states': {'domain': state['value']}, 'error': None}
        self.monitor.engine.blocking(entries, lookup)
        self.assertEqual(self.monitor.alerts(), [])
        state['value'] = 'absent'
        self.monitor.engine.blocking(entries, lookup)
        self.monitor.engine.blocking(entries, lookup)
        self.assertEqual(len(self.monitor.alerts()), 1)
        self.assertEqual(self.monitor.alerts()[0]['severity'], 'Warning')
        self.now += 61
        state['value'] = 'active'
        self.monitor.engine.blocking(entries, lookup)
        self.assertEqual(len(self.monitor.alerts()), 2)
        self.assertEqual(self.monitor.alerts()[0]['severity'], 'Information')

    def test_inspection_failure_does_not_claim_rule_was_removed(self):
        self.monitor.engine.blocking([{'target': 'fixture.example'}],
                                     lambda _: {'states': {}, 'error': 'denied'})
        self.assertEqual(self.monitor.alerts()[0]['kind'], 'Blocking inspection')

    def test_visible_dashboard_checks_blocking_without_collecting_adapter_counters(self):
        self.monitor.touch()
        state = {'value': 'active'}
        with patch('src.activity.blocklist.list_entries', return_value=[{'target': 'fixture.example', 'type': 'Domain'}]), patch(
            'src.activity.entry_status', side_effect=lambda *_a, **_k: {'states': {'domain': state['value']}, 'error': None}), patch(
            'src.activity.psutil.net_io_counters') as counters:
            self.monitor.tick()
            self.now += 30
            self.monitor.touch()
            state['value'] = 'absent'
            self.monitor.tick()
            counters.assert_not_called()
        self.assertEqual(self.monitor.alerts()[0]['kind'], 'Blocking status change')

    def test_each_alert_type_can_be_disabled(self):
        self.monitor.configure(self.monitor.config | {key: False for key in ['new_service', 'new_process', 'high_usage', 'repeated', 'blocking']})
        self.monitor.on_flow('1', flow())
        self.monitor.engine.sample({'download_mbps': 100, 'upload_mbps': 100})
        self.assertEqual(self.monitor.alerts(), [])

    def test_read_dismiss_and_clear_survive_restart(self):
        self.monitor.on_flow('1', flow())
        first = self.monitor.alerts()[0]['id']
        self.monitor.alert_action('read')
        self.assertTrue(all(row['read'] for row in ActivityMonitor(self.path, background=False).alerts()))
        self.monitor.alert_action('dismiss', first)
        self.assertEqual(len(self.monitor.alerts()), 1)
        self.monitor.alert_action('clear')
        self.assertEqual(ActivityMonitor(self.path, background=False).alerts(), [])

    def test_clear_history_removes_aggregates_alerts_and_dedup_state(self):
        self.monitor.configure(self.monitor.config | {'names': True})
        self.monitor.on_flow('1', flow())
        self.monitor.store.record_usage('fixture', {'timestamp': self.now, 'download': 100, 'upload': 20, 'seconds': 2})
        self.assertTrue(self.monitor.clear_history())
        self.assertEqual(self.monitor.alerts(), [])
        self.assertEqual(self.monitor.store.query('flows', 0, self.now + 1), [])
        self.assertEqual(self.monitor.store.query('usage', 0, self.now + 1), [])
        for path in self.path.parent.glob('*'):
            self.assertNotIn(b'fixture.exe', path.read_bytes())
        self.monitor.on_flow('1', flow())
        self.assertEqual(self.monitor.store.query('flows', 0, self.now + 1), [])

    def test_parameterized_summary_values_cannot_change_schema(self):
        self.monitor.configure(self.monitor.config | {'names': True})
        self.monitor.on_flow('sql-fixture', flow(**{'Detected Service': "Fixture'); DROP TABLE flows; --"}))
        self.assertEqual(self.monitor.store.query('flows', 0, self.now + 1)[0]['count'], 1)

    def test_retention_and_row_caps(self):
        self.monitor.on_flow('1', flow())
        self.now += 8 * 86400
        self.assertTrue(self.monitor.store.prune(7))
        self.assertEqual(self.monitor.store.query('flows', 0, self.now + 1), [])
        self.assertEqual(self.monitor.alerts(), [])
        with self.monitor.store.connection() as db:
            db.executemany('INSERT INTO alerts VALUES(?,?,?,?,?,0,0)',
                           [(str(i), self.now, 'Fixture', 'Information', 'Synthetic') for i in range(1005)])
        self.monitor.store.prune(7)
        with self.monitor.store.connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM alerts').fetchone()[0], 1000)

    def test_concurrent_flow_inserts_are_idempotent(self):
        row = {'timestamp': self.now, 'service': 'Fixture', 'process': 'fixture.exe', 'protocol': 'TCP',
               'status': 'Identified', 'bytes': 400, 'upload': 100, 'download': 300}
        stores = [HistoryStore(self.path, self.clock) for _ in range(4)]
        with ThreadPoolExecutor(4) as pool:
            result = list(pool.map(lambda store: store.record_flow('same-event', row), stores))
        self.assertEqual(sum(result), 1)
        self.assertEqual(self.monitor.store.query('flows', 0, self.now + 1)[0]['count'], 1)

    def test_concurrent_alert_cooldowns_emit_only_one_record(self):
        stores = [HistoryStore(self.path, self.clock) for _ in range(4)]
        with ThreadPoolExecutor(4) as pool:
            rows = list(pool.map(lambda store: store.emit('Fixture', 'shared-event', 'Information', 'Synthetic', 60), stores))
        self.assertEqual(sum(row is not None for row in rows), 1)
        self.assertEqual(len(self.monitor.store.alerts()), 1)

    def test_corruption_and_locked_database_do_not_raise_into_capture(self):
        bad = Path(self.temp.name) / 'corrupt.sqlite3'
        bad.write_bytes(b'not a database')
        store = HistoryStore(bad)
        self.assertFalse(store.ready)
        self.assertIn('unavailable', store.error)
        self.assertEqual(store.query('usage', 0, self.now), [])
        with self.monitor.store.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            self.monitor.on_flow('1', flow())
            self.assertIsNotNone(self.monitor.store.error)
        self.monitor.on_flow('2', flow())
        self.assertEqual(len(self.monitor.flows), 2)

    def test_sampling_reset_missing_adapter_and_exclusive_capture(self):
        self.assertTrue(self.monitor.acquire('owner', 'fixture'))
        self.assertFalse(self.monitor.acquire('other-owner', 'fixture'))
        binding = lambda _: ('Fixture adapter', ['192.0.2.10'])
        with patch('src.activity.blocklist.list_entries', return_value=[]):
            self.monitor.tick(resolver=binding, counters={'Fixture adapter': SimpleNamespace(bytes_recv=10, bytes_sent=20)})
            self.assertIsNone(self.monitor.latest)
            self.now += 2
            self.monitor.tick(resolver=binding, counters={'Fixture adapter': SimpleNamespace(bytes_recv=110, bytes_sent=220)})
            self.assertEqual(self.monitor.latest['download'], 100)
            self.monitor.tick(resolver=binding, counters={})
            self.assertIsNone(self.monitor.latest)
        self.monitor.release('owner')
        self.assertEqual(self.monitor.snapshot()['state'], 'Stopped')
        self.assertTrue(self.monitor.acquire('owner2', 'fixture'))
        self.assertIsNone(self.monitor.latest)

    def test_separate_app_instances_share_a_capture_lease(self):
        other = ActivityMonitor(self.path, clock=self.clock, background=False)
        self.assertTrue(self.monitor.acquire('owner', 'fixture'))
        self.assertFalse(other.acquire('other', 'fixture'))
        self.monitor.release('owner')
        self.assertTrue(other.acquire('other', 'fixture'))
        other.release('other')

    def test_stop_during_slow_inspection_does_not_reacquire_capture_lease(self):
        self.monitor.acquire('owner', 'fixture')
        def inspect(*_a, **_k):
            self.monitor.release('owner')
            return {'states': {'domain': 'active'}, 'error': None}
        with patch('src.activity.blocklist.list_entries', return_value=[{'target': 'fixture.example', 'type': 'Domain'}]), patch(
            'src.activity.entry_status', side_effect=inspect), patch('src.activity.psutil.net_io_counters') as counters:
            self.monitor.tick()
            counters.assert_not_called()
        with self.monitor.store.connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM capture_lease').fetchone()[0], 0)

    def test_stale_rates_are_not_displayed_as_live(self):
        self.monitor.acquire('owner', 'fixture')
        self.monitor.latest = {'timestamp': self.now, 'seconds': 2, 'download_mbps': 1, 'upload_mbps': 1}
        self.now += 7
        self.assertIsNone(self.monitor.snapshot()['latest'])
        self.assertIn('fresh', self.monitor.snapshot()['state'])

    def test_full_activity_queue_drops_history_without_interrupting_capture(self):
        self.monitor.background = True
        with patch.object(self.monitor._pending, 'put_nowait', side_effect=queue.Full):
            session = CaptureSession(activity=self.monitor)
            session._accept({'type': 'flow', 'row': flow()})
        self.assertEqual(session.snapshot()['total_flows'], 1)
        self.assertEqual(self.monitor.dropped_events, 1)

    def test_capture_ingestion_event_ids_do_not_duplicate_on_snapshots(self):
        session = CaptureSession(activity=self.monitor)
        self.addCleanup(session.stop)
        message = {'type': 'flow', 'event_id': 1, 'row': flow()}
        session._accept(message)
        session._accept(message)
        for _ in range(5):
            session.snapshot()
        self.assertEqual(session.snapshot()['total_flows'], 1)
        self.assertEqual(len(self.monitor.flows), 1)


if __name__ == '__main__':
    unittest.main()
