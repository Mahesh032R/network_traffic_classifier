"""Mocked hardware, real subprocess lifecycle, and RF feature compatibility tests."""
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import numpy as np
import pandas as pd
import psutil

from src import capture, capture_worker
from src.model_utils import PROJECT_ROOT
from src.predict import load_model, predict_with_model

FIXTURE = Path(__file__).with_name('capture_fixture_worker.py')
REAL_POPEN = subprocess.Popen


def fixture_popen(scenario='idle'):
    def start(_command, **kwargs):
        control_file = _command[_command.index('--control-file') + 1]
        return REAL_POPEN([sys.executable, '-B', str(FIXTURE), '--scenario', scenario,
                           '--control-file', control_file], **kwargs)
    return start


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class FlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = load_model()
        cls.values = pd.read_csv(PROJECT_ROOT / 'data/test_flows.csv').iloc[0].to_dict()
        cls.values.update(src_ip='192.0.2.1', dst_ip='198.51.100.2', src_port=12345, dst_port=443)

    def test_complete_features_match_pcap_prediction(self):
        row = capture_worker.process_flow(SimpleNamespace(**self.values), self.bundle)
        expected = predict_with_model(pd.DataFrame([self.values]), self.bundle).iloc[0]
        self.assertEqual(row['Predicted App'], expected.pred_label)
        self.assertEqual(row['Confidence'], expected.pred_confidence)
        self.assertIn('unverified', row['Prediction Status'])
        self.assertEqual(row['src_ip'], '192.0.2.1')

    def test_missing_and_none_features_skip_prediction(self):
        feature = self.bundle[2][-1]
        for value in ['missing', None]:
            values = dict(self.values)
            if value == 'missing':
                values.pop(feature)
            else:
                values[feature] = None
            row = capture_worker.process_flow(SimpleNamespace(**values), self.bundle)
            self.assertIsNone(row['Confidence'])
            self.assertIn(feature, row['Prediction Status'])

    def test_nonnumeric_feature_error_is_visible(self):
        values = dict(self.values)
        values[self.bundle[2][-1]] = 'invalid'
        row = capture_worker.process_flow(SimpleNamespace(**values), self.bundle)
        self.assertIsNone(row['Confidence'])
        self.assertIn('numeric', row['Prediction Status'])

    def test_undefined_statistics_use_existing_preprocessing(self):
        values = dict(self.values)
        values[self.bundle[2][-1]] = np.inf
        row = capture_worker.process_flow(SimpleNamespace(**values), self.bundle)
        self.assertIsInstance(row['Confidence'], float)

    def test_missing_model_keeps_observed_flows(self):
        row = capture_worker.process_flow(SimpleNamespace(**self.values))
        self.assertIsNone(row['Confidence'])
        self.assertEqual(row['bidirectional_bytes'], self.values['bidirectional_bytes'])

    def test_worker_options_and_stop_interrupt(self):
        stop, cleaned = threading.Event(), threading.Event()

        def flows():
            stop.set()
            try:
                yield SimpleNamespace(**self.values)
            except KeyboardInterrupt:
                cleaned.set()

        factory = Mock(return_value=flows())
        events = []
        with patch.object(capture_worker, 'load_model', return_value=self.bundle):
            capture_worker.run_capture('test-interface', stop, events.append, factory)
        self.assertTrue(cleaned.is_set())
        self.assertEqual([e for e in events if e['type'] != 'diagnostic'], [{'type': 'ready'}])
        self.assertEqual(factory.call_args.kwargs['n_meters'], 1)
        self.assertEqual(factory.call_args.kwargs['n_dissections'], 32)
        self.assertTrue(factory.call_args.kwargs['statistical_analysis'])

    def test_model_load_failure_warns_and_still_collects_flows(self):
        events = []
        with patch.object(capture_worker, 'load_model', side_effect=ValueError('bad model')):
            capture_worker.run_capture('test', threading.Event(), events.append,
                                       Mock(return_value=iter([SimpleNamespace(**self.values)])))
        self.assertTrue(any(e['type'] == 'warning' and 'bad model' in e['message'] for e in events))
        row = next(e['row'] for e in events if e['type'] == 'flow')
        self.assertIsNone(row['Confidence'])
        self.assertEqual(row['src_ip'], self.values['src_ip'])


class CaptureSessionTests(unittest.TestCase):
    def session(self, scenario='idle', **kwargs):
        patcher = patch.object(capture.subprocess, 'Popen', side_effect=fixture_popen(scenario))
        patcher.start()
        self.addCleanup(patcher.stop)
        session = capture.CaptureSession(**kwargs)
        self.addCleanup(session.stop)
        self.assertTrue(session.start('test-interface'))
        return session

    def test_duplicate_start_and_idle_stop(self):
        session = self.session()
        self.assertTrue(wait_for(lambda: session.snapshot()['status'] == 'running'))
        process_id = session.snapshot()['pid']
        self.assertFalse(session.start('another-interface'))
        started = time.monotonic()
        self.assertTrue(session.stop())
        self.assertLess(time.monotonic() - started, 5)
        self.assertFalse(psutil.pid_exists(process_id))
        self.assertEqual(session.snapshot()['status'], 'stopped')
        self.assertTrue(session.stop())

    def test_flow_totals_remain_correct_when_history_is_bounded(self):
        session = self.session('flows', max_flows=2)
        self.assertTrue(wait_for(lambda: session.snapshot()['total_flows'] == 3))
        snapshot = session.snapshot()
        self.assertEqual(len(snapshot['flows']), 2)
        self.assertEqual((snapshot['packets'], snapshot['bytes'], snapshot['predicted_flows']), (9, 600, 3))
        self.assertEqual(snapshot['protocols']['TCP']['Flows'], 2)
        self.assertEqual(snapshot['protocols']['UDP']['Flows'], 1)
        snapshot['flows'][0]['src_ip'] = 'modified'
        self.assertNotEqual(session.snapshot()['flows'][0]['src_ip'], 'modified')

    def test_capture_error_is_reported_and_can_restart(self):
        session = self.session('error')
        self.assertTrue(wait_for(lambda: not session.snapshot()['running']))
        self.assertEqual(session.snapshot()['status'], 'error')
        self.assertIn('permission denied', session.snapshot()['error'])
        self.assertTrue(session.start('test-interface'))
        self.assertTrue(wait_for(lambda: not session.snapshot()['running']))

    def test_unexpected_exit_is_visible(self):
        session = self.session('crash')
        self.assertTrue(wait_for(lambda: not session.snapshot()['running']))
        self.assertIn('unexpectedly', session.snapshot()['error'])

    def test_worker_launch_failure(self):
        session = capture.CaptureSession()
        with patch.object(capture.subprocess, 'Popen', side_effect=OSError('launch failed')):
            session.start('test-interface')
            self.assertTrue(wait_for(lambda: not session.snapshot()['running']))
        self.assertIn('launch failed', session.snapshot()['error'])

    def test_unwritable_control_directory_is_visible(self):
        session = capture.CaptureSession()
        with patch.object(capture.tempfile, 'TemporaryDirectory', side_effect=PermissionError('temp folder denied')):
            session.start('test-interface')
            self.assertTrue(wait_for(lambda: not session.snapshot()['running']))
        self.assertEqual(session.snapshot()['status'], 'error')
        self.assertIn('temp folder denied', session.snapshot()['error'])

    def test_startup_timeout(self):
        session = self.session('no_ready', startup_timeout=0.3)
        self.assertTrue(wait_for(lambda: not session.snapshot()['running']))
        self.assertIn('startup timed out', session.snapshot()['error'])

    def test_browser_lease_expiry_stops_capture(self):
        session = self.session(lease_seconds=0.4)
        self.assertTrue(wait_for(lambda: not session.snapshot()['running']))
        self.assertIn('disconnected', session.snapshot()['warning'])

    def test_heartbeat_keeps_capture_alive(self):
        session = self.session(lease_seconds=0.5)
        for _ in range(10):
            session.touch()
            time.sleep(0.1)
        self.assertTrue(session.snapshot()['running'])

    def test_stop_kills_stubborn_meter_descendants(self):
        session = self.session('tree')
        self.assertTrue(wait_for(lambda: session.snapshot()['status'] == 'running'))
        root = psutil.Process(session.snapshot()['pid'])
        self.assertTrue(wait_for(lambda: len(root.children(recursive=True)) >= 1))
        children = root.children(recursive=True)
        self.assertTrue(session.stop())
        self.assertTrue(all(not child.is_running() for child in children))
        self.assertFalse(root.is_running())

    def test_invalid_selection(self):
        with self.assertRaises(ValueError):
            capture.CaptureSession().start('')

    def test_failed_cleanup_prevents_another_worker(self):
        session = capture.CaptureSession()
        session._cleanup_failed = True
        with self.assertRaisesRegex(RuntimeError, 'Restart Streamlit'):
            session.start('test-interface')

    def test_model_warning_and_bounded_diagnostics(self):
        session = capture.CaptureSession()
        session._accept({'type': 'warning', 'message': 'model unavailable'})
        self.assertEqual(session.snapshot()['warning'], 'model unavailable')
        process = SimpleNamespace(stdout=iter(['not json\n'] * 30))
        session._read_stdout(process)
        self.assertEqual(len(session.snapshot()['diagnostics']), 10)

    @unittest.skipUnless(os.environ.get('TRAFFIC_TEST_PCAP'), 'Set TRAFFIC_TEST_PCAP for the real isolated worker')
    def test_real_isolated_worker_on_existing_pcap(self):
        session = capture.CaptureSession()
        self.addCleanup(session.stop)
        session.start(str(Path(os.environ['TRAFFIC_TEST_PCAP']).resolve()))
        self.assertTrue(wait_for(lambda: not session.snapshot()['running'], timeout=25))
        snapshot = session.snapshot()
        self.assertIsNone(snapshot['error'])
        self.assertGreater(snapshot['total_flows'], 0)
        self.assertEqual(snapshot['total_flows'], snapshot['predicted_flows'])
        for field in ('application_name', 'application_category_name',
                      'application_is_guessed', 'application_confidence',
                      'requested_server_name', 'client_fingerprint',
                      'server_fingerprint', 'user_agent', 'content_type',
                      'Unknown Reason'):
            self.assertIn(field, snapshot['flows'][0])
        self.assertFalse(any('ScriptRunContext' in line for line in snapshot['diagnostics']))


class InterfaceTests(unittest.TestCase):
    def test_missing_npcap_has_actionable_error(self):
        with patch.object(capture.os, 'add_dll_directory', side_effect=FileNotFoundError('Npcap')):
            with self.assertRaisesRegex(RuntimeError, 'Npcap.*Administrator'):
                capture.list_capture_interfaces()


if __name__ == '__main__':
    unittest.main()
