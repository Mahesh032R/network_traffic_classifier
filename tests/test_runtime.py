"""Regression checks; no real firewall or hosts-file writes are performed."""
import importlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import zipfile

import joblib
import numpy as np
import pandas as pd
import pyarrow as pa
import streamlit as st
from streamlit.testing.v1 import AppTest

from src import blocklist, capture, domain_blocker, extract, firewall, predict, predict_xgboost
from test_capture import fixture_popen, wait_for
from src.model_utils import PROJECT_ROOT, prepare_features
from src.scenario_b import ARFF_FILE, FEATURE_NAMES, load_scenario_b


def arff_bytes(rows=70):
    labels = ['BROWSING', 'CHAT', 'FT', 'MAIL', 'P2P', 'STREAMING', 'VOIP']
    header = '@relation traffic\n' + ''.join(f'@attribute {f} numeric\n' for f in FEATURE_NAMES)
    header += '@attribute label {' + ','.join(labels) + '}\n@data\n'
    body = ''.join(','.join([str(i + 1)] * 23 + [labels[i % 7]]) + '\n' for i in range(rows))
    return (header + body).encode()


class PredictionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rf = predict.load_model()
        cls.xgb = predict_xgboost.load_xgboost_model()
        cls.rf_input = pd.read_csv(PROJECT_ROOT / 'data/test_flows.csv').head(4)

    def test_rf_keeps_model_application_labels(self):
        with patch.object(predict, 'load_model', return_value=self.rf):
            result = predict.predict_df(self.rf_input)
        expected = self.rf[0].predict(self.rf_input[self.rf[2]])
        np.testing.assert_array_equal(result.pred_label, expected)
        self.assertTrue(result.pred_confidence.between(0, 100).all())
        self.assertIsNone(self.rf[1])  # The old, unrelated encoder is unnecessary.

    def test_xgboost_predictions_decode_and_preserve_index(self):
        frame = pd.DataFrame(1.0, index=[5, 9], columns=FEATURE_NAMES)
        with patch.object(predict_xgboost, 'load_xgboost_model', return_value=self.xgb):
            result = predict_xgboost.predict_xgboost_df(frame[FEATURE_NAMES[::-1]])
        self.assertEqual(list(result.index), [5, 9])
        self.assertTrue(set(result.pred_label).issubset(self.xgb[2].classes_))
        self.assertTrue(result.pred_confidence.between(0, 100).all())
        self.assertNotIn('pred_label', frame)

    def test_default_models_load_outside_project_directory(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as folder:
            try:
                os.chdir(folder)
                self.assertEqual(len(predict.load_model()[2]), 61)
                self.assertEqual(len(predict_xgboost.load_xgboost_model()[1]), 23)
            finally:
                os.chdir(previous)

    def test_missing_and_corrupt_artifacts_have_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(FileNotFoundError, 'rf_model.pkl'):
                predict.load_model(folder)
            (Path(folder) / 'rf_model.pkl').write_bytes(b'broken pickle')
            with self.assertRaisesRegex(RuntimeError, 'rf_model.pkl'):
                predict.load_model(folder)
            joblib.dump({'not': 'a classifier'}, Path(folder) / 'rf_model.pkl')
            joblib.dump(['a'], Path(folder) / 'feature_names.pkl')
            with self.assertRaisesRegex(ValueError, 'classifier'):
                predict.load_model(folder)

    def test_incompatible_feature_artifacts_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            joblib.dump(self.rf[0], Path(folder) / 'rf_model.pkl')
            joblib.dump(['wrong'], Path(folder) / 'feature_names.pkl')
            with self.assertRaisesRegex(ValueError, 'feature counts'):
                predict.load_model(folder)

    def test_invalid_features_are_rejected(self):
        cases = [
            (pd.DataFrame(), 'empty'),
            (pd.DataFrame({'other': [1]}), 'Missing required'),
            (pd.DataFrame({'a': ['bad']}), 'numeric'),
            (pd.DataFrame([[1, 2]], columns=['a', 'a']), 'duplicate'),
        ]
        for frame, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                prepare_features(frame, ['a'])

    def test_numeric_strings_and_undefined_statistics(self):
        frame = pd.DataFrame({'a': ['1', None, 'inf', '-inf']})
        np.testing.assert_array_equal(prepare_features(frame, ['a']).a, [1, 0, 0, 0])

    def test_prediction_helpers_reject_missing_columns(self):
        with self.assertRaisesRegex(ValueError, 'Missing required'):
            predict.predict_df(pd.DataFrame({'unrelated': [1]}))
        with self.assertRaisesRegex(ValueError, 'Missing required'):
            predict_xgboost.predict_xgboost_df(pd.DataFrame({'unrelated': [1]}))

    def test_training_modules_import_without_training(self):
        with patch('joblib.dump', side_effect=AssertionError('Import must not save models')):
            for name in ['src.train', 'src.train_metadata', 'src.train_scenario_b', 'src.train_xgboost']:
                module = importlib.import_module(name)
                self.assertTrue(callable(module.main))


class BlockingTests(unittest.TestCase):
    def test_domain_add_remove_preserves_hosts_and_markers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'hosts'
            path.write_text('127.0.0.1 localhost\n# keep this\n', encoding='utf-8')
            with patch.object(domain_blocker, 'HOSTS_FILE', path):
                domain_blocker.block_domain('one.example', confirmed=True)
                domain_blocker.block_domain('two.example', confirmed=True)
                domain_blocker.block_domain('two.example', confirmed=True)
                self.assertEqual(path.read_text().count('127.0.0.1 two.example\n'), 1)
                self.assertTrue(domain_blocker.is_domain_blocked('two.example'))
                domain_blocker.unblock_domain('one.example', confirmed=True)
                self.assertTrue(domain_blocker.is_domain_blocked('two.example'))
                domain_blocker.unblock_domain('two.example', confirmed=True)
                self.assertNotIn(domain_blocker.MARKER_START, path.read_text())
                self.assertIn('# keep this', path.read_text())

    def test_invalid_hosts_markers_refuse_edit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'hosts'
            for content in [domain_blocker.MARKER_START,
                            domain_blocker.MARKER_END + '\n' + domain_blocker.MARKER_START]:
                path.write_text(content)
                with patch.object(domain_blocker, 'HOSTS_FILE', path):
                    with self.assertRaises(RuntimeError):
                        domain_blocker.block_domain('one.example', confirmed=True)
                self.assertEqual(path.read_text(), content)

    def test_blocklist_round_trip_uses_temporary_file(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(blocklist, 'DATA_DIR', Path(folder)), patch.object(
                blocklist, 'BLOCKLIST_FILE', Path(folder) / 'blocklist.json'
            ):
                self.assertTrue(blocklist.add_target('EXAMPLE.com.')[0])
                self.assertFalse(blocklist.add_target('example.com')[0])
                self.assertTrue(blocklist.add_target('192.0.2.10')[0])
                self.assertEqual(blocklist.list_blocked(), (['example.com'], ['192.0.2.10']))
                self.assertTrue(blocklist.remove_target('example.com')[0])
                self.assertEqual(len(blocklist.list_events()), 3)

    def test_invalid_block_targets(self):
        for value in ['', 'https://example.com', '*.example.com', 'example.com/path']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                blocklist.normalize_target(value)

    def test_firewall_absent_rule_exit_code_one(self):
        with patch.object(firewall, '_managed_rules', return_value=[]):
            self.assertFalse(firewall.firewall_rule_exists('203.0.113.254'))

    def test_firewall_errors_and_command_arguments(self):
        with patch.object(firewall, '_managed_rules', side_effect=RuntimeError('Access is denied.')):
            with self.assertRaisesRegex(RuntimeError, 'Access is denied'):
                firewall.firewall_rule_exists('192.0.2.10')
        states = iter(['absent', 'active', 'active', 'absent'])
        with patch.object(firewall, 'critical_ip_reasons', return_value=[]), patch.object(
            firewall, 'managed_rule_state', side_effect=lambda *_args, **_kwargs: next(states)
        ), patch.object(firewall, '_run_netsh') as run:
            firewall.block_ip('192.0.2.10', confirmed=True)
            self.assertIn('remoteip=192.0.2.10', run.call_args.args[0])
            self.assertIn('dir=out', run.call_args.args[0])
            firewall.unblock_ip('192.0.2.10', confirmed=True)
            self.assertIn('delete', run.call_args.args[0])
            self.assertIn('remoteip=192.0.2.10', run.call_args.args[0])
            with self.assertRaises(ValueError):
                firewall.block_ip('127.0.0.1', confirmed=True)


class ExtractionTests(unittest.TestCase):
    def test_zip_extraction_cleans_temporary_capture(self):
        sources = []
        expected = pd.DataFrame({'flow': [1]})

        def streamer(**kwargs):
            source = Path(kwargs['source'])
            sources.append(source)
            self.assertEqual(source.read_bytes(), b'\xd4\xc3\xb2\xa1capture')
            return Mock(to_pandas=lambda: expected)

        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / 'capture.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('nested/capture.pcap', b'\xd4\xc3\xb2\xa1capture')
            with patch.object(extract, 'NFStreamer', side_effect=streamer):
                self.assertIs(extract.extract_from_pcap_zip(archive), expected)
            self.assertFalse(sources[0].exists())
            with self.assertRaisesRegex(ValueError, 'member not found'):
                extract.extract_from_pcap_zip(archive, 'missing.pcap')

    def test_invalid_archive_and_missing_nfstream(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / 'empty.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('notes.txt', 'no captures')
            with self.assertRaisesRegex(ValueError, 'No pcap'):
                extract.extract_from_pcap_zip(archive)
            with patch.object(extract, 'NFStreamer', None):
                with self.assertRaisesRegex(RuntimeError, 'NFStreamer'):
                    extract.extract_from_pcap_zip(archive)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        st.cache_data.clear()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.dataset = folder / 'scenario.zip'
        with zipfile.ZipFile(self.dataset, 'w') as archive:
            archive.writestr(ARFF_FILE, arff_bytes())
        for patcher in [patch.dict(os.environ, {'SCENARIO_B_DATASET': str(self.dataset)}),
                        patch.object(blocklist, 'DATA_DIR', folder),
                        patch.object(blocklist, 'BLOCKLIST_FILE', folder / 'blocklist.json'),
                        patch.object(capture, 'list_capture_interfaces', return_value=[{'name': 'test-interface', 'description': 'Test adapter'}])]:
            patcher.start()
            self.addCleanup(patcher.stop)

    def app(self):
        app = AppTest.from_file(str(PROJECT_ROOT / 'dashboard.py'), default_timeout=45).run()
        self.addCleanup(app.session_state['live_capture_runtime'].stop)
        return app

    def assert_clean(self, app):
        self.assertEqual([e.message for e in app.exception], [])
        for table in app.dataframe:
            pa.Table.from_pandas(table.value)

    def test_all_modes_render_with_empty_blocklist(self):
        app = self.app()
        for option in app.radio[0].options:
            app.radio[0].set_value(option).run()
            self.assert_clean(app)
            self.assertFalse(app.error)
        self.assertEqual(app.radio[0].options, ["Monitor", "Analyze file", "Settings"])
        self.assertTrue(any("Blocking & Protection" in e.value for e in app.header))

    def test_csv_upload_and_invalid_numeric_input(self):
        app = self.app()
        app.radio[0].set_value(app.radio[0].options[1]).run()
        frame = pd.DataFrame(1.0, index=[0, 1], columns=FEATURE_NAMES)
        app.file_uploader[0].upload('flows.csv', frame.to_csv(index=False).encode()).run()
        self.assert_clean(app)
        self.assertTrue(any('Analyzed 2 flows' in e.value for e in app.success))
        frame[FEATURE_NAMES[0]] = 'bad'
        app.file_uploader[0].upload('bad.csv', frame.to_csv(index=False).encode()).run()
        self.assert_clean(app)
        self.assertTrue(any('numeric' in e.value for e in app.error))

    def test_arff_upload_decodes_nominal_labels(self):
        app = self.app()
        app.radio[0].set_value(app.radio[0].options[1]).run()
        app.file_uploader[0].upload('flows.arff', arff_bytes(7)).run()
        self.assert_clean(app)
        self.assertTrue(any('Analyzed 7 flows' in e.value for e in app.success))

    def test_rf_csv_upload_keeps_service_and_model_outputs_separate(self):
        frame = pd.read_csv(PROJECT_ROOT / 'data/test_flows.csv').head(2)
        frame['application_name'] = 'TLS'
        frame['requested_server_name'] = 'www.youtube.com'
        frame['src_ip'] = '192.0.2.1'
        frame['dst_ip'] = '198.51.100.2'
        frame['src_port'] = 50000
        frame['dst_port'] = 443
        app = self.app()
        app.radio[0].set_value('Analyze file').run()
        self.assertEqual(len(app.file_uploader), 1)
        app.file_uploader[0].upload('nfstream.csv', frame.to_csv(index=False).encode()).run()
        self.assert_clean(app)
        self.assertTrue(any('Random Forest historical classes' in e.value for e in app.success))
        service_table = next(t.value for t in app.dataframe
                             if 'Detected Service' in t.value.columns and 'Process Name' in t.value.columns)
        self.assertEqual(set(service_table['Detected Service']), {'YouTube'})
        self.assertEqual(set(service_table['Process Name']), {'Unknown Process'})
        model_table = next(t.value for t in app.dataframe if 'Predicted App' in t.value.columns)
        self.assertTrue(model_table['Confidence'].notna().all())

    def test_missing_and_empty_csv_inputs(self):
        app = self.app()
        app.radio[0].set_value(app.radio[0].options[1]).run()
        for content, message in [(b'other\n1\n', 'Unsupported dataset schema'),
                                 ((','.join(FEATURE_NAMES) + '\n').encode(), 'empty')]:
            app.file_uploader[0].upload('invalid.csv', content).run()
            self.assert_clean(app)
            self.assertTrue(any(message in e.value for e in app.error))

    def test_missing_evaluation_dataset_keeps_blocklist_available(self):
        with patch.dict(os.environ, {'SCENARIO_B_DATASET': str(self.dataset) + '.missing'}):
            app = self.app()
            app.radio[0].set_value("Settings").run()
            app.button(key="run_scenario_b_eval").click().run()
        self.assert_clean(app)
        self.assertTrue(any('evaluation unavailable' in e.value for e in app.warning))
        self.assertTrue(any('Blocking & Protection' in e.value for e in app.header))

    def test_missing_xgboost_model_keeps_other_features_available(self):
        st.cache_resource.clear()
        self.addCleanup(st.cache_resource.clear)
        with patch.object(predict_xgboost, 'load_xgboost_model', side_effect=FileNotFoundError('missing model')):
            app = self.app()
            app.radio[0].set_value("Settings").run()
        self.assert_clean(app)
        self.assertTrue(any('Scenario B model unavailable' in e.value for e in app.warning))
        self.assertTrue(any('Blocking & Protection' in e.value for e in app.header))

    def test_capture_state_survives_rerun(self):
        app = self.app()
        runtime = app.session_state['live_capture_runtime']
        runtime._accept({'type': 'warning', 'message': 'sentinel'})
        app.radio[0].set_value("Analyze file").run()
        self.assertIs(app.session_state['live_capture_runtime'], runtime)
        self.assertEqual(runtime.snapshot()['warning'], 'sentinel')
        self.assert_clean(app)

    def test_pcap_and_zip_upload_charts_with_real_rf(self):
        frame = pd.read_csv(PROJECT_ROOT / 'data/test_flows.csv').head(4)
        for column, value in {'src_ip': '192.0.2.1', 'dst_ip': '198.51.100.1',
                              'src_port': 12345, 'dst_port': 443}.items():
            frame[column] = value
        with patch.object(extract, 'NFStreamer', return_value=Mock(to_pandas=lambda: frame.copy())):
            app = self.app()
            app.radio[0].set_value("Analyze file").run()
            app.file_uploader[0].upload('test.pcap', b'\xd4\xc3\xb2\xa1fixture').run()
            self.assert_clean(app)
            self.assertTrue(any(m.label == 'Total flows' and m.value == '4' for m in app.metric))
            content = io.BytesIO()
            with zipfile.ZipFile(content, 'w') as archive:
                archive.writestr('test.pcap', b'\xd4\xc3\xb2\xa1fixture')
            app.file_uploader[0].upload('test.zip', content.getvalue()).run()
            self.assert_clean(app)
            self.assertFalse(app.error)

    def test_partial_label_map_produces_serializable_app_names(self):
        frame = pd.read_csv(PROJECT_ROOT / 'data/test_flows.csv').head(2)
        for column, value in {'src_ip': '192.0.2.1', 'dst_ip': '198.51.100.1',
                              'src_port': 12345, 'dst_port': 443}.items():
            frame[column] = value
        rf = Mock()
        rf.predict.return_value = np.array([0, 99])
        rf.predict_proba.return_value = np.array([[0.9, 0.1], [0.2, 0.8]])
        features = joblib.load(PROJECT_ROOT / 'models/feature_names.pkl')
        st.cache_resource.clear()
        self.addCleanup(st.cache_resource.clear)
        with patch.object(predict, 'load_model', return_value=(rf, None, features)), patch.object(
            extract, 'NFStreamer', return_value=Mock(to_pandas=lambda: frame.copy())
        ):
            app = self.app()
            app.radio[0].set_value("Analyze file").run()
            app.file_uploader[0].upload('test.pcap', b'\xd4\xc3\xb2\xa1fixture').run()
        self.assert_clean(app)
        table = next(t.value for t in app.dataframe if 'Predicted App' in t.value.columns)
        self.assertTrue(all(isinstance(value, str) for value in table['Predicted App']))

    def test_live_start_stop_and_rerun_with_fake_capture(self):
        with patch.object(capture.subprocess, 'Popen', side_effect=fixture_popen('flows')):
            app = self.app()
            app.button(key='start_live_capture').click().run()
            runtime = app.session_state['live_capture_runtime']
            self.assertTrue(wait_for(lambda: runtime.snapshot()['total_flows'] == 3))
            app.button(key='refresh_block_candidates').click().run()
            self.assertTrue(runtime.snapshot()['running'])
            app.run()
            self.assertIs(app.session_state['live_capture_runtime'], runtime)
            self.assertEqual(next(m.value for m in app.metric if m.label == 'Captured flows'), '3')
            self.assertEqual(next(m.value for m in app.metric if m.label == 'Detected services'), '1')
            self.assertEqual(next(m.value for m in app.metric if m.label == 'Unknown flows'), '1')
            live_table = next(table.value for table in app.dataframe if 'Unknown Reason' in table.value.columns)
            self.assertEqual(set(live_table['Detected Service']), {'YouTube', 'Unknown', 'Ambiguous'})
            self.assertIn('Evidence Source', live_table)
            self.assertIn('Process Name', live_table)
            self.assertIn('Unknown Reason', live_table)
            self.assertNotIn('Predicted App', live_table)
            app.text_input(key='live_search').set_value('YouTube').run()
            filtered_table = next(table.value for table in app.dataframe if 'Unknown Reason' in table.value.columns)
            self.assertEqual(set(filtered_table['Detected Service']), {'YouTube'})
            app.text_input(key='live_search').set_value('').run()
            self.assertFalse(app.checkbox(key='confirm_live_csv_export').value)
            app.checkbox(key='confirm_live_csv_export').set_value(True).run()
            self.assertTrue(app.checkbox(key='confirm_live_csv_export').value)
            self.assertIs(app.session_state['live_capture_runtime'], runtime)
            reason_table = next(table.value for table in app.dataframe if 'Unknown reason' in table.value.columns)
            self.assertEqual(int(reason_table['Flows'].sum()), 1)
            self.assertTrue(app.button(key='start_live_capture').disabled)
            app.button(key='stop_live_capture').click().run()
            self.assertFalse(runtime.snapshot()['running'])
            self.assertEqual(runtime.snapshot()['status'], 'stopped')
            self.assert_clean(app)

    def test_leaving_live_mode_stops_its_worker(self):
        with patch.object(capture.subprocess, 'Popen', side_effect=fixture_popen()):
            app = self.app()
            app.button(key='start_live_capture').click().run()
            runtime = app.session_state['live_capture_runtime']
            self.assertTrue(wait_for(lambda: runtime.snapshot()['status'] == 'running'))
            app.radio[0].set_value("Analyze file").run()
            self.assertFalse(runtime.snapshot()['running'])
            self.assert_clean(app)

    def test_capture_failure_is_visible_in_dashboard(self):
        with patch.object(capture.subprocess, 'Popen', side_effect=fixture_popen('error')):
            app = self.app()
            app.button(key='start_live_capture').click().run()
            runtime = app.session_state['live_capture_runtime']
            self.assertTrue(wait_for(lambda: not runtime.snapshot()['running']))
            app.run()
            self.assertTrue(any('permission denied' in error.value for error in app.error))
            self.assert_clean(app)

    def test_interface_discovery_failure_disables_start(self):
        with patch.object(capture, 'list_capture_interfaces', side_effect=RuntimeError('Npcap missing')):
            app = self.app()
            self.assertTrue(any('Npcap missing' in error.value for error in app.error))
            self.assertTrue(app.button(key='start_live_capture').disabled)
            self.assert_clean(app)

    def test_enforcement_buttons_need_target_specific_confirmation(self):
        with patch('src.blocking_ui.is_windows_admin', return_value=True), patch(
            'src.blocking_center.critical_ip_reasons', return_value=[]
        ), patch('src.blocking_ui.firewall._managed_rules', return_value=[]), patch(
            'src.blocking_ui.firewall.block_ip'
        ) as block_ip_call, patch('src.blocking_ui.domain_blocker.block_domain') as block_domain_call:
            app = self.app()
            app.radio[0].set_value("Settings").run()
            app.text_input[0].set_value('192.0.2.10')
            app.button(key='FormSubmitter:preview_ip_form-Preview IP rule').click().run()
            self.assertTrue(any('Target' in table.value.columns for table in app.dataframe))
            block_ip_call.assert_not_called()
            app.button(key='open_block_dialog').click().run()
            self.assertIn('confirm_block_phrase', [item.key for item in app.text_input])
            block_ip_call.assert_not_called()
            app.run()
            app.button(key='save_block_intent').click().run()
            self.assertEqual(blocklist.list_blocked()[1], ['192.0.2.10'])
            block_ip_call.assert_not_called()
            app.text_input[1].set_value('one.example')
            app.button(key='FormSubmitter:preview_domain_form-Preview domain entry').click().run()
            block_domain_call.assert_not_called()
            self.assert_clean(app)

    def test_website_preview_uses_only_recent_hostname_evidence(self):
        with patch('src.blocking_ui.is_windows_admin', return_value=True), patch(
            'src.blocking_ui.domain_blocker.block_domain') as enforce:
            app = self.app()
            runtime = app.session_state['live_capture_runtime']
            runtime._accept({'type': 'flow', 'row': {
                'protocol': 6, 'bidirectional_packets': 2, 'bidirectional_bytes': 200,
                'Detected Service': 'YouTube', 'Detected Hostname': 'www.youtube.com',
                'Identification Status': 'Hostname evidence', 'Evidence Source': 'TLS server name (SNI)',
                'application_name': 'TLS', 'src_port': 50000, 'dst_port': 443, 'Confidence': None,
            }})
            runtime._accept({'type': 'flow', 'row': {
                'protocol': 6, 'bidirectional_packets': 2, 'bidirectional_bytes': 100,
                'Detected Service': 'Ambiguous', 'Detected Hostname': 'cdn.cloudflare.net',
                'Identification Status': 'Ambiguous', 'Evidence Source': 'TLS server name (SNI)',
                'application_name': 'TLS', 'src_port': 50001, 'dst_port': 443, 'Confidence': None,
            }})
            app.radio[0].set_value('Settings').run()
            self.assertEqual(app.selectbox(key='blocking_service').options, ['YouTube'])
            app.multiselect(key='blocking_hostnames').set_value(['www.youtube.com']).run()
            app.button(key='preview_website_targets').click().run()
            preview = next(table.value for table in app.dataframe if 'Enforcement method' in table.value.columns)
            self.assertEqual(preview['Type'].tolist(), ['Website'])
            self.assertEqual(preview['Target'].tolist(), ['www.youtube.com'])
            enforce.assert_not_called()
            self.assert_clean(app)

    def test_monitor_block_action_prefills_exact_hostname_and_survives_reruns(self):
        with patch('src.blocking_ui.is_windows_admin', return_value=True), patch(
            'src.blocking_ui.domain_blocker.block_domain') as enforce:
            app = self.app()
            runtime = app.session_state['live_capture_runtime']
            runtime._accept({'type': 'flow', 'row': {
                'protocol': 6, 'bidirectional_packets': 2, 'bidirectional_bytes': 200,
                'first_seen': '2026-11-01T10:00:00+00:00',
                'Detected Service': 'YouTube', 'Detected Hostname': 'www.youtube.com',
                'Identification Status': 'Hostname evidence', 'Evidence Source': 'TLS server name (SNI)',
                'application_name': 'TLS', 'src_port': 50000, 'dst_port': 443,
                'Predicted App': 'Facebook Chat', 'Confidence': 70,
            }})
            runtime._accept({'type': 'flow', 'row': {
                'protocol': 6, 'bidirectional_packets': 2, 'bidirectional_bytes': 100,
                'first_seen': '2026-11-01T10:00:01+00:00',
                'Detected Service': 'Unknown', 'Detected Hostname': None,
                'Identification Status': 'Unknown', 'Evidence Source': 'None',
                'Predicted App': 'Instagram', 'Confidence': 90,
            }})
            app.run()
            self.assertTrue(any('Website & application usage' in item.value for item in app.subheader))
            self.assertTrue(any('Blocking & Protection' in item.value for item in app.header))
            self.assertEqual(len([item for item in app.button if item.label == 'Block www.youtube.com']), 1)
            self.assertFalse(any('Block Instagram' in item.label for item in app.button))
            next(item for item in app.button if item.label == 'Block www.youtube.com').click().run()
            self.assertEqual(app.session_state['monitor_block_type'], 'Website')
            self.assertEqual(app.session_state['monitor_block_target'], 'www.youtube.com')
            enforce.assert_not_called()
            app.button(key='FormSubmitter:monitor_preview_form-Preview target').click().run()
            self.assertEqual(app.session_state['block_preview'][0]['target'], 'www.youtube.com')
            self.assertEqual(app.session_state['block_preview'][0]['type'], 'Website')
            app.run()
            self.assertIs(app.session_state['live_capture_runtime'], runtime)
            self.assertEqual(app.session_state['block_preview'][0]['target'], 'www.youtube.com')
            app.button(key='refresh_block_candidates').click().run()
            self.assertEqual(app.session_state['block_preview'][0]['target'], 'www.youtube.com')
            app.radio[0].set_value('Settings').run()
            self.assertEqual(app.session_state['block_preview'][0]['target'], 'www.youtube.com')
            app.radio[0].set_value('Monitor').run()
            self.assertEqual(app.session_state['block_preview'][0]['target'], 'www.youtube.com')
            enforce.assert_not_called()
            self.assert_clean(app)

    def test_monitor_ip_action_prefills_only_the_exact_remote_address(self):
        with patch('src.blocking_ui.remote_ip_candidates', return_value=['198.51.100.9']), patch(
            'src.blocking_center.critical_ip_reasons', return_value=[]), patch(
            'src.blocking_ui.firewall.block_ip') as enforce:
            app = self.app()
            next(item for item in app.button if item.label == 'Block 198.51.100.9').click().run()
            self.assertEqual(app.session_state['monitor_block_type'], 'IP')
            self.assertEqual(app.session_state['monitor_block_target'], '198.51.100.9')
            app.button(key='FormSubmitter:monitor_preview_form-Preview target').click().run()
            self.assertEqual(app.session_state['block_preview'][0]['target'], '198.51.100.9')
            self.assertEqual(app.session_state['block_preview'][0]['direction'], 'out')
            enforce.assert_not_called()
            self.assert_clean(app)

    def test_monitor_manual_domain_and_ip_validation_do_not_enforce(self):
        with patch('src.blocking_ui.is_windows_admin', return_value=True), patch(
            'src.blocking_center.critical_ip_reasons', return_value=[]), patch(
            'src.blocking_ui.firewall.block_ip') as ip_enforce, patch(
            'src.blocking_ui.domain_blocker.block_domain') as domain_enforce:
            app = self.app()
            app.selectbox(key='monitor_block_type').set_value('Domain')
            app.text_input(key='monitor_block_target').set_value('Example.COM')
            app.button(key='FormSubmitter:monitor_preview_form-Preview target').click().run()
            self.assertEqual(app.session_state['block_preview'][0]['target'], 'example.com')
            app.selectbox(key='monitor_block_type').set_value('IP')
            app.text_input(key='monitor_block_target').set_value('127.0.0.1')
            app.button(key='FormSubmitter:monitor_preview_form-Preview target').click().run()
            self.assertEqual(app.session_state['block_preview'], [])
            self.assertTrue(any('Refusing to block' in error.value for error in app.error))
            ip_enforce.assert_not_called()
            domain_enforce.assert_not_called()
            self.assert_clean(app)

    def test_monitor_undo_opens_confirmation_without_removing(self):
        active = {'value': True}

        with patch('src.blocking_ui.is_windows_admin', return_value=True), patch(
            'src.blocking_ui.domain_blocker.is_domain_blocked',
            side_effect=lambda *_args: active['value']), patch(
            'src.blocking_ui.domain_blocker.unblock_domain') as remove:
            blocklist.add_target('example.com')
            app = self.app()
            self.assertTrue(any('Active hosts entry' in table.value.to_string()
                                for table in app.dataframe))
            app.button(key='open_remove_dialog').click().run()
            remove.assert_not_called()
            self.assertIn('confirm_remove_phrase', [item.key for item in app.text_input])
            self.assertEqual(len(blocklist.list_entries()), 1)
            restarted_view = self.app()
            self.assertTrue(any('Active hosts entry' in table.value.to_string()
                                for table in restarted_view.dataframe))
            self.assert_clean(app)

    @unittest.skipUnless(os.environ.get('TRAFFIC_TEST_PCAP'), 'Set TRAFFIC_TEST_PCAP for real NFStream integration')
    def test_real_nfstream_capture_upload(self):
        source = Path(os.environ['TRAFFIC_TEST_PCAP'])
        app = self.app()
        app.radio[0].set_value("Analyze file").run()
        app.file_uploader[0].upload(source.name, source.read_bytes()).run()
        self.assert_clean(app)
        self.assertFalse(app.error, [e.value for e in app.error])
        self.assertTrue(any(m.label == 'Total flows' and int(m.value) > 0 for m in app.metric))


if __name__ == '__main__':
    unittest.main()
