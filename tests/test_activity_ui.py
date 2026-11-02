"""Reruns and privacy controls use temporary stores and synthetic activity."""
from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from src.activity_ui import activity_resource, period_bounds
from src.model_utils import PROJECT_ROOT
from test_activity import flow


class HistoryUiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        environment = patch.dict(os.environ, {'NTC_HISTORY_DIR': str(self.folder)})
        environment.start()
        self.addCleanup(environment.stop)
        interfaces = patch('src.capture.list_capture_interfaces', return_value=[{'name': 'fixture', 'description': 'Synthetic adapter'}])
        interfaces.start()
        self.addCleanup(interfaces.stop)

    def app(self):
        app = AppTest.from_file(str(PROJECT_ROOT / 'dashboard.py'), default_timeout=45).run()
        self.addCleanup(app.session_state['live_capture_runtime'].stop)
        self.addCleanup(app.session_state['live_capture_runtime'].activity.close)
        self.assertFalse(app.exception)
        return app

    def test_reruns_preserve_worker_history_and_do_not_duplicate_alerts(self):
        app = self.app()
        runtime = app.session_state['live_capture_runtime']
        runtime._accept({'type': 'flow', 'event_id': 1, 'row': flow(
            bidirectional_last_seen_ms=int(time.time() * 1000),
            first_seen=datetime.now(timezone.utc).isoformat(),
            **{'Evidence Source': 'Synthetic fixture', 'Unknown Reason': None})})
        for _ in range(3):
            app.run()
            self.assertFalse(app.exception)
        self.assertIs(app.session_state['live_capture_runtime'], runtime)
        self.assertEqual(runtime.snapshot()['total_flows'], 1)
        self.assertEqual(len(runtime.activity.alerts()), 2)
        stored = runtime.activity.store.query('flows', 0, time.time() + 60)
        self.assertEqual(sum(r['count'] for r in stored), 1)
        activity = runtime.activity
        activity.store.record_usage('synthetic-adapter', {'timestamp': time.time(), 'seconds': 2, 'download': 2000, 'upload': 1000})
        app.run()
        self.assertFalse(app.exception)
        self.assertTrue(any(m.label == 'Download Mbps' and m.value == '—' for m in app.metric))
        app.button(key='activity_read').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(all(row['read'] for row in runtime.activity.alerts()))
        app.button(key='activity_dismiss').click().run()
        self.assertFalse(app.exception)
        self.assertEqual(len(runtime.activity.alerts()), 1)
        app.button(key='activity_clear_alerts').click().run()
        self.assertFalse(app.exception)
        self.assertEqual(runtime.activity.alerts(), [])

    def test_history_privacy_settings_and_confirmed_deletion(self):
        app = self.app()
        activity = app.session_state['live_capture_runtime'].activity
        activity.on_flow('fixture-event', flow())
        app.radio[0].set_value('Settings').run()
        self.assertFalse(app.exception)
        self.assertFalse(next(item for item in app.checkbox if item.label == 'Also save service and process names').value)
        next(item for item in app.checkbox if item.label == 'Also save service and process names').check()
        next(item for item in app.button if item.label == 'Save history and alert settings').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(activity.config['names'])
        self.assertTrue(app.button(key='activity_clear_history').disabled)
        app.checkbox(key='activity_confirm_clear').check().run()
        app.button(key='activity_clear_history').click().run()
        self.assertFalse(app.exception)
        self.assertEqual(activity.store.query('flows', 0, time.time() + 60), [])
        self.assertEqual(activity.alerts(), [])

    def test_custom_period_and_unknown_filters_render_without_data(self):
        app = self.app()
        app.selectbox(key='history_period').select('Custom').run()
        self.assertFalse(app.exception)
        app.selectbox(key='history_period').select('Last 7 days').run()
        self.assertFalse(app.exception)

    def test_periods_use_local_day_boundaries(self):
        now = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
        start, end = period_bounds('Today', now)
        self.assertEqual(start, datetime(2026, 11, 2, tzinfo=timezone.utc).timestamp())
        start, end = period_bounds('Last hour', now)
        self.assertEqual(end - start, 3600)


if __name__ == '__main__':
    unittest.main()
