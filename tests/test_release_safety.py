"""Sensitive exports and enforcement guards use only mocks or temporary files."""
from pathlib import Path
from io import BytesIO
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd

from src import domain_blocker, firewall
from src.export_utils import flow_csv_bytes


class ReleaseSafetyTests(unittest.TestCase):
    def test_csv_export_neutralizes_spreadsheet_formulas_without_changing_input(self):
        frame = pd.DataFrame([{
            'Detected Hostname': '=HYPERLINK("https://example.invalid")',
            'user_agent': '\t+bad-formula',
            'src_ip': '192.0.2.1',
            'bidirectional_bytes': 500,
        }])
        exported = pd.read_csv(BytesIO(flow_csv_bytes(frame)))
        self.assertTrue(exported['Detected Hostname'].iloc[0].startswith("'="))
        self.assertTrue(exported['user_agent'].iloc[0].startswith("'"))
        self.assertEqual(exported['src_ip'].iloc[0], '192.0.2.1')
        self.assertEqual(exported['bidirectional_bytes'].iloc[0], 500)
        self.assertTrue(frame['Detected Hostname'].iloc[0].startswith('='))

    def test_firewall_enforcement_requires_confirmation_and_valid_ip(self):
        states = iter(['absent', 'active', 'active', 'absent'])
        with patch.object(firewall, '_run_netsh') as command, patch.object(
            firewall, 'critical_ip_reasons', return_value=[]
        ), patch.object(firewall, 'managed_rule_state', side_effect=lambda *_a, **_k: next(states)):
            with self.assertRaisesRegex(PermissionError, 'Confirm'):
                firewall.block_ip('192.0.2.10')
            command.assert_not_called()
            for invalid in ('127.0.0.1', '169.254.1.2', '255.255.255.255', ''):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    firewall.block_ip(invalid, confirmed=True)
            command.assert_not_called()
            firewall.block_ip('192.0.2.10', confirmed=True)
            self.assertIn('remoteip=192.0.2.10', command.call_args.args[0])
            firewall.unblock_ip('192.0.2.10', confirmed=True)
            self.assertIn('delete', command.call_args.args[0])

    def test_hosts_enforcement_requires_confirmation_and_can_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            hosts = Path(folder) / 'hosts'
            original = '127.0.0.1 localhost\n# keep\n'
            hosts.write_text(original, encoding='utf-8')
            with patch.object(domain_blocker, 'HOSTS_FILE', hosts):
                with self.assertRaisesRegex(PermissionError, 'Confirm'):
                    domain_blocker.block_domain('example.com')
                self.assertEqual(hosts.read_text(encoding='utf-8'), original)
                for invalid in ('example.com..', 'https://example.com', 'bad host.example'):
                    with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                        domain_blocker.block_domain(invalid, confirmed=True)
                domain_blocker.block_domain('example.com', confirmed=True)
                self.assertTrue(domain_blocker.is_domain_blocked('example.com'))
                domain_blocker.unblock_domain('example.com', confirmed=True)
                self.assertFalse(domain_blocker.is_domain_blocked('example.com'))
                self.assertEqual(hosts.read_text(encoding='utf-8'), original)

    def test_hosts_refuses_ambiguous_markers_and_unreadable_encoding(self):
        with tempfile.TemporaryDirectory() as folder:
            hosts = Path(folder) / 'hosts'
            with patch.object(domain_blocker, 'HOSTS_FILE', hosts):
                duplicate = domain_blocker.MARKER_START + '\n' + domain_blocker.MARKER_START
                hosts.write_text(duplicate, encoding='utf-8')
                with self.assertRaisesRegex(RuntimeError, 'Multiple'):
                    domain_blocker.block_domain('example.com', confirmed=True)
                self.assertEqual(hosts.read_text(encoding='utf-8'), duplicate)
                hosts.write_bytes(b'\xff invalid encoding')
                with self.assertRaises(UnicodeDecodeError):
                    domain_blocker.block_domain('example.com', confirmed=True)
                self.assertEqual(hosts.read_bytes(), b'\xff invalid encoding')


if __name__ == '__main__':
    unittest.main()
