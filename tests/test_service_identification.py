"""Service attribution must not convert DNS lookups, ports, or shared CDNs into visits."""
from types import SimpleNamespace
import unittest

from src.capture import CaptureSession
from src.capture_worker import process_flow
from src.service_identification import identify_service, normalize_hostname


class ServiceIdentificationTests(unittest.TestCase):
    def identify(self, **kwargs):
        return identify_service(application_name='TLS', **kwargs)

    def test_direct_hostname_matches_and_suffix_boundaries(self):
        for host, expected in [('www.youtube.com', 'YouTube'),
                               ('instagram.com.', 'Instagram'),
                               ('web.whatsapp.com', 'WhatsApp'),
                               ('www.google.com', 'Google'),
                               ('chatgpt.com', 'ChatGPT')]:
            with self.subTest(host=host):
                row = self.identify(requested_server_name=host)
                self.assertEqual(row['Detected Service'], expected)
                self.assertEqual(row['Identification Status'], 'Hostname evidence')
                self.assertEqual(row['Evidence Source'], 'TLS server name (SNI)')
        for host in ['evil-youtube.com', 'youtube.com.evil.org',
                     'chatgpt.com.attacker.example', 'https://youtube.com/',
                     '203.0.113.4']:
            with self.subTest(host=host):
                self.assertEqual(self.identify(requested_server_name=host)['Detected Service'], 'Unknown')

    def test_related_resource_is_heuristic_and_shared_cdn_ambiguous(self):
        resource = self.identify(requested_server_name='r1.googlevideo.com')
        self.assertEqual((resource['Detected Service'], resource['Identification Status']),
                         ('YouTube', 'Heuristic'))
        for host in ['edge.cloudfront.net', 'fonts.googleapis.com', 'x.googleusercontent.com']:
            with self.subTest(host=host):
                row = self.identify(requested_server_name=host)
                self.assertEqual((row['Detected Service'], row['Identification Status']),
                                 ('Ambiguous', 'Ambiguous'))

    def test_openai_domain_is_not_chatgpt(self):
        self.assertEqual(self.identify(requested_server_name='api.openai.com')['Detected Service'], 'OpenAI')
        self.assertEqual(self.identify(requested_server_name='chat.openai.com')['Detected Service'], 'ChatGPT')
        self.assertEqual(self.identify(requested_server_name='desktop.chat.openai.com')['Detected Service'], 'ChatGPT')
        self.assertEqual(self.identify(requested_server_name='chat.openai.com.evil.example')['Detected Service'], 'Unknown')

    def test_verified_provider_domains_and_resource_limits(self):
        self.assertEqual(self.identify(requested_server_name='redacted.invalid')['Detected Service'],
                         '360 Total Security')
        self.assertEqual(self.identify(requested_server_name='vht.tradedoubler.com')['Detected Service'],
                         'Tradedoubler')
        resource = self.identify(requested_server_name='cdn.oaistatic.com')
        self.assertEqual((resource['Detected Service'], resource['Identification Status']),
                         ('OpenAI', 'Heuristic'))
        for host in ('static-lib.com', 'cdn.cloudfront.net', '360totalsecurity.com.evil.example'):
            self.assertNotIn(self.identify(requested_server_name=host)['Detected Service'],
                             {'360 Total Security', 'Tradedoubler', 'ChatGPT'})

    def test_dns_lookup_does_not_prove_contact(self):
        row = identify_service(application_name='DNS', requested_server_name='youtube.com', dst_port=53)
        self.assertEqual(row['Detected Service'], 'Unknown')
        self.assertEqual(row['DNS Query Service'], 'YouTube')
        self.assertEqual(row['Identification Status'], 'Lookup only')
        self.assertEqual(row['Evidence Source'], 'DNS query')
        self.assertEqual(row['Unknown Reason'], 'DNS lookup only')

    def test_unknown_reasons_are_specific_and_cautious(self):
        cases = [
            ({'application_name': 'TLS'}, 'Encrypted flow without hostname'),
            ({'application_name': 'QUIC'}, 'Encrypted flow without hostname'),
            ({'application_name': 'Unknown'}, 'No nDPI application or hostname'),
            ({'application_name': 'TLS', 'requested_server_name': 'unmapped.example'},
             'Hostname outside service map'),
            ({'application_name': 'TLS', 'requested_server_name': 'https://youtube.com/'},
             'Invalid server-name metadata'),
            ({'application_name': 'TLS.YouTube', 'application_confidence': 1},
             'nDPI port-only result'),
            ({'application_name': 'TLS.YouTube', 'application_confidence': 0},
             'nDPI result lacks reliable confidence'),
            ({'application_name': 'TLS.Spotify', 'application_confidence': 6},
             'nDPI application not mapped'),
            ({'application_name': 'NTP'}, 'Protocol without service identity'),
        ]
        for fields, expected in cases:
            with self.subTest(fields=fields):
                row = identify_service(**fields)
                self.assertEqual(row['Detected Service'], 'Unknown')
                self.assertEqual(row['Unknown Reason'], expected)

    def test_ndpi_confidence_and_mapping_precedence(self):
        strong = identify_service(application_name='TLS.YouTube', application_confidence=6,
                                  application_is_guessed=0)
        self.assertEqual((strong['Detected Service'], strong['Identification Status']),
                         ('YouTube', 'Protocol evidence'))
        weak = identify_service(application_name='TLS.YouTube', application_confidence=3,
                                requested_server_name='instagram.com')
        self.assertEqual((weak['Detected Service'], weak['Identification Status']),
                         ('Instagram', 'Hostname evidence'))
        conflict = identify_service(application_name='TLS.YouTube', application_confidence=6,
                                    requested_server_name='instagram.com')
        self.assertEqual((conflict['Detected Service'], conflict['Identification Status']),
                         ('Ambiguous', 'Ambiguous'))
        guessed = identify_service(application_name='TLS.YouTube', application_confidence=6,
                                   application_is_guessed=1)
        self.assertEqual(guessed['Identification Status'], 'Heuristic')
        port_only = identify_service(application_name='TLS.YouTube', application_confidence=1,
                                     dst_port=443)
        self.assertEqual(port_only['Detected Service'], 'Unknown')

    def test_generic_protocol_port_ip_and_hidden_hostname_do_not_identify_service(self):
        for app, host in [('TLS', None), ('QUIC', None), ('HTTP/3', None),
                          ('TLS', '203.0.113.7'), ('TLS', 'unknown.example')]:
            with self.subTest(app=app, host=host):
                row = identify_service(application_name=app, requested_server_name=host,
                                       src_port=12345, dst_port=443)
                self.assertEqual(row['Detected Service'], 'Unknown')
        self.assertIsNone(normalize_hostname('bad..host'))
        self.assertIsNone(normalize_hostname('youtube.com..'))

    def test_worker_preserves_metadata_and_rf_is_separate(self):
        flow = SimpleNamespace(src_ip='192.0.2.1', dst_ip='198.51.100.1',
                               src_port=50000, dst_port=443, protocol=6,
                               bidirectional_packets=3, bidirectional_bytes=300,
                               application_name='TLS', application_category_name='Web',
                               application_is_guessed=0, application_confidence=6,
                               requested_server_name='www.youtube.com',
                               client_fingerprint='client-fp', server_fingerprint='server-fp',
                               user_agent='Test agent', content_type='text/html')
        row = process_flow(flow)
        self.assertEqual(row['Detected Service'], 'YouTube')
        self.assertEqual(row['requested_server_name'], 'www.youtube.com')
        self.assertEqual(row['application_category_name'], 'Web')
        self.assertEqual(row['client_fingerprint'], 'client-fp')
        self.assertEqual(row['server_fingerprint'], 'server-fp')
        self.assertEqual(row['user_agent'], 'Test agent')
        self.assertEqual(row['content_type'], 'text/html')
        self.assertEqual(row['Predicted App'], 'Not classified')
        self.assertIsNone(row['Confidence'])

        flow.requested_server_name = ''
        flow.user_agent = 'YouTube app'
        flow.client_fingerprint = 'same-fingerprint-as-some-browser'
        unknown = process_flow(flow)
        self.assertEqual(unknown['Detected Service'], 'Unknown')
        self.assertEqual(unknown['Unknown Reason'], 'Encrypted flow without hostname')

    def test_cumulative_service_counts_survive_bounded_history_and_reset(self):
        session = CaptureSession(max_flows=1)
        base = {'protocol': 6, 'bidirectional_packets': 1, 'bidirectional_bytes': 100,
                'Confidence': None}
        for service, reason in [('YouTube', None), ('Unknown', 'DNS lookup only'),
                                ('Ambiguous', None), ('YouTube', None)]:
            session._accept({'type': 'flow', 'row': dict(base, **{
                'Detected Service': service, 'Unknown Reason': reason})})
        snapshot = session.snapshot()
        self.assertEqual((snapshot['total_flows'], len(snapshot['flows'])), (4, 1))
        self.assertEqual((snapshot['identified_flows'], snapshot['unknown_flows'],
                          snapshot['ambiguous_flows']), (2, 1, 1))
        self.assertEqual(snapshot['service_counts'], {'YouTube': 2})
        self.assertEqual(snapshot['service_bytes'], {'YouTube': 200, 'Unknown': 100, 'Ambiguous': 100})
        self.assertEqual(snapshot['unknown_reasons'], {'DNS lookup only': 1})
        session._reset()
        self.assertEqual(session.snapshot()['service_counts'], {})
        self.assertEqual(session.snapshot()['unknown_reasons'], {})


if __name__ == '__main__':
    unittest.main()
