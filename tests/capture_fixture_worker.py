"""Hardware-free subprocess fixture for controller lifecycle tests."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', default='idle')
    parser.add_argument('--control-file', type=Path)
    arguments = parser.parse_args()
    scenario = arguments.scenario
    if scenario == 'no_ready':
        time.sleep(60)
        return
    if scenario == 'error':
        print(json.dumps({'type': 'error', 'message': 'Npcap permission denied (test fixture)'}), flush=True)
        sys.exit(1)
    if scenario == 'crash':
        sys.exit(9)
    if scenario == 'tree':
        subprocess.Popen([sys.executable, '-B', __file__, '--scenario', 'no_ready'])
    print(json.dumps({'type': 'ready'}), flush=True)
    if scenario == 'flows':
        for index, protocol in enumerate([6, 17, 6]):
            row = {'src_ip': '192.0.2.1', 'dst_ip': '198.51.100.2', 'src_port': 50000,
                   'dst_port': 443, 'protocol': protocol, 'bidirectional_packets': 3,
                   'bidirectional_bytes': 200, 'first_seen': '2026-11-01T00:00:00+00:00',
                   'Predicted App': 'Fixture estimate', 'Confidence': 61.0,
                   'Prediction Status': 'Model estimate; application identity unverified'}
            row.update({
                'Detected Hostname': ['www.youtube.com', 'unknown.example', 'edge.cloudfront.net'][index],
                'Detected Service': ['YouTube', 'Unknown', 'Ambiguous'][index],
                'Evidence Source': ['TLS server name (SNI)', 'TLS server name (SNI)', 'TLS server name (SNI)'][index],
                'Identification Status': ['Hostname evidence', 'Unknown', 'Ambiguous'][index],
                'Identification Note': 'Test fixture', 'DNS Query Service': None,
                'application_name': 'TLS', 'application_category_name': 'Web',
                'application_is_guessed': 0, 'application_confidence': 6,
                'requested_server_name': ['www.youtube.com', 'unknown.example', 'edge.cloudfront.net'][index],
            })
            print(json.dumps({'type': 'flow', 'row': row}), flush=True)
    if scenario == 'tree':
        time.sleep(60)  # Intentionally ignores Stop to exercise bounded tree cleanup.
    else:
        while arguments.control_file is not None and not arguments.control_file.exists():
            time.sleep(0.05)


if __name__ == '__main__':
    main()
