
"""Bounded hardware check using the dashboard's exact capture controller."""
import argparse
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.capture import CaptureSession, list_capture_interfaces


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true', help='List actual Npcap adapters without capturing')
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument('--interface', help='Npcap device name from --list')
    sources.add_argument('--pcap', type=Path, help='Exercise the same worker on an existing PCAP/PCAPNG')
    parser.add_argument('--duration', type=float, default=20, help='Maximum capture duration in seconds')
    parser.add_argument('--require-flows', action='store_true', help='Fail if no actual flows arrive')
    arguments = parser.parse_args(argv)
    if arguments.duration <= 0:
        parser.error('--duration must be positive')
    try:
        if arguments.list or arguments.interface:
            interfaces = list_capture_interfaces()
            if arguments.list:
                for item in interfaces:
                    print(f"{item['description']}\n  {item['name']}")
                return 0
            if arguments.interface not in {item['name'] for item in interfaces}:
                parser.error('Interface not detected. Copy the exact name from --list.')
        if not arguments.interface and not arguments.pcap:
            parser.error('Use --list, --interface DEVICE, or --pcap FILE.')
        if arguments.pcap and not arguments.pcap.is_file():
            parser.error('The PCAP/PCAPNG file does not exist.')
        session = CaptureSession()
        try:
            session.start(arguments.interface or str(arguments.pcap.resolve()))
            print('Capture requested. Generate traffic on the selected adapter; Ctrl+C stops early.')
            deadline, shown = time.monotonic() + arguments.duration, 0
            while time.monotonic() < deadline:
                session.touch()
                snapshot = session.snapshot()
                if snapshot['total_flows'] != shown:
                    shown = snapshot['total_flows']
                    print(f"Flows: {shown}; packets: {snapshot['packets']}; bytes: {snapshot['bytes']}; "
                          f"identified: {snapshot['identified_flows']}; unknown: {snapshot['unknown_flows']}; "
                          f"ambiguous: {snapshot['ambiguous_flows']}; RF estimates: {snapshot['predicted_flows']}")
                if not snapshot['running']:
                    break
                time.sleep(0.2)
        except KeyboardInterrupt:
            print('Stop requested.')
        finally:
            if not session.stop():
                print('ERROR: Capture cleanup did not finish. Restart the app before capturing again.')
                return 3
        snapshot = session.snapshot()
        print(f"Final status: {snapshot['status']}; flows: {snapshot['total_flows']}; RF estimates: {snapshot['predicted_flows']}")
        print('Protocol statistics:', snapshot['protocols'])
        print('Detected services:', snapshot['service_counts'])
        print('Service bytes:', snapshot['service_bytes'])
        print('Unknown reasons:', snapshot['unknown_reasons'])
        if snapshot['warning']:
            print('Warning:', snapshot['warning'])
        if snapshot['error']:
            print('ERROR:', snapshot['error'])
            print('\n'.join(snapshot['diagnostics']))
            return 1
        skipped = [row['Prediction Status'] for row in snapshot['flows'] if row['Confidence'] is None]
        if skipped:
            print('Unclassified flow example:', skipped[0])
        if arguments.require_flows and not snapshot['total_flows']:
            print('No flows observed. Check the selected adapter and generate traffic before retrying.')
            print('\n'.join(snapshot['diagnostics']))
            return 2
        return 0
    except (OSError, RuntimeError) as exc:
        print(f'ERROR: {exc}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
