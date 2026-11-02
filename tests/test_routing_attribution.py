"""Format/schema routing and exact local socket attribution safeguards."""
import socket
from types import SimpleNamespace
import unittest

import pandas as pd
import psutil

from src.file_routing import detect_format, read_dataset, route_schema
from src.process_attribution import SocketSampler
from src.scenario_b import FEATURE_NAMES


class UploadRoutingTests(unittest.TestCase):
    def test_capture_magic_and_extension_must_agree(self):
        self.assertEqual(detect_format("capture.pcapng", b"\x0a\x0d\x0d\x0a"), "pcapng")
        self.assertEqual(detect_format("capture.pcap", b"\xd4\xc3\xb2\xa1"), "pcap")
        with self.assertRaisesRegex(ValueError, "filename says CSV"):
            detect_format("capture.csv", b"\x0a\x0d\x0d\x0a")
        with self.assertRaisesRegex(ValueError, "Unrecognized binary"):
            detect_format("capture.pcap", b"\x00\x01\x02\x03")

    def test_arff_and_csv_detected_from_content(self):
        self.assertEqual(detect_format("flows.arff", b"@relation flows\n@attribute x numeric\n@data\n1\n"), "arff")
        self.assertEqual(detect_format("flows.csv", b"x,y\n1,2\n"), "csv")
        with self.assertRaisesRegex(ValueError, "filename says ARFF"):
            detect_format("flows.arff", b"x,y\n1,2\n")

    def test_schema_never_silently_chooses_an_unrelated_model(self):
        self.assertEqual(route_schema(pd.DataFrame(columns=FEATURE_NAMES), ["rf_only"]), "scenario_b")
        self.assertEqual(route_schema(pd.DataFrame(columns=["rf_only"]), ["rf_only"]), "random_forest")
        with self.assertRaisesRegex(ValueError, "both model schemas"):
            route_schema(pd.DataFrame(columns=FEATURE_NAMES + ["rf_only"]), ["rf_only"])
        with self.assertRaisesRegex(ValueError, "Unsupported dataset schema"):
            route_schema(pd.DataFrame(columns=["unrelated"]), ["rf_only"])

    def test_empty_and_malformed_dataset_errors(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            detect_format("x.csv", b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            read_dataset(b"x,y\n", "csv")
        with self.assertRaisesRegex(ValueError, "Could not parse"):
            read_dataset(b"@relation x\n@attribute f numeric\n@data\nnotnumeric", "arff")
        with self.assertRaisesRegex(ValueError, "duplicate column"):
            read_dataset(b"x,x\n1,2\n", "csv")


class ProcessAttributionTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.flow = {"protocol": 6, "src_ip": "192.0.2.1", "src_port": 50000,
                     "dst_ip": "198.51.100.2", "dst_port": 443,
                     "bidirectional_first_seen_ms": 999000,
                     "bidirectional_last_seen_ms": 1001000,
                     "src2dst_bytes": 120, "dst2src_bytes": 340}
        self.connection = SimpleNamespace(type=socket.SOCK_STREAM,
                                          laddr=("192.0.2.1", 50000),
                                          raddr=("198.51.100.2", 443),
                                          status=psutil.CONN_ESTABLISHED, pid=1234)
        self.proc = SimpleNamespace(create_time=lambda: 900.0, name=lambda: "browser.exe",
                                    exe=lambda: r"C:\Program Files\Browser\browser.exe")

    def sampler(self, connections=None, **kwargs):
        return SocketSampler(connections=lambda: [self.connection] if connections is None else connections,
                             process_factory=lambda pid: self.proc, clock=lambda: self.now,
                             platform="nt", **kwargs)

    def test_exact_tcp_match_reports_observed_process(self):
        sampler = self.sampler()
        sampler.sample()
        result = sampler.match(self.flow)
        self.assertEqual(result["Process Name"], "browser.exe")
        self.assertEqual(result["Process PID"], 1234)
        self.assertEqual((result["Upload Bytes"], result["Download Bytes"]), (120, 340))
        self.assertIn("Exact connected socket", result["Process Evidence"])

    def test_port_or_remote_address_alone_never_attributes(self):
        sampler = self.sampler()
        sampler.sample()
        for change in ({"src_ip": "192.0.2.99"}, {"dst_ip": "198.51.100.99"},
                       {"protocol": 17}, {"src_port": 50001}):
            with self.subTest(change=change):
                self.assertEqual(sampler.match(self.flow | change)["Process Name"], "Unknown Process")

    def test_missing_timestamps_and_stale_observation_are_unknown(self):
        sampler = self.sampler()
        sampler.sample()
        self.assertIn("timestamps", sampler.match(self.flow | {"bidirectional_first_seen_ms": None})["Process Evidence"])
        self.assertEqual(sampler.match(self.flow | {"bidirectional_first_seen_ms": 2000000,
                                                    "bidirectional_last_seen_ms": 2001000})["Process Name"],
                         "Unknown Process")

    def test_multiple_process_owners_are_ambiguous(self):
        other = SimpleNamespace(**(vars(self.connection) | {"pid": 5678}))
        sampler = self.sampler(connections=[self.connection, other])
        sampler._process_factory = lambda pid: SimpleNamespace(create_time=lambda: 900.0,
                                                                name=lambda: f"{pid}.exe", exe=lambda: None)
        sampler.sample()
        self.assertEqual(sampler.match(self.flow)["Process Evidence"], "Multiple matching process owners")

    def test_udp_ipv6_requires_connected_remote_endpoint(self):
        connected = SimpleNamespace(type=socket.SOCK_DGRAM,
                                    laddr=("fe80::1%5", 53000), raddr=("2001:db8::1", 443),
                                    status=psutil.CONN_NONE, pid=1234)
        flow = self.flow | {"protocol": 17, "src_ip": "fe80::1", "src_port": 53000,
                            "dst_ip": "2001:db8::1"}
        sampler = self.sampler(connections=[connected])
        sampler.sample()
        self.assertEqual(sampler.match(flow)["Process Name"], "browser.exe")
        sampler = self.sampler(connections=[SimpleNamespace(**(vars(connected) | {"raddr": ()}))])
        sampler.sample()
        self.assertEqual(sampler.match(flow)["Process Name"], "Unknown Process")

    def test_history_is_bounded_and_permissions_fail_closed(self):
        sampler = self.sampler(max_samples=2)
        for _ in range(5):
            sampler.sample()
        self.assertEqual(len(sampler._samples), 2)
        denied = SocketSampler(connections=lambda: (_ for _ in ()).throw(psutil.AccessDenied()),
                               platform="nt", clock=lambda: self.now)
        denied.sample()
        self.assertEqual(denied.match(self.flow)["Process Name"], "Unknown Process")


if __name__ == "__main__":
    unittest.main()
