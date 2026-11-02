"""Exact-target previews, false-positive guards, and mocked enforcement rollback."""
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from src import blocklist, domain_blocker, firewall, network_safety
from src.blocking_center import (SCOPE, eligible_service_hosts, entry_status,
                                 observed_services, preview_domain, preview_ip,
                                 remote_ip_candidates, website_candidates)


class BlockingPreviewTests(unittest.TestCase):
    def test_exact_ip_preview_and_special_address_rejection(self):
        outbound = preview_ip(" 192.0.2.10 ", critical_lookup=lambda _: [])
        inbound = preview_ip("2001:db8::10", "in", critical_lookup=lambda _: [])
        self.assertEqual((outbound["target"], outbound["direction"], outbound["scope"]),
                         ("192.0.2.10", "out", SCOPE))
        self.assertEqual((inbound["target"], inbound["direction"]), ("2001:db8::10", "in"))
        for value in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.1.2", "ff02::1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                preview_ip(value, critical_lookup=lambda _: [])

    def test_gateway_dns_and_own_ip_require_extra_confirmation(self):
        records = {"adapter": [SimpleNamespace(family=socket.AF_INET, address="192.0.2.10")]}
        reply = subprocess.CompletedProcess([], 0, '["192.0.2.1","2001:db8::53"]', '')
        lookup = lambda value: network_safety.critical_ip_reasons(
            value, interfaces=records, run=lambda *_a, **_k: reply)
        self.assertIn("default gateway", " ".join(lookup("192.0.2.1")))
        self.assertIn("DNS resolver", " ".join(lookup("2001:db8::53")))
        self.assertIn("own network address", " ".join(lookup("192.0.2.10")))
        self.assertEqual(lookup("198.51.100.8"), [])

    def test_unknown_network_inventory_fails_closed(self):
        with patch.object(network_safety.psutil, "net_if_addrs", side_effect=OSError("denied")):
            with self.assertRaisesRegex(RuntimeError, "disabled"):
                network_safety.critical_ip_reasons("192.0.2.10")
        denied = subprocess.CompletedProcess([], 1, '', 'denied')
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            network_safety.critical_ip_reasons(
                "192.0.2.10", interfaces={}, run=lambda *_a, **_k: denied)
        bad_json = subprocess.CompletedProcess([], 0, '{broken', '')
        with self.assertRaisesRegex(RuntimeError, "invalid"):
            network_safety.critical_ip_reasons(
                "192.0.2.10", interfaces={}, run=lambda *_a, **_k: bad_json)
        wrong_shape = subprocess.CompletedProcess([], 0, '{"address":"192.0.2.1"}', '')
        with self.assertRaisesRegex(RuntimeError, "invalid"):
            network_safety.critical_ip_reasons(
                "192.0.2.10", interfaces={}, run=lambda *_a, **_k: wrong_shape)

    def test_domain_preview_is_exact_and_rejects_wildcards(self):
        preview = preview_domain("Example.COM.")
        self.assertEqual((preview["target"], preview["type"]), ("example.com", "Domain"))
        self.assertIn("Subdomains", preview["coverage"])
        for value in ("*.example.com", "https://example.com", "192.0.2.10"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                preview_domain(value)

    def test_service_proposals_require_rechecked_direct_hostname(self):
        direct = {"Detected Service": "YouTube", "Identification Status": "Hostname evidence",
                  "Detected Hostname": "www.youtube.com", "Evidence Source": "TLS server name (SNI)",
                  "application_name": "TLS", "src_port": 50000, "dst_port": 443}
        flows = [direct, direct.copy(),
                 direct | {"Detected Hostname": "github.com"},
                 direct | {"Detected Hostname": "r1.googlevideo.com", "Identification Status": "Heuristic"},
                 direct | {"Detected Hostname": "cdn.cloudflare.net", "Identification Status": "Ambiguous"},
                 direct | {"Detected Hostname": "www.youtube.com", "Identification Status": "Lookup only",
                           "application_name": "DNS", "dst_port": 53},
                 {"Detected Service": "Unknown", "Detected Hostname": None}]
        self.assertEqual(observed_services(flows), ["YouTube"])
        self.assertEqual(eligible_service_hosts(flows, "YouTube"),
                         [{"hostname": "www.youtube.com", "evidence": "TLS server name (SNI)"}])
        self.assertEqual(eligible_service_hosts(flows, "Unknown"), [])
        self.assertEqual(website_candidates(flows), [
            {"target": "www.youtube.com", "type": "Website", "service": "YouTube",
             "evidence": "TLS server name (SNI)"}])

    def test_ip_quick_actions_require_one_local_endpoint(self):
        interfaces = {"adapter": [SimpleNamespace(family=socket.AF_INET, address="192.0.2.10"),
                                  SimpleNamespace(family=socket.AF_INET6, address="2001:db8::10%3")]}
        flows = [{"src_ip": "192.0.2.10", "dst_ip": "198.51.100.4"},
                 {"src_ip": "198.51.100.4", "dst_ip": "192.0.2.10"},
                 {"src_ip": "2001:db8::10", "dst_ip": "2001:db8::20"},
                 {"src_ip": "198.51.100.5", "dst_ip": "203.0.113.8"},
                 {"src_ip": "192.0.2.10", "dst_ip": "127.0.0.1"},
                 {"src_ip": "192.0.2.10", "dst_ip": "192.0.2.10"}]
        self.assertEqual(remote_ip_candidates(flows, interfaces=interfaces),
                         ["198.51.100.4", "2001:db8::20"])

    def test_blocklist_distinguishes_website_intent_from_enforcement(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(blocklist, "DATA_DIR", Path(folder)), patch.object(
            blocklist, "BLOCKLIST_FILE", Path(folder) / "blocklist.json"):
            self.assertTrue(blocklist.add_target("www.youtube.com", kind="Website",
                                                 service="YouTube", evidence="TLS server name (SNI)")[0])
            entry = blocklist.list_entries()[0]
            self.assertEqual((entry["type"], entry["service"], entry["target"]),
                             ("Website", "YouTube", "www.youtube.com"))
            self.assertIn("T", entry["created"])
            self.assertFalse(blocklist.add_target("www.youtube.com")[0])
            with patch.object(domain_blocker, "is_domain_blocked", return_value=False):
                self.assertEqual(entry_status(entry)["status"], "Intent only")
            blocklist.remove_target("www.youtube.com")
            self.assertEqual(blocklist.list_entries(), [])

    def test_malformed_hosts_section_never_looks_like_an_unenforced_intent(self):
        with tempfile.TemporaryDirectory() as folder:
            hosts = Path(folder) / "hosts"
            hosts.write_text(domain_blocker.MARKER_START + "\n127.0.0.1 example.com\n",
                             encoding="utf-8")
            with patch.object(domain_blocker, "HOSTS_FILE", hosts):
                result = entry_status({"target": "example.com", "type": "Domain"})
            self.assertEqual(result["status"], "Status unavailable")
            self.assertIn("markers", result["error"])


class FirewallRuleTests(unittest.TestCase):
    @staticmethod
    def rule(ip="192.0.2.10", direction="Outbound", **changes):
        return {"DisplayName": firewall.RULE_PREFIX + ip,
                "Direction": direction, "Action": "Block", "Enabled": "True",
                "RemoteAddress": [ip], "LocalAddress": ["Any"],
                "Profile": "Any", "Program": "Any", "Protocol": "Any",
                "LocalPort": "Any", "RemotePort": "Any", "Service": "Any",
                "InterfaceType": "Any"} | changes

    def test_exact_rule_state_and_conflicts(self):
        rule = self.rule()
        self.assertEqual(firewall.managed_rule_state("192.0.2.10", rules=[]), "absent")
        self.assertEqual(firewall.managed_rule_state("192.0.2.10", rules=[rule]), "active")
        self.assertEqual(firewall.managed_rule_state("192.0.2.10", rules=[rule | {"Enabled": "False"}]), "disabled")
        for changed in ({"RemoteAddress": ["198.51.100.1"]}, {"Action": "Allow"},
                        {"Direction": "Inbound"}, {"Program": "C:\\other.exe"}):
            with self.subTest(changed=changed):
                self.assertEqual(firewall.managed_rule_state("192.0.2.10", rules=[rule | changed]), "conflict")
        self.assertEqual(firewall.managed_rule_state("192.0.2.10", rules=[rule, rule]), "conflict")
        inbound = self.rule(direction="Inbound", DisplayName=firewall.RULE_PREFIX + "In-192.0.2.10")
        self.assertEqual(firewall.managed_rule_state("192.0.2.10", "in", rules=[inbound]), "active")

    def test_duplicate_and_conflict_never_add_or_delete_rules(self):
        with patch.object(firewall, "critical_ip_reasons", return_value=[]), patch.object(
            firewall, "managed_rule_state", return_value="active"
        ), patch.object(firewall, "_run_netsh") as command:
            self.assertIn("already exists", firewall.block_ip("192.0.2.10", confirmed=True))
            command.assert_not_called()
        with patch.object(firewall, "managed_rule_state", return_value="conflict"), patch.object(
            firewall, "_run_netsh") as command:
            with self.assertRaisesRegex(RuntimeError, "conflict"):
                firewall.unblock_ip("192.0.2.10", confirmed=True)
            command.assert_not_called()

    def test_add_and_undo_are_exact_and_verified(self):
        current = {"state": "absent"}

        def command(arguments):
            current["state"] = "active" if "add" in arguments else "absent"
            self.assertIn("remoteip=192.0.2.10", arguments)
            self.assertIn("dir=out", arguments)
        with patch.object(firewall, "critical_ip_reasons", return_value=[]), patch.object(
            firewall, "managed_rule_state", side_effect=lambda *_a, **_k: current["state"]
        ), patch.object(firewall, "_run_netsh", side_effect=command) as run:
            firewall.block_ip("192.0.2.10", confirmed=True)
            self.assertEqual(current["state"], "active")
            with self.assertRaises(PermissionError):
                firewall.unblock_ip("192.0.2.10")
            firewall.unblock_ip("192.0.2.10", confirmed=True)
            self.assertEqual(current["state"], "absent")
            self.assertEqual(run.call_count, 2)

    def test_critical_target_needs_additional_confirmation(self):
        with patch.object(firewall, "critical_ip_reasons", return_value=["default gateway or active DNS resolver"]), patch.object(
            firewall, "_run_netsh") as run:
            with self.assertRaisesRegex(PermissionError, "Additional confirmation"):
                firewall.block_ip("192.0.2.1", confirmed=True)
            run.assert_not_called()

    def test_status_failure_prevents_rule_changes(self):
        with patch.object(firewall, "critical_ip_reasons", return_value=[]), patch.object(
            firewall, "managed_rule_state", side_effect=RuntimeError("inspection denied")
        ), patch.object(firewall, "_run_netsh") as command:
            with self.assertRaisesRegex(RuntimeError, "inspection denied"):
                firewall.block_ip("192.0.2.10", confirmed=True)
            command.assert_not_called()

    def test_firewall_command_timeout_has_actionable_error(self):
        with patch.object(firewall.subprocess, "run", side_effect=subprocess.TimeoutExpired("netsh", 15)):
            with self.assertRaisesRegex(RuntimeError, "inspect the rule status"):
                firewall._run_netsh(["add", "rule"])


class DialogSafetyTests(unittest.TestCase):
    def test_confirmation_dialog_never_enforces_without_exact_phrase(self):
        script = ("from src.blocking_ui import confirm_enforcement\n"
                  "from src.blocking_center import preview_domain\n"
                  "confirm_enforcement([preview_domain('example.com')], [])")
        with tempfile.TemporaryDirectory() as folder, patch.object(blocklist, "DATA_DIR", Path(folder)), patch.object(
            blocklist, "BLOCKLIST_FILE", Path(folder) / "blocklist.json"), patch(
            "src.blocking_ui.is_windows_admin", return_value=True), patch(
            "src.blocking_ui.domain_blocker.block_domain", return_value="blocked") as block, patch(
            "src.blocking_ui.domain_blocker.is_domain_blocked", return_value=True):
            app = AppTest.from_string(script, default_timeout=30).run()
            app.button(key="apply_blocking_rules").click().run()
            block.assert_not_called()
            self.assertTrue(any("Type BLOCK" in item.value for item in app.error))
            app.text_input(key="confirm_block_phrase").set_value("BLOCK")
            app.button(key="apply_blocking_rules").click().run()
            self.assertEqual(block.call_count, 1)
            self.assertEqual(block.call_args.kwargs, {"confirmed": True})
            self.assertEqual(blocklist.list_entries()[0]["target"], "example.com")
            self.assertFalse(app.exception)

    def test_critical_ip_dialog_requires_second_acknowledgement(self):
        script = ("from src.blocking_ui import confirm_enforcement\n"
                  "from src.blocking_center import preview_ip\n"
                  "confirm_enforcement([preview_ip('192.0.2.1', critical_lookup=lambda _: ['default gateway'])], [])")
        with tempfile.TemporaryDirectory() as folder, patch.object(blocklist, "DATA_DIR", Path(folder)), patch.object(
            blocklist, "BLOCKLIST_FILE", Path(folder) / "blocklist.json"), patch(
            "src.blocking_ui.is_windows_admin", return_value=True), patch(
            "src.blocking_center.critical_ip_reasons", return_value=["default gateway"]), patch(
            "src.blocking_ui.firewall.block_ip", return_value="blocked") as block, patch(
            "src.blocking_ui.firewall.managed_rule_state", return_value="active"):
            app = AppTest.from_string(script, default_timeout=30).run()
            app.text_input(key="confirm_block_phrase").set_value("BLOCK")
            app.button(key="apply_blocking_rules").click().run()
            block.assert_not_called()
            self.assertTrue(any("critical-address" in item.value for item in app.error))
            app.text_input(key="confirm_block_phrase").set_value("BLOCK")
            app.checkbox(key="confirm_critical_ip").set_value(True)
            app.button(key="apply_blocking_rules").click().run()
            self.assertEqual(block.call_args.kwargs["critical_confirmed"], True)
            self.assertFalse(app.exception)

    def test_undo_dialog_requires_phrase_and_removes_only_managed_entry(self):
        script = ("from src.blocking_ui import confirm_removal\n"
                  "confirm_removal({'target': 'example.com', 'type': 'Domain'})")
        active = {"value": True}

        def undo(*_args, **_kwargs):
            active["value"] = False

        with tempfile.TemporaryDirectory() as folder, patch.object(blocklist, "DATA_DIR", Path(folder)), patch.object(
            blocklist, "BLOCKLIST_FILE", Path(folder) / "blocklist.json"), patch(
            "src.blocking_ui.is_windows_admin", return_value=True), patch(
            "src.blocking_ui.domain_blocker.is_domain_blocked",
            side_effect=lambda *_args: active["value"]), patch(
            "src.blocking_ui.domain_blocker.unblock_domain", side_effect=undo) as unblock:
            blocklist.add_target("example.com")
            app = AppTest.from_string(script, default_timeout=30).run()
            app.button(key="apply_remove_target").click().run()
            unblock.assert_not_called()
            self.assertEqual(len(blocklist.list_entries()), 1)
            app.text_input(key="confirm_remove_phrase").set_value("REMOVE")
            app.button(key="apply_remove_target").click().run()
            self.assertEqual(unblock.call_args.kwargs, {"confirmed": True})
            self.assertEqual(blocklist.list_entries(), [])
            self.assertFalse(app.exception)


if __name__ == "__main__":
    unittest.main()
