"""Pure previews and read-only status for device-local blocking controls."""
import ctypes
import ipaddress
import os
import socket

import psutil

from . import domain_blocker, firewall
from .network_safety import critical_ip_reasons
from .service_identification import identify_service


SCOPE = "This Windows device only"


def is_windows_admin():
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def preview_ip(value, direction="out", *, critical_lookup=None):
    target = firewall._validate_ip(value)
    if direction not in ("out", "in"):
        raise ValueError("Choose outbound or inbound firewall direction.")
    lookup = critical_lookup or critical_ip_reasons
    return {"target": target, "type": "IP", "direction": direction,
            "method": "Windows Firewall", "scope": SCOPE,
            "critical_reasons": lookup(target),
            "coverage": "One exact remote IPv4 or IPv6 address; shared hosts may be affected."}


def preview_domain(value, *, kind="Domain", service=None, evidence=None):
    target = domain_blocker._validate_domain(value)
    if kind not in ("Domain", "Website"):
        raise ValueError("Choose a domain or website entry.")
    if kind == "Website" and not service:
        raise ValueError("A website entry needs an observed service name.")
    return {"target": target, "type": kind, "service": service,
            "evidence": evidence, "method": "Managed Windows hosts entry",
            "scope": SCOPE, "critical_reasons": [],
            "coverage": "Only this exact hostname. Subdomains, other hostnames, DNS bypass, and IP access are not covered."}


def observed_services(flows):
    return sorted({str(row.get("Detected Service")) for row in flows
                   if row.get("Detected Service") not in (None, "Unknown", "Ambiguous")})


def eligible_service_hosts(flows, service):
    """Only direct, rechecked hostname evidence may produce website proposals."""
    hosts = {}
    for row in flows:
        if row.get("Detected Service") != service or row.get("Identification Status") != "Hostname evidence":
            continue
        observed = row.get("Detected Hostname")
        try:
            target = domain_blocker._validate_domain(observed)
        except ValueError:
            continue
        checked = identify_service(
            application_name=row.get("application_name"),
            application_category_name=row.get("application_category_name"),
            application_is_guessed=row.get("application_is_guessed"),
            application_confidence=row.get("application_confidence"),
            requested_server_name=target,
            src_port=row.get("src_port"), dst_port=row.get("dst_port"),
        )
        if (checked["Detected Service"] == service and
                checked["Identification Status"] == "Hostname evidence"):
            hosts[target] = checked["Evidence Source"]
    return [{"hostname": host, "evidence": hosts[host]} for host in sorted(hosts)]


def website_candidates(flows):
    """Exact observed hostnames suitable for a user-initiated website preview."""
    return [{"target": host["hostname"], "type": "Website", "service": service,
             "evidence": host["evidence"]}
            for service in observed_services(flows)
            for host in eligible_service_hosts(flows, service)]


def remote_ip_candidates(flows, *, interfaces=None):
    """Offer an IP only when exactly one flow endpoint is on this device."""
    if interfaces is None:
        try:
            interfaces = psutil.net_if_addrs()
        except (OSError, psutil.Error):
            return []
    local = set()
    for records in interfaces.values():
        for record in records:
            if record.family in (socket.AF_INET, socket.AF_INET6):
                try:
                    local.add(ipaddress.ip_address(record.address.split("%", 1)[0]))
                except (ValueError, AttributeError):
                    continue
    candidates = set()
    for row in flows:
        try:
            source = ipaddress.ip_address(row["src_ip"])
            destination = ipaddress.ip_address(row["dst_ip"])
        except (KeyError, ValueError, TypeError):
            continue
        if (source in local) == (destination in local):
            continue
        remote = destination if source in local else source
        try:
            candidates.add(firewall._validate_ip(str(remote)))
        except ValueError:
            continue
    return sorted(candidates, key=lambda value: (ipaddress.ip_address(value).version,
                                                  ipaddress.ip_address(value)))


def entry_status(entry, *, rules=None):
    target = entry["target"]
    try:
        if entry["type"] == "IP":
            inventory = firewall._managed_rules() if rules is None else rules
            outbound = firewall.managed_rule_state(target, "out", rules=inventory)
            inbound = firewall.managed_rule_state(target, "in", rules=inventory)
            states = {"out": outbound, "in": inbound}
            if "conflict" in states.values():
                label = "Conflict — manual review"
            elif "active" in states.values():
                active = ["outbound" if direction == "out" else "inbound"
                          for direction, state in states.items() if state == "active"]
                label = "Enabled firewall rule: " + ", ".join(active)
            elif "disabled" in states.values():
                label = "Disabled rule present"
            else:
                label = "Intent only"
        else:
            active = domain_blocker.is_domain_blocked(target)
            states = {"domain": "active" if active else "absent"}
            label = "Active hosts entry" if active else "Intent only"
    except (OSError, RuntimeError, ValueError) as exc:
        states = {}
        label = "Status unavailable"
        return {"status": label, "states": states, "error": str(exc)}
    return {"status": label, "states": states, "error": None}
