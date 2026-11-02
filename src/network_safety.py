"""Read-only checks for device addresses, gateways, and active DNS resolvers."""
import ipaddress
import json
import os
import socket
import subprocess

import psutil


_NETWORK_CONFIGURATION = r"""
$ErrorActionPreference = 'Stop'
$addresses = @()
Get-NetIPConfiguration | ForEach-Object {
    if ($_.IPv4DefaultGateway) { $addresses += @($_.IPv4DefaultGateway.NextHop) }
    if ($_.IPv6DefaultGateway) { $addresses += @($_.IPv6DefaultGateway.NextHop) }
    if ($_.DNSServer) { $addresses += @($_.DNSServer.ServerAddresses) }
}
ConvertTo-Json -InputObject @($addresses | Where-Object { $_ } | Select-Object -Unique) -Compress
"""


def critical_ip_reasons(value, *, run=None, interfaces=None):
    """Return reasons for extra confirmation; fail closed if Windows data is unavailable."""
    address = ipaddress.ip_address(value)
    reasons = []
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        reasons.append("special or local-network address")
    if str(address) == "255.255.255.255":
        reasons.append("broadcast address")
    if interfaces is None:
        try:
            interfaces = psutil.net_if_addrs()
        except (OSError, psutil.Error) as exc:
            raise RuntimeError("Could not inspect this device's network addresses; IP enforcement is disabled.") from exc
    for records in interfaces.values():
        for record in records:
            if record.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                configured = ipaddress.ip_address(record.address.split("%", 1)[0])
            except (ValueError, AttributeError):
                continue
            if address == configured:
                reasons.append("this device's own network address")
    if os.name != "nt" and run is None:
        return sorted(set(reasons))
    command = run or subprocess.run
    try:
        result = command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                          _NETWORK_CONFIGURATION], capture_output=True, text=True,
                         timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not verify gateway and DNS addresses; IP enforcement is disabled.") from exc
    if result.returncode != 0:
        raise RuntimeError("Could not verify gateway and DNS addresses; IP enforcement is disabled.")
    try:
        addresses = json.loads(result.stdout.strip() or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows returned invalid network configuration; IP enforcement is disabled.") from exc
    if not isinstance(addresses, list) or not all(isinstance(item, str) for item in addresses):
        raise RuntimeError("Windows returned invalid network configuration; IP enforcement is disabled.")
    for item in addresses:
        try:
            if address == ipaddress.ip_address(str(item).split("%", 1)[0]):
                reasons.append("default gateway or active DNS resolver")
        except ValueError:
            continue
    return sorted(set(reasons))
