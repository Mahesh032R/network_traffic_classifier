
import ipaddress
import json
import subprocess

from .network_safety import critical_ip_reasons

RULE_PREFIX = "NetworkTrafficClassifier-Block-"
_RULE_INVENTORY = r"""
$ErrorActionPreference = 'Stop'
$items = foreach ($rule in @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.DisplayName -like 'NetworkTrafficClassifier-Block-*' })) {
    $filter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $ports = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $service = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    $interface = $rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
    [PSCustomObject]@{
        DisplayName = [string]$rule.DisplayName
        Direction = [string]$rule.Direction
        Action = [string]$rule.Action
        Enabled = [string]$rule.Enabled
        RemoteAddress = @($filter.RemoteAddress)
        LocalAddress = @($filter.LocalAddress)
        Profile = [string]$rule.Profile
        Program = [string]$application.Program
        Protocol = [string]$ports.Protocol
        LocalPort = [string]$ports.LocalPort
        RemotePort = [string]$ports.RemotePort
        Service = [string]$service.Service
        InterfaceType = [string]$interface.InterfaceType
    }
}
ConvertTo-Json -InputObject @($items) -Compress -Depth 4
"""


def _validate_ip(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter an IP address before changing Windows Firewall.")
    ip = ipaddress.ip_address(value.strip())
    checked = getattr(ip, "ipv4_mapped", None) or ip

    # Prevent blocking special/local destinations by accident.
    if (checked.is_loopback or checked.is_unspecified or checked.is_multicast or
            checked.is_link_local or str(checked) == "255.255.255.255"):
        raise ValueError("Refusing to block loopback, link-local, unspecified, multicast, or broadcast IPs.")

    return str(ip)


def _run_netsh(args, allow_no_rules=False):
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall"] + args,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Windows Firewall did not complete the command; inspect the rule status before retrying.") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        # netsh returns exit code 1 for an ordinary absent-rule query.
        if allow_no_rules and "no rules match" in result.stdout.lower():
            return result.stdout.strip()
        raise RuntimeError(detail or "Windows Firewall command failed.")

    return result.stdout.strip()


def _rule_name(ip, direction):
    if direction not in ("out", "in"):
        raise ValueError("Firewall direction must be outbound or inbound.")
    return RULE_PREFIX + ("In-" if direction == "in" else "") + ip


def _managed_rules():
    """Read local managed-rule candidates without changing firewall policy."""
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _RULE_INVENTORY],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not inspect local Windows Firewall rules.") from exc
    if result.returncode != 0:
        raise RuntimeError("Could not inspect local Windows Firewall rules: " +
                           (result.stderr.strip() or "PowerShell failed."))
    try:
        rules = json.loads(result.stdout.strip() or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows returned invalid firewall rule data.") from exc
    return rules if isinstance(rules, list) else [rules]


def managed_rule_state(value, direction="out", *, rules=None):
    """Return absent, active, disabled, or conflict for one exact managed rule."""
    ip = _validate_ip(value)
    name = _rule_name(ip, direction)
    matches = [rule for rule in (_managed_rules() if rules is None else rules)
               if rule.get("DisplayName") == name]
    if not matches:
        return "absent"
    if len(matches) != 1:
        return "conflict"
    rule = matches[0]
    expected_direction = {"out": {"out", "outbound"}, "in": {"in", "inbound"}}[direction]
    raw_addresses = rule.get("RemoteAddress") or []
    if isinstance(raw_addresses, str):
        raw_addresses = [raw_addresses]
    try:
        addresses = [str(ipaddress.ip_address(item)) for item in raw_addresses]
    except (ValueError, TypeError):
        return "conflict"
    if (str(rule.get("Direction", "")).lower() not in expected_direction
            or str(rule.get("Action", "")).lower() != "block"
            or addresses != [ip]
            or rule.get("LocalAddress") != ["Any"]
            or any(str(rule.get(field, "")).lower() != "any" for field in (
                "Profile", "Program", "Protocol", "LocalPort", "RemotePort",
                "Service", "InterfaceType"))):
        return "conflict"
    return "active" if str(rule.get("Enabled", "")).lower() == "true" else "disabled"


def block_ip(value, *, confirmed=False, direction="out", critical_confirmed=False):
    ip = _validate_ip(value)
    rule_name = _rule_name(ip, direction)
    if confirmed is not True:
        raise PermissionError("Confirm the target IP before enforcing a Windows Firewall block.")
    reasons = critical_ip_reasons(ip)
    if reasons and critical_confirmed is not True:
        raise PermissionError("Additional confirmation is required for a critical address: " +
                              ", ".join(reasons))
    state = managed_rule_state(ip, direction)
    if state == "active":
        return f"The managed {direction}bound rule for {ip} already exists."
    if state != "absent":
        raise RuntimeError("A conflicting or disabled rule already uses this managed name; inspect it manually.")

    _run_netsh([
        "add", "rule",
        f"name={rule_name}",
        f"dir={direction}",
        "action=block",
        f"remoteip={ip}",
        "enable=yes",
        "profile=any",
    ])
    if managed_rule_state(ip, direction) != "active":
        raise RuntimeError("The firewall command returned, but its exact rule could not be verified. Inspect Windows Firewall before retrying.")
    return f"Managed {direction}bound rule for {ip} is active on this Windows device."


def unblock_ip(value, *, direction="out", confirmed=False):
    ip = _validate_ip(value)
    rule_name = _rule_name(ip, direction)
    if confirmed is not True:
        raise PermissionError("Confirm the exact managed firewall rule before removing it.")
    state = managed_rule_state(ip, direction)
    if state == "absent":
        return f"No managed {direction}bound rule exists for {ip}."
    if state == "conflict":
        raise RuntimeError("The rule name conflicts with an unexpected firewall rule; refusing to remove it.")

    _run_netsh([
        "delete", "rule",
        f"name={rule_name}",
        f"dir={direction}",
        f"remoteip={ip}",
    ])
    if managed_rule_state(ip, direction) != "absent":
        raise RuntimeError("The managed firewall rule still appears present after removal.")
    return f"Removed the managed {direction}bound rule for {ip}."


def firewall_rule_exists(value, *, direction="out"):
    state = managed_rule_state(value, direction)
    if state == "conflict":
        raise RuntimeError("A conflicting firewall rule uses the managed name.")
    return state == "active"
