
import ipaddress
import subprocess

RULE_PREFIX = "NetworkTrafficClassifier-Block-"


def _validate_ip(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter an IP address before changing Windows Firewall.")
    ip = ipaddress.ip_address(value.strip())

    # Prevent blocking special/local destinations by accident.
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or str(ip) == "255.255.255.255":
        raise ValueError("Refusing to block loopback, link-local, unspecified, multicast, or broadcast IPs.")

    return str(ip)


def _run_netsh(args, allow_no_rules=False):
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall"] + args,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        # netsh returns exit code 1 for an ordinary absent-rule query.
        if allow_no_rules and "no rules match" in result.stdout.lower():
            return result.stdout.strip()
        raise RuntimeError(detail or "Windows Firewall command failed.")

    return result.stdout.strip()


def block_ip(value, *, confirmed=False):
    ip = _validate_ip(value)
    if confirmed is not True:
        raise PermissionError("Confirm the target IP before enforcing a Windows Firewall block.")
    rule_name = RULE_PREFIX + ip

    _run_netsh([
        "add", "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={ip}",
        "enable=yes",
        "profile=any",
    ])

    return f"Outbound traffic to {ip} is blocked by Windows Firewall."


def unblock_ip(value):
    ip = _validate_ip(value)
    rule_name = RULE_PREFIX + ip

    _run_netsh([
        "delete", "rule",
        f"name={rule_name}",
    ])

    return f"Removed the firewall rule for {ip}."


def firewall_rule_exists(value):
    ip = _validate_ip(value)
    rule_name = RULE_PREFIX + ip

    output = _run_netsh([
        "show", "rule",
        f"name={rule_name}",
    ], allow_no_rules=True)

    return "no rules match" not in output.lower()
