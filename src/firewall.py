
import ipaddress
import subprocess

RULE_PREFIX = "NetworkTrafficClassifier-Block-"


def _validate_ip(value):
    ip = ipaddress.ip_address(value.strip())

    # Prevent blocking special/local destinations by accident.
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        raise ValueError("Refusing to block loopback, unspecified, or multicast IPs.")

    return str(ip)


def _run_netsh(args):
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall"] + args,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(detail or "Windows Firewall command failed.")

    return result.stdout.strip()


def block_ip(value):
    ip = _validate_ip(value)
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
    ])

    return "No rules match" not in output
