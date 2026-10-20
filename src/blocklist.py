
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
BLOCKLIST_FILE = DATA_DIR / "blocklist.json"


def normalize_target(target):
    """Validate and normalize a domain name or IP address."""
    target = target.strip().lower()

    if not target:
        raise ValueError("Enter a domain name or IP address.")

    # Accept IPv4 and IPv6 addresses.
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass

    # Domain names only: no URL scheme, path, port, or wildcard.
    if (
        "://" in target
        or "/" in target
        or ":" in target
        or "*" in target
        or len(target) > 253
    ):
        raise ValueError("Enter a domain or IP address, not a URL.")

    target = target.rstrip(".")

    labels = target.split(".")
    valid_label = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    if len(labels) < 2 or not all(
        valid_label.fullmatch(label) for label in labels
    ):
        raise ValueError("Enter a valid domain, e.g. example.com.")

    return target


def _load():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not BLOCKLIST_FILE.exists():
        return {"domains": [], "ips": [], "events": []}

    with BLOCKLIST_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    data.setdefault("domains", [])
    data.setdefault("ips", [])
    data.setdefault("events", [])
    return data


def _save(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with BLOCKLIST_FILE.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def list_blocked():
    data = _load()
    return data["domains"], data["ips"]


def add_target(target):
    target = normalize_target(target)
    data = _load()

    try:
        ipaddress.ip_address(target)
        category = "ips"
    except ValueError:
        category = "domains"

    if target in data[category]:
        return False, f"{target} is already in the blocklist."

    data[category].append(target)
    data["events"].append({
        "action": "added",
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    _save(data)

    return True, f"{target} added to the blocklist."


def remove_target(target):
    target = normalize_target(target)
    data = _load()

    try:
        ipaddress.ip_address(target)
        category = "ips"
    except ValueError:
        category = "domains"

    if target not in data[category]:
        return False, f"{target} is not in the blocklist."

    data[category].remove(target)
    data["events"].append({
        "action": "removed",
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    _save(data)

    return True, f"{target} removed from the blocklist."


def list_events():
    return _load()["events"]
