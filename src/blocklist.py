
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
    if not isinstance(target, str):
        raise ValueError("Enter a domain name or IP address.")
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


def add_target(target, *, kind=None, service=None, evidence=None):
    target = normalize_target(target)
    data = _load()

    try:
        ipaddress.ip_address(target)
        category = "ips"
    except ValueError:
        category = "domains"

    if kind not in (None, "IP", "Domain", "Website"):
        raise ValueError("Blocklist type must be IP, Domain, or Website.")
    if kind == "Website" and (category != "domains" or not isinstance(service, str) or not service.strip()):
        raise ValueError("A website entry requires an exact domain and observed service name.")
    if kind == "Domain" and category != "domains" or kind == "IP" and category != "ips":
        raise ValueError("Blocklist type does not match the target.")

    if target in data[category]:
        return False, f"{target} is already in the blocklist."

    data[category].append(target)
    event = {
        "action": "added",
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": kind or ("IP" if category == "ips" else "Domain"),
    }
    if kind == "Website":
        event["service"] = service.strip()
        event["evidence"] = str(evidence or "Observed hostname")
    data["events"].append(event)
    _save(data)

    return True, f"{target} added to the blocklist."


def list_entries():
    """Current intended targets with their last addition metadata."""
    data = _load()
    latest = {}
    for event in data["events"]:
        if event.get("action") == "added":
            latest[event.get("target")] = event
    entries = []
    for category in ("ips", "domains"):
        for target in data[category]:
            event = latest.get(target, {})
            entries.append({
                "target": target,
                "type": event.get("kind") or ("IP" if category == "ips" else "Domain"),
                "service": event.get("service"),
                "evidence": event.get("evidence"),
                "created": event.get("timestamp") or "Date unavailable",
            })
    return entries


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
