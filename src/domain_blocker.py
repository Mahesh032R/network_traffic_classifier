
from pathlib import Path
import ipaddress
import os
import re

HOSTS_FILE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"
MARKER_START = "# BEGIN NetworkTrafficClassifier"
MARKER_END = "# END NetworkTrafficClassifier"


def _validate_domain(domain):
    if not isinstance(domain, str):
        raise ValueError("Enter a domain name before changing the Windows hosts file.")
    domain = domain.strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]

    # Accept a domain, not a URL or IP address.
    try:
        ipaddress.ip_address(domain)
        raise ValueError("Enter a domain name, not an IP address.")
    except ValueError as exc:
        if str(exc) == "Enter a domain name, not an IP address.":
            raise

    valid_label = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if (
        not domain
        or len(domain) > 253
        or "/" in domain
        or ":" in domain
        or "://" in domain
        or "*" in domain
        or any(not valid_label.fullmatch(label) for label in domain.split("."))
        or "." not in domain
    ):
        raise ValueError("Enter a valid domain, e.g. example.com.")

    return domain


def block_domain(domain, *, confirmed=False):
    domain = _validate_domain(domain)
    if confirmed is not True:
        raise PermissionError("Confirm the target domain before changing the Windows hosts file.")

    if not HOSTS_FILE.exists():
        raise FileNotFoundError(f"Hosts file not found: {HOSTS_FILE}")

    text = HOSTS_FILE.read_text(encoding="utf-8")

    if text.count(MARKER_START) > 1 or text.count(MARKER_END) > 1:
        raise RuntimeError("Multiple managed hosts-file sections found; refusing to edit.")

    start = text.find(MARKER_START)
    end = text.find(MARKER_END)

    if (start == -1) != (end == -1) or (start != -1 and end < start):
        raise RuntimeError("Hosts file markers are incomplete; refusing to edit.")

    if start != -1:
        section = text[start:end]
        if any(
            line.split()[-1:] == [domain]
            for line in section.splitlines()
            if not line.lstrip().startswith("#") and line.split()
        ):
            return f"{domain} is already blocked."

        replacement = section.rstrip() + f"\n127.0.0.1 {domain}\n"
        text = text[:start] + replacement + text[end:]
    else:
        section = (
            f"{MARKER_START}\n"
            f"127.0.0.1 {domain}\n"
            f"{MARKER_END}"
        )
        text = text.rstrip() + "\n\n" + section + "\n"

    HOSTS_FILE.write_text(text, encoding="utf-8")
    if not is_domain_blocked(domain):
        raise RuntimeError("The managed hosts entry could not be verified after writing.")
    return f"Added {domain} to the Windows hosts-file block section."


def unblock_domain(domain, *, confirmed=False):
    domain = _validate_domain(domain)
    if confirmed is not True:
        raise PermissionError("Confirm the exact managed hosts entry before removing it.")

    if not HOSTS_FILE.exists():
        raise FileNotFoundError(f"Hosts file not found: {HOSTS_FILE}")

    text = HOSTS_FILE.read_text(encoding="utf-8")
    if text.count(MARKER_START) > 1 or text.count(MARKER_END) > 1:
        raise RuntimeError("Multiple managed hosts-file sections found; refusing to edit.")
    start = text.find(MARKER_START)
    end = text.find(MARKER_END)

    if start == -1 or end == -1 or end < start:
        return "No managed domain-blocking section was found."

    before = text[:start]
    section = text[start:end]
    after = text[end + len(MARKER_END):]

    lines = section.splitlines()
    kept = [
        line for line in lines
        if not (
            not line.lstrip().startswith("#")
            and len(line.split()) >= 2
            and line.split()[-1].lower() == domain
        )
    ]

    if len(kept) == len(lines):
        return f"{domain} was not in the managed block section."

    remaining = "\n".join(kept).strip()

    if remaining == MARKER_START:
        new_text = before.rstrip() + "\n" + after.lstrip("\n")
    else:
        new_text = before + remaining + "\n" + MARKER_END + after

    HOSTS_FILE.write_text(new_text, encoding="utf-8")
    if is_domain_blocked(domain):
        raise RuntimeError("The managed hosts entry still appears after removal.")
    return f"Removed {domain} from the managed hosts-file block section."

def is_domain_blocked(domain: str) -> bool:
    """Check whether a domain is in the managed Windows hosts section."""
    domain = _validate_domain(domain)

    if not HOSTS_FILE.exists():
        return False

    content = HOSTS_FILE.read_text(encoding="utf-8")
    starts, ends = content.count(MARKER_START), content.count(MARKER_END)
    if starts == ends == 0:
        return False
    if starts != 1 or ends != 1 or content.index(MARKER_END) < content.index(MARKER_START):
        raise RuntimeError("Managed hosts-file markers are incomplete or ambiguous; inspect manually.")

    section = content.split(MARKER_START, 1)[1].split(MARKER_END, 1)[0]

    for line in section.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "127.0.0.1":
            if domain.lower() in [item.lower() for item in parts[1:]]:
                return True

    return False
