
from pathlib import Path
import ipaddress

HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")
MARKER_START = "# BEGIN NetworkTrafficClassifier"
MARKER_END = "# END NetworkTrafficClassifier"


def _validate_domain(domain):
    domain = domain.strip().lower().rstrip(".")

    # Accept a domain, not a URL or IP address.
    try:
        ipaddress.ip_address(domain)
        raise ValueError("Enter a domain name, not an IP address.")
    except ValueError as exc:
        if str(exc) == "Enter a domain name, not an IP address.":
            raise

    if (
        not domain
        or len(domain) > 253
        or "/" in domain
        or ":" in domain
        or "://" in domain
        or "*" in domain
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not label.replace("-", "").isalnum()
            for label in domain.split(".")
        )
        or "." not in domain
    ):
        raise ValueError("Enter a valid domain, e.g. example.com.")

    return domain


def block_domain(domain):
    domain = _validate_domain(domain)

    if not HOSTS_FILE.exists():
        raise FileNotFoundError(f"Hosts file not found: {HOSTS_FILE}")

    text = HOSTS_FILE.read_text(encoding="utf-8", errors="replace")

    start = text.find(MARKER_START)
    end = text.find(MARKER_END)

    if (start == -1) != (end == -1):
        raise RuntimeError("Hosts file markers are incomplete; refusing to edit.")

    if start != -1:
        section = text[start:end]
        if any(
            line.split()[-1:] == [domain]
            for line in section.splitlines()
            if not line.lstrip().startswith("#") and line.split()
        ):
            return f"{domain} is already blocked."

        replacement = section + f"\n127.0.0.1 {domain}"
        text = text[:start] + replacement + text[end:]
    else:
        section = (
            f"{MARKER_START}\n"
            f"127.0.0.1 {domain}\n"
            f"{MARKER_END}"
        )
        text = text.rstrip() + "\n\n" + section + "\n"

    HOSTS_FILE.write_text(text, encoding="utf-8")
    return f"Added {domain} to the Windows hosts-file block section."


def unblock_domain(domain):
    domain = _validate_domain(domain)

    if not HOSTS_FILE.exists():
        raise FileNotFoundError(f"Hosts file not found: {HOSTS_FILE}")

    text = HOSTS_FILE.read_text(encoding="utf-8", errors="replace")
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
    return f"Removed {domain} from the managed hosts-file block section."

def is_domain_blocked(domain: str) -> bool:
    """Check whether a domain is in the managed Windows hosts section."""
    domain = _validate_domain(domain)

    if not HOSTS_FILE.exists():
        return False

    content = HOSTS_FILE.read_text(encoding="utf-8", errors="ignore")
    if MARKER_START not in content or MARKER_END not in content:
        return False

    section = content.split(MARKER_START, 1)[1].split(MARKER_END, 1)[0]

    for line in section.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "127.0.0.1":
            if domain.lower() in [item.lower() for item in parts[1:]]:
                return True

    return False
