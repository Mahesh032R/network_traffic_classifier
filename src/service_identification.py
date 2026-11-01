"""Conservative service attribution from observed NFStream metadata.

DNS queries are observations, not proof that a later connection visited a host.
Random Forest predictions are deliberately never used here.
"""
import ipaddress
import json
from functools import lru_cache
from pathlib import Path
import re

from .model_utils import PROJECT_ROOT

DOMAIN_MAP = PROJECT_ROOT / "data" / "service_domains.json"
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
GENERIC_APPS = {"unknown", "tls", "ssl", "http", "https", "http/3", "quic", "dns",
                "mdns", "llmnr", "tcp", "udp", "stun", "ntp", "netbios", "ssh"}
NDPI_SERVICES = {
    "youtube": "YouTube", "instagram": "Instagram", "whatsapp": "WhatsApp",
    "google": "Google", "facebook": "Facebook", "chatgpt": "ChatGPT",
    "openai": "OpenAI", "github": "GitHub", "netflix": "Netflix",
    "reddit": "Reddit", "wikipedia": "Wikipedia", "microsoft": "Microsoft",
    "bing": "Bing",
}

ENCRYPTED_PROTOCOLS = {"tls", "ssl", "https", "http/3", "quic"}


@lru_cache(maxsize=1)
def load_domain_map():
    """Read the small, reviewable domain map once per capture worker."""
    mapping = json.loads(DOMAIN_MAP.read_text(encoding="utf-8"))
    if not all(key in mapping for key in ("direct", "resource", "shared")):
        raise ValueError(f"Invalid service domain map: {DOMAIN_MAP}")
    return mapping


def normalize_hostname(value):
    if not isinstance(value, str):
        return None
    host = value.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if len(host) > 253 or "." not in host or ":" in host or "/" in host or " " in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if any(not HOST_LABEL.fullmatch(label) for label in labels) or labels[-1].isdigit():
        return None
    return host


def _match_domain(host, mapping):
    matches = ((domain, service) for domain, service in mapping.items()
               if host == domain or host.endswith("." + domain))
    return max(matches, key=lambda pair: len(pair[0]), default=(None, None))


def _hostname_evidence(host):
    mapping = load_domain_map()
    candidates = []
    for kind in ("direct", "resource"):
        domain, service = _match_domain(host, mapping[kind])
        if domain:
            candidates.append((len(domain), service, kind))
    shared = [domain for domain in mapping["shared"]
              if host == domain or host.endswith("." + domain)]
    if shared:
        candidates.append((max(map(len, shared)), "Ambiguous", "shared"))
    if not candidates:
        return None, "unknown"
    _, service, kind = max(candidates, key=lambda item: item[0])
    return service, kind


def _host_source(app):
    family = app.split(".", 1)[0].lower()
    if family in {"tls", "ssl"}:
        return "TLS server name (SNI)"
    if family == "http":
        return "HTTP Host"
    if family == "quic":
        return "QUIC server name"
    return "nDPI requested server name"


def _unknown_reason(app, host, raw_host, ndpi_service, confidence):
    """Explain unavailable evidence without claiming to detect ECH or a process."""
    family = app.split(".", 1)[0].lower()
    if host:
        return "Hostname outside service map"
    if raw_host:
        return "Invalid server-name metadata"
    if ndpi_service and confidence == 1:
        return "nDPI port-only result"
    if ndpi_service and confidence < 1:
        return "nDPI result lacks reliable confidence"
    leaf = app.rsplit(".", 1)[-1].lower()
    if leaf not in GENERIC_APPS and family != leaf and confidence >= 2:
        return "nDPI application not mapped"
    if family in ENCRYPTED_PROTOCOLS:
        return "Encrypted flow without hostname"
    if not app or app.lower() == "unknown":
        return "No nDPI application or hostname"
    if ndpi_service is None and family not in GENERIC_APPS and confidence >= 2:
        return "nDPI application not mapped"
    return "Protocol without service identity"


def identify_service(*, application_name=None, application_category_name=None,
                     application_is_guessed=None, application_confidence=None,
                     requested_server_name=None, src_port=None, dst_port=None):
    """Return service, evidence, and reliability without consulting model labels.

    nDPI confidence 1 is port-only and cannot establish a service. A DNS query
    is exposed separately because observing a lookup does not prove a connection.
    """
    app = str(application_name or "").strip()
    host = normalize_hostname(requested_server_name)
    result = {"Detected Hostname": host, "Detected Service": "Unknown",
              "Evidence Source": "None", "Identification Status": "Unknown",
              "Identification Note": "No specific hostname or protocol evidence",
              "DNS Query Service": None, "Unknown Reason": None}

    is_dns = app.split(".", 1)[0].lower() in {"dns", "mdns", "llmnr"} or 53 in (src_port, dst_port)
    host_service, host_kind = _hostname_evidence(host) if host else (None, "unknown")
    if is_dns:
        result["Evidence Source"] = "DNS query" if host else "None"
        result["Identification Status"] = "Lookup only" if host else "Unknown"
        result["Identification Note"] = "DNS lookup observed; a connection to this service is unverified" if host else result["Identification Note"]
        if host_kind in {"direct", "resource"}:
            result["DNS Query Service"] = host_service
        result["Unknown Reason"] = "DNS lookup only" if host else "DNS traffic without hostname"
        return result

    app_key = app.lower().split(".")[-1]
    ndpi_service = NDPI_SERVICES.get(app_key) if app_key not in GENERIC_APPS else None
    try:
        confidence = int(application_confidence)
    except (ValueError, TypeError):
        confidence = 0
    guessed = application_is_guessed in (True, 1, "1")
    ndpi_strong = ndpi_service is not None and confidence == 6 and not guessed
    ndpi_weak = ndpi_service is not None and confidence in (2, 3, 4, 5, 6) and not ndpi_strong

    if host_service and host_kind == "direct":
        if ndpi_strong and ndpi_service != host_service:
            result.update({"Detected Service": "Ambiguous", "Evidence Source": _host_source(app) + " and nDPI",
                           "Identification Status": "Ambiguous",
                           "Identification Note": "Hostname and protocol identify different services"})
            return result
        result.update({"Detected Service": host_service, "Evidence Source": _host_source(app),
                       "Identification Status": "Hostname evidence",
                       "Identification Note": "Direct service hostname observed"})
        return result

    if ndpi_strong:
        result.update({"Detected Service": ndpi_service, "Evidence Source": "nDPI",
                       "Identification Status": "Protocol evidence",
                       "Identification Note": "nDPI DPI identification; verify for critical use"})
        return result

    if host_kind == "shared":
        result.update({"Detected Service": "Ambiguous", "Evidence Source": _host_source(app),
                       "Identification Status": "Ambiguous",
                       "Identification Note": "Shared infrastructure hostname does not identify a website"})
        return result

    if host_kind == "resource":
        if ndpi_weak and ndpi_service != host_service:
            result.update({"Detected Service": "Ambiguous", "Evidence Source": _host_source(app) + " and nDPI",
                           "Identification Status": "Ambiguous",
                           "Identification Note": "Resource hostname and nDPI disagree"})
            return result
        result.update({"Detected Service": host_service, "Evidence Source": _host_source(app) + " (resource)",
                       "Identification Status": "Heuristic",
                       "Identification Note": "Service resource contacted; website visit unverified"})
        return result

    if ndpi_weak:
        result.update({"Detected Service": ndpi_service, "Evidence Source": "nDPI",
                       "Identification Status": "Heuristic",
                       "Identification Note": "nDPI identification is guessed or below DPI confidence"})
    elif host:
        result.update({"Evidence Source": _host_source(app), "Identification Note": "Hostname observed but not mapped to a known service"})
    result["Unknown Reason"] = _unknown_reason(app, host, requested_server_name,
                                                ndpi_service, confidence)
    return result
