"""Counter-based adapter rates and conservative endpoint direction; no packet writes."""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time

import psutil


def address(value):
    try:
        ip = ipaddress.ip_address(str(value).split('%', 1)[0])
        return getattr(ip, 'ipv4_mapped', None) or ip
    except ValueError:
        return None


def flow_direction(row, local_addresses):
    """Return directional bytes and remote IP only for exactly one local endpoint."""
    source, destination = address(row.get('src_ip')), address(row.get('dst_ip'))
    local = {ip for item in local_addresses if (ip := address(item)) is not None}
    if source is None or destination is None or (source in local) == (destination in local):
        return None, None, None
    if source.is_loopback or destination.is_loopback:
        return None, None, None
    try:
        forward, reverse = int(row['src2dst_bytes']), int(row['dst2src_bytes'])
        if min(forward, reverse) < 0:
            raise ValueError('Negative counter')
        if row.get('bidirectional_bytes') is not None and forward + reverse != int(row['bidirectional_bytes']):
            raise ValueError('Inconsistent counters')
    except (KeyError, TypeError, ValueError, OverflowError):
        return None, None, None
    if source in local:
        return forward, reverse, str(destination)
    return reverse, forward, str(source)


def adapter_key(name):
    return hashlib.sha256(name.encode()).hexdigest()[:24]


def resolve_adapter(source, *, inventory=None, addresses=None):
    """Require an exact Npcap GUID -> Windows name -> psutil counter match."""
    guid = re.fullmatch(r'\\Device\\NPF_\{([0-9a-fA-F-]{36})\}', str(source))
    if not guid:
        return None
    if inventory is None:
        if os.name != 'nt':
            return None
        command = "Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object Name,InterfaceGuid | ConvertTo-Json -Compress"
        try:
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                                    capture_output=True, text=True, timeout=10, check=False)
            if result.returncode:
                return None
            inventory = json.loads(result.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return None
    if isinstance(inventory, dict):
        inventory = [inventory]
    if not isinstance(inventory, list) or not all(isinstance(item, dict) for item in inventory):
        return None
    matches = [item['Name'] for item in inventory if isinstance(item.get('Name'), str)
               and str(item.get('InterfaceGuid', '')).strip('{}').lower() == guid[1].lower()]
    if len(matches) != 1:
        return None
    name = matches[0]
    try:
        records = (psutil.net_if_addrs() if addresses is None else addresses).get(name, [])
    except (OSError, psutil.Error):
        return None
    return name, [item.address for item in records]


class CounterRate:
    """A baseline is required; resets, missing adapters and invalid time yield no rate."""
    def __init__(self):
        self.previous = None

    def sample(self, received, sent, monotonic=None, timestamp=None):
        now = time.monotonic() if monotonic is None else monotonic
        wall = time.time() if timestamp is None else timestamp
        previous, self.previous = self.previous, (now, received, sent)
        if previous is None:
            return None
        duration = now - previous[0]
        download, upload = received - previous[1], sent - previous[2]
        if duration <= 0 or min(download, upload, received, sent) < 0:
            return None
        return {'timestamp': wall, 'seconds': duration, 'download': download, 'upload': upload,
                'download_mbps': download * 8 / duration / 1_000_000,
                'upload_mbps': upload * 8 / duration / 1_000_000}
