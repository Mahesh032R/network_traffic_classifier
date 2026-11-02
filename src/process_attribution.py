"""Read-only, conservative Windows socket-to-flow attribution.

An exact connected socket and a capture-time overlap are required. A hostname,
port, or remote IP alone is never evidence of the owning process.
"""
from collections import deque
import ipaddress
import os
import socket
import threading
import time

import psutil


UNKNOWN = {"Process Name": "Unknown Process", "Process PID": None,
           "Process Executable": None, "Process Evidence": "No exact socket match",
           "Upload Bytes": None, "Download Bytes": None}


def _address(endpoint):
    if not endpoint or len(endpoint) < 2:
        return None
    try:
        address = ipaddress.ip_address(str(endpoint[0]).split("%", 1)[0])
        if getattr(address, "ipv4_mapped", None):
            address = address.ipv4_mapped
        return str(address), int(endpoint[1])
    except (ValueError, TypeError, IndexError):
        return None


def _flow_key(flow):
    try:
        protocol = int(flow.get("protocol"))
        if protocol not in (6, 17):
            return None
        return (protocol, _address((flow["src_ip"], flow["src_port"])),
                _address((flow["dst_ip"], flow["dst_port"])))
    except (KeyError, TypeError, ValueError):
        return None


class SocketSampler:
    """Keep a bounded window of observed, connected TCP/UDP sockets."""

    def __init__(self, interval=0.25, retention=30, max_samples=4096, connections=None,
                 process_factory=None, clock=None, platform=None):
        self.interval, self.retention = interval, retention
        self._samples = deque(maxlen=max_samples)
        self._lock = threading.RLock()
        self.platform = platform or os.name
        self._connections = connections or (lambda: psutil.net_connections(kind="inet"))
        self._process_factory = process_factory or psutil.Process
        self._clock = clock or time.time
        self._stop = threading.Event()
        self._thread = None
        self.error = None

    def sample(self):
        now = self._clock()
        try:
            connections = self._connections()
        except (psutil.Error, OSError) as exc:
            self.error = f"Socket inspection unavailable: {exc}"
            return
        collected = []
        for connection in connections:
            protocol = {socket.SOCK_STREAM: 6, socket.SOCK_DGRAM: 17}.get(connection.type)
            local, remote = _address(connection.laddr), _address(connection.raddr)
            if protocol is None or local is None or remote is None or not connection.pid:
                continue
            if protocol == 6 and connection.status != psutil.CONN_ESTABLISHED:
                continue
            try:
                process = self._process_factory(connection.pid)
                created = process.create_time()
                name = process.name()
                try:
                    executable = process.exe() or None
                except (psutil.Error, OSError):
                    executable = None
            except (psutil.Error, OSError):
                continue
            collected.append((now, (protocol, local, remote),
                              connection.pid, created, name, executable))
        with self._lock:
            self._samples.extend(collected)
            self._discard_old(now)

    def _discard_old(self, now):
        while self._samples and now - self._samples[0][0] > self.retention:
            self._samples.popleft()

    def match(self, flow):
        result = dict(UNKNOWN)
        if self.platform != "nt":
            result["Process Evidence"] = "Windows socket attribution unavailable on this platform"
            return result
        key = _flow_key(flow)
        try:
            start = int(flow["bidirectional_first_seen_ms"]) / 1000
            end = int(flow["bidirectional_last_seen_ms"]) / 1000
        except (KeyError, ValueError, TypeError):
            result["Process Evidence"] = "Capture timestamps unavailable"
            return result
        if key is None or None in key or end < start:
            return result
        reverse = (key[0], key[2], key[1])
        with self._lock:
            self._discard_old(self._clock())
            observations = [(socket_key, pid, created, name, executable)
                            for observed, socket_key, pid, created, name, executable in self._samples
                            if socket_key in (key, reverse) and start - 1 <= observed <= end + 1]
            matches = {(pid, created, name, executable)
                       for _, pid, created, name, executable in observations}
        if len(matches) != 1:
            if len(matches) > 1:
                result["Process Evidence"] = "Multiple matching process owners"
            elif self.error:
                result["Process Evidence"] = self.error
            return result
        pid, _, name, executable = matches.pop()
        if not name:
            return result
        directions = {socket_key == key for socket_key, observed_pid, _, _, _ in observations
                      if observed_pid == pid}
        upload = download = None
        if len(directions) == 1:
            first = "src2dst_bytes" if True in directions else "dst2src_bytes"
            second = "dst2src_bytes" if True in directions else "src2dst_bytes"
            try:
                upload, download = int(flow[first]), int(flow[second])
            except (KeyError, TypeError, ValueError):
                pass
        return {"Process Name": name, "Process PID": pid,
                "Process Executable": executable,
                "Process Evidence": "Exact connected socket and capture-time overlap",
                "Upload Bytes": upload, "Download Bytes": download}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self.sample()
        self._thread = threading.Thread(target=self._run, daemon=True, name="socket-sampler")
        self._thread.start()

    def _run(self):
        while not self._stop.wait(self.interval):
            self.sample()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
