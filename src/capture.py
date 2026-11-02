"""Npcap discovery and a bounded, per-session capture subprocess controller."""
import atexit
from collections import deque
import ctypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import weakref
import uuid

import psutil

from .model_utils import PROJECT_ROOT

MAX_RECENT_FLOWS = 500
_sessions = weakref.WeakSet()


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)), ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p), ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]


def list_capture_interfaces():
    """Enumerate Npcap's actual source names, preserving their descriptions."""
    if os.name != "nt":
        raise RuntimeError("Interface discovery requires Windows and Npcap.")
    directory = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/Npcap"
    try:
        with os.add_dll_directory(str(directory)):
            pcap = ctypes.WinDLL(str(directory / "wpcap.dll"))
            pointer = ctypes.POINTER(_PcapIf)
            pcap.pcap_findalldevs.argtypes = [ctypes.POINTER(pointer), ctypes.c_char_p]
            pcap.pcap_findalldevs.restype = ctypes.c_int
            pcap.pcap_freealldevs.argtypes = [pointer]
            pcap.pcap_freealldevs.restype = None
            devices = pointer()
            error = ctypes.create_string_buffer(256)
            if pcap.pcap_findalldevs(ctypes.byref(devices), error) != 0:
                raise RuntimeError(error.value.decode(errors="replace"))
            try:
                interfaces = []
                item = devices
                while item:
                    device = item.contents
                    if device.name:
                        name = device.name.decode(errors="replace")
                        description = (device.description or device.name).decode(errors="replace")
                        interfaces.append({"name": name, "description": description})
                    item = device.next
                return sorted(interfaces, key=lambda d: (
                    any(word in d["description"].lower() for word in ("wan miniport", "virtual", "loopback")),
                    d["description"],
                ))
            finally:
                if devices:
                    pcap.pcap_freealldevs(devices)
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(
            f"Npcap interface discovery failed: {exc}. Check that Npcap is installed "
            "and its driver is running; use an Administrator terminal if access is denied."
        ) from exc


def terminate_process_tree(process, known_children=()):
    """Stop only this controller's subprocess and its NFStream descendants."""
    children = {child.pid: child for child in known_children}
    try:
        children.update({child.pid: child for child in psutil.Process(process.pid).children(recursive=True)})
    except psutil.NoSuchProcess:
        pass
    targets = list(reversed(list(children.values())))
    for child in targets:
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            pass
    if process.poll() is None:
        process.terminate()
    _, alive = psutil.wait_procs(targets, timeout=1)
    for child in alive:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    if process.poll() is None:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
    process.wait(timeout=2)


class CaptureSession:
    """One worker, bounded history, cumulative counters, and a browser lease.

    All UI calls stay in dashboard.py. Launching the worker as a separate module
    prevents Windows multiprocessing from importing the Streamlit script.
    """
    def __init__(self, max_flows=MAX_RECENT_FLOWS, lease_seconds=30, startup_timeout=20, activity=None):
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None
        self._process = None
        self._cleanup_failed = False
        self._lease_seconds = lease_seconds
        self._startup_timeout = startup_timeout
        self._heartbeat = time.monotonic()
        self._flows = deque(maxlen=max_flows)
        self._logs = deque(maxlen=10)
        self.activity = activity
        self._reset()
        _sessions.add(self)

    def _reset(self):
        self._session_id = uuid.uuid4().hex
        self._sequence = 0
        self._event_ids = deque(maxlen=5000)
        self._flows.clear()
        self._logs.clear()
        self._status = "stopped"
        self._error = None
        self._warning = None
        self._interface = None
        self._started_at = None
        self._total = self._packets = self._bytes = self._predicted = 0
        self._identified_flows = self._unknown_flows = self._ambiguous_flows = 0
        self._service_counts = {}
        self._service_bytes = {}
        self._unknown_reasons = {}
        self._protocols = {name: {"Flows": 0, "Packets": 0, "Bytes": 0} for name in ("TCP", "UDP", "Other")}

    def touch(self):
        with self._lock:
            self._heartbeat = time.monotonic()

    def start(self, interface):
        if not isinstance(interface, str) or not interface.strip():
            raise ValueError("Select a detected Npcap interface first.")
        with self._lock:
            if self._cleanup_failed:
                raise RuntimeError("Previous capture cleanup failed. Restart Streamlit before starting another capture.")
            if self._thread is not None and self._thread.is_alive():
                return False
            self._reset()
            if self.activity and not self.activity.acquire(self._session_id, interface.strip()):
                raise RuntimeError('Another dashboard session is already monitoring. Stop it before starting a capture here.')
            self._interface = interface.strip()
            self._started_at = datetime.now(timezone.utc).isoformat()
            self._status = "starting"
            self._heartbeat = time.monotonic()
            self._stop.clear()
            self._thread = threading.Thread(target=self._monitor, daemon=True, name="traffic-capture-supervisor")
            self._thread.start()
            return True

    def stop(self, timeout=5):
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                return True
            self._status = "stopping"
            self._stop.set()
        thread.join(timeout)
        return not thread.is_alive()

    def snapshot(self):
        with self._lock:
            return {
                "status": self._status, "error": self._error, "warning": self._warning,
                "interface": self._interface, "started_at": self._started_at,
                "running": self._thread is not None and self._thread.is_alive(),
                "pid": self._process.pid if self._process is not None else None,
                "flows": [dict(row) for row in self._flows],
                "total_flows": self._total, "packets": self._packets, "bytes": self._bytes,
                "predicted_flows": self._predicted,
                "identified_flows": self._identified_flows,
                "unknown_flows": self._unknown_flows,
                "ambiguous_flows": self._ambiguous_flows,
                "service_counts": dict(self._service_counts),
                "service_bytes": dict(self._service_bytes),
                "unknown_reasons": dict(self._unknown_reasons),
                "protocols": {name: dict(values) for name, values in self._protocols.items()},
                "diagnostics": list(self._logs),
            }

    def _accept(self, message):
        with self._lock:
            kind = message["type"]
            if kind == "ready":
                if not self._stop.is_set():
                    self._status = "running"
            elif kind == "error":
                self._error = str(message["message"])
            elif kind == "warning":
                self._warning = str(message["message"])
            elif kind == "diagnostic":
                self._logs.append(str(message["message"]))
            elif kind == "flow":
                supplied_id = message.get('event_id')
                if supplied_id is not None and supplied_id in self._event_ids:
                    return
                if supplied_id is not None:
                    self._event_ids.append(supplied_id)
                row = message["row"]
                packets, byte_count = int(row["bidirectional_packets"]), int(row["bidirectional_bytes"])
                self._flows.append(dict(row))
                self._total += 1
                self._packets += packets
                self._bytes += byte_count
                self._predicted += row.get("Confidence") is not None
                service = row.get("Detected Service", "Unknown")
                self._service_bytes[service] = self._service_bytes.get(service, 0) + byte_count
                if service == "Ambiguous":
                    self._ambiguous_flows += 1
                elif service == "Unknown":
                    self._unknown_flows += 1
                    reason = row.get("Unknown Reason") or "Insufficient evidence"
                    self._unknown_reasons[reason] = self._unknown_reasons.get(reason, 0) + 1
                else:
                    self._identified_flows += 1
                    self._service_counts[service] = self._service_counts.get(service, 0) + 1
                protocol = {6: "TCP", 17: "UDP"}.get(row["protocol"], "Other")
                stats = self._protocols[protocol]
                stats["Flows"] += 1
                stats["Packets"] += packets
                stats["Bytes"] += byte_count
                self._sequence += 1
                if self.activity:
                    try:
                        self.activity.enqueue_flow(self._session_id + ':' + str(supplied_id or self._sequence), row)
                    except Exception:
                        self._logs.append('Local activity recording unavailable; capture continues.')

    def _read_stdout(self, process):
        for line in process.stdout:
            try:
                self._accept(json.loads(line))
            except (ValueError, TypeError, KeyError) as exc:
                with self._lock:
                    self._logs.append(f"Worker output: {line[:300].strip()} ({exc})")

    def _read_stderr(self, process):
        for line in process.stderr:
            with self._lock:
                self._logs.append(line[:500].strip())

    def _monitor(self):
        process, readers, children = None, [], {}
        control_directory = None
        try:
            control_directory = tempfile.TemporaryDirectory(prefix="traffic_capture_control_")
            stop_file = Path(control_directory.name) / "stop"
            environment = os.environ.copy()
            environment["PYTHONUNBUFFERED"] = "1"
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            process = subprocess.Popen(
                [sys.executable, "-B", "-m", "src.capture_worker", "--source", self._interface,
                 "--control-file", str(stop_file), "--parent-pid", str(os.getpid())],
                cwd=str(PROJECT_ROOT), env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            with self._lock:
                self._process = process
            for target in (self._read_stdout, self._read_stderr):
                reader = threading.Thread(target=target, args=(process,), daemon=True)
                reader.start()
                readers.append(reader)
            started, stopping_at = time.monotonic(), None
            while process.poll() is None:
                try:
                    children.update({c.pid: c for c in psutil.Process(process.pid).children(recursive=True)})
                except psutil.NoSuchProcess:
                    pass
                now = time.monotonic()
                with self._lock:
                    if now - self._heartbeat > self._lease_seconds:
                        self._warning = "Capture stopped because the dashboard disconnected or stopped refreshing."
                        self._stop.set()
                    if self._status == "starting" and now - started > self._startup_timeout:
                        self._error = "Capture startup timed out. Check Npcap, the adapter, and Administrator permissions."
                        self._stop.set()
                if self._stop.is_set():
                    if stopping_at is None:
                        stopping_at = now
                        with self._lock:
                            self._status = "stopping"
                        try:
                            stop_file.touch()
                        except (OSError, ValueError):
                            pass
                    elif now - stopping_at >= 0.75:
                        break
                time.sleep(0.1)
        except Exception as exc:
            with self._lock:
                self._error = f"Could not run capture worker: {exc}"
        finally:
            if process is not None:
                try:
                    terminate_process_tree(process, children.values())
                except (OSError, psutil.Error, subprocess.TimeoutExpired) as exc:
                    with self._lock:
                        self._error = f"Could not stop capture processes: {exc}. Restart the application."
                        self._cleanup_failed = True
                for reader in readers:
                    reader.join(timeout=1)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            if control_directory is not None:
                control_directory.cleanup()
            with self._lock:
                if process is not None and process.returncode and not self._stop.is_set() and not self._error:
                    detail = self._logs[-1] if self._logs else f"exit code {process.returncode}"
                    self._error = f"Capture worker exited unexpectedly: {detail}"
                self._status = "error" if self._error else "stopped"
                self._process = None
                if self.activity:
                    self.activity.release(self._session_id)


@atexit.register
def _stop_sessions():
    for session in list(_sessions):
        session.stop()
