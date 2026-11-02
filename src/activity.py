"""Local activity recording, adapter sampling and bounded non-blocking notifications."""
from collections import OrderedDict, deque
from datetime import datetime
from pathlib import PureWindowsPath
import queue
import threading
import time

import psutil

from . import blocklist, firewall
from .blocking_center import entry_status
from .history import HistoryStore, fingerprint
from .telemetry import CounterRate, adapter_key, resolve_adapter


class AlertEngine:
    def __init__(self, store, config, clock=time.time):
        self.store, self.config, self.clock = store, config, clock
        self.memory = OrderedDict()
        self.cooldowns = OrderedDict()
        self.notifications = deque(maxlen=100)
        self.connections = deque(maxlen=10000)
        self.usage = deque(maxlen=3601)

    def _state(self, key, value):
        previous = self.memory.get(key)
        if self.config['enabled']:
            saved = self.store.state(key, value)
            if saved is not None:
                previous = saved
        self.memory[key] = value
        self.memory.move_to_end(key)
        while len(self.memory) > 10000:
            self.memory.popitem(last=False)
        return previous

    def emit(self, kind, key, severity, message):
        now = self.clock()
        if now - self.cooldowns.get(key, float('-inf')) < self.config['cooldown_seconds']:
            return
        row = None
        if self.config['enabled']:
            row = self.store.emit(kind, key, severity, message, self.config['cooldown_seconds'],
                                  save=self.config['save_alerts'])
            if row is None and not self.store.error:
                return
        if row is None:
            import uuid
            row = {'id': uuid.uuid4().hex, 'timestamp': now, 'kind': kind, 'severity': severity,
                   'message': message, 'read': 0, 'dismissed': 0}
        self.cooldowns[key] = now
        self.cooldowns.move_to_end(key)
        while len(self.cooldowns) > 1000:
            self.cooldowns.popitem(last=False)
        self.notifications.append(row)

    def flow(self, original, row):
        config, now = self.config, self.clock()
        service, process = row['service'], row['process']
        if config['new_service'] and service not in ('Unknown', 'Ambiguous', ''):
            if self._state('service:' + fingerprint(service), 'seen') is None:
                label = f': {service}' if config['names'] else ''
                self.emit('New service', 'service:' + fingerprint(service), 'Information',
                          'New identified service observed' + label)
        if (config['new_process'] and process != 'Unknown Process' and
                original.get('Process Evidence') == 'Exact connected socket and capture-time overlap'):
            if self._state('process:' + fingerprint(process), 'seen') is None:
                label = f': {process}' if config['names'] else ''
                self.emit('New process', 'process:' + fingerprint(process), 'Information',
                          'New Windows process observed with exact socket evidence' + label)
        window = config['window_seconds']
        second = int(now)
        if self.usage and self.usage[-1][0] == second:
            self.usage[-1] = (second, self.usage[-1][1] + row['bytes'])
        else:
            self.usage.append((second, row['bytes']))
        while self.usage and self.usage[0][0] + 1 <= now - window:
            self.usage.popleft()
        if config['high_usage'] and sum(value for _, value in self.usage) >= config['usage_mb'] * 1_000_000:
            self.emit('High flow usage', 'flow_usage', 'Warning',
                      'Completed-flow data exceeded the configured window limit; this is not instantaneous bandwidth.')
        if config['repeated'] and config['destination_key']:
            candidates = [original.get('Remote IP')]
            if original.get('Identification Status') != 'Lookup only' and original.get('dst_port') != 53 and original.get('src_port') != 53:
                candidates.append(original.get('Detected Hostname'))
            if any(value and fingerprint(value) == config['destination_key'] for value in candidates):
                self.connections.append(now)
            while self.connections and self.connections[0] < now - window:
                self.connections.popleft()
            if len(self.connections) >= config['connection_count']:
                self.emit('Repeated connections', 'destination:' + config['destination_key'], 'Information',
                          'The selected destination exceeded the configured connection count and time window.')

    def sample(self, sample):
        if self.config['high_usage'] and max(sample['download_mbps'], sample['upload_mbps']) >= self.config['bandwidth_mbps']:
            self.emit('High adapter throughput', 'bandwidth', 'Warning',
                      'Selected device adapter exceeded the configured Mbps threshold (OS counter interval average).')

    def blocking(self, entries, lookup=entry_status):
        if not self.config['blocking']:
            return
        for entry in entries:
            key = 'blocking:' + fingerprint(entry['target'])
            status = lookup(entry)
            if status['error']:
                self.emit('Blocking inspection', key + ':error', 'Warning',
                          'A managed blocking target could not be inspected; enforcement is unverified.')
                continue
            states = status['states']
            for direction, state in states.items():
                state_key = key + ':' + direction
                previous = self._state(state_key, state)
                if previous is not None and previous != state:
                    self.emit('Blocking status change', state_key, 'Information' if state == 'active' else 'Warning',
                              f'A saved managed rule changed from {previous} to {state}; inspect Blocking & Protection.')


class ActivityMonitor:
    def __init__(self, path, *, clock=time.time, monotonic=time.monotonic, background=True):
        self.clock, self.monotonic = clock, monotonic
        self.store = HistoryStore(path, clock=clock)
        self.config = self.store.settings()
        self.engine = AlertEngine(self.store, self.config, clock)
        self.lock = threading.RLock()
        self.flows = deque(maxlen=5000)
        self.samples = deque(maxlen=1800)
        self.events = OrderedDict()
        self.owner = self.source = self.adapter = None
        self._coordinated = True
        self.rate = CounterRate()
        self.latest = None
        self.rate_state = 'Stopped'
        self.background = background
        self._thread = None
        self._stop = threading.Event()
        self._pending = queue.Queue(maxsize=10000)
        self.dropped_events = 0
        self.ingestion_error = None
        self._last_sample = float('-inf')
        self._dashboard_seen = float('-inf')
        self._last_check = self._last_prune = float('-inf')
        self.store.prune(self.config['retention_days'])

    def acquire(self, owner, source):
        with self.lock:
            if self.owner is not None and self.owner != owner:
                return False
            lease = self.store.claim_capture(owner)
            if lease is False:
                return False
            self._coordinated = lease is True
            self.owner, self.source = owner, source
            self.adapter, self.latest, self.rate = None, None, CounterRate()
            self.rate_state = 'Waiting for selected adapter counters'
            if self.background and (self._thread is None or not self._thread.is_alive()):
                self._stop.clear()
                self._thread = threading.Thread(target=self._run, daemon=True, name='local-activity-sampler')
                self._thread.start()
            return True

    def release(self, owner):
        with self.lock:
            if self.owner == owner:
                self.store.release_capture(owner)
                self.owner = None
                self.latest = None
                self.rate_state = 'Stopped'

    def close(self):
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=3)

    def touch(self):
        """Keep read-only blocking checks alive while a dashboard is viewing alerts."""
        self._dashboard_seen = self.monotonic()
        if self.background:
            self._ensure_worker()

    def _ensure_worker(self):
        with self.lock:
            if self._thread is None or not self._thread.is_alive():
                self._stop.clear()
                self._thread = threading.Thread(target=self._run, daemon=True, name='local-activity-sampler')
                self._thread.start()

    def enqueue_flow(self, event_id, row):
        if not self.background:
            return self.on_flow(event_id, row)
        try:
            self._pending.put_nowait((event_id, dict(row)))
        except queue.Full:
            self.dropped_events += 1
            return
        if self._thread is None or not self._thread.is_alive():
            self._ensure_worker()

    def _run(self):
        while True:
            try:
                for _ in range(100):
                    try:
                        event_id, row = self._pending.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        self.on_flow(event_id, row)
                    except Exception:
                        self.ingestion_error = 'Some activity events could not be recorded; capture continues.'
                    finally:
                        self._pending.task_done()
                if self.monotonic() - self._last_sample >= 2:
                    self._last_sample = self.monotonic()
                    self.tick()
            except Exception:
                # Activity failures must not interrupt capture or fabricate measurements.
                with self.lock:
                    self.latest = None
                    self.rate_state = 'Adapter measurement unavailable'
            with self.lock:
                idle = self.owner is None and self.monotonic() - self._dashboard_seen > 30
                if (idle or self._stop.is_set()) and self._pending.empty():
                    self._thread = None
                    return
            self._stop.wait(0.1)

    def maintain(self):
        now = self.clock()
        with self.lock:
            if now - self._last_prune < 60:
                return
            self._last_prune = now
        self.store.prune(self.config['retention_days'])

    def tick(self, *, resolver=resolve_adapter, counters=None):
        self.maintain()
        now = self.clock()
        with self.lock:
            owner, source = self.owner, self.source
        if now - self._last_check >= 30 and (owner is not None or self.monotonic() - self._dashboard_seen <= 30):
            self._last_check = now
            try:
                entries = blocklist.list_entries()
                inventory, inventory_error = [], None
                if any(entry['type'] == 'IP' for entry in entries):
                    try:
                        inventory = firewall._managed_rules()
                    except RuntimeError as exc:
                        inventory_error = str(exc)
                inspected = {entry['target']: ({'states': {}, 'error': inventory_error}
                             if entry['type'] == 'IP' and inventory_error else entry_status(entry, rules=inventory))
                             for entry in entries}
                with self.lock:
                    self.engine.blocking(entries, lookup=lambda entry: inspected[entry['target']])
            except (OSError, ValueError, RuntimeError):
                pass
        if owner is None:
            return
        with self.lock:
            if self.owner != owner:
                return
            lease = self.store.claim_capture(owner)
            self._coordinated = lease is True
            if lease is False:
                self.latest = None
                self.rate_state = 'Adapter history coordination unavailable; capture continues'
                return
        binding = resolver(source) if self.adapter is None else self.adapter
        if binding is None:
            with self.lock:
                self.rate_state = 'Unavailable: no exact OS adapter match'
        else:
            try:
                inventory = psutil.net_io_counters(pernic=True, nowrap=False) if counters is None else counters
                counter = inventory.get(binding[0])
            except (OSError, psutil.Error):
                counter = None
            with self.lock:
                if self.owner != owner:
                    return
                self.adapter = binding
                if counter is None:
                    self.latest, self.rate = None, CounterRate()
                    self.rate_state = 'Unavailable: selected adapter counters missing'
                else:
                    sample = self.rate.sample(counter.bytes_recv, counter.bytes_sent, self.monotonic(), now)
                    self.latest = sample
                    self.rate_state = 'Measuring' if sample else 'Waiting for baseline after start/reset'
                    if sample:
                        sample = sample | {'adapter': adapter_key(binding[0])}
                        self.samples.append(sample)
                        if self.config['enabled'] and self._coordinated:
                            if self.store.record_usage(sample['adapter'], sample) is None and self.store.error:
                                self.ingestion_error = 'Some local history writes failed. Stored usage has gaps; capture continues.'
                        self.engine.sample(sample)

    def on_flow(self, event_id, original):
        with self.lock:
            if event_id in self.events:
                return
            self.events[event_id] = True
            while len(self.events) > 5000:
                self.events.popitem(last=False)
            try:
                timestamp = float(original['bidirectional_last_seen_ms']) / 1000
            except (KeyError, TypeError, ValueError):
                try:
                    timestamp = datetime.fromisoformat(original['first_seen']).timestamp()
                except (KeyError, TypeError, ValueError):
                    timestamp = self.clock()
            row = {'timestamp': timestamp, 'service': str(original.get('Detected Service') or 'Unknown'),
                   'process': PureWindowsPath(str(original.get('Process Name') or 'Unknown Process')).name,
                   'protocol': {6: 'TCP', 17: 'UDP'}.get(original.get('protocol'), 'Other'),
                   'status': ('Unknown' if original.get('Detected Service', 'Unknown') == 'Unknown' else
                              'Ambiguous' if original.get('Detected Service') == 'Ambiguous' else 'Identified'),
                   'bytes': max(0, int(original.get('bidirectional_bytes') or 0)),
                   'upload': original.get('Upload Bytes'), 'download': original.get('Download Bytes')}
            if original.get('Process Evidence') != 'Exact connected socket and capture-time overlap':
                row['process'] = 'Unknown Process'
            if self.config['enabled'] and self._coordinated:
                inserted = self.store.record_flow(event_id, row, self.config['names'])
                if not inserted and not self.store.error:
                    return
                if not inserted:
                    self.ingestion_error = 'Some local history writes failed. Stored activity has gaps; capture continues.'
            self.flows.append(row | {'count': 1, 'last_seen': timestamp})
            self.engine.flow(original, row)

    def configure(self, settings):
        with self.lock:
            if not self.store.configure(settings):
                return False
            configured = self.store.settings()
            if self.store.error:
                return False
            self.config = configured
            self.engine.config = self.config
            self.engine.connections.clear()
            self.engine.usage.clear()
            self.store.prune(self.config['retention_days'])
            return True

    def alerts(self):
        with self.lock:
            persisted = self.store.alerts()
            rows = {row['id']: row for row in self.engine.notifications}
            rows.update({row['id']: row for row in persisted})
            cutoff = self.clock() - self.config['retention_days'] * 86400
            return sorted((row for row in rows.values() if not row['dismissed'] and row['timestamp'] >= cutoff),
                          key=lambda row: row['timestamp'], reverse=True)[:100]

    def alert_action(self, action, alert_id=None):
        with self.lock:
            self.store.update_alerts(action, alert_id)
            for row in self.engine.notifications:
                if alert_id is None or row['id'] == alert_id:
                    if action == 'read':
                        row['read'] = 1
                    elif action in ('dismiss', 'clear'):
                        row['dismissed'] = 1

    def clear_history(self):
        with self.lock:
            if not self.store.clear():
                return False
            self.flows.clear()
            self.samples.clear()
            self.engine = AlertEngine(self.store, self.config, self.clock)
            # Preserve consumed event IDs: a rerun must not recreate deleted history.
            return True

    def snapshot(self):
        with self.lock:
            fresh = self.latest is not None and self.clock() - self.latest['timestamp'] <= 6
            state = 'Waiting for fresh adapter counters' if self.owner and self.latest and not fresh else self.rate_state
            return {'latest': dict(self.latest) if fresh else None, 'state': state,
                    'flows': [dict(row) for row in self.flows], 'samples': [dict(row) for row in self.samples]}
