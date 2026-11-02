"""Bounded local aggregates and alert state. No endpoints, packets or executable paths."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
import uuid


DEFAULTS = {'enabled': True, 'names': False, 'retention_days': 7, 'save_alerts': True,
            'new_service': True, 'new_process': True, 'high_usage': True,
            'repeated': False, 'blocking': True, 'bandwidth_mbps': 20.0,
            'usage_mb': 100.0, 'window_seconds': 60, 'connection_count': 20,
            'destination_key': '', 'cooldown_seconds': 60}


def fingerprint(value):
    return hashlib.sha256(str(value).strip().lower().encode()).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS capture_lease (id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS usage (
 minute INTEGER, adapter TEXT, download INTEGER, upload INTEGER, seconds REAL,
 PRIMARY KEY(minute,adapter));
CREATE TABLE IF NOT EXISTS flows (
 minute INTEGER, service TEXT, process TEXT, protocol TEXT, status TEXT,
 bytes INTEGER, count INTEGER, upload INTEGER, download INTEGER, last_seen REAL,
 PRIMARY KEY(minute,service,process,protocol,status));
CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp REAL);
CREATE TABLE IF NOT EXISTS state (id TEXT PRIMARY KEY, value TEXT, timestamp REAL);
CREATE TABLE IF NOT EXISTS alerts (
 id TEXT PRIMARY KEY, timestamp REAL, kind TEXT, severity TEXT, message TEXT,
 read INTEGER DEFAULT 0, dismissed INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS alert_time ON alerts(timestamp);
"""


class HistoryStore:
    def __init__(self, path, clock=time.time):
        self.path, self.clock = Path(path), clock
        self.lock = threading.RLock()
        self.error = None
        self.ready = False
        self._prepare()

    def _prepare(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.connection() as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.executescript(SCHEMA)
            self.ready = True
            self.error = None
        except (OSError, sqlite3.Error) as exc:
            self.error = f'Local history unavailable: {exc}. Retry after fixing access/locks or restore a private backup.'

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=0.2)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA secure_delete=ON')
            with db:
                yield db
        finally:
            db.close()

    def run(self, operation, default=None):
        with self.lock:
            if not self.ready:
                return default
            try:
                with self.connection() as db:
                    result = operation(db)
                self.error = None
                return result
            except (OSError, sqlite3.Error) as exc:
                self.error = f'Local history unavailable: {exc}. Monitoring continues; history may have gaps.'
                return default

    def settings(self):
        row = self.run(lambda db: db.execute('SELECT value FROM settings WHERE id=1').fetchone())
        try:
            return DEFAULTS | (json.loads(row['value']) if row else {})
        except (ValueError, TypeError):
            self.error = 'Invalid history settings; safe defaults are in use.'
            return dict(DEFAULTS)

    def claim_capture(self, owner):
        now = self.clock()
        return self.run(lambda db: db.execute('''INSERT INTO capture_lease VALUES(1,?,?)
            ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires
            WHERE capture_lease.expires<? OR capture_lease.owner=?''', (owner, now + 60, now, owner)).rowcount == 1)

    def release_capture(self, owner):
        return self.run(lambda db: db.execute('DELETE FROM capture_lease WHERE owner=?', (owner,)))

    def configure(self, settings):
        settings = {key: settings.get(key, value) for key, value in DEFAULTS.items()}
        settings['retention_days'] = max(1, min(30, int(settings['retention_days'])))
        settings['cooldown_seconds'] = max(5, min(3600, int(settings['cooldown_seconds'])))
        settings['window_seconds'] = max(10, min(3600, int(settings['window_seconds'])))
        settings['connection_count'] = max(2, min(10000, int(settings['connection_count'])))
        for key in ('bandwidth_mbps', 'usage_mb'):
            settings[key] = max(0.01, min(1_000_000, float(settings[key])))
        return self.run(lambda db: db.execute('INSERT OR REPLACE INTO settings VALUES(1,?)',
                                              (json.dumps(settings),)).rowcount == 1, False)

    def record_usage(self, adapter, sample):
        return self.run(lambda db: db.execute('''INSERT INTO usage VALUES(?,?,?,?,?)
            ON CONFLICT(minute,adapter) DO UPDATE SET download=download+excluded.download,
            upload=upload+excluded.upload,seconds=seconds+excluded.seconds''',
            (int(sample['timestamp'] // 60) * 60, adapter, sample['download'], sample['upload'], sample['seconds'])))

    def record_flow(self, event_id, row, names=False):
        def record(db):
            if not db.execute('INSERT OR IGNORE INTO events VALUES(?,?)', (event_id, self.clock())).rowcount:
                return False
            service = str(row['service'])[:80] if names else ''
            process = str(row['process'])[:120] if names else ''
            db.execute('''INSERT INTO flows VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(minute,service,process,protocol,status) DO UPDATE SET
                bytes=bytes+excluded.bytes,count=count+1,
                upload=CASE WHEN upload IS NULL AND excluded.upload IS NULL THEN NULL
                            ELSE coalesce(upload,0)+coalesce(excluded.upload,0) END,
                download=CASE WHEN download IS NULL AND excluded.download IS NULL THEN NULL
                              ELSE coalesce(download,0)+coalesce(excluded.download,0) END,
                last_seen=max(last_seen,excluded.last_seen)''',
                (int(row['timestamp'] // 60) * 60, service, process, row['protocol'], row['status'],
                 row['bytes'], 1, row['upload'], row['download'], row['timestamp']))
            return True
        return self.run(record, False)

    def query(self, table, start, end):
        if table not in {'flows', 'usage'}:
            raise ValueError('Unknown history table')
        return self.run(lambda db: [dict(row) for row in db.execute(
            f'SELECT * FROM {table} WHERE minute>=? AND minute<? ORDER BY minute',
            (int(start // 60) * 60, end))], [])

    def state(self, key, value=None):
        def update(db):
            if value is not None:
                db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT value FROM state WHERE id=?', (key,)).fetchone()
            if value is not None:
                db.execute('INSERT OR REPLACE INTO state VALUES(?,?,?)', (key, str(value), self.clock()))
            return previous['value'] if previous else None
        return self.run(update)

    def emit(self, kind, key, severity, message, cooldown, save=True):
        now = self.clock()
        def emit(db):
            db.execute('BEGIN IMMEDIATE')
            state = db.execute('SELECT timestamp FROM state WHERE id=?', ('cooldown:' + key,)).fetchone()
            if state and now - state['timestamp'] < cooldown:
                return None
            db.execute('INSERT OR REPLACE INTO state VALUES(?,?,?)', ('cooldown:' + key, '', now))
            row = {'id': uuid.uuid4().hex, 'timestamp': now, 'kind': kind, 'severity': severity,
                   'message': message, 'read': 0, 'dismissed': 0}
            if save:
                db.execute('INSERT INTO alerts VALUES(:id,:timestamp,:kind,:severity,:message,:read,:dismissed)', row)
            return row
        return self.run(emit)

    def alerts(self):
        return self.run(lambda db: [dict(row) for row in db.execute(
            'SELECT * FROM alerts WHERE dismissed=0 ORDER BY timestamp DESC LIMIT 100')], [])

    def update_alerts(self, action, alert_id=None):
        if action not in ('read', 'dismiss', 'clear'):
            raise ValueError('Unknown alert action')
        def update(db):
            if action == 'clear':
                db.execute('DELETE FROM alerts')
            elif action == 'read':
                db.execute('UPDATE alerts SET read=1' + (' WHERE id=?' if alert_id else ''),
                           (alert_id,) if alert_id else ())
            else:
                db.execute('UPDATE alerts SET dismissed=1 WHERE id=?', (alert_id,))
            return True
        return self.run(update, False)

    def prune(self, days=7):
        cutoff = self.clock() - max(1, min(30, days)) * 86400
        def prune(db):
            for table, column, cap in [('usage', 'minute', 45000), ('flows', 'minute', 50000),
                                       ('events', 'timestamp', 50000), ('state', 'timestamp', 10000),
                                       ('alerts', 'timestamp', 1000)]:
                db.execute(f'DELETE FROM {table} WHERE {column}<?', (cutoff,))
                db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} '
                           f'ORDER BY {column} DESC LIMIT -1 OFFSET ?)', (cap,))
            return True
        return self.run(prune, False)

    def clear(self):
        def clear(db):
            for table in ('usage', 'flows', 'events', 'state', 'alerts'):
                db.execute(f'DELETE FROM {table}')
            return True
        if not self.run(clear, False):
            return False
        try:
            with self.lock, self.connection() as db:
                db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                db.execute('VACUUM')
            return True
        except sqlite3.Error as exc:
            self.error = f'History rows cleared; compaction failed: {exc}.'
            return False
