"""Sentinel event persistence fixes D1-D4: real temporary SQLite, no network.

Contention is produced by a real SQLite writer or exclusive lock held by another
connection. The synthetic error codes (LOCKED, extended codes) are used only to
test the classification of the native code, through an explicit proxy.
"""
import datetime
import sqlite3
import uuid
from contextlib import contextmanager
from unittest.mock import Mock

import pytest

import core.database as db
import sentinel.sentinel_manager as manager
from sentinel.alerting import AlertCounter
from sentinel.baseline import BaselineEntry
from sentinel.monitor import NetworkChange
from sentinel.whitelist import Whitelist

NET = 'persistence-fix-net'
RUN = 'persistence-fix-run'
TARGET = '192.0.2.0/24'
OLD = '2020-01-01T00:00:00+00:00'
CANARY = 'PRIVATE_SQLITE_CANARY'
CHANGE = NetworkChange('new_host', '192.0.2.99', 'new host detected', 'synthetic')


@pytest.fixture
def storage(tmp_path, monkeypatch):
    """Every netlab path (sessions and Sentinel) lives under tmp_path."""
    monkeypatch.setattr(db, '_real_user_home', lambda: tmp_path)
    monkeypatch.setattr(manager, 'get_baseline', lambda *args: {
        '192.0.2.10': BaselineEntry(asset_id='known', ip='192.0.2.10', mac='', ports=[22],
                                    last_scan='2026-01-01T00:00:00+00:00'),
    })
    db.init_sentinel_db(NET)
    db.sentinel_update_state(NET, 'active', last_check_time=OLD, target_network=TARGET,
                             gateway_ip='192.0.2.1', gateway_mac='')
    db.init_db(RUN)
    db.save_session(RUN, target=TARGET)
    assert db.get_db_path(RUN).is_relative_to(tmp_path)
    assert db.get_sentinel_db_path(NET).is_relative_to(tmp_path)
    return tmp_path


@contextmanager
def held_lock(path, exclusive=False):
    """A real competing connection holding a write lock until the block ends."""
    holder = sqlite3.connect(str(path), timeout=0)
    try:
        if exclusive:
            # Readers are blocked too; a plain writer lock does not block WAL readers.
            holder.execute('PRAGMA locking_mode=EXCLUSIVE')
            holder.execute('BEGIN EXCLUSIVE')
        else:
            holder.execute('BEGIN IMMEDIATE')
        yield holder
    finally:
        holder.rollback()
        holder.close()


def record_connect_timeouts(monkeypatch):
    """Record the effective busy_timeout (ms) of each connection opened from now on."""
    seen = []
    real_connect = sqlite3.connect

    def spy(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        seen.append(conn.execute('PRAGMA busy_timeout').fetchone()[0])
        return conn

    monkeypatch.setattr(sqlite3, 'connect', spy)
    return seen


def run_check(changes, whitelist=None):
    return manager._do_check(
        target_network=TARGET, network_id=NET, run_session_id=RUN,
        identity=object(), interval=60,
        whitelist=whitelist if whitelist is not None else Whitelist(),
        counter=AlertCounter(),
    )


def make_error(code, message=CANARY):
    error = sqlite3.OperationalError(message)
    if code is not None:
        error.sqlite_errorcode = code
    return error


# ---------------------------------------------------------------------------
# D1 — last_check_time only after the cycle's changes are persisted
# ---------------------------------------------------------------------------

def test_failed_event_write_does_not_advance_last_check(storage, monkeypatch):
    monkeypatch.setattr(manager, 'check_network', lambda **kwargs: [CHANGE])
    real_process_changes = manager.process_changes

    def process_under_real_lock(**kwargs):
        # Real contention on the event write only, after the old code's state write point.
        with held_lock(db.get_sentinel_db_path(NET)):
            return real_process_changes(**kwargs)

    monkeypatch.setattr(manager, 'process_changes', process_under_real_lock)

    with pytest.raises(db.SentinelStorageError) as failed:
        run_check([CHANGE])

    assert failed.value.contention is True
    assert isinstance(failed.value.__cause__, sqlite3.OperationalError)
    assert failed.value.__cause__.sqlite_errorcode & 0xff == sqlite3.SQLITE_BUSY
    state = db.sentinel_get_state(NET)
    assert state['last_check_time'] == OLD
    assert db.sentinel_get_events(NET) == []
    assert db.get_findings(RUN) == []


def test_successful_cycle_advances_last_check(storage, monkeypatch):
    monkeypatch.setattr(manager, 'check_network', lambda **kwargs: [CHANGE])

    run_check([CHANGE])

    state = db.sentinel_get_state(NET)
    assert state['sentinel_status'] == 'active'
    assert state['last_check_time'] != OLD
    assert (datetime.datetime.fromisoformat(state['last_check_time'])
            > datetime.datetime.fromisoformat(OLD))
    assert len(db.sentinel_get_events(NET)) == 1
    assert len(db.get_findings(RUN)) == 1


def test_successful_empty_cycle_advances_last_check(storage, monkeypatch):
    monkeypatch.setattr(manager, 'check_network', lambda **kwargs: [])

    run_check([])

    state = db.sentinel_get_state(NET)
    assert state['last_check_time'] != OLD
    assert db.sentinel_get_events(NET) == []


# ---------------------------------------------------------------------------
# D2 — an unreadable alert count is unavailable, never zero
# ---------------------------------------------------------------------------

def test_status_zero_events_reports_zero(storage):
    assert manager.status(NET)['unresolved_alerts'] == 0


def test_status_reports_real_unresolved_count(storage):
    for index, resolved in enumerate((False, False, True)):
        db.sentinel_save_event(NET, f'event-{index}', 'new_host', OLD, None,
                               {'ip': '192.0.2.99'}, resolved)
    assert manager.status(NET)['unresolved_alerts'] == 2


def test_status_count_failure_is_unavailable_and_keeps_other_fields(storage, monkeypatch):
    def failing_count(network_id):
        raise sqlite3.OperationalError(CANARY)

    monkeypatch.setattr(manager, 'sentinel_count_unresolved_events', failing_count)

    result = manager.status(NET)

    assert result['unresolved_alerts'] is None
    assert result['sentinel_state'] == 'active'
    assert result['last_check_time'] == OLD
    assert result['target_network'] == TARGET
    assert result['known_hosts'] == 0


def _display_text(monkeypatch, count_error):
    shown = Mock()
    monkeypatch.setattr(manager, 'display', shown)
    if count_error:
        def failing_count(network_id):
            raise sqlite3.OperationalError(CANARY)
        monkeypatch.setattr(manager, 'sentinel_count_unresolved_events', failing_count)
    manager.display_status(NET)
    return ' '.join(str(call) for call in shown.call_args_list)


def test_display_status_shows_unavailable_not_zero(storage, monkeypatch):
    text = _display_text(monkeypatch, count_error=True)
    assert 'alertes: indisponible' in text
    assert 'alertes: 0' not in text
    assert CANARY not in text


def test_display_status_shows_real_zero(storage, monkeypatch):
    text = _display_text(monkeypatch, count_error=False)
    assert 'alertes: 0' in text


# ---------------------------------------------------------------------------
# D3 — 1.0 s busy timeout, classified BUSY/LOCKED, native cause kept
# ---------------------------------------------------------------------------

def _call(operation):
    if operation == 'save_event':
        return db.sentinel_save_event(NET, str(uuid.uuid4()), 'new_host',
                                      OLD, None, {'ip': '192.0.2.99'}, False)
    if operation == 'update_state':
        return db.sentinel_update_state(NET, 'active', last_check_time=OLD)
    return db.sentinel_count_unresolved_events(NET)


OPERATIONS = ['save_event', 'update_state', 'count']


@pytest.mark.parametrize('operation', OPERATIONS)
def test_real_busy_contention_is_classified_with_native_cause(storage, monkeypatch, operation):
    path = db.get_sentinel_db_path(NET)
    # Exclusive mode also blocks the count read; a write lock alone would not.
    with held_lock(path, exclusive=(operation == 'count')):
        timeouts = record_connect_timeouts(monkeypatch)
        with pytest.raises(db.SentinelStorageError) as failed:
            _call(operation)

    assert failed.value.contention is True
    assert 'SQLITE_BUSY' in str(failed.value)
    assert isinstance(failed.value.__cause__, sqlite3.OperationalError)
    assert failed.value.__cause__.sqlite_errorcode & 0xff == sqlite3.SQLITE_BUSY
    assert timeouts == [1000]
    assert 'database is locked' not in str(failed.value)


@pytest.mark.parametrize('operation', OPERATIONS)
def test_busy_failure_persists_nothing(storage, monkeypatch, operation):
    with held_lock(db.get_sentinel_db_path(NET), exclusive=(operation == 'count')):
        with pytest.raises(db.SentinelStorageError):
            _call(operation)
    assert db.sentinel_get_events(NET) == []
    assert db.sentinel_get_state(NET)['last_check_time'] == OLD


@pytest.mark.parametrize('code,is_contention,label', [
    (sqlite3.SQLITE_BUSY, True, 'SQLITE_BUSY'),
    (sqlite3.SQLITE_LOCKED, True, 'SQLITE_LOCKED'),
    (sqlite3.SQLITE_LOCKED | (1 << 8), True, 'SQLITE_LOCKED'),      # LOCKED_SHAREDCACHE
    (sqlite3.SQLITE_BUSY | (2 << 8), True, 'SQLITE_BUSY'),          # BUSY_TIMEOUT
    (sqlite3.SQLITE_BUSY | (1 << 8), True, 'SQLITE_BUSY'),          # BUSY_RECOVERY
    (sqlite3.SQLITE_READONLY, False, None),
    (sqlite3.SQLITE_IOERR, False, None),
    (sqlite3.SQLITE_CORRUPT, False, None),
    (None, False, None),
])
def test_classification_uses_primary_native_code(code, is_contention, label):
    error = make_error(code)
    assert (db._sqlite_contention_name(error) is not None) is is_contention
    wrapped = db._sentinel_storage_error(error, 'sujet')
    assert wrapped.contention is is_contention
    assert (label in str(wrapped)) if label else ('contention/verrouillage' not in str(wrapped))
    assert CANARY not in str(wrapped)


@pytest.mark.parametrize('operation', OPERATIONS)
@pytest.mark.parametrize('code', [sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_LOCKED | (1 << 8)])
def test_locked_errors_on_each_operation_keep_original_cause(storage, monkeypatch, operation, code):
    """LOCKED cannot be produced reliably with a single file; inject the native code."""
    original = make_error(code)
    real_open = db._open_sentinel_event_connection

    class FailingExecute:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *args):
            if sql.lstrip().upper().startswith('PRAGMA'):
                return self._conn.execute(sql, *args)
            raise original

        def __getattr__(self, name):
            return getattr(self._conn, name)

    monkeypatch.setattr(db, '_open_sentinel_event_connection',
                        lambda network_id, subject: FailingExecute(real_open(network_id, subject)))
    with pytest.raises(db.SentinelStorageError) as failed:
        _call(operation)
    assert failed.value.contention is True
    assert 'SQLITE_LOCKED' in str(failed.value)
    assert failed.value.__cause__ is original
    assert CANARY not in str(failed.value)


@pytest.mark.parametrize('operation,table', [
    ('save_event', 'events'),
    ('count', 'events'),
    ('update_state', 'sentinel_state'),
])
def test_non_contention_error_is_not_classified_as_contention(storage, monkeypatch, operation, table):
    conn = sqlite3.connect(str(db.get_sentinel_db_path(NET)))
    try:
        conn.execute(f'DROP TABLE {table}')
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(db.SentinelStorageError) as failed:
        _call(operation)

    assert failed.value.contention is False
    assert 'hors contention' in str(failed.value)
    assert 'code SQLite 1' in str(failed.value)
    assert isinstance(failed.value.__cause__, sqlite3.OperationalError)
    assert failed.value.__cause__.sqlite_errorcode & 0xff == sqlite3.SQLITE_ERROR
    assert 'no such table' not in str(failed.value)


# ---------------------------------------------------------------------------
# D4 — unconfirmed session closure: 1.0 s timeout, classified, never fabricated
# ---------------------------------------------------------------------------

def _session_status(session_id):
    conn = sqlite3.connect(str(db.get_db_path(session_id)))
    try:
        return conn.execute('SELECT status FROM sessions WHERE id=?', (session_id,)).fetchone()[0]
    finally:
        conn.close()


def test_unconfirmed_session_closure_succeeds_without_contention(storage):
    assert db.sentinel_fail_unconfirmed_session(RUN) is True
    assert _session_status(RUN) == 'failed'


def test_unconfirmed_closure_real_contention_is_classified_and_not_fabricated(storage, monkeypatch):
    path = db.get_db_path(RUN)
    with held_lock(path):
        timeouts = record_connect_timeouts(monkeypatch)
        with pytest.raises(db.SentinelControlError, match=r'contention/verrouillage \(SQLITE_BUSY\)') as failed:
            db.sentinel_fail_unconfirmed_session(RUN)
    assert timeouts == [1000]
    assert isinstance(failed.value.__cause__, sqlite3.OperationalError)
    assert failed.value.__cause__.sqlite_errorcode & 0xff == sqlite3.SQLITE_BUSY
    assert _session_status(RUN) == 'running'


def test_unconfirmed_closure_non_contention_error_keeps_cause_and_closes_nothing(storage):
    path = db.get_db_path(RUN)
    path.write_bytes(b'not a sqlite database' + b'\0' * 4096)
    with pytest.raises(db.SentinelControlError, match='erreur hors contention') as failed:
        db.sentinel_fail_unconfirmed_session(RUN)
    assert isinstance(failed.value.__cause__, sqlite3.Error)
    assert failed.value.__cause__.sqlite_errorcode & 0xff == sqlite3.SQLITE_NOTADB
    assert 'not a sqlite' not in str(failed.value)
