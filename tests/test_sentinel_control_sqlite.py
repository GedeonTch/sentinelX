"""Real temporary SQLite contention, explicit barriers, no network or stop ack."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import threading

import pytest

from core import database as db

NET, INSTANCE = 'control-timeout-test', 'owner-instance'
UPDATE = "UPDATE sentinel_control SET stop_requested=1 WHERE instance=?"


@pytest.fixture
def control(tmp_path, monkeypatch):
    monkeypatch.setattr(db, '_real_user_home', lambda: tmp_path)
    db.init_sentinel_db(NET)
    db.sentinel_control_register(NET, INSTANCE, 'run', 123, 'simulated-birth')
    return db.get_sentinel_db_path(NET)


@contextmanager
def traced_control(monkeypatch):
    """Observe the actual UPDATE and keep the production timeout unmodified."""
    entered = threading.Event()
    timeouts = []
    original = db._sentinel_control_connection

    @contextmanager
    def observed(network):
        with original(network) as conn:
            timeouts.append(conn.execute('PRAGMA busy_timeout').fetchone()[0])
            conn.set_trace_callback(lambda sql: entered.set() if sql.startswith('UPDATE sentinel_control SET stop_requested') else None)
            yield conn

    with monkeypatch.context() as patch:
        patch.setattr(db, '_sentinel_control_connection', observed)
        yield entered, timeouts


def test_control_resumes_after_real_contention_before_deadline(control, monkeypatch):
    """Hold an actual writer lock through a bounded competing SQL probe.

    Release is driven by real SQLITE_BUSY from that probe, not a random sleep or
    a barrier that substitutes for SQL. The 300ms probe exceeds the old 200ms
    budget and leaves margin within the new 1000ms production busy timeout.
    """
    holder = db.sqlite3.connect(str(control), timeout=0)
    probe = db.sqlite3.connect(str(control), timeout=0.3)
    holder.execute('BEGIN IMMEDIATE')
    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with traced_control(monkeypatch) as (entered, timeouts):
                pending = pool.submit(db.sentinel_control_request_stop, NET, INSTANCE)
                assert entered.wait(5), 'Control UPDATE not reached'
                with pytest.raises(db.sqlite3.OperationalError) as blocked:
                    probe.execute(UPDATE, (INSTANCE,))
                assert blocked.value.sqlite_errorcode & 0xff == db.sqlite3.SQLITE_BUSY
                assert holder.in_transaction
                assert timeouts == [1000]
                assert not pending.done(), 'Control failed before bounded lock release'
                holder.rollback()  # release only after proven contention
                assert pending.result(timeout=5) is None
        finally:
            holder.rollback()
            holder.close()
            probe.close()
    row = db.sentinel_control_get(NET, INSTANCE)
    assert row['stop_requested'] == 1
    assert row['result'] == 'running'  # request persisted, NOT a confirmed stop
    assert row['cycle_active'] == 0


def test_control_persistent_lock_fails_without_confirming_stop(control, monkeypatch):
    holder = db.sqlite3.connect(str(control), timeout=0)
    holder.execute('BEGIN IMMEDIATE')
    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with traced_control(monkeypatch) as (entered, timeouts):
                pending = pool.submit(db.sentinel_control_request_stop, NET, INSTANCE)
                assert entered.wait(5)
                with pytest.raises(db.SentinelControlError, match='contention/verrouillage.*arrêt non confirmé') as failed:
                    pending.result(timeout=5)  # writer remains locked until failure
                assert timeouts == [1000]
                assert holder.in_transaction
                cause = failed.value.__cause__
                assert isinstance(cause, db.sqlite3.OperationalError)
                assert cause.sqlite_errorcode & 0xff == db.sqlite3.SQLITE_BUSY
        finally:
            holder.rollback()
            holder.close()
    row = db.sentinel_control_get(NET, INSTANCE)
    assert row['stop_requested'] == 0
    assert row['result'] == 'running'


@pytest.mark.parametrize('failure', ['schema', 'corrupt', 'missing'])
def test_non_contention_sqlite_errors_keep_original_cause(control, failure):
    if failure == 'corrupt':
        control.write_bytes(b'not a sqlite database')
    elif failure == 'missing':
        control = control.with_name('missing.db')
    error = None
    with pytest.raises(db.SentinelControlError, match='erreur hors contention.*arrêt non confirmé') as failed:
        network = 'missing' if failure == 'missing' else NET
        with db._sentinel_control_connection(network) as conn:
            try:
                conn.execute('SELECT * FROM missing_table')
            except db.sqlite3.Error as exc:
                error = exc
                raise
    assert isinstance(failed.value.__cause__, db.sqlite3.Error)
    if error is not None:
        assert failed.value.__cause__ is error
    expected = {'schema': db.sqlite3.SQLITE_ERROR, 'corrupt': db.sqlite3.SQLITE_NOTADB,
                'missing': db.sqlite3.SQLITE_CANTOPEN}[failure]
    assert failed.value.__cause__.sqlite_errorcode & 0xff == expected
    if failure == 'missing':
        assert not control.exists()


@pytest.mark.parametrize('code,is_contention', [
    (db.sqlite3.SQLITE_BUSY, True), (db.sqlite3.SQLITE_LOCKED, True),
    (db.sqlite3.SQLITE_BUSY | (2 << 8), True),
    (db.sqlite3.SQLITE_LOCKED | (1 << 8), True),
    (db.sqlite3.SQLITE_READONLY, False), (db.sqlite3.SQLITE_PERM, False),
    (db.sqlite3.SQLITE_IOERR, False), (db.sqlite3.SQLITE_CORRUPT, False),
    (None, False),
])
def test_diagnostic_uses_codes_not_messages(control, code, is_contention):
    original = db.sqlite3.OperationalError('database is locked PRIVATE_DIAGNOSTIC_CANARY')
    if code is not None:
        original.sqlite_errorcode = code
    with pytest.raises(db.SentinelControlError) as failed:
        with db._sentinel_control_connection(NET):
            raise original
    assert failed.value.__cause__ is original
    assert ('contention/verrouillage' in str(failed.value)) is is_contention
    assert 'PRIVATE_DIAGNOSTIC_CANARY' not in str(failed.value)
    assert 'arrêt non confirmé' in str(failed.value)
