"""Real A/B CLI processes, isolated SQLite and deterministic scan barriers."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from core import database as db
from sentinel import lifecycle as lc
from sentinel.baseline import NetworkIdentity, compute_network_id

TARGET = '192.0.2.0/24'
IDENTITY = NetworkIdentity(TARGET, '192.0.2.1', '02:00:00:00:00:01')
NETWORK = compute_network_id(IDENTITY)
CHILD = Path(__file__).with_name('sentinel_cli_child.py')


def eventually(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.02)
    raise AssertionError('Timed out waiting for test barrier')


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setattr(db, '_real_user_home', lambda: tmp_path)
    processes = []
    logs = []

    def spawn(args, run='run-a', mode='normal'):
        env = os.environ.copy()
        env.update(SENTINEL_TEST_HOME=str(tmp_path), SENTINEL_TEST_RUN=run,
                   SENTINEL_TEST_MODE=mode, PYTHONDONTWRITEBYTECODE='1')
        path = tmp_path / f'child-{len(processes)}.log'
        log = path.open('w')
        process = subprocess.Popen([sys.executable, str(CHILD), 'sentinel', *args],
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        logs.append(log)
        process.output_path = path
        return process

    def marker(run, suffix):
        return tmp_path / 'markers' / f'{run}.{suffix}'

    yield spawn, marker
    # Failure recovery only: nominal tests assert A/B exit before this teardown.
    for process in processes:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    for log in logs:
        log.close()


def start(lab, run='run-a', mode='normal', target=TARGET):
    spawn, marker = lab
    a = spawn(['start', '--target', target, '--session', run], run, mode)
    eventually(lambda: marker(run, 'entered').exists() or a.poll() is not None)
    assert a.poll() is None, a.output_path.read_text()
    return a


def stop(lab, network=NETWORK, timeout='5', session=None):
    spawn, _ = lab
    selector = ['--session', session] if session else ['--network', network]
    return spawn(['stop', *selector, '--timeout', timeout])


def assert_exit(process, code=0):
    assert process.wait(timeout=12) == code, process.output_path.read_text()
    return process.output_path.read_text()


def requested(network=NETWORK):
    return bool(lc.records(network)[0]['stop_requested'])


def test_two_real_cli_processes_stop_inflight_and_restart(lab):
    _, marker = lab
    a = start(lab)
    b = stop(lab)
    eventually(requested)
    assert b.poll() is None  # request alone cannot report success
    assert a.poll() is None
    assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'active'
    marker('run-a', 'release').touch()
    assert 'terminaison confirmées' in assert_exit(b)
    assert_exit(a)
    assert marker('run-a', 'cycles').read_text() == '1'
    row = lc.records(NETWORK)[0]
    assert row['result'] == 'completed'
    assert lc.lock_is_free(NETWORK)
    assert db.get_session('run-a')['status'] == 'completed'
    assert db.get_session('run-a')['end_time']
    assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'inactive'
    assert len(db.sentinel_get_events(NETWORK)) == 1
    assert len(db.get_findings('run-a')) == 1
    assert db.get_events('run-a') == []
    assert len(db.sentinel_get_baseline_entries(NETWORK, TARGET, IDENTITY.gateway_ip, IDENTITY.gateway_mac)) == 1
    lock_inode = lc._lock_path(NETWORK).stat().st_ino
    a2 = start(lab, 'run-new')
    assert not requested()  # old stop request is never inherited
    assert lc.records(NETWORK)[1]['stop_requested'] == 1
    b2 = stop(lab, session='run-new')
    eventually(requested)
    marker('run-new', 'release').touch()
    assert_exit(b2)
    assert_exit(a2)
    assert lc._lock_path(NETWORK).stat().st_ino == lock_inode
    assert len(db.sentinel_get_events(NETWORK)) == 2
    assert len(db.get_findings('run-new')) == 1


def test_stop_during_wait_not_full_interval(lab):
    _, marker = lab
    a = start(lab)
    marker('run-a', 'release').touch()
    eventually(lambda: marker('run-a', 'waiting').exists())
    b = stop(lab, session=NETWORK)  # legacy network alias with control evidence
    assert_exit(b)
    assert_exit(a)
    assert marker('run-a', 'cycles').read_text() == '1'


@pytest.mark.parametrize('mode,expected_code,result', [
    ('degraded', 0, 'completed'), ('fatal', 1, 'failed'),
    ('finalization-failure', 1, 'finalization_failed'), ('whitelisted', 0, 'completed')])
def test_control_outcomes(lab, mode, expected_code, result):
    _, marker = lab
    a = start(lab, mode=mode)
    b = stop(lab)
    eventually(requested)
    marker('run-a', 'release').touch()
    output = assert_exit(b, expected_code)
    a_output = assert_exit(a, 1 if mode in ('fatal', 'finalization-failure') else 0)
    assert 'Traceback' not in a_output and 'Traceback' not in output
    assert 'FATAL_SECRET_CANARY' not in a_output + output
    if mode == 'fatal':
        assert 'RuntimeError' in a_output
        assert lc.records(NETWORK)[0]['error'] == 'RuntimeError: surveillance failed'
        assert db.get_session('run-a')['status'] == 'failed'
        assert db.get_session('run-a')['end_time']
        assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'inactive'
    assert lc.records(NETWORK)[0]['result'] == result
    assert lc.lock_is_free(NETWORK)
    assert marker('run-a', 'cycles').read_text() == '1'
    if expected_code:
        assert 'terminaison confirmées' not in output
    if mode == 'whitelisted':
        assert len(db.sentinel_get_events(NETWORK, resolved=True)) == 1
        assert db.get_findings('run-a') == []
    if mode == 'degraded':
        assert len(db.sentinel_get_events(NETWORK)) == 1
        assert len(db.get_findings('run-a')) == 1
    if mode == 'finalization-failure':
        assert 'session finalization failed' in lc.records(NETWORK)[0]['error']


@pytest.mark.skipif(sys.platform != 'linux', reason='POSIX SIGINT; Windows control event needs native validation')
@pytest.mark.parametrize('during_wait', [False, True])
def test_ctrl_c_common_finalization(lab, during_wait):
    _, marker = lab
    a = start(lab)
    if during_wait:
        marker('run-a', 'release').touch()
        eventually(lambda: marker('run-a', 'waiting').exists())
    a.send_signal(signal.SIGINT)
    assert_exit(a)
    assert db.get_session('run-a')['status'] == 'partial'
    assert db.get_session('run-a')['end_time']
    assert lc.records(NETWORK)[0]['result'] == 'completed'
    assert lc.lock_is_free(NETWORK)
    assert_exit(stop(lab))  # already cleanly terminated, distinguished from crash


def test_concurrent_start_cannot_mutate_owner(lab):
    spawn, marker = lab
    a = start(lab)
    before = lc.records(NETWORK)
    state = db.sentinel_get_state(NETWORK)
    other = spawn(['start', '--target', TARGET, '--session', 'run-duplicate'], 'run-duplicate')
    output = assert_exit(other, 1)
    assert 'possède déjà ce réseau' in output
    assert 'Traceback' not in output
    assert lc.records(NETWORK) == before
    assert db.sentinel_get_state(NETWORK) == state
    assert not db.get_db_path('run-duplicate').exists()
    b = stop(lab)
    eventually(requested)
    marker('run-a', 'release').touch()
    assert_exit(b)
    assert_exit(a)


def test_two_networks_independent(lab):
    _, marker = lab
    target2 = '198.51.100.0/24'
    network2 = compute_network_id(NetworkIdentity(target2, IDENTITY.gateway_ip, IDENTITY.gateway_mac))
    a = start(lab)
    a2 = start(lab, 'run-other', target=target2)
    b = stop(lab)
    eventually(requested)
    marker('run-a', 'release').touch()
    assert_exit(b)
    assert_exit(a)
    assert a2.poll() is None
    assert not requested(network2)
    b2 = stop(lab, network2)
    eventually(lambda: requested(network2))
    marker('run-other', 'release').touch()
    assert_exit(b2)
    assert_exit(a2)


def test_timeout_is_failure_request_remains(lab):
    _, marker = lab
    a = start(lab)
    b = stop(lab, timeout='.2')
    output = assert_exit(b, 1)
    assert 'arrêt non confirmé' in output
    assert 'terminaison confirmées' not in output
    assert a.poll() is None and requested()
    marker('run-a', 'release').touch()
    assert_exit(a)
    assert_exit(stop(lab))


def test_unknown_does_not_create_database(lab):
    assert_exit(stop(lab, 'unknown'), 1)
    assert not db.get_sentinel_db_path('unknown').exists()
    assert_exit(stop(lab, session='unknown-session'), 1)
    assert not db.get_sentinel_db_path('unknown-session').exists()


def test_crash_is_not_clean_stop_and_restart_recovers_control(lab):
    _, marker = lab
    a = start(lab)
    # Explicit crash test ONLY, never used in nominal acceptance.
    a.kill()
    a.wait(timeout=5)
    output = assert_exit(stop(lab), 1)
    assert 'état périmé' in output
    assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'active'
    a2 = start(lab, 'after-crash')
    assert lc.records(NETWORK)[1]['result'] == 'stale'
    b = stop(lab)
    eventually(requested)
    marker('after-crash', 'release').touch()
    assert_exit(b)
    assert_exit(a2)


def test_reused_pid_is_not_owner():
    with lc.ProcessIdentity(os.getpid(), 'not-this-birth') as process:
        assert process.exited()
    with lc.ProcessIdentity(os.getpid()) as process:
        assert process.birth and not process.exited()


def test_legacy_ambiguity_rejected(lab):
    for network, run in [('first', 'ambiguous'), ('ambiguous', 'second')]:
        db.init_sentinel_db(network)
        with lc.network_lock(network):
            lc.Owner(network, run)
    with pytest.raises(lc.LifecycleError, match='Ambiguous'):
        lc.resolve_owner(session_id='ambiguous')


def test_stable_private_lock(lab):
    path = lc._lock_path(NETWORK)
    with lc.network_lock(NETWORK):
        assert not lc.lock_is_free(NETWORK)
    inode = path.stat().st_ino
    assert lc.lock_is_free(NETWORK)
    assert path.stat().st_ino == inode
    if os.name != 'nt':
        assert path.parent.stat().st_mode & 0o777 == 0o700
        assert path.stat().st_mode & 0o777 == 0o600


def test_ack_and_free_lock_without_os_exit_are_not_success(lab):
    _, marker = lab
    a = start(lab, mode='delayed-exit')
    b = stop(lab)
    eventually(requested)
    marker('run-a', 'release').touch()
    eventually(lambda: marker('run-a', 'finalized').exists())
    assert lc.records(NETWORK)[0]['result'] == 'completed'
    assert lc.lock_is_free(NETWORK)
    assert a.poll() is None
    assert b.poll() is None
    marker('run-a', 'exit').touch()
    assert_exit(b)
    assert_exit(a)


def test_old_request_targets_old_execution_only(lab):
    _, marker = lab
    a = start(lab)
    b = stop(lab)
    eventually(requested)
    marker('run-a', 'release').touch()
    assert_exit(b)
    assert_exit(a)
    a2 = start(lab, 'new-owner')
    old_stop = stop(lab, session='run-a', timeout='.1')
    assert_exit(old_stop, 1)  # conservative: network is owned by the new run
    assert not requested()
    assert a2.poll() is None
    b2 = stop(lab)
    eventually(requested)
    marker('new-owner', 'release').touch()
    assert_exit(b2)
    assert_exit(a2)


@pytest.mark.parametrize('failure', ['session', 'network', 'control'])
def test_finalization_failure_is_not_hidden(lab, monkeypatch, failure):
    from sentinel import sentinel_manager as manager
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    monkeypatch.setattr(manager, '_start_owned', lambda *args: 'completed')
    def failed(*args, **kwargs):
        raise OSError('simulated storage failure')
    if failure == 'session':
        monkeypatch.setattr(manager, 'close_session', failed)
    elif failure == 'network':
        monkeypatch.setattr(manager, 'sentinel_update_state', failed)
    else:
        monkeypatch.setattr(lc.Owner, 'finish', failed)
    with pytest.raises(lc.LifecycleError, match='non finalisé'):
        manager.start(TARGET, 'finalize-test')
    row = lc.records(NETWORK)[0]
    assert row['result'] == ('running' if failure == 'control' else 'finalization_failed')
    assert lc.lock_is_free(NETWORK)
    if failure != 'session':
        assert db.get_session('finalize-test')['end_time']


def test_run_identifier_cannot_overwrite_existing_session(lab, monkeypatch):
    from sentinel import sentinel_manager as manager
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    db.init_db('existing')
    db.save_session('existing', target='untouched')
    with pytest.raises(lc.LifecycleError, match='already exists'):
        manager.start(TARGET, 'existing')
    assert db.get_session('existing')['target'] == 'untouched'
    assert not db.get_sentinel_db_path(NETWORK).exists()


def test_windows_process_handle_contract_simulated(monkeypatch):
    # API contract simulation, NOT native Windows operational validation.
    from types import SimpleNamespace
    from unittest.mock import Mock
    class WinError(Exception):
        winerror = 5
    handle = Mock()
    api = SimpleNamespace(OpenProcess=Mock(return_value=handle))
    events = SimpleNamespace(WAIT_OBJECT_0=0, WAIT_TIMEOUT=258,
                             WaitForSingleObject=Mock(return_value=258))
    monkeypatch.setitem(sys.modules, 'win32api', api)
    monkeypatch.setitem(sys.modules, 'win32event', events)
    monkeypatch.setitem(sys.modules, 'pywintypes', SimpleNamespace(error=WinError))
    monkeypatch.setattr(lc, '_windows_birth', lambda h: 'creation-100ns')
    with monkeypatch.context() as scoped:
        scoped.setattr(sys, 'platform', 'win32')
        with lc.ProcessIdentity(42, 'creation-100ns') as process:
            assert not process.exited()
            events.WaitForSingleObject.return_value = 0
            assert process.exited()
        handle.Close.assert_called_once()
        with lc.ProcessIdentity(42, 'old-birth') as process:
            assert process.exited()
        api.OpenProcess.side_effect = WinError()
        with pytest.raises(lc.LifecycleError, match="WinError.*non confirmé"):  # access denied is not death
            lc.ProcessIdentity(42)


def test_linux_identity_parser_parenthesized_comm(monkeypatch):
    fields = ['S'] + ['0'] * 18 + ['12345']
    def read(path):
        return 'boot' if str(path).endswith('boot_id') else '1 (odd ) name) ' + ' '.join(fields)
    monkeypatch.setattr(Path, 'read_text', read)
    assert lc._linux_identity(1) == 'boot:12345'


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux kernel API')
def test_missing_proc_identity_is_not_evidence_of_exit(monkeypatch):
    monkeypatch.setattr(lc, '_linux_identity', lambda pid: None)
    with pytest.raises(lc.LifecycleError, match='unconfirmed'):
        lc.ProcessIdentity(os.getpid())


def test_control_storage_error_is_explicit(lab):
    db.get_sentinel_db_path(NETWORK).write_text('not a sqlite database')
    with pytest.raises(lc.LifecycleError, match='non confirmé'):
        lc.resolve_owner(network_id=NETWORK)


def test_windows_private_acl_contract_simulated(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from unittest.mock import Mock
    token, acl = Mock(), Mock()
    security = SimpleNamespace(
        OpenProcessToken=Mock(return_value=token), TokenUser=1,
        GetTokenInformation=Mock(return_value=('user-sid', 0)),
        ACL=Mock(return_value=acl), ACL_REVISION=2, SE_FILE_OBJECT=1,
        DACL_SECURITY_INFORMATION=4, PROTECTED_DACL_SECURITY_INFORMATION=0x80000000,
        SetNamedSecurityInfo=Mock())
    monkeypatch.setitem(sys.modules, 'win32api', SimpleNamespace(GetCurrentProcess=lambda: 123))
    monkeypatch.setitem(sys.modules, 'win32security', security)
    lc._private_windows_path(tmp_path, directory=True)
    acl.AddAccessAllowedAceEx.assert_called_once_with(2, 3, 0x1F01FF, 'user-sid')
    token.Close.assert_called_once()
    security.SetNamedSecurityInfo.assert_called_once_with(
        str(tmp_path), 1, 0x80000004, None, None, acl, None)


@pytest.mark.parametrize('first', ['stop', 'admission'])
def test_atomic_stop_cycle_race_with_two_real_cli_barriers(lab, first):
    spawn, marker = lab
    a = spawn(['start', '--target', TARGET, '--session', 'race-run'],
              'race-run', 'race-' + first + '-first')
    eventually(lambda: marker('race-run', 'admission-ready').exists() or a.poll() is not None)
    assert a.poll() is None, a.output_path.read_text()
    row = lc.records(NETWORK)[0]
    assert row['cycle_number'] == (1 if first == 'admission' else 0)
    assert bool(row['cycle_active']) == (first == 'admission')
    assert not marker('race-run', 'entered').exists()
    b = stop(lab)
    eventually(requested)  # stop transaction COMMITTED before releasing A
    assert b.poll() is None
    marker('race-run', 'admission-release').touch()
    if first == 'admission':
        eventually(lambda: marker('race-run', 'entered').exists())
        assert a.poll() is None and b.poll() is None
        marker('race-run', 'release').touch()
    assert_exit(b)
    assert_exit(a)
    row = lc.records(NETWORK)[0]
    assert row['cycle_number'] == (1 if first == 'admission' else 0)
    assert row['cycle_active'] == 0 and row['result'] == 'completed'
    if first == 'stop':
        assert not marker('race-run', 'cycles').exists()
        assert db.sentinel_get_events(NETWORK) == []
        assert db.get_findings('race-run') == []
    else:
        assert marker('race-run', 'cycles').read_text() == '1'
        assert len(db.sentinel_get_events(NETWORK)) == 1
        assert len(db.get_findings('race-run')) == 1
    assert db.get_session('race-run')['end_time']
    assert lc.lock_is_free(NETWORK)


INVALID_NETWORKS = ['', '.', '..', '../escape', 'a/b', 'a\\b', '/absolute',
                    'C:\\escape', 'abc\n', 'a' * 65, 'a.db', 'é', 'NUL', 'COM1']


@pytest.mark.parametrize('network', INVALID_NETWORKS)
def test_network_validation_precedes_any_path(network, monkeypatch):
    from unittest.mock import Mock
    home = Mock(side_effect=AssertionError('Must not construct any data path'))
    monkeypatch.setattr(db, '_real_user_home', home)
    with pytest.raises(ValueError):
        db.get_sentinel_db_path(network)
    home.assert_not_called()
    path = Mock(side_effect=AssertionError('Must validate before path helper'))
    monkeypatch.setattr(db, 'get_sentinel_db_path', path)
    for operation in (lc._lock_path, lc.records,
                      lambda key: lc.resolve_owner(network_id=key)):
        with pytest.raises(ValueError):
            operation(network)
    path.assert_not_called()


@pytest.mark.parametrize('network', ['../escape', 'a/b', 'a\\b', 'abc\n'])
def test_invalid_network_rejected_by_real_cli(lab, network):
    output = assert_exit(stop(lab, network=network), 1)
    assert 'Invalid Sentinel network_id' in output
    assert not (db._real_user_home() / '.netlab').exists()


def test_safe_unknown_network_does_not_construct_paths(lab, monkeypatch):
    from unittest.mock import Mock
    path = Mock(side_effect=AssertionError('Unknown network must not construct paths'))
    monkeypatch.setattr(db, 'get_sentinel_db_path', path)
    with pytest.raises(lc.LifecycleError, match='inconnue'):
        lc.resolve_owner(network_id='safe-but-unknown')
    path.assert_not_called()


@pytest.mark.parametrize('stage', ['network-init', 'owner-init', 'session-init'])
def test_failed_preparation_releases_own_empty_reservation(lab, monkeypatch, stage):
    from sentinel import sentinel_manager as manager
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    monkeypatch.setattr(manager, '_start_owned', lambda *args: 'completed')
    def failed(*args, **kwargs):
        raise OSError('preparation failed')
    attribute = {'network-init': 'init_sentinel_db', 'owner-init': 'Owner',
                 'session-init': 'init_db'}[stage]
    with monkeypatch.context() as scoped:
        scoped.setattr(manager, attribute, failed)
        with pytest.raises(OSError, match='preparation failed'):
            manager.start(TARGET, 'retry-reservation')
    assert not db.get_db_path('retry-reservation').exists()
    # Same ID is immediately reusable, not just a claim based on file absence.
    manager.start(TARGET, 'retry-reservation')
    assert db.get_session('retry-reservation')['status'] == 'completed'
    assert db.get_session('retry-reservation')['end_time']


@pytest.mark.parametrize('content', [b'', b'preexisting data'])
def test_reservation_never_removes_preexisting_file(lab, content):
    path = db.get_db_path('existing-reservation')
    path.write_bytes(content)
    before = path.stat()
    with pytest.raises(lc.LifecycleError, match='already exists'):
        with db.reserve_sentinel_session_file('existing-reservation'):
            pytest.fail('Existing file must not enter reservation body')
    assert path.read_bytes() == content
    assert path.stat().st_ino == before.st_ino


def test_reservation_preserves_replaced_path(lab):
    path = db.get_db_path('replacement')
    with pytest.raises(RuntimeError):
        with db.reserve_sentinel_session_file('replacement'):
            original = path.with_suffix('.original')
            path.rename(original)
            path.touch()
            raise RuntimeError('preparation failed after path replacement')
    assert path.exists() and original.exists()


def test_created_session_survives_uncertain_save_error(lab, monkeypatch):
    from sentinel import sentinel_manager as manager
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    save = manager.save_session
    def save_then_fail(*args, **kwargs):
        save(*args, **kwargs)
        raise OSError('uncertain acknowledgement after commit')
    monkeypatch.setattr(manager, 'save_session', save_then_fail)
    with pytest.raises(OSError, match='uncertain'):
        manager.start(TARGET, 'created-before-error')
    assert db.get_db_path('created-before-error').stat().st_size > 0
    assert db.get_session('created-before-error')['id'] == 'created-before-error'


def test_lifecycle_has_no_direct_database_access():
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(lc))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name != 'sqlite3' for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != 'sqlite3'
        if isinstance(node, ast.Attribute):
            assert node.attr not in {'execute', 'executemany', 'executescript',
                                     'cursor', 'connect', 'commit', 'rollback'}


@pytest.mark.parametrize('first', ['stop', 'admission'])
def test_control_transactions_serialize_competing_writes(lab, monkeypatch, first):
    """Prove real SQLITE_BUSY while the first writer remains uncommitted, then
    retry the second operation after the first commit. No timing-based order.
    """
    from contextlib import contextmanager
    from concurrent.futures import ThreadPoolExecutor
    import threading

    db.init_sentinel_db(NETWORK)
    with lc.network_lock(NETWORK):
        owner = lc.Owner(NETWORK, 'transaction-race')
        original = db._sentinel_control_connection
        connect = db.sqlite3.connect
        first_written = threading.Event()
        release_first = threading.Event()
        local = threading.local()

        def immediate_busy(*args, **kwargs):
            # Test-only: fail immediately on an actual SQLite writer conflict.
            # Production timeout and transaction implementation remain intact.
            kwargs['timeout'] = 0
            return connect(*args, **kwargs)

        @contextmanager
        def gated_connection(network):
            with original(network) as conn:
                yield conn
                if getattr(local, 'order', None) == 'first':
                    first_written.set()
                    assert release_first.wait(5), 'Missing transaction release'

        monkeypatch.setattr(db.sqlite3, 'connect', immediate_busy)
        monkeypatch.setattr(db, '_sentinel_control_connection', gated_connection)

        def operate(operation, order):
            local.order = order
            if operation == 'stop':
                return db.sentinel_control_request_stop(NETWORK, owner.instance)
            return db.sentinel_control_admit_cycle(NETWORK, owner.instance)

        second = 'admission' if first == 'stop' else 'stop'
        with ThreadPoolExecutor(max_workers=2) as pool:
            primary = pool.submit(operate, first, 'first')
            try:
                assert first_written.wait(5)
                blocked_write = pool.submit(operate, second, 'second')
                with pytest.raises(lc.LifecycleError) as failure:
                    blocked_write.result(timeout=5)
                # This comes from the real competing UPDATE, not an entry
                # barrier before execute, nor a guessed scheduling delay.
                assert isinstance(failure.value.__cause__, db.sqlite3.OperationalError)
                assert failure.value.__cause__.sqlite_errorcode == db.sqlite3.SQLITE_BUSY
                assert not primary.done()
                assert not release_first.is_set()
            finally:
                release_first.set()
            primary_value = primary.result(timeout=5)  # includes successful commit
            secondary_value = pool.submit(operate, second, 'second').result(timeout=5)
        assert (primary_value if first == 'admission' else secondary_value) is (first == 'admission')
        row = db.sentinel_control_get(NETWORK, owner.instance)
        assert row['stop_requested'] == 1
        assert row['cycle_number'] == (1 if first == 'admission' else 0)


@pytest.mark.parametrize('command', ['start', 'stop'])
@pytest.mark.parametrize('stage', ['open', 'birth', 'wait', 'close', 'wait-status'])
def test_windows_api_errors_are_lifecycle_failures_without_cli_traceback(monkeypatch, command, stage):
    """Contract simulation only: access/API errors never imply process death."""
    from types import SimpleNamespace
    from unittest.mock import Mock
    from typer.testing import CliRunner
    from cli import app
    from sentinel import sentinel_manager as manager

    class WindowsAPIError(Exception):
        winerror = 5  # ACCESS_DENIED, never an absent process

    failure = WindowsAPIError('WINDOWS_SECRET_CANARY access details')
    handle = Mock()
    api = SimpleNamespace(OpenProcess=Mock(return_value=handle))
    events = SimpleNamespace(WAIT_OBJECT_0=0, WAIT_TIMEOUT=258,
                             WaitForSingleObject=Mock(return_value=258))
    birth = Mock(return_value='creation-100ns')
    if stage == 'open':
        api.OpenProcess.side_effect = failure
    elif stage == 'birth':
        birth.side_effect = failure
    elif stage == 'wait':
        events.WaitForSingleObject.side_effect = failure
    elif stage == 'close':
        handle.Close.side_effect = failure
    else:
        events.WaitForSingleObject.return_value = 0xFFFFFFFF
    monkeypatch.setitem(sys.modules, 'win32api', api)
    monkeypatch.setitem(sys.modules, 'win32event', events)
    monkeypatch.setitem(sys.modules, 'pywintypes', SimpleNamespace(error=WindowsAPIError))
    monkeypatch.setattr(lc, '_windows_birth', birth)
    caught = []

    def verify(*args, **kwargs):
        with monkeypatch.context() as scoped:
            scoped.setattr(sys, 'platform', 'win32')
            try:
                with lc.ProcessIdentity(42, 'creation-100ns') as process:
                    # Only close-stage reaches this assertion: its process is
                    # still alive. Other API failures MUST raise, not return True.
                    assert process.exited() is False
            except lc.LifecycleError as exc:
                caught.append(exc)
                raise

    monkeypatch.setattr(manager, command, verify)
    args = ['start', '--target', TARGET] if command == 'start' else ['stop', '--network', NETWORK]
    result = CliRunner().invoke(app, ['sentinel', *args])
    assert result.exit_code == 1
    assert len(caught) == 1
    assert 'WINDOWS_SECRET_CANARY' not in str(caught[0]) + result.output
    assert 'Traceback' not in result.output
    if stage != 'wait-status':
        assert 'WindowsAPIError' in result.output
        assert 'non confirmé' in ' '.join(result.output.split())
    assert 'terminaison confirmées' not in result.output
    if stage == 'open':
        handle.Close.assert_not_called()
    else:
        handle.Close.assert_called_once()


@pytest.mark.parametrize('error_type', [RuntimeError, OSError, ValueError])
def test_unexpected_start_failure_is_sanitized_at_cli_boundary(monkeypatch, error_type):
    from typer.testing import CliRunner
    from cli import app
    from sentinel import sentinel_manager as manager

    def failed(*args, **kwargs):
        raise error_type('CLI_SECRET_CANARY arbitrary exception message')

    monkeypatch.setattr(manager, 'start', failed)
    result = CliRunner().invoke(app, ['sentinel', 'start', '--target', TARGET])
    assert result.exit_code == 1
    assert error_type.__name__ in result.output
    assert 'CLI_SECRET_CANARY' not in result.output
    assert 'Traceback' not in result.output


@pytest.mark.parametrize('stage', ['network-before', 'network-after', 'owner-before', 'owner-after'])
def test_pre_owner_failure_reconciles_existing_state_without_ack(lab, monkeypatch, stage):
    from unittest.mock import Mock
    from sentinel import sentinel_manager as manager
    db.init_sentinel_db(NETWORK)
    db.sentinel_update_state(NETWORK, 'active', last_check_time='2026-10-10T12:00:00+00:00')
    db.sentinel_save_asset(NETWORK, 'preserved-asset', '192.0.2.10', '2026-10-10T12:00:00+00:00')
    db.sentinel_save_event(NETWORK, 'preserved-event', 'new_host',
                           '2026-10-10T12:00:00+00:00', None, {}, False)
    db.init_db('preexisting-run')
    db.save_session('preexisting-run', target=TARGET)
    session_before = db.get_db_path('preexisting-run').read_bytes()
    db.sentinel_control_register(NETWORK, 'prior-instance', 'preexisting-run', os.getpid(), 'prior-birth')
    events_before = db.sentinel_get_events(NETWORK)
    assets_before = db.sentinel_get_assets(NETWORK)
    inode = db.get_sentinel_db_path(NETWORK).stat().st_ino
    original_error = RuntimeError('PREPARATION_SECRET_CANARY')
    init = manager.init_sentinel_db
    owner_type = manager.Owner
    finish = Mock(side_effect=AssertionError('Unregistered owner must not acknowledge'))
    monkeypatch.setattr(owner_type, 'finish', finish)
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)

    def fail_init(*args, **kwargs):
        if stage == 'network-after':
            init(*args, **kwargs)
        raise original_error

    def fail_owner(*args, **kwargs):
        if stage == 'owner-after':
            owner_type(*args, **kwargs)  # simulate uncertain registration return
        raise original_error

    if stage.startswith('network'):
        monkeypatch.setattr(manager, 'init_sentinel_db', fail_init)
    else:
        monkeypatch.setattr(manager, 'Owner', fail_owner)
    with pytest.raises(RuntimeError) as failure:
        manager.start(TARGET, 'failed-preparation')
    assert failure.value is original_error
    state = db.sentinel_get_state(NETWORK)
    assert state['sentinel_status'] == 'inactive'
    assert state['last_check_time'] == '2026-10-10T12:00:00+00:00'
    finish.assert_not_called()
    rows = lc.records(NETWORK)
    assert len(rows) == (2 if stage == 'owner-after' else 1)
    assert all(row['result'] != 'completed' for row in rows)
    if stage != 'owner-after':
        assert rows[0]['result'] == 'running'  # no mutation of previous control
    assert db.get_sentinel_db_path(NETWORK).stat().st_ino == inode
    assert db.sentinel_get_events(NETWORK) == events_before
    assert db.sentinel_get_assets(NETWORK) == assets_before
    assert db.get_db_path('preexisting-run').read_bytes() == session_before
    assert not db.get_db_path('failed-preparation').exists()
    assert lc.lock_is_free(NETWORK)
    assert 'PREPARATION_SECRET_CANARY' not in str(rows)


@pytest.mark.parametrize('stage', ['network', 'owner'])
def test_pre_owner_cleanup_failure_preserves_initial_error_and_cli_sanitization(lab, monkeypatch, stage):
    from unittest.mock import Mock
    from typer.testing import CliRunner
    from cli import app
    from sentinel import sentinel_manager as manager
    db.init_sentinel_db(NETWORK)
    db.sentinel_update_state(NETWORK, 'active')
    initial = RuntimeError('INITIAL_SECRET_CANARY')
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    def failed(*args, **kwargs):
        raise initial
    monkeypatch.setattr(manager, 'init_sentinel_db' if stage == 'network' else 'Owner', failed)
    cleanup = Mock(side_effect=PermissionError('CLEANUP_SECRET_CANARY'))
    monkeypatch.setattr(db, 'sentinel_reconcile_failed_start', cleanup)
    shown = Mock()
    real_display = manager.display
    monkeypatch.setattr(manager, 'display', shown)
    with pytest.raises(RuntimeError) as failure:
        manager.start(TARGET, 'failed-cleanup')
    assert failure.value is initial
    assert cleanup.call_count == 1
    assert 'PermissionError' in str(shown.call_args_list)
    assert 'SECRET_CANARY' not in str(shown.call_args_list)
    monkeypatch.setattr(manager, 'display', real_display)
    result = CliRunner().invoke(app, ['sentinel', 'start', '--target', TARGET, '--session', 'failed-cleanup'])
    assert result.exit_code == 1
    assert 'RuntimeError' in result.output and 'PermissionError' in result.output
    assert 'Traceback' not in result.output and 'SECRET_CANARY' not in result.output
    assert 'terminaison confirmées' not in result.output
    assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'active'  # write unavailable, reported honestly
    assert lc.records(NETWORK) == []
    assert not db.get_db_path('failed-cleanup').exists()
    assert lc.lock_is_free(NETWORK)


@pytest.mark.parametrize('storage', ['absent', 'empty', 'corrupt'])
def test_failed_network_init_does_not_create_or_replace_storage(lab, monkeypatch, storage):
    from sentinel import sentinel_manager as manager
    path = db.get_sentinel_db_path(NETWORK)
    if storage != 'absent':
        path.write_bytes(b'' if storage == 'empty' else b'not a SQLite database')
        before = path.read_bytes()
        inode = path.stat().st_ino
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    original = RuntimeError('original startup failure')
    def failed(*args, **kwargs):
        raise original
    monkeypatch.setattr(manager, 'init_sentinel_db', failed)
    with pytest.raises(RuntimeError) as failure:
        manager.start(TARGET, 'failed-init')
    assert failure.value is original
    if storage == 'absent':
        assert not path.exists()
    else:
        assert path.read_bytes() == before
        assert path.stat().st_ino == inode
    assert not db.get_db_path('failed-init').exists()
    assert lc.lock_is_free(NETWORK)


@pytest.mark.parametrize('stage', ['network-before', 'network-after', 'owner-before', 'owner-after', 'session-init', 'session-save'])
def test_interrupt_before_confirmed_session_is_not_success(lab, monkeypatch, stage):
    from unittest.mock import Mock
    from typer.testing import CliRunner
    from cli import app
    from sentinel import sentinel_manager as manager

    db.init_sentinel_db(NETWORK)
    db.sentinel_update_state(NETWORK, 'active')
    db.init_db('preserved-session')
    db.save_session('preserved-session', target=TARGET)
    preserved = db.get_db_path('preserved-session').read_bytes()
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    interruption = KeyboardInterrupt('INTERRUPTION_SECRET_CANARY')
    init = manager.init_sentinel_db
    owner_type = manager.Owner
    finish = Mock(wraps=db.sentinel_control_finish)
    monkeypatch.setattr(db, 'sentinel_control_finish', finish)

    def interrupt_init(*args, **kwargs):
        if stage == 'network-after':
            init(*args, **kwargs)
        raise interruption

    def interrupt_owner(*args, **kwargs):
        if stage == 'owner-after':
            owner_type(*args, **kwargs)  # registration committed, constructor did not return
        raise interruption

    def interrupt(*args, **kwargs):
        raise interruption

    if stage.startswith('network'):
        monkeypatch.setattr(manager, 'init_sentinel_db', interrupt_init)
    elif stage.startswith('owner'):
        monkeypatch.setattr(manager, 'Owner', interrupt_owner)
    else:
        monkeypatch.setattr(manager, 'init_db' if stage == 'session-init' else 'save_session', interrupt)

    with pytest.raises(KeyboardInterrupt) as failure:
        manager.start(TARGET, 'interrupted-direct')
    assert failure.value is interruption  # never replaced by a cleanup exception
    assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'inactive'
    assert lc.lock_is_free(NETWORK)

    db.sentinel_update_state(NETWORK, 'active')
    result = CliRunner().invoke(app, ['sentinel', 'start', '--target', TARGET, '--session', 'interrupted-cli'])
    assert result.exit_code == 130
    assert 'démarrage interrompu' in result.output
    assert 'Traceback' not in result.output and 'INTERRUPTION_SECRET_CANARY' not in result.output
    assert 'terminaison confirmées' not in result.output
    assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'inactive'
    assert lc.lock_is_free(NETWORK)
    rows = lc.records(NETWORK)
    assert all(row['result'] != 'completed' for row in rows)
    assert 'INTERRUPTION_SECRET_CANARY' not in str(rows)
    if stage.startswith(('network', 'owner')):
        finish.assert_not_called()  # no owner available, including uncertain registration
    else:
        assert finish.call_count == 2
        assert all(call.args[2] == 'failed' for call in finish.call_args_list)
    for run in ('interrupted-direct', 'interrupted-cli'):
        path = db.get_db_path(run)
        if stage == 'session-save':
            # Schema already written: retain nonempty uncertain data, not an empty reservation.
            assert path.stat().st_size > 0
            assert db.get_session(run) is None
        else:
            assert not path.exists()
    assert db.get_db_path('preserved-session').read_bytes() == preserved


@pytest.mark.parametrize('stage', ['network', 'owner'])
def test_pre_session_interrupt_survives_failed_reconciliation(lab, monkeypatch, stage):
    from unittest.mock import Mock
    from typer.testing import CliRunner
    from cli import app
    from sentinel import sentinel_manager as manager
    db.init_sentinel_db(NETWORK)
    db.sentinel_update_state(NETWORK, 'active')
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    original = KeyboardInterrupt('INTERRUPTION_SECRET_CANARY')
    def interrupt(*args, **kwargs):
        raise original
    monkeypatch.setattr(manager, 'init_sentinel_db' if stage == 'network' else 'Owner', interrupt)
    monkeypatch.setattr(db, 'sentinel_reconcile_failed_start',
                        Mock(side_effect=PermissionError('CLEANUP_SECRET_CANARY')))
    with pytest.raises(KeyboardInterrupt) as failure:
        manager.start(TARGET, 'interrupted-cleanup')
    assert failure.value is original
    result = CliRunner().invoke(app, ['sentinel', 'start', '--target', TARGET, '--session', 'interrupted-cleanup'])
    assert result.exit_code == 130
    assert 'PermissionError' in result.output
    assert 'SECRET_CANARY' not in result.output and 'Traceback' not in result.output
    assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'active'  # no claim that failed write succeeded
    assert lc.records(NETWORK) == []
    assert not db.get_db_path('interrupted-cleanup').exists()
    assert lc.lock_is_free(NETWORK)


@pytest.mark.parametrize('cleanup_fails', [False, True])
def test_save_commits_then_interrupts_preserves_interrupt_and_closes_actual_session(lab, monkeypatch, cleanup_fails):
    from unittest.mock import Mock
    from typer.testing import CliRunner
    from cli import app
    from sentinel import sentinel_manager as manager
    monkeypatch.setattr(manager, 'detect_network_identity', lambda target: IDENTITY)
    original_save = manager.save_session
    interruption = KeyboardInterrupt('SAVE_SECRET_CANARY')
    def save_then_interrupt(*args, **kwargs):
        original_save(*args, **kwargs)
        raise interruption
    monkeypatch.setattr(manager, 'save_session', save_then_interrupt)
    if cleanup_fails:
        monkeypatch.setattr(db, 'sentinel_fail_unconfirmed_session',
                            Mock(side_effect=PermissionError('CLEANUP_SECRET_CANARY')))
    with pytest.raises(KeyboardInterrupt) as caught:
        manager.start(TARGET, 'uncertain-save-direct')
    assert caught.value is interruption
    result = CliRunner().invoke(app, ['sentinel', 'start', '--target', TARGET,
                                      '--session', 'uncertain-save-cli'])
    assert result.exit_code == 130
    assert 'Traceback' not in result.output and 'SECRET_CANARY' not in result.output
    assert 'terminaison confirmées' not in result.output
    if cleanup_fails:
        assert 'PermissionError' in result.output
    for run in ('uncertain-save-direct', 'uncertain-save-cli'):
        session = db.get_session(run)
        assert session['id'] == run
        assert session['status'] == ('running' if cleanup_fails else 'failed')
        assert bool(session['end_time']) is (not cleanup_fails)
        assert db.get_db_path(run).stat().st_size > 0
    rows = lc.records(NETWORK)
    assert len(rows) == 2
    assert all(row['result'] == ('finalization_failed' if cleanup_fails else 'failed') for row in rows)
    assert 'SECRET_CANARY' not in str(rows)
    assert db.sentinel_get_state(NETWORK)['sentinel_status'] == 'inactive'
    assert lc.lock_is_free(NETWORK)


def test_real_cli_save_committed_then_interrupted(lab):
    spawn, _ = lab
    a = spawn(['start', '--target', TARGET, '--session', 'save-interrupted'],
              'save-interrupted', 'save-interrupt')
    output = assert_exit(a, 130)
    assert 'Traceback' not in output and 'SAVE_SECRET_CANARY' not in output
    session = db.get_session('save-interrupted')
    assert session['status'] == 'failed' and session['end_time']
    assert lc.records(NETWORK)[0]['result'] == 'failed'
    assert lc.lock_is_free(NETWORK)
    b_output = assert_exit(stop(lab), 1)
    assert 'terminaison confirmées' not in b_output


@pytest.mark.parametrize('storage', ['absent', 'empty', 'schema-only', 'other-session', 'corrupt'])
def test_unconfirmed_session_cleanup_never_invents_or_deletes_rows(lab, storage):
    run = 'uncertain-storage'
    path = db.get_db_path(run)
    if storage == 'empty':
        path.touch()
    elif storage in ('schema-only', 'other-session'):
        db.init_db(run)
        if storage == 'other-session':
            # Deliberately mismatched row: only the reserved ID may be updated.
            conn = db.get_connection(run)
            try:
                conn.execute("INSERT INTO sessions (id, start_time, target, profile, status) VALUES (?,?,?,?,?)",
                             ('not-this-attempt', '2026-10-10', TARGET, 'sentinel', 'running'))
                conn.commit()
            finally:
                conn.close()
    elif storage == 'corrupt':
        path.write_bytes(b'uncertain nonempty data')
    before = path.read_bytes() if path.exists() else None
    if storage == 'corrupt':
        with pytest.raises(lc.LifecycleError):
            db.sentinel_fail_unconfirmed_session(run)
    else:
        assert db.sentinel_fail_unconfirmed_session(run) is False
    if before is None:
        assert not path.exists()
    else:
        assert path.exists() and path.read_bytes() == before
