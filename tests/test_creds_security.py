"""CRED-01 security contracts: root refusal, home resolution, vault creation.

All vaults are temporary, all secrets are synthetic, and no network is used.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import os
import stat
import sys

import pytest
import typer
from typer.testing import CliRunner

import cli
import core.credential_vault as cv
import core.user_paths as user_paths
import detect.default_creds as dc

PHRASE = 'Synthetic CRED-01 vault phrase 2026!'
MESSAGE = ('Les commandes creds ne peuvent pas être exécutées avec les privilèges root. '
           'Relancez SentinelX sans sudo.')
runner = CliRunner()

pytestmark = pytest.mark.skipif(
    os.name == 'nt',
    reason='POSIX root and permission contracts; Windows Administrator policy is out of scope',
)


def _normalized(value: str) -> str:
    return ' '.join(value.split())


def _tty(monkeypatch) -> None:
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: True)


def _vault(tmp_path: Path) -> Path:
    return tmp_path / 'user' / '.netlab' / 'credentials' / 'vault.enc'


# --- Phase A: the three commands refuse effective root -----------------------

COMMANDS = (
    ('check', ['creds_check', '--target', '192.0.2.1']),
    ('list', ['creds', 'list']),
    ('show', ['creds', 'show', 'opaque-record']),
)


@pytest.mark.parametrize('name,args', COMMANDS, ids=[name for name, _ in COMMANDS])
@pytest.mark.parametrize('sudo_identity', [None, ('alice', '1000')], ids=['no-sudo', 'with-sudo'])
def test_all_creds_commands_refuse_euid_zero_before_any_work(monkeypatch, tmp_path, name, args, sudo_identity):
    monkeypatch.setattr(user_paths.os, 'geteuid', lambda: 0)
    if sudo_identity is None:
        monkeypatch.delenv('SUDO_USER', raising=False)
        monkeypatch.delenv('SUDO_UID', raising=False)
    else:
        monkeypatch.setenv('SUDO_USER', sudo_identity[0])
        monkeypatch.setenv('SUDO_UID', sudo_identity[1])
    opened = Mock(side_effect=AssertionError('vault must not be opened under root'))
    session = Mock(side_effect=AssertionError('session must not be created under root'))
    network = Mock(side_effect=AssertionError('network must not be used under root'))
    check = Mock(side_effect=AssertionError('credential checks must not start under root'))
    save = Mock(side_effect=AssertionError('persistence must not be touched under root'))
    monkeypatch.setattr(cli, '_open_credential_vault', opened)
    monkeypatch.setattr(cli, '_standalone_session_id', session)
    monkeypatch.setattr(dc.socket, 'socket', network)
    monkeypatch.setattr(dc, 'check_default_creds', check)
    monkeypatch.setattr('core.database.save_findings', save)

    result = runner.invoke(cli.app, args)

    assert result.exit_code == 1
    assert _normalized(MESSAGE) in _normalized(result.output)
    opened.assert_not_called()
    session.assert_not_called()
    network.assert_not_called()
    check.assert_not_called()
    save.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_check_default_creds_refuses_root_as_defence_in_depth(monkeypatch):
    monkeypatch.setattr(user_paths.os, 'geteuid', lambda: 0)
    monkeypatch.setenv('SUDO_USER', 'alice')
    monkeypatch.setenv('SUDO_UID', '1000')
    confirm = Mock(side_effect=AssertionError('no prompt under root'))
    recorder = Mock(ready=True)
    monkeypatch.setattr(dc.typer, 'confirm', confirm)

    with pytest.raises(user_paths.CredentialPrivilegeError, match='privilèges root'):
        dc.check_default_creds('192.0.2.1', 'session', recorder=recorder, candidates=[])

    confirm.assert_not_called()
    recorder.record.assert_not_called()


def test_open_credential_vault_refuses_root_before_path_resolution(monkeypatch):
    monkeypatch.setattr(user_paths.os, 'geteuid', lambda: 0)
    path = Mock(side_effect=AssertionError('vault path must not be resolved under root'))
    monkeypatch.setattr(cv, 'default_vault_path', path)

    with pytest.raises(user_paths.CredentialPrivilegeError, match='privilèges root'):
        cli._open_credential_vault()

    path.assert_not_called()


def test_non_root_credentials_commands_keep_working(monkeypatch):
    monkeypatch.setattr(user_paths.os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(cli, '_open_credential_vault', Mock(side_effect=cv.VaultError('Vault absent; initialize through creds_check')))
    result = runner.invoke(cli.app, ['creds', 'list'])
    assert result.exit_code == 1
    assert 'Vault absent' in result.output
    assert MESSAGE not in result.output


# --- Phase B: effective-UID home resolution ----------------------------------

def test_credential_paths_follow_effective_uid_not_sudo_or_home(monkeypatch, tmp_path):
    home = tmp_path / 'effective-user'
    home.mkdir()
    monkeypatch.setattr(user_paths.os, 'geteuid', lambda: 1204)
    monkeypatch.setenv('HOME', '/root')
    monkeypatch.setenv('SUDO_USER', 'contradictory')
    monkeypatch.setenv('SUDO_UID', '0')
    monkeypatch.setattr(user_paths.pwd, 'getpwuid', lambda uid: SimpleNamespace(pw_dir=str(home)))

    assert cv.default_vault_path() == home / '.netlab' / 'credentials' / 'vault.enc'
    assert dc.ssh_trust_path() == home / '.netlab' / 'ssh_known_hosts'


def test_unresolvable_effective_home_is_reported_without_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(user_paths.os, 'geteuid', lambda: 1204)
    monkeypatch.setattr(user_paths.pwd, 'getpwuid', lambda uid: (_ for _ in ()).throw(KeyError(uid)))
    monkeypatch.setenv('HOME', str(tmp_path))
    _tty(monkeypatch)
    messages = []
    monkeypatch.setattr(cli, 'display', lambda message: messages.append(str(message)))

    with pytest.raises(typer.Exit) as caught:
        cli.creds_list()

    assert caught.value.exit_code == 1
    assert any('Unable to resolve' in message for message in messages)
    assert list(tmp_path.iterdir()) == []


def test_validate_vault_location_absent_creates_nothing(tmp_path):
    path = _vault(tmp_path)
    assert cv.validate_vault_location(path) is True
    assert not path.exists()
    assert not path.parent.exists()


def test_validate_vault_location_refuses_invalid_permissions_without_repair(tmp_path):
    path = _vault(tmp_path)
    with cv.open_vault(path, PHRASE, create=True):
        pass
    before = path.read_bytes()
    path.chmod(0o644)

    with pytest.raises(cv.VaultError, match='private'):
        cv.validate_vault_location(path)

    assert path.read_bytes() == before
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_validate_vault_location_refuses_foreign_owner(monkeypatch, tmp_path):
    path = _vault(tmp_path)
    with cv.open_vault(path, PHRASE, create=True):
        pass
    real_uid = os.getuid()
    monkeypatch.setattr(cv.os, 'getuid', lambda: real_uid + 1)

    with pytest.raises(cv.VaultError, match='private'):
        cv.validate_vault_location(path)


# --- Phase C: first-vault creation -------------------------------------------

def test_existing_valid_vault_does_not_ask_for_creation(monkeypatch, tmp_path):
    path = _vault(tmp_path)
    with cv.open_vault(path, PHRASE, create=True, writable=True):
        pass
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    _tty(monkeypatch)
    confirm = Mock(return_value=True)
    monkeypatch.setattr(cli.typer, 'confirm', confirm)
    monkeypatch.setattr(cli.typer, 'prompt', Mock(return_value=PHRASE))

    with cli._open_credential_vault(writable=True) as vault:
        assert vault.ready

    confirm.assert_not_called()


def test_absent_vault_confirmed_creates_private_file(monkeypatch, tmp_path):
    path = _vault(tmp_path)
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    _tty(monkeypatch)
    confirm = Mock(return_value=True)
    monkeypatch.setattr(cli.typer, 'confirm', confirm)
    monkeypatch.setattr(cli.typer, 'prompt', Mock(return_value=PHRASE))

    with cli._open_credential_vault(writable=True) as vault:
        assert vault.ready

    confirm.assert_called_once()
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert path.stat().st_uid == os.getuid()


def test_absent_vault_refused_creates_nothing(monkeypatch, tmp_path):
    path = _vault(tmp_path)
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    _tty(monkeypatch)
    monkeypatch.setattr(cli.typer, 'confirm', Mock(return_value=False))

    with pytest.raises(typer.Abort):
        cli._open_credential_vault(writable=True)

    assert not path.exists()
    assert not path.parent.exists()


def test_non_interactive_abandons_without_file(monkeypatch, tmp_path):
    path = _vault(tmp_path)
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(sys.stdout, 'isatty', lambda: False)

    with pytest.raises(cv.VaultError, match='interactive private terminal'):
        cli._open_credential_vault(writable=True)

    assert not path.exists()
    assert not path.parent.exists()


def test_invalid_existing_vault_is_refused_without_replacement(monkeypatch, tmp_path):
    path = _vault(tmp_path)
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_bytes(b'existing-vault-bytes')
    path.chmod(0o644)
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    _tty(monkeypatch)
    confirm = Mock(return_value=True)
    monkeypatch.setattr(cli.typer, 'confirm', confirm)

    with pytest.raises(cv.VaultError, match='private'):
        cli._open_credential_vault(writable=True)

    confirm.assert_not_called()
    assert path.read_bytes() == b'existing-vault-bytes'
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_vault_path_that_is_a_directory_is_not_treated_as_absent(monkeypatch, tmp_path):
    path = _vault(tmp_path)
    path.parent.mkdir(parents=True, mode=0o700)
    path.mkdir(mode=0o700)
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    _tty(monkeypatch)

    with pytest.raises(cv.VaultError, match='regular file'):
        cli._open_credential_vault(writable=True)


def test_corrupt_existing_vault_is_not_replaced(monkeypatch, tmp_path):
    path = _vault(tmp_path)
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_bytes(b'not-a-valid-vault')
    path.chmod(0o600)
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    _tty(monkeypatch)
    monkeypatch.setattr(cli.typer, 'prompt', Mock(return_value=PHRASE))

    with pytest.raises(cv.VaultError):
        with cli._open_credential_vault(writable=True):
            pass

    assert path.read_bytes() == b'not-a-valid-vault'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_possible_old_root_vault_is_warned_about_but_never_inspected_or_moved(monkeypatch, tmp_path):
    old = tmp_path / 'old-root' / '.netlab' / 'credentials' / 'vault.enc'
    old.parent.mkdir(parents=True, mode=0o700)
    old.write_bytes(b'old-root-vault')
    path = _vault(tmp_path)
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    _tty(monkeypatch)
    monkeypatch.setattr(cli.typer, 'confirm', Mock(return_value=True))
    monkeypatch.setattr(cli.typer, 'prompt', Mock(return_value=PHRASE))
    messages = []
    monkeypatch.setattr(cli, 'display', lambda message: messages.append(str(message)))
    real_exists = Path.exists

    def guarded_exists(self):
        if str(self).startswith('/root'):
            raise AssertionError('root vault must not be inspected')
        return real_exists(self)

    monkeypatch.setattr(Path, 'exists', guarded_exists)

    with cli._open_credential_vault(writable=True) as vault:
        assert vault.ready

    assert any('/root/.netlab' in message for message in messages)
    assert old.read_bytes() == b'old-root-vault'
    assert not (path.parent / 'vault.enc.old').exists()
    assert path.read_bytes() != b'old-root-vault'


# --- Phase E: list/show never initialize a missing vault ---------------------

@pytest.mark.parametrize('command,args', [(cli.creds_list, ()), (cli.creds_show, ('opaque-record',))],
                         ids=['list', 'show'])
def test_list_and_show_do_not_create_an_absent_vault(monkeypatch, tmp_path, command, args):
    path = _vault(tmp_path)
    monkeypatch.setattr(cv, 'default_vault_path', lambda: path)
    _tty(monkeypatch)
    confirm = Mock(side_effect=AssertionError('no creation prompt'))
    monkeypatch.setattr(cli.typer, 'confirm', confirm)
    messages = []
    monkeypatch.setattr(cli, 'display', lambda message: messages.append(str(message)))

    with pytest.raises(typer.Exit) as caught:
        command(*args)

    assert caught.value.exit_code == 1
    assert any('Vault absent' in message for message in messages)
    confirm.assert_not_called()
    assert not path.exists()
    assert not path.parent.exists()
