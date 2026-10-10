"""T22 CLI contract with simulated backends and a temporary real vault."""
from contextlib import nullcontext
import json
import socket
from unittest.mock import Mock
import pytest
from typer.testing import CliRunner
from core.credential_vault import VaultError, open_vault
import cli
import detect.default_creds as dc

SECRET='Synthetic_No_Leak_654'
PHRASE='Synthetic passphrase for testing 684!'
runner=CliRunner()


@pytest.fixture
def setup(tmp_path,monkeypatch):
    path=tmp_path/'private'/'vault.enc'
    monkeypatch.setattr(cli,'_open_credential_vault',lambda writable=False:open_vault(path,PHRASE,create=writable,writable=writable))
    monkeypatch.setattr(dc.socket,'socket',Mock(side_effect=AssertionError('No network')))
    monkeypatch.setattr(dc,'_try_ftp_login',Mock(return_value=dc.CredentialProbeResult('ftp',dc.SUCCESS,'AUTHENTICATED')))
    monkeypatch.setattr(dc,'_try_snmp_community',Mock(return_value=dc.CredentialProbeResult('snmp',dc.TIMEOUT,'NO_RESPONSE')))
    monkeypatch.setattr(dc.time,'sleep',lambda s:None)
    dictionary=tmp_path/'dictionary with spaces.txt'
    dictionary.write_text(json.dumps(dict(service='ftp',username='Synthetic_Identity',password=SECRET)))
    return path,dictionary


def test_custom_file_to_vault_not_session_findings(setup,monkeypatch):
    path,dictionary=setup
    save=Mock();monkeypatch.setattr('core.database.save_findings',save)
    result=runner.invoke(cli.app,['creds_check','-t','192.0.2.1','--dict',str(dictionary)],input='y\n')
    assert result.exit_code==0,result.output
    assert 'NO_COMPATIBLE_CANDIDATE' in result.output
    assert 'confirmed=1' in result.output and 'stored=1' in result.output
    assert SECRET not in result.output and 'Synthetic_Identity' not in result.output
    assert 'netlab creds list' in result.output and 'netlab creds show <id>' in result.output
    save.assert_not_called()
    with open_vault(path,PHRASE) as v:
        meta=v.list_metadata();assert len(meta)==1
        assert v.reveal(meta[0]['id'])['secret']==SECRET
    listed=runner.invoke(cli.app,['creds','list'])
    assert listed.exit_code==0 and SECRET not in listed.output and 'Synthetic_Identity' not in listed.output
    denied=runner.invoke(cli.app,['creds','show',meta[0]['id']],input='n\n')
    assert denied.exit_code==0 and SECRET not in denied.output
    shown=runner.invoke(cli.app,['creds','show',meta[0]['id']],input='y\n')
    assert shown.exit_code==0 and SECRET in shown.output


def test_explicit_gap_and_invalid_tail_prevent_vault_and_network(setup,monkeypatch):
    path,dictionary=setup
    prepare=Mock(side_effect=AssertionError('Vault must not open'))
    monkeypatch.setattr(cli,'_open_credential_vault',prepare)
    args=['creds_check','--target','192.0.2.1','--dict',str(dictionary)]
    result=runner.invoke(cli.app,args+['--service','ftp','--service','snmp'])
    assert result.exit_code==1
    dictionary.write_text(dictionary.read_text()+'\nBAD '+SECRET)
    result=runner.invoke(cli.app,args)
    assert result.exit_code==1 and SECRET not in result.output
    prepare.assert_not_called();dc._try_ftp_login.assert_not_called()


def test_locked_vault_no_network(setup,monkeypatch):
    _,dictionary=setup
    monkeypatch.setattr(cli,'_open_credential_vault',Mock(side_effect=VaultError('Vault locked')))
    result=runner.invoke(cli.app,['creds_check','-t','192.0.2.1','--dict',str(dictionary)])
    assert result.exit_code==1
    dc._try_ftp_login.assert_not_called()


def test_no_new_protocol_activation(setup):
    _,dictionary=setup
    result=runner.invoke(cli.app,['creds_check','-t','192.0.2.1','--service','ssh','--dict',str(dictionary)])
    assert result.exit_code==1
    dc._try_ftp_login.assert_not_called();dc._try_snmp_community.assert_not_called()


def test_consultation_requires_terminal(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin,'isatty',lambda:False)
    with pytest.raises(VaultError,match='terminal'):cli._open_credential_vault()


def test_profile_required_for_default_qualification(setup):
    result=runner.invoke(cli.app,['creds_check','-t','192.0.2.1','--service','snmp','--profile','cisco-wlc-7.4'],input='n\n')
    assert result.exit_code==0
    assert 'cancelled' in result.output
    dc._try_snmp_community.assert_not_called()


def test_unexpected_vault_error_does_not_leak_traceback(setup,monkeypatch):
    _,dictionary=setup
    monkeypatch.setattr(cli,'_open_credential_vault',Mock(side_effect=RuntimeError(SECRET)))
    result=runner.invoke(cli.app,['creds_check','-t','192.0.2.1','--dict',str(dictionary)])
    assert result.exit_code==1 and SECRET not in result.output
    assert 'Traceback' not in result.output
    dc._try_ftp_login.assert_not_called()


def test_show_display_failure_is_sanitized(setup,monkeypatch):
    path,_=setup
    with open_vault(path,PHRASE,create=True,writable=True) as v:
        v.record(service='ftp',endpoint='192.0.2.1:21',context='password',username='identity',secret=SECRET)
        key=v.list_metadata()[0]['id']
    monkeypatch.setattr(cli,'display',Mock(side_effect=RuntimeError(SECRET)))
    result=runner.invoke(cli.app,['creds','show',key],input='y\n')
    assert result.exit_code==1 and SECRET not in result.output


def test_first_usage_prompts_without_echo_and_checks_writes(tmp_path,monkeypatch):
    import sys
    import core.credential_vault as cv
    path=tmp_path/'private'/'vault.enc'
    monkeypatch.setattr(cv,'default_vault_path',lambda:path)
    monkeypatch.setattr(sys.stdin,'isatty',lambda:True)
    monkeypatch.setattr(sys.stdout,'isatty',lambda:True)
    monkeypatch.setattr(cli.typer,'confirm',Mock(return_value=True))
    prompt=Mock(return_value=PHRASE);monkeypatch.setattr(cli.typer,'prompt',prompt)
    with cli._open_credential_vault(writable=True) as v:
        assert v.ready and v.list_metadata()==[]
    assert prompt.call_args.kwargs=={'hide_input':True,'confirmation_prompt':True}
    assert path.exists()


def test_initialization_refusal_no_file(tmp_path,monkeypatch):
    import sys
    import core.credential_vault as cv
    import typer
    path=tmp_path/'private'/'vault.enc'
    monkeypatch.setattr(cv,'default_vault_path',lambda:path)
    monkeypatch.setattr(sys.stdin,'isatty',lambda:True)
    monkeypatch.setattr(sys.stdout,'isatty',lambda:True)
    monkeypatch.setattr(cli.typer,'confirm',Mock(return_value=False))
    with pytest.raises(typer.Abort):cli._open_credential_vault(writable=True)
    assert not path.exists()


def test_show_escapes_control_sequences(setup):
    path,_=setup
    with open_vault(path,PHRASE,create=True,writable=True) as v:
        v.record(service='ftp',endpoint='192.0.2.1:21',context='password',username='[red]user',secret='\x1b[2J\n[red]')
        key=v.list_metadata()[0]['id']
    result=runner.invoke(cli.app,['creds','show',key],input='y\n')
    assert result.exit_code==0 and '\\u001b' in result.output and '\x1b[2J' not in result.output


@pytest.mark.parametrize('uncertain', [False, True])
def test_cli_distinguishes_save_failure_and_uncertain_without_secret(setup, monkeypatch, uncertain):
    _, dictionary = setup
    error = dc.VaultWriteUncertain() if uncertain else VaultError('Safe pre-replacement failure')
    sink = Mock(ready=True, record=Mock(side_effect=error))
    monkeypatch.setattr(cli, '_open_credential_vault', lambda writable=False: nullcontext(sink))
    result = runner.invoke(cli.app, ['creds_check', '-t', '192.0.2.1', '--dict', str(dictionary)], input='y\n')
    assert result.exit_code == 1
    assert f'save_failures={int(not uncertain)}' in result.output
    assert f'save_uncertain={int(uncertain)}' in result.output
    assert 'confirmed=1' in result.output and 'stored=0' in result.output
    if uncertain:
        assert 'last record may already exist' in result.output
    assert SECRET not in result.output and 'Synthetic_Identity' not in result.output
    assert 'Traceback' not in result.output
    assert dc._try_ftp_login.call_count == 1
    dc._try_snmp_community.assert_not_called()


def test_cli_uncertain_preflight_stops_before_any_probe(setup, monkeypatch):
    _, dictionary = setup
    monkeypatch.setattr(cli, '_open_credential_vault', Mock(side_effect=dc.VaultWriteUncertain()))
    result = runner.invoke(cli.app, ['creds_check', '-t', '192.0.2.1', '--dict', str(dictionary)])
    assert result.exit_code == 1 and 'uncertain' in result.output
    assert SECRET not in result.output
    dc._try_ftp_login.assert_not_called(); dc._try_snmp_community.assert_not_called()


@pytest.mark.parametrize('status', [dc.INCONCLUSIVE, dc.ANONYMOUS])
def test_cli_ambiguous_or_anonymous_not_stored(setup, status):
    path, dictionary = setup
    dc._try_ftp_login.return_value = dc.CredentialProbeResult('ftp', status, 'PASSWORD_NOT_CHECKED')
    result = runner.invoke(cli.app, ['creds_check', '-t', '192.0.2.1', '--dict', str(dictionary)], input='y\n')
    assert result.exit_code == 1 and status in result.output
    assert 'confirmed=0' in result.output and 'stored=0' in result.output
    with open_vault(path, PHRASE) as v:
        assert v.list_metadata() == []
