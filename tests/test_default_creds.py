"""T22: simulated FTP/SNMP only. No live network or authentication."""
from unittest.mock import Mock
import ftplib
import json
import socket
import pytest
import typer
from core.finding import Category, Confidence, FindingStatus, Severity
import detect.default_creds as dc
from detect.credential_dictionary import Candidate, load_catalog
from detect.credential_snmp import *

HOST, SESSION = '192.0.2.10', 'test-creds'
CANARY = 'SYNTHETIC_SECRET_42'


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr(dc.socket, 'socket', Mock(side_effect=AssertionError('No real network')))
    monkeypatch.setattr(dc.typer, 'confirm', Mock(return_value=True))
    monkeypatch.setattr(dc.time, 'sleep', lambda seconds: None)


@pytest.fixture
def sink():
    return Mock(ready=True, record=Mock(return_value=True))


def run(monkeypatch, sink, candidates, outcomes, services=('ftp','snmp')):
    monkeypatch.setattr(dc, '_try_ftp_login', Mock(side_effect=outcomes))
    monkeypatch.setattr(dc, '_try_snmp_community', Mock(side_effect=outcomes))
    report=dc.CheckReport()
    findings=dc.check_default_creds(HOST,SESSION,candidates=candidates,recorder=sink,report=report,services=services)
    return findings,report


def ftp(user='u',password=CANARY, qualified=False):
    return Candidate('ftp',user,password,qualified=qualified,
                     provenance=load_catalog('tp-link-td-w8990-guide')[0].provenance if qualified else None)


def success(protocol='ftp', detail='AUTHENTICATED'):
    return dc.CredentialProbeResult(protocol,dc.SUCCESS,detail)


def test_multiple_identities_one_finding_skip_same_identity(monkeypatch,sink):
    candidates=[ftp('a',qualified=True),ftp('a','OTHER_SECRET',True),ftp('b',qualified=True)]
    findings,report=run(monkeypatch,sink,candidates,[success(),success()])
    assert len(findings)==1 and sink.record.call_count==2
    r=report.services[0]
    assert r.attempts==2 and r.created==2 and r.skipped['IDENTITY_ALREADY_AUTHENTICATED']==1
    f=findings[0]
    assert (f.category,f.severity,f.confidence)==(Category.CREDENTIAL,Severity.HIGH,Confidence.CONFIRMED)
    assert f.risk_score is None and f.explanation is None and f.status==FindingStatus.OPEN
    assert CANARY not in json.dumps(f.to_dict())
    assert 'successful_usernames' not in f.evidence.raw


def test_custom_success_not_qualified(monkeypatch,sink):
    findings,report=run(monkeypatch,sink,[ftp()],[success()])
    assert findings==[] and report.services[0].created==1


@pytest.mark.parametrize('state',[dc.NO_MATCH,dc.TIMEOUT,dc.INACCESSIBLE,dc.ERROR,dc.INCONCLUSIVE])
def test_normalized_non_success(monkeypatch,sink,state):
    findings,report=run(monkeypatch,sink,[ftp(qualified=True)],[dc.CredentialProbeResult('ftp',state)])
    assert findings==[] and report.services[0].outcomes[state]==1
    sink.record.assert_not_called()


def test_vault_mandatory_before_any_prompt(sink):
    sink.ready=False
    with pytest.raises(dc.VaultError):dc.check_default_creds(HOST,SESSION,recorder=sink)
    dc.typer.confirm.assert_not_called()


def test_confirmation_per_service_not_candidate(monkeypatch,sink):
    monkeypatch.setattr(dc.typer,'confirm',Mock(side_effect=[False,True]))
    cs=[ftp(),Candidate('snmp',community=CANARY)]
    findings,report=run(monkeypatch,sink,cs,[success('snmp')])
    assert dc.typer.confirm.call_count==2
    dc._try_ftp_login.assert_not_called()
    assert report.services[0].state=='cancelled'
    assert report.services[1].created==1


def test_missing_implicit_service_no_prompt(monkeypatch,sink):
    _,report=run(monkeypatch,sink,[ftp()],[success()])
    assert dc.typer.confirm.call_count==1
    assert report.services[1].reason=='NO_COMPATIBLE_CANDIDATE'


def test_two_snmp_communities_distinct(monkeypatch,sink):
    cs=[Candidate('snmp',community='one',qualified=True,provenance=load_catalog('cisco-wlc-7.4')[0].provenance),Candidate('snmp',community='two',qualified=True,provenance=load_catalog('cisco-wlc-7.4')[0].provenance)]
    fs,r=run(monkeypatch,sink,cs,[success('snmp','READ_OK'),success('snmp','OID_UNAVAILABLE')])
    assert len(fs)==1 and sink.record.call_count==2
    assert r.services[1].created==2
    assert 'one' not in fs[0].evidence.raw and 'two' not in fs[0].evidence.raw


def test_account_and_service_budgets(monkeypatch,sink):
    cs=[ftp('a',str(i)) for i in range(3)]+[ftp('b'),ftp('c')]
    _,r=run(monkeypatch,sink,cs,[dc.CredentialProbeResult('ftp',dc.NO_MATCH)]*3)
    assert r.services[0].attempts==3 and r.services[0].skipped['BUDGET']==2


def test_exact_duplicates_not_retested(monkeypatch,sink):
    _,r=run(monkeypatch,sink,[ftp(),ftp()],[dc.CredentialProbeResult('ftp',dc.NO_MATCH)])
    assert r.services[0].candidates==1 and r.services[0].attempts==1


def test_save_failure_stops_everything_preserves_finding(monkeypatch,sink,capsys):
    sink.record.side_effect=RuntimeError(CANARY)
    fs,r=run(monkeypatch,sink,[ftp(qualified=True),ftp('other'),Candidate('snmp',community='x')],[success()])
    assert len(fs)==1 and r.services[0].save_uncertain==1
    assert r.services[0].attempts==1 and r.services[1].attempts==0
    assert CANARY not in capsys.readouterr().out


def test_lockout_stops_all(monkeypatch,sink):
    _,r=run(monkeypatch,sink,[ftp(),Candidate('snmp',community='x')],[dc.CredentialProbeResult('ftp',dc.LOCKED)])
    assert r.services[1].attempts==0


def test_unexpected_error_has_no_secret(monkeypatch,sink,capsys):
    _,r=run(monkeypatch,sink,[ftp(),ftp('next')],[RuntimeError(CANARY)])
    assert r.services[0].outcomes[dc.ERROR]==1 and r.services[0].attempts==1
    assert CANARY not in repr(r) and CANARY not in capsys.readouterr().out


@pytest.mark.parametrize('interrupt',[KeyboardInterrupt,typer.Abort])
def test_interrupt_preserves_previous_records(monkeypatch,sink,interrupt):
    monkeypatch.setattr(dc,'_try_ftp_login',Mock(side_effect=[success(),interrupt()]))
    r=dc.CheckReport()
    with pytest.raises(interrupt):dc.check_default_creds(HOST,SESSION,candidates=[ftp('a'),ftp('b')],recorder=sink,report=r)
    assert sink.record.call_count==1 and r.interrupted
    assert r.services[0].outcomes['CANCELLED']==1


@pytest.mark.parametrize('phase,code,expected',[
    ('connect','530 denied',dc.INACCESSIBLE),('user','530 rejected',dc.NO_MATCH),
    ('password','530 rejected',dc.NO_MATCH),('password','550 unavailable',dc.ERROR),
    ('password','530 account locked',dc.LOCKED),
])
def test_ftp_phase_classification(monkeypatch,phase,code,expected):
    client=Mock()
    if phase=='connect':client.connect.side_effect=ftplib.error_perm(code+' '+CANARY)
    elif phase=='user':client.sendcmd.side_effect=ftplib.error_perm(code+' '+CANARY)
    else:client.sendcmd.side_effect=['331 password',ftplib.error_perm(code+' '+CANARY)]
    monkeypatch.setattr(dc,'_BoundedFTP',Mock(return_value=client))
    result=dc._try_ftp_login(HOST,'u',CANARY)
    assert result.status==expected and CANARY not in repr(result)
    client.close.assert_called_once()


@pytest.mark.parametrize('replies,status',[
    (['331 password','230 logged in'],dc.SUCCESS),
    (['230 anonymous'],dc.ANONYMOUS),(['331 password','230 guest session'],dc.ANONYMOUS),
    (['331 password','332 account needed'],dc.INCONCLUSIVE),
])
def test_ftp_complete_password_auth_only(monkeypatch,replies,status):
    client=Mock();client.sendcmd.side_effect=replies
    monkeypatch.setattr(dc,'_BoundedFTP',Mock(return_value=client))
    assert dc._try_ftp_login(HOST,'u',CANARY).status==status
    client.close.assert_called_once()


@pytest.mark.parametrize('exc,status',[(socket.timeout(),dc.TIMEOUT),(ConnectionRefusedError(),dc.INACCESSIBLE),(OSError(CANARY),dc.ERROR)])
def test_ftp_transport(monkeypatch,exc,status):
    client=Mock();client.connect.side_effect=exc
    monkeypatch.setattr(dc,'_BoundedFTP',Mock(return_value=client))
    assert dc._try_ftp_login(HOST,'u',CANARY).status==status


def response(community='test',request_id=42,error=0,index=0,oid=bytes.fromhex('2b06010201010100'),version=0,pdu=0xA2):
    value=tlv(4,b'description') if error==0 else tlv(5,b'')
    bindings=tlv(0x30,tlv(0x30,tlv(6,oid)+value))
    return tlv(0x30,integer(version)+tlv(4,community.encode())+tlv(pdu,integer(request_id)+integer(error)+integer(index)+bindings))


@pytest.mark.parametrize('error,index,result',[(0,0,'READ_OK'),(2,1,'OID_UNAVAILABLE'),(1,0,'INDICATIVE'),(5,1,'INDICATIVE'),(3,1,'INDICATIVE'),(4,1,'INDICATIVE')])
def test_snmp_acceptance_separate_from_read(error,index,result):
    assert classify_response(response(error=error,index=index),'test',42)==result


@pytest.mark.parametrize('data',[
    b'\x30not-snmp',b'\x30\x80',b'\x01bad',b'',response()[:-1],response()+b'x',
    response(request_id=43),response(community='other'),response(version=1),
    response(pdu=0xA0),response(oid=b'\x2b\x01'),response(error=2,index=0),
    response(error=6,index=1),response(index=1),
])
def test_invalid_snmp_never_accepted(data):
    with pytest.raises(InvalidResponse):classify_response(data,'test',42)


def snmp_socket(monkeypatch,events):
    sock=Mock();sock.recvfrom.side_effect=events
    manager=Mock();manager.__enter__=Mock(return_value=sock);manager.__exit__=Mock(return_value=False)
    monkeypatch.setattr(dc.socket,'socket',Mock(return_value=manager))
    monkeypatch.setattr(dc,'new_request_id',lambda:42)
    return sock


def test_snmp_foreign_then_valid(monkeypatch):
    sock=snmp_socket(monkeypatch,[(response(),('192.0.2.99',161)),(response(),(HOST,999)),(response(),(HOST,161))])
    assert dc._try_snmp_community(HOST,'test').status==dc.SUCCESS
    assert sock.sendto.call_count==1 and sock.recvfrom.call_count==3


@pytest.mark.parametrize('events,status',[
    ([socket.timeout()],dc.TIMEOUT),
    ([(b'\x30bad',(HOST,161)),socket.timeout()],dc.INCONCLUSIVE),
    ([(response(request_id=1),(HOST,161))]*16,dc.INCONCLUSIVE),
    ([(response(error=5,index=1),(HOST,161))],dc.INCONCLUSIVE),
    ([(response(error=2,index=1),(HOST,161))],dc.SUCCESS),
    ([ConnectionRefusedError()],dc.INACCESSIBLE),([OSError(CANARY)],dc.ERROR),
])
def test_snmp_transport_outcomes(monkeypatch,events,status):
    sock=snmp_socket(monkeypatch,events)
    result=dc._try_snmp_community(HOST,'test')
    assert result.status==status and CANARY not in repr(result)
    assert sock.sendto.call_count==1


@pytest.mark.parametrize('value',['é','x\n','', 'x'*65])
def test_community_not_silently_modified(value):
    with pytest.raises(ValueError):build_get(value,42)


def test_packet_and_request_id():
    assert dc._build_snmp_v1_get('test')[0]==0x30
    assert b'test' in build_get('test',42)
    assert build_get('test',42)!=build_get('test',43)


def test_global_budget_even_with_distinct_services(monkeypatch,sink):
    monkeypatch.setattr(dc,'MAX_TOTAL',2)
    cs=[ftp('a'),ftp('b'),Candidate('snmp',community='x')]
    _,r=run(monkeypatch,sink,cs,[success(),success()])
    assert sum(s.attempts for s in r.services)==2
    assert r.services[1].skipped['BUDGET']==1


def test_deadline_prevents_attempt(monkeypatch,sink):
    clock=Mock(side_effect=[0,25,25,25])
    monkeypatch.setattr(dc.time,'monotonic',clock)
    _,r=run(monkeypatch,sink,[ftp()],[success()])
    assert r.services[0].attempts==0 and r.services[0].skipped['SERVICE_DEADLINE']==1


def test_interval_respected(monkeypatch,sink):
    monkeypatch.setattr(dc.time,'monotonic',lambda:0)
    sleep=Mock();monkeypatch.setattr(dc.time,'sleep',sleep)
    run(monkeypatch,sink,[ftp('a'),ftp('b')],[success(),success()])
    sleep.assert_called_once_with(2)


def test_bounded_ftp_trickle_and_line_limit(monkeypatch):
    client=dc._BoundedFTP(2)
    client.sock=Mock();client.sock.recv.return_value=b'x'
    monkeypatch.setattr(dc.time,'monotonic',Mock(side_effect=[0,1,3]))
    with pytest.raises(socket.timeout):client.getline()
    monkeypatch.setattr(dc.time,'monotonic',lambda:0)
    client.maxline=2
    with pytest.raises(ftplib.Error):client.getline()


def test_snmp_error_packet_no_leak_in_report(monkeypatch,sink,capsys,caplog):
    # A malicious response value never becomes evidence or a log.
    snmp_socket(monkeypatch,[(b'\x30'+CANARY.encode(),(HOST,161)),socket.timeout()])
    report=dc.CheckReport()
    fs=dc.check_default_creds(HOST,SESSION,candidates=[Candidate('snmp',community='test')],recorder=sink,report=report)
    assert fs==[] and report.services[1].outcomes[dc.INCONCLUSIVE]==1
    assert CANARY not in repr(report)+capsys.readouterr().out+caplog.text


def test_no_secret_in_session_json_html(monkeypatch,sink,tmp_path,capsys,caplog):
    import core.database as db
    from reports.generator import generate_report
    monkeypatch.setattr(db,'get_db_path',lambda sid:tmp_path/f'{sid}.db')
    fs,r=run(monkeypatch,sink,[ftp('IDENTITY_CANARY',CANARY,True)],[success()])
    db.init_db(SESSION);db.save_session(SESSION,target=HOST);db.save_findings(fs)
    for fmt in ('html','json'):
        output=tmp_path/f'report.{fmt}'
        assert generate_report(SESSION,fmt,str(output))
        text=output.read_text()
        assert CANARY not in text and 'IDENTITY_CANARY' not in text
    assert CANARY.encode() not in (tmp_path/f'{SESSION}.db').read_bytes()
    assert 'IDENTITY_CANARY'.encode() not in (tmp_path/f'{SESSION}.db').read_bytes()
    assert CANARY not in capsys.readouterr().out+caplog.text


def test_second_save_failure_preserves_first_and_stops(monkeypatch,sink):
    sink.record.side_effect=[True,RuntimeError(CANARY)]
    cs=[ftp('a',qualified=True),ftp('b',qualified=True),ftp('c'),Candidate('snmp',community='x')]
    fs,r=run(monkeypatch,sink,cs,[success(),success()])
    assert len(fs)==1 and r.services[0].created==1 and r.services[0].save_uncertain==1
    assert r.services[0].outcomes[dc.SUCCESS]==2
    assert r.services[0].attempts==2 and r.services[1].attempts==0
    assert r.services[0].state=='partial'


def test_case_aliases_cannot_bypass_account_budget(monkeypatch,sink):
    cs=[ftp('User','one'),ftp('user','two'),ftp('USER','three')]
    _,r=run(monkeypatch,sink,cs,[dc.CredentialProbeResult('ftp',dc.NO_MATCH)]*2)
    assert r.services[0].attempts==2 and r.services[0].skipped['BUDGET']==1


def test_temporary_lockout_stops_all(monkeypatch):
    client=Mock();client.connect.side_effect=ftplib.error_temp('421 too many attempts '+CANARY)
    monkeypatch.setattr(dc,'_BoundedFTP',Mock(return_value=client))
    result=dc._try_ftp_login(HOST,'user',CANARY)
    assert result.status==dc.LOCKED and CANARY not in repr(result)


def test_ftp_multiline_reply_is_bounded(monkeypatch):
    client=dc._BoundedFTP(10)
    monkeypatch.setattr(client,'getline',Mock(return_value='220-continue'))
    with pytest.raises(ftplib.Error):client.getmultiline()
    assert client.getline.call_count==16
    monkeypatch.setattr(client,'getline',Mock(side_effect=['220-welcome','notice','220 ready']))
    assert client.getmultiline().endswith('220 ready')


def test_nonminimal_ber_integer_rejected():
    with pytest.raises(InvalidResponse):Reader(b'\x02\x02\x00\x00').number()


def test_malformed_ftp_success_code_not_accepted(monkeypatch):
    client=Mock();client.sendcmd.side_effect=['331 password','230not-a-valid-reply']
    monkeypatch.setattr(dc,'_BoundedFTP',Mock(return_value=client))
    assert dc._try_ftp_login(HOST,'u',CANARY).status!=dc.SUCCESS


@pytest.mark.parametrize('username,replies,status', [
    ('ftp', ['331 Password required', '230 Login successful.'], dc.INCONCLUSIVE),
    ('FTP', ['331 Password required', '230 Login successful.'], dc.INCONCLUSIVE),
    (' ftp ', ['331 Password required', '230 Login successful.'], dc.INCONCLUSIVE),
    ('guest', ['331 Password required', '230 Login successful.'], dc.INCONCLUSIVE),
    ('ftp', ['331 Password required', '230 Anonymous access granted'], dc.ANONYMOUS),
    ('NamedUser', ['331 Guest login; send email', '230 Login successful.'], dc.ANONYMOUS),
    ('NamedUser', ['230 Login successful.'], dc.INCONCLUSIVE),
    ('NamedUser', ['331 Password required', '230 Login successful.'], dc.SUCCESS),
])
def test_ftp_alias_and_access_classification_end_to_end(monkeypatch, sink, username, replies, status):
    client = Mock(); client.sendcmd.side_effect = replies
    monkeypatch.setattr(dc, '_BoundedFTP', Mock(return_value=client))
    report = dc.CheckReport()
    findings = dc.check_default_creds(HOST, SESSION, candidates=[ftp(username, qualified=True)],
                                     services=('ftp',), recorder=sink, report=report)
    assert report.services[0].outcomes[status] == 1
    assert sink.record.call_count == int(status == dc.SUCCESS)
    assert len(findings) == int(status == dc.SUCCESS)
    assert CANARY not in repr(report)
    client.close.assert_called_once()


def test_authenticated_casefold_uses_budget_key_and_preserves_original(monkeypatch, sink):
    candidates = [ftp('User'), ftp('user', 'DIFFERENT_SYNTHETIC_SECRET'), ftp('Other')]
    _, report = run(monkeypatch, sink, candidates, [success(), success()])
    assert dc._try_ftp_login.call_count == 2
    assert [c.args[1] for c in dc._try_ftp_login.call_args_list] == ['User', 'Other']
    assert [c.kwargs['username'] for c in sink.record.call_args_list] == ['User', 'Other']
    assert sink.record.call_args_list[0].kwargs['secret'] == CANARY
    assert report.services[0].skipped['IDENTITY_ALREADY_AUTHENTICATED'] == 1
    assert report.services[0].attempts == 2


def test_snmp_case_is_exact_after_success(monkeypatch, sink):
    candidates = [Candidate('snmp', community='CaseSensitive'), Candidate('snmp', community='casesensitive')]
    _, report = run(monkeypatch, sink, candidates, [success('snmp'), success('snmp')])
    assert report.services[1].attempts == 2
    assert [c.kwargs['secret'] for c in sink.record.call_args_list] == ['CaseSensitive', 'casesensitive']


@pytest.mark.parametrize('profile', ['tp-link-td-w8990-guide', 'cisco-wlc-7.4'])
def test_real_catalog_provenance_reaches_evidence_without_candidate_reference(monkeypatch, sink, profile):
    candidates = load_catalog(profile)
    protocol = candidates[0].service
    findings, _ = run(monkeypatch, sink, candidates,
                      [success(protocol, 'READ_OK' if protocol == 'snmp' else 'AUTHENTICATED')] * len(candidates))
    assert len(findings) == 1
    evidence = json.loads(findings[0].evidence.raw)
    expected = candidates[0].provenance.as_evidence()
    assert evidence['provenance'] == [expected]
    assert expected['profile_id'] == profile
    assert expected['catalog_version'] == '2026-10-10.2'
    assert all(ref['url'].startswith('https://') and ref['section'] for ref in expected['documentation'])
    assert set(evidence) == {'service', 'authentication', 'qualified_success_count', 'qualified_proofs', 'proof_scope', 'provenance'}
    for forbidden in ('username', 'password', 'community', 'candidate_id', 'candidate_index', 'secret_hash', 'vault_id'):
        assert f'"{forbidden}"' not in findings[0].evidence.raw
    for c in candidates:
        assert f'"{c.secret()}"' not in findings[0].evidence.raw


def test_bare_qualification_flag_cannot_qualify_and_custom_remains_unqualified(monkeypatch, sink):
    for candidate in [Candidate('ftp', 'SyntheticUser', CANARY, qualified=True), ftp()]:
        findings, _ = run(monkeypatch, sink, [candidate], [success()])
        assert not findings


def test_unverified_brocade_profile_does_not_qualify_or_expand_budget(monkeypatch, sink):
    candidates = load_catalog('brocade-fos-legacy-snmp')
    findings, report = run(monkeypatch, sink, candidates, [success('snmp')] * len(candidates))
    assert not findings
    assert report.services[1].attempts == 3 and report.services[1].skipped['BUDGET'] == 3
    assert (dc.MAX_SERVICE, dc.MAX_ACCOUNT, dc.MAX_TOTAL) == (3, 2, 10)


@pytest.mark.parametrize('error,certain,uncertain', [
    (dc.VaultError('Safe pre-replacement error'), 1, 0),
    (dc.VaultWriteUncertain(), 0, 1),
    (RuntimeError(CANARY), 0, 1),
])
def test_save_outcomes_distinct_stop_all_without_fallback(monkeypatch, sink, error, certain, uncertain, capsys):
    sink.record.side_effect = error
    candidates = [ftp('User', qualified=True), ftp('Other'), Candidate('snmp', community=CANARY)]
    findings, report = run(monkeypatch, sink, candidates, [success()])
    r = report.services[0]
    assert (r.save_failures, r.save_uncertain, r.created, r.updated) == (certain, uncertain, 0, 0)
    assert r.state == 'partial' and r.attempts == 1
    assert report.services[1].reason == 'GLOBAL_STOP'
    dc._try_snmp_community.assert_not_called()
    assert len(findings) == 1  # protocol proof exists independently of local persistence
    assert CANARY not in json.dumps(findings[0].to_dict()) + repr(report) + capsys.readouterr().out


def test_interrupted_commit_counted_uncertain_without_next_probe(monkeypatch, sink):
    sink.record.side_effect = dc.VaultWriteUncertain(interrupted=True)
    probe = Mock(return_value=success()); monkeypatch.setattr(dc, '_try_ftp_login', probe)
    report = dc.CheckReport()
    with pytest.raises(KeyboardInterrupt):
        dc.check_default_creds(HOST, SESSION, candidates=[ftp(), ftp('Other')], services=('ftp',), recorder=sink, report=report)
    assert report.interrupted and report.services[0].save_uncertain == 1
    assert probe.call_count == 1


# Independent wire vectors: no SYS_DESCR, tlv(), integer(), Reader or response().
# Community "test", request-id 42; sysDescr.0 = 1.3.6.1.2.1.1.1.0.
_REFERENCE_GET = bytes.fromhex(
    '3024 020100 040474657374 a019 02012a 020100 020100'
    '300e 300c 0608 2b06010201010100 0500'
)
_REFERENCE_READ = bytes.fromhex(
    '3025 020100 040474657374 a21a 02012a 020100 020100'
    '300f 300d 0608 2b06010201010100 040178'
)
_REFERENCE_NO_SUCH_NAME = bytes.fromhex(
    '3024 020100 040474657374 a219 02012a 020102 020101'
    '300e 300c 0608 2b06010201010100 0500'
)
# Old incorrect OID: 1.3.6.1.2.1.1.1.1.0; BER lengths adjusted independently.
_OLD_OID_READ = bytes.fromhex(
    '3026 020100 040474657374 a21b 02012a 020100 020100'
    '3010 300e 0609 2b0601020101010100 040178'
)
_OLD_OID_NO_SUCH_NAME = bytes.fromhex(
    '3025 020100 040474657374 a21a 02012a 020102 020101'
    '300f 300d 0609 2b0601020101010100 0500'
)
_WRONG_REQUEST_READ = bytes.fromhex(
    '3025 020100 040474657374 a21a 02012b 020100 020100'
    '300f 300d 0608 2b06010201010100 040178'
)


def test_snmp_get_matches_independent_sysdescr_wire_vector():
    # Exact whole-packet equality checks OID content, location, tag and lengths.
    assert build_get('test', 42) == _REFERENCE_GET


@pytest.mark.parametrize('packet,expected', [
    (_REFERENCE_READ, 'READ_OK'),
    (_REFERENCE_NO_SUCH_NAME, 'OID_UNAVAILABLE'),
])
def test_snmp_parser_accepts_independent_sysdescr_vectors(packet, expected):
    assert classify_response(packet, 'test', 42) == expected


@pytest.mark.parametrize('packet,reason', [
    (_OLD_OID_READ, 'Uncorrelated OID'),
    (_OLD_OID_NO_SUCH_NAME, 'Uncorrelated OID'),
    (_REFERENCE_READ[:-1], 'Invalid BER size'),
    (_WRONG_REQUEST_READ, 'Uncorrelated request'),
])
def test_snmp_parser_rejects_independent_invalid_vectors(packet, reason):
    with pytest.raises(InvalidResponse, match=reason):
        classify_response(packet, 'test', 42)


@pytest.mark.parametrize('packet,status,detail', [
    (_REFERENCE_READ, dc.SUCCESS, 'READ_OK'),
    (_REFERENCE_NO_SUCH_NAME, dc.SUCCESS, 'OID_UNAVAILABLE'),
    (_OLD_OID_READ, dc.INCONCLUSIVE, 'NO_CORRELATED_RESPONSE'),
    (_OLD_OID_NO_SUCH_NAME, dc.INCONCLUSIVE, 'NO_CORRELATED_RESPONSE'),
    (_REFERENCE_READ[:-1], dc.INCONCLUSIVE, 'NO_CORRELATED_RESPONSE'),
    (_WRONG_REQUEST_READ, dc.INCONCLUSIVE, 'NO_CORRELATED_RESPONSE'),
])
def test_snmp_independent_vectors_transport_and_conservation(monkeypatch, sink, packet, status, detail):
    sock = snmp_socket(monkeypatch, [(packet, (HOST, 161)), socket.timeout()])
    report = dc.CheckReport()
    findings = dc.check_default_creds(
        HOST, SESSION, candidates=[Candidate('snmp', community='test')],
        services=('snmp',), recorder=sink, report=report,
    )
    assert report.services[0].outcomes[status] == 1
    assert report.services[0].details[detail] == 1
    assert sink.record.call_count == int(status == dc.SUCCESS)
    assert findings == []  # custom candidate never qualifies automatically
    sock.sendto.assert_called_once_with(_REFERENCE_GET, (HOST, 161))
