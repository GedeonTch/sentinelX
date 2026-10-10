"""Real local cryptography and temporary files only; no authentication/network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest
import core.credential_vault as cv

PHRASE='A long synthetic vault phrase 47!'
SECRET='NEVER_IN_PLAINTEXT_Secret42'


@pytest.fixture
def path(tmp_path):
    return tmp_path/'private'/'vault.enc'


def record(vault, **overrides):
    kw=dict(service='ftp',endpoint='192.0.2.1:21',context='password',username='TEST_IDENTITY',
            domain='',secret=SECRET,kind='password',proof='AUTHENTICATED')
    kw.update(overrides)
    return vault.record(**kw)


def test_roundtrip_dedup_and_all_identity_dimensions(path):
    with cv.open_vault(path,PHRASE,create=True,writable=True) as v:
        assert v.ready
        assert record(v)
        original=v.list_metadata()[0]['id']
        assert not record(v)
        assert v.list_metadata()[0]['id']==original
        for kw in [dict(username='OTHER_IDENTITY'),dict(domain='OTHER_DOMAIN'),dict(context='other'),
                   dict(secret='OTHER_SECRET'),dict(endpoint='192.0.2.2:21'),dict(service='snmp')]:
            assert record(v,**kw)
        assert len(v.list_metadata())==7
        assert SECRET not in repr(v) and 'TEST_IDENTITY' not in json.dumps(v.list_metadata())
    with cv.open_vault(path,PHRASE) as v:
        assert len(v.list_metadata())==7 and v.reveal(original)['secret']==SECRET
        assert not v.ready
        with pytest.raises(cv.VaultError):record(v)
    for file in path.parent.iterdir():
        if file.is_file():
            assert SECRET.encode() not in file.read_bytes()
            assert b'TEST_IDENTITY' not in file.read_bytes()
    assert v.reveal(original) is None


def test_snmp_exact_community_identity(path):
    with cv.open_vault(path,PHRASE,create=True,writable=True) as v:
        assert record(v,service='snmp',username='',kind='community',secret='one')
        assert record(v,service='snmp',username='',kind='community',secret='two')
        assert not record(v,service='snmp',username='',kind='community',secret='one')
        assert len(v.list_metadata())==2


def test_new_process_recovery_and_backup(path,tmp_path):
    with cv.open_vault(path,PHRASE,create=True,writable=True) as v:
        record(v); key=v.list_metadata()[0]['id']
    # Synthetic test phrase is provided on stdin, never subprocess argv.
    code='''import json,sys
from pathlib import Path
from core.credential_vault import open_vault
phrase, secret = json.loads(sys.stdin.read())
with open_vault(Path(sys.argv[1]),phrase) as v:
    assert v.reveal(sys.argv[2])["secret"] == secret
'''
    child=subprocess.run([sys.executable,'-c',code,str(path),key],input=json.dumps([PHRASE,SECRET]),
                         text=True,capture_output=True,timeout=30,
                         env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    assert child.returncode==0 and child.stdout=='' and child.stderr==''
    backup=tmp_path/'restore'/'vault.enc';backup.parent.mkdir(mode=0o700)
    backup.write_bytes(path.read_bytes());backup.chmod(0o600)
    with cv.open_vault(backup,PHRASE) as v:assert v.reveal(key)['secret']==SECRET


def test_wrong_phrase_and_corruption_never_overwrite(path):
    with cv.open_vault(path,PHRASE,create=True,writable=True) as v:record(v)
    original=path.read_bytes()
    with pytest.raises(cv.VaultError) as caught:
        with cv.open_vault(path,'wrong',create=True,writable=True):pass
    assert path.read_bytes()==original and 'wrong' not in str(caught.value)
    path.write_bytes(original[:-7])
    corrupt=path.read_bytes()
    with pytest.raises(cv.VaultError):
        with cv.open_vault(path,PHRASE,create=True):pass
    assert path.read_bytes()==corrupt


@pytest.mark.parametrize('phrase',['short','x'*30,'x'*1025])
def test_weak_initial_phrase_refused(path,phrase):
    with pytest.raises(cv.VaultError):
        with cv.open_vault(path,phrase,create=True):pass
    assert not path.exists()


def test_absent_not_created_for_consultation(path):
    with pytest.raises(cv.VaultError):
        with cv.open_vault(path,PHRASE):pass
    assert not path.exists()


def test_concurrent_writer_refused(path):
    with cv.open_vault(path,PHRASE,create=True,writable=True):
        with pytest.raises(cv.VaultError,match='locked'):
            with cv.open_vault(path,PHRASE,writable=True):pass


def test_failed_replace_preserves_committed_records(path,monkeypatch):
    with cv.open_vault(path,PHRASE,create=True,writable=True) as v:
        record(v)
        old=path.read_bytes()
        with monkeypatch.context() as m:
            def fail(*a):raise OSError(SECRET)
            m.setattr(cv.os,'replace',fail)
            with pytest.raises(cv.VaultError) as caught:record(v,username='other')
            assert SECRET not in str(caught.value) and not v.ready
        assert path.read_bytes()==old
    with cv.open_vault(path,PHRASE) as v:assert len(v.list_metadata())==1
    assert not list(path.parent.glob('.vault-*'))


def test_write_check_failure_prevents_ready(path,monkeypatch):
    def fail(self):raise OSError(SECRET)
    with cv.open_vault(path,PHRASE,create=True):pass
    monkeypatch.setattr(cv.CredentialVault,'_write',fail)
    with pytest.raises(cv.VaultError,match='write/read'):
        with cv.open_vault(path,PHRASE,writable=True):pass


def test_kdf_header_tampering_rejected_before_derivation(path,monkeypatch):
    with cv.open_vault(path,PHRASE,create=True):pass
    data=json.loads(path.read_bytes());data['header']['kdf'][0]=2**40
    path.write_text(json.dumps(data))
    monkeypatch.setattr(cv,'_derive',lambda *a:pytest.fail('Untrusted KDF parameters reached derivation'))
    with pytest.raises(cv.VaultError):
        with cv.open_vault(path,PHRASE):pass


@pytest.mark.skipif(os.name=='nt',reason='POSIX-specific permissions; Windows requires dedicated ACL lab')
def test_permissions_and_symlink_refused(path,tmp_path):
    with cv.open_vault(path,PHRASE,create=True):pass
    assert path.stat().st_mode & 0o777==0o600
    assert path.parent.stat().st_mode & 0o777==0o700
    path.chmod(0o644)
    with pytest.raises(cv.VaultError,match='private'):
        with cv.open_vault(path,PHRASE):pass
    path.chmod(0o600)
    link=path.parent/'link';link.symlink_to(path)
    with pytest.raises(cv.VaultError):
        with cv.open_vault(link,PHRASE):pass


def test_ciphertext_tampering(path):
    with cv.open_vault(path,PHRASE,create=True):pass
    data=json.loads(path.read_bytes());raw=bytearray(cv._decode(data['data']));raw[-1]^=1
    data['data']=cv._encode(raw);path.write_text(json.dumps(data))
    with pytest.raises(cv.VaultError):
        with cv.open_vault(path,PHRASE):pass


def test_windows_acl_logic_rejects_null_or_broad_acl(tmp_path,monkeypatch):
    """Simulated Win32 APIs only: not a substitute for real Windows validation."""
    import types
    from unittest.mock import Mock
    user,system,other='USER_SID','SYSTEM_SID','EVERYONE_SID'
    acl=Mock();acl.GetAceCount.return_value=2
    acl.GetAce.side_effect=lambda i:((0,0),1,[user,system][i])
    descriptor=Mock();descriptor.GetSecurityDescriptorOwner.return_value=user
    descriptor.GetSecurityDescriptorDacl.return_value=acl
    ws=types.SimpleNamespace(OpenProcessToken=Mock(),GetTokenInformation=lambda *a:(user,),
        TokenUser=1,CreateWellKnownSid=lambda *a:system,WinLocalSystemSid=22,
        ACL=Mock(return_value=acl),ACL_REVISION=2,SetNamedSecurityInfo=Mock(),
        SE_FILE_OBJECT=1,DACL_SECURITY_INFORMATION=4,PROTECTED_DACL_SECURITY_INFORMATION=16,
        OWNER_SECURITY_INFORMATION=1,GetNamedSecurityInfo=lambda *a:descriptor,
        ConvertSidToStringSid=lambda s:s,ACCESS_ALLOWED_ACE_TYPE=0)
    monkeypatch.setitem(sys.modules,'win32security',ws)
    monkeypatch.setitem(sys.modules,'win32api',types.SimpleNamespace(GetCurrentProcess=lambda:1))
    monkeypatch.setitem(sys.modules,'win32con',types.SimpleNamespace(TOKEN_QUERY=8,GENERIC_ALL=0x10000000))
    cv._windows_acl(tmp_path,create=True)
    assert ws.SetNamedSecurityInfo.call_count==1
    acl.GetAce.side_effect=lambda i:((0,0),1,[user,other][i])
    with pytest.raises(cv.VaultError):cv._windows_acl(tmp_path,create=False)
    descriptor.GetSecurityDescriptorDacl.return_value=None
    with pytest.raises(cv.VaultError):cv._windows_acl(tmp_path,create=False)


def test_keyboard_interrupt_releases_preparation_lock(path,monkeypatch):
    real=cv._derive
    monkeypatch.setattr(cv,'_derive',lambda *a:(_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        with cv.open_vault(path,PHRASE,create=True):pass
    monkeypatch.setattr(cv,'_derive',real)
    with cv.open_vault(path,PHRASE,create=True,writable=True) as v:assert v.ready


@pytest.mark.skipif(os.name=='nt',reason='Windows read-only attribute needs Windows validation')
def test_readonly_vault_consultation_not_testing(path):
    with cv.open_vault(path,PHRASE,create=True,writable=True) as v:record(v)
    before=path.read_bytes();path.chmod(0o400)
    with cv.open_vault(path,PHRASE) as v:assert len(v.list_metadata())==1
    with pytest.raises(cv.VaultError,match='read-only'):
        with cv.open_vault(path,PHRASE,writable=True):pass
    assert path.read_bytes()==before


def test_certain_failure_before_replace_is_distinct(path, monkeypatch):
    with cv.open_vault(path, PHRASE, create=True, writable=True) as v:
        record(v)
        original = path.read_bytes()
        with monkeypatch.context() as m:
            replace = __import__('unittest.mock', fromlist=['Mock']).Mock()
            m.setattr(cv.os, 'replace', replace)
            m.setattr(cv.os, 'fsync', lambda fd: (_ for _ in ()).throw(OSError(SECRET)))
            with pytest.raises(cv.VaultError) as caught:
                record(v, username='SecondOriginalIdentity')
            assert type(caught.value) is cv.VaultError
            assert SECRET not in str(caught.value) and not v.ready
            replace.assert_not_called()
        assert path.read_bytes() == original
    with cv.open_vault(path, PHRASE) as v:
        assert len(v.list_metadata()) == 1


@pytest.mark.parametrize('phase', ['replace_ack', 'directory_fsync', 'read_back', 'read_mismatch', 'interrupt'])
def test_post_replace_failure_is_uncertain_and_recoverable(path, monkeypatch, phase):
    if phase == 'directory_fsync' and os.name == 'nt':
        pytest.skip('POSIX directory fsync; not a Windows validation')
    with cv.open_vault(path, PHRASE, create=True, writable=True) as v:
        record(v)
        with monkeypatch.context() as m:
            original_replace, original_fsync = cv.os.replace, cv.os.fsync
            if phase == 'replace_ack':
                def replace_then_fail(src, dst):
                    original_replace(src, dst)
                    raise OSError(SECRET)
                m.setattr(cv.os, 'replace', replace_then_fail)
            elif phase == 'directory_fsync':
                count = 0
                def fail_second(fd):
                    nonlocal count
                    count += 1
                    if count == 2:
                        raise OSError(SECRET)
                    original_fsync(fd)
                m.setattr(cv.os, 'fsync', fail_second)
            elif phase == 'read_mismatch':
                m.setattr(v, '_payload', lambda raw: {'records': []})
            else:
                def fail_read(path):
                    if phase == 'interrupt':
                        raise KeyboardInterrupt
                    raise OSError(SECRET)
                m.setattr(cv, '_read', fail_read)
            with pytest.raises(cv.VaultWriteUncertain) as caught:
                record(v, username='SecondOriginalIdentity', secret='ExactSecondSyntheticSecret')
            assert caught.value.interrupted == (phase == 'interrupt')
            assert not v.ready and SECRET not in str(caught.value)
            assert 'uncertain' in str(caught.value)
            with pytest.raises(cv.VaultError): record(v, username='NeverRetried')
    # Visibility in this process is tested, not crash-proof durability after a power loss.
    with cv.open_vault(path, PHRASE) as v:
        assert len(v.list_metadata()) == 2
        rows = [v.reveal(meta['id']) for meta in v.list_metadata()]
        assert rows[1]['username'] == 'SecondOriginalIdentity'
        assert rows[1]['secret'] == 'ExactSecondSyntheticSecret'
    for file in path.parent.iterdir():
        if file.is_file():
            assert SECRET.encode() not in file.read_bytes()
            assert b'ExactSecondSyntheticSecret' not in file.read_bytes()
    assert not list(path.parent.glob('.vault-*'))


def test_preflight_preserves_uncertain_exception_type(path, monkeypatch):
    with cv.open_vault(path, PHRASE, create=True): pass
    def fail_write(self): raise cv.VaultWriteUncertain()
    monkeypatch.setattr(cv.CredentialVault, '_write', fail_write)
    with pytest.raises(cv.VaultWriteUncertain):
        with cv.open_vault(path, PHRASE, writable=True):
            pytest.fail('Uncertain preflight must never yield a ready vault')


def test_vault_preserves_case_even_when_attempt_budget_folds_case(path):
    with cv.open_vault(path, PHRASE, create=True, writable=True) as v:
        assert record(v, username='User')
        assert record(v, username='user')  # exact vault dedup, distinct across runs
        rows = [v.reveal(meta['id']) for meta in v.list_metadata()]
        assert [row['username'] for row in rows] == ['User', 'user']
