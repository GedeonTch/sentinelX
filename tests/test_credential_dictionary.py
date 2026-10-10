"""No network: bounded JSONL preparation and catalog qualification."""
import json
from pathlib import Path
import pytest
from detect.credential_dictionary import *


def file(tmp_path, rows):
    p = tmp_path / 'dictionary with spaces.txt'
    p.write_text('\n'.join(json.dumps(r) for r in rows), encoding='utf-8')
    return p


def test_exact_special_values(tmp_path):
    row = dict(service='ftp', username=' spaced user ', password=' :;\\" secret ')
    c, = load_dictionary(file(tmp_path, [row]))
    assert c.username == row['username'] and c.password == row['password']
    assert c.password not in repr(c)
    assert not c.qualified


@pytest.mark.parametrize('row', [
    {}, [], {'service':'unknown'},
    {'service':'ftp','username':'u'},
    {'service':'ftp','username':'u','password':'p','host':'example'},
    {'service':'ftp','username':'u','password':'p','domain':'d'},
    {'service':'ftp','username':'u','password':True},
    {'service':'ftp','username':'','password':'p'},
    {'service':'ftp','username':'anonymous','password':'p'},
    {'service':'ftp','username':'u','password':'é'},
    {'service':'ftp','username':'u','password':'line\nbreak'},
    {'service':'ftp','username':'u','password':'p'*1025},
    {'service':'snmp','community':'é'},
    {'service':'snmp','community':''},
    {'service':'snmp','community':'x'*65},
    {'service':'snmp','community':'x','password':'y'},
])
def test_invalid_rows_do_not_disclose_values(tmp_path, row):
    with pytest.raises(DictionaryError) as caught:
        load_dictionary(file(tmp_path, [row]))
    assert str(caught.value) == 'Invalid dictionary structure at line 1'


@pytest.mark.parametrize('raw', [b'\xff', b'', b' \n', b'{"service":"ftp","service":"snmp"}',
                                   b'x'*(MAX_BYTES+1), b' '* (MAX_LINE+1)])
def test_invalid_files(tmp_path, raw):
    p = tmp_path / 'in.txt'; p.write_bytes(raw)
    with pytest.raises(DictionaryError):
        load_dictionary(p)


def test_all_file_validated_and_limit_before_dedup(tmp_path):
    row = dict(service='ftp', username='u', password='SAFE_SYNTHETIC_CANARY')
    p = file(tmp_path, [row]*501)
    with pytest.raises(DictionaryError):load_dictionary(p)
    p = file(tmp_path, [row]); p.write_text(p.read_text()+'\ninvalid SAFE_SYNTHETIC_CANARY')
    with pytest.raises(DictionaryError) as caught:load_dictionary(p)
    assert 'CANARY' not in str(caught.value)


def test_bom_crlf_blanks_dedup(tmp_path):
    row = dict(service='snmp', community='test')
    p = file(tmp_path, [row,row])
    p.write_bytes(b'\xef\xbb\xbf'+p.read_bytes().replace(b'\n',b'\r\n')+b'\r\n')
    assert len(load_dictionary(p)) == 1


def test_selection_and_replacement(tmp_path):
    p = file(tmp_path, [dict(service='ftp',username='u',password='p')])
    cs, ss = prepare_candidates(p, ())
    assert ss == ('ftp','snmp') and len(cs)==1
    with pytest.raises(DictionaryError):prepare_candidates(p, ('ftp','snmp'))
    assert prepare_candidates(p, ('ftp','ftp'))[1] == ('ftp',)
    with pytest.raises(DictionaryError):prepare_candidates(p, ('ssh',))
    with pytest.raises(DictionaryError):prepare_candidates(p, (), 'legacy')


def test_dictionary_never_enables_ssh(tmp_path):
    p=file(tmp_path,[dict(service='ssh',username='u',password='p')])
    with pytest.raises(DictionaryError):prepare_candidates(p, ())


def test_missing_and_directory(tmp_path):
    for p in [tmp_path, tmp_path/'missing']:
        with pytest.raises(DictionaryError):load_dictionary(p)


def test_catalog_honest_provenance():
    assert len(load_catalog()) == 5
    assert not any(c.qualified for c in load_catalog())
    sourced=load_catalog('cisco-wlc-7.4')
    assert all(c.qualified and c.service=='snmp' for c in sourced)
    with pytest.raises(DictionaryError):load_catalog('unknown')


def test_catalog_expanded_product_sources_and_safe_provenance():
    document = json.loads(CATALOG.read_text())
    assert document['catalog_version'] == '2026-10-10.2'
    unique = set()
    for key, profile in document['profiles'].items():
        candidates = load_catalog(key)
        assert profile['product_family'] and profile['versions'] and profile['limits']
        for c in candidates:
            unique.add((c.service, c.username, c.password, c.domain, c.community))
            if profile['provenance'] == 'verified':
                assert c.qualified and c.provenance.profile_id == key
                assert c.provenance.catalog_version == document['catalog_version']
                assert c.provenance.references[0].url == profile['source']['url']
                assert c.provenance.references[0].section == profile['source']['section']
            else:
                assert not c.qualified and c.provenance is None
    assert len(document['profiles']) == 9 and len(unique) == 14
    assert len({row for row in unique if row[0] == 'ftp'}) == 8
    assert len({row for row in unique if row[0] == 'snmp'}) == 6
    assert len(load_catalog()) == 5  # never implicit merging


@pytest.mark.parametrize('field,value', [('qualified', True), ('provenance', {'profile_id': 'cisco-wlc-7.4'}),
                                         ('catalog_version', '2026-10-10.2')])
def test_custom_cannot_supply_provenance(tmp_path, field, value):
    row = dict(service='ftp', username='synthetic', password='synthetic')
    row[field] = value
    with pytest.raises(DictionaryError): load_dictionary(file(tmp_path, [row]))


def test_attempt_identity_conservative_but_candidate_values_exact():
    a = Candidate('ftp', 'User', 'OriginalSecret', domain='DOMAIN')
    b = Candidate('ftp', 'user', 'OtherSecret', domain='domain')
    assert a.identity() == b.identity()
    assert a.username == 'User' and a.domain == 'DOMAIN' and a.password == 'OriginalSecret'
    assert Candidate('snmp', community='Public').identity() != Candidate('snmp', community='public').identity()
