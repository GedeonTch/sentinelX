"""
Tests for SENTINEL-LIST-01 — sentinel findings list command.
"""
import json, uuid, datetime
from unittest.mock import patch
import pytest
from rich.console import Console
from typer.testing import CliRunner
from cli import app
from core import database as db, logger
from core.database import sentinel_link_finding, sentinel_find_network_for_session
from core.finding import (
    Finding, Evidence, Category, Severity, Confidence, Exposure, FindingStatus,
    format_finding_id,
)

runner = CliRunner()

def _ts(offset=0):
    base = datetime.datetime(2026, 11, 20, 10, 0, 0, tzinfo=datetime.timezone.utc)
    return (base + datetime.timedelta(seconds=offset)).isoformat()

def _f(session_id, fid, ip="10.0.0.1", change_type="new_port", port=80, ts=None,
       module=None):
    return Finding(
        id=fid, session_id=session_id,
        module=module or f"sentinel.{change_type}",
        created_at=ts or _ts(),
        target_ip=ip, target_port=port, target_service="",
        category=Category.NETWORK, severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED, exposure=Exposure.INTERNAL,
        evidence=Evidence(raw="proof", command="sentinel monitor"),
        status=FindingStatus.OPEN,
    )

def _ev(event_id, fid, change_type, ip, notif_state, ts=None):
    details = {"ip": ip, "detail": "event", "whitelisted": False}
    if fid:
        details["finding_id"] = fid
    if notif_state:
        details["notification"] = {"version": 1, "state": notif_state, "decided_at": ts or _ts()}
    return {"id": event_id, "timestamp": ts or _ts(), "type": change_type,
            "asset_id": None, "details": details, "resolved": 0}

def _invoke(session, findings, events, network_id="net-abc123"):
    with patch("core.database.sentinel_read_findings",
               lambda sid: findings if sid == session else []), \
         patch("core.database.sentinel_network_snapshot",
               lambda nid: {"events": events}), \
         patch("core.database.sentinel_find_network_for_session",
               lambda sid: network_id if sid == session else None):
        return runner.invoke(app, ["sentinel", "findings", "list", "--session", session])


# T1: confirmed + masked on same host, different ports
def test_confirmed_and_masked_in_correct_groups():
    s = "sess-t1"
    f1, f2 = str(uuid.uuid4()), str(uuid.uuid4())
    e1, e2 = str(uuid.uuid4()), str(uuid.uuid4())
    findings = [_f(s, f1, port=22, ts=_ts(0)), _f(s, f2, port=443, ts=_ts(1))]
    events = [_ev(e1, f1, "new_port", "10.0.0.1", "confirmed", _ts(0)),
              _ev(e2, f2, "new_port", "10.0.0.1", "masked", _ts(1))]
    result = _invoke(s, findings, events)
    assert result.exit_code == 0, result.output
    out = result.output
    assert f1 in out and f2 in out
    # EMISES before MASQUEES
    assert out.index("EMISES") < out.index("MASQUEES")
    confirmed_part = out[:out.index("MASQUEES")]
    masked_part = out[out.index("MASQUEES"):]
    assert f1 in confirmed_part, "f1 should be in EMISES"
    assert f2 in masked_part, "f2 should be in MASQUEES"


# T2: multiple events of same type, same host
def test_multiple_same_type_all_groups():
    s = "sess-t2"
    fids = [str(uuid.uuid4()) for _ in range(3)]
    eids = [str(uuid.uuid4()) for _ in range(3)]
    states = ["confirmed", "masked", "confirmed"]
    findings = [_f(s, fids[i], port=100+i, ts=_ts(i)) for i in range(3)]
    events = [_ev(eids[i], fids[i], "new_port", "10.0.0.1", states[i], _ts(i)) for i in range(3)]
    result = _invoke(s, findings, events)
    assert result.exit_code == 0
    out = result.output
    for fid in fids:
        assert fid in out
    assert "2 emis" in out
    assert "1 masques" in out


# T3: Finding with no event -> INDETERMINE
def test_finding_no_event_is_undetermined():
    s = "sess-t3"
    fid = str(uuid.uuid4())
    result = _invoke(s, [_f(s, fid)], events=[])
    assert result.exit_code == 0
    out = result.output
    assert fid in out
    assert "INDETERMINE" in out
    assert "0 emis" in out


# T4: Old event without finding_id -> no association
def test_old_event_no_finding_id_stays_undetermined():
    s = "sess-t4"
    fid = str(uuid.uuid4())
    eid = str(uuid.uuid4())
    old_ev = {"id": eid, "timestamp": _ts(0), "type": "new_port",
              "asset_id": None, "resolved": 0,
              "details": {"ip": "10.0.0.1", "detail": "x", "whitelisted": False,
                          "notification": {"version": 1, "state": "confirmed", "decided_at": _ts(0)}}}
    result = _invoke(s, [_f(s, fid)], events=[old_ev])
    assert result.exit_code == 0
    out = result.output
    assert fid in out
    assert "INDETERMINE" in out
    assert "0 emis" in out, "No explicit link -> must not be confirmed"


# T5: Unresolvable network_id -> all INDETERMINE
def test_no_network_id_all_undetermined():
    s = "sess-t5"
    fid = str(uuid.uuid4())
    result = _invoke(s, [_f(s, fid)], events=[], network_id=None)
    assert result.exit_code == 0
    out = result.output
    assert fid in out
    assert "INDETERMINE" in out
    assert "Network_id non resolu" in out


# T6: Chronological order within group
def test_chronological_order_in_group():
    s = "sess-t6"
    f_old, f_new = str(uuid.uuid4()), str(uuid.uuid4())
    e_old, e_new = str(uuid.uuid4()), str(uuid.uuid4())
    findings = [_f(s, f_new, port=443, ts=_ts(100)), _f(s, f_old, port=22, ts=_ts(0))]
    events = [_ev(e_old, f_old, "new_port", "10.0.0.1", "confirmed", _ts(0)),
              _ev(e_new, f_new, "new_port", "10.0.0.1", "confirmed", _ts(100))]
    result = _invoke(s, findings, events)
    assert result.exit_code == 0
    out = result.output
    assert out.index(f_old) < out.index(f_new), "oldest finding must appear first"


# T7: UUID in output is full canonical UUID
def test_uuid_is_full_canonical():
    s = "sess-t7"
    fid = str(uuid.uuid4())
    eid = str(uuid.uuid4())
    result = _invoke(s, [_f(s, fid)],
                     events=[_ev(eid, fid, "new_port", "10.0.0.1", "confirmed")])
    assert result.exit_code == 0
    assert fid in result.output
    assert str(uuid.UUID(fid)) == fid


# T8a: Empty session
def test_empty_session():
    with patch("core.database.sentinel_read_findings", return_value=[]), \
         patch("core.database.sentinel_find_network_for_session", return_value=None):
        result = runner.invoke(app, ["sentinel", "findings", "list", "--session", "empty"])
    assert result.exit_code == 0
    assert "Aucun Finding Sentinel" in result.output


# T8b: Non-existent session (unit-level guard; real path test below)
def test_nonexistent_session():
    with patch("core.database.sentinel_read_findings", side_effect=FileNotFoundError("no db")), \
         patch("core.database.sentinel_find_network_for_session", return_value=None):
        result = runner.invoke(app, ["sentinel", "findings", "list", "--session", "ghost"])
    assert result.exit_code == 1
    assert "Impossible" in result.output


# T9: Whitelisted event -> INDETERMINE
def test_whitelisted_not_confirmed_or_masked():
    s = "sess-t9"
    fid = str(uuid.uuid4())
    eid = str(uuid.uuid4())
    result = _invoke(s, [_f(s, fid)],
                     events=[_ev(eid, fid, "new_port", "10.0.0.1", "whitelisted")])
    assert result.exit_code == 0
    out = result.output
    assert fid in out
    assert "INDETERMINE" in out
    assert "0 emis" in out
    assert "0 masques" in out


# ---------------------------------------------------------------------------
# Real isolated session storage — R2 / R3 / R4 regression coverage
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Use only a temporary sessions/sentinel home; never the owner's state."""
    monkeypatch.setattr(db, "_real_user_home", lambda: tmp_path)
    return tmp_path


def _create_session(session_id, profile="sentinel"):
    db.init_db(session_id)
    db.save_session(session_id, target="192.0.2.0/24", profile=profile)


# R2: unknown session is refused before any writable connection creates a DB.
def test_unknown_session_does_not_create_db_or_block_reservation(isolated_home):
    sessions_dir = isolated_home / ".netlab" / "sessions"
    result = runner.invoke(app, ["sentinel", "findings", "list", "-s", "ghost"])
    assert result.exit_code == 1
    assert "Session inconnue" in result.output
    assert not (sessions_dir / "ghost.db").exists()

    # The start/reservation path remains usable afterward. An untouched empty
    # reservation is removed; a real session can then be initialized.
    with db.reserve_sentinel_session_file("ghost"):
        pass
    assert not (sessions_dir / "ghost.db").exists()
    with db.reserve_sentinel_session_file("ghost"):
        db.init_db("ghost")
        db.save_session("ghost", target="192.0.2.0/24", profile="sentinel")
    assert (sessions_dir / "ghost.db").is_file()
    result = runner.invoke(app, ["sentinel", "findings", "list", "-s", "ghost"])
    assert result.exit_code == 0, result.output
    assert "Aucun Finding Sentinel" in result.output


# R3: list and show accept the same valid Sentinel session.
def test_list_and_show_accept_same_valid_session(isolated_home):
    s = "valid-sentinel"
    _create_session(s)
    fid = str(uuid.uuid4())
    db.save_finding(_f(s, fid, port=22))
    listed = runner.invoke(app, ["sentinel", "findings", "list", "-s", s])
    shown = runner.invoke(app, ["sentinel", "findings", "show", fid, "-s", s])
    assert listed.exit_code == 0, listed.output
    assert shown.exit_code == 0, shown.output
    assert fid in listed.output and fid in shown.output


# R1/R3: real explicit finding_id link + automatic session→network resolution.
def test_real_link_and_network_resolution_reach_confirmed_group(isolated_home):
    s, net = "linked-sentinel", "linked-network"
    _create_session(s)
    fid = str(uuid.uuid4())
    db.save_finding(_f(s, fid, port=22))
    db.init_sentinel_db(net)
    db.sentinel_control_register(net, "instance-1", s, 1234, "birth")
    event_id = str(uuid.uuid4())
    db.sentinel_save_event(
        net, event_id, "new_port", _ts(), None,
        {"ip": "10.0.0.1", "detail": "event", "whitelisted": False,
         "notification": {"version": 1, "state": "confirmed", "decided_at": _ts()}},
    )
    db.sentinel_link_finding(net, event_id, fid)

    assert sentinel_find_network_for_session(s) == net
    event = next(e for e in db.sentinel_get_events(net) if e["id"] == event_id)
    assert event["details"]["finding_id"] == fid

    result = runner.invoke(app, ["sentinel", "findings", "list", "-s", s])
    assert result.exit_code == 0, result.output
    assert fid in result.output
    assert "1 emis" in result.output
    assert "EMISES" in result.output


# R3: list and show refuse the same mixed/invalid contexts.
@pytest.mark.parametrize("case", ["mixed-finding", "mixed-outcome", "normal-profile"])
def test_list_and_show_refuse_same_invalid_session(isolated_home, case):
    s = f"invalid-{case}"
    _create_session(s, profile="normal" if case == "normal-profile" else "sentinel")
    fid = str(uuid.uuid4())
    db.save_finding(_f(s, fid))
    if case == "mixed-finding":
        db.save_finding(_f(s, str(uuid.uuid4()), module="tcp_scan"))
    elif case == "mixed-outcome":
        db.save_scan_outcome(s, "192.0.2.10", "tcp_scan", "completed", 0)

    listed = runner.invoke(app, ["sentinel", "findings", "list", "-s", s])
    shown = runner.invoke(app, ["sentinel", "findings", "show", fid, "-s", s])
    assert listed.exit_code == 1
    assert shown.exit_code == 1
    assert fid not in listed.output


# R4: both identifiers stay complete at narrow and normal terminal widths.
@pytest.mark.parametrize("width", [40, 50, 120])
def test_identifiers_remain_visible_at_all_widths(isolated_home, monkeypatch, width):
    s = f"width-{width}"
    _create_session(s)
    fid = str(uuid.uuid4())
    db.save_finding(_f(s, fid))
    monkeypatch.setattr(logger, "_console", Console(width=width))
    result = runner.invoke(app, ["sentinel", "findings", "list", "-s", s])
    assert result.exit_code == 0, result.output
    assert format_finding_id(fid) in result.output
    assert fid in result.output


# R4: narrow vertical layout covers all three groups without truncation.
def test_narrow_layout_keeps_identifiers_in_every_group(monkeypatch):
    s = "width-groups"
    fids = [str(uuid.uuid4()) for _ in range(3)]
    eids = [str(uuid.uuid4()) for _ in range(3)]
    findings = [_f(s, fids[i], port=100 + i, ts=_ts(i)) for i in range(3)]
    events = [
        _ev(eids[0], fids[0], "new_port", "10.0.0.1", "confirmed", _ts(0)),
        _ev(eids[1], fids[1], "new_port", "10.0.0.1", "masked", _ts(1)),
        _ev(eids[2], None, "new_port", "10.0.0.1", "confirmed", _ts(2)),
    ]
    monkeypatch.setattr(logger, "_console", Console(width=40))
    result = _invoke(s, findings, events)
    assert result.exit_code == 0, result.output
    out = result.output
    for fid in fids:
        assert fid in out
        assert format_finding_id(fid) in out
    assert out.index("EMISES") < out.index("MASQUEES") < out.index("INDETERMINE")
