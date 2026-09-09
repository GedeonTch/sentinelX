"""
tests/test_database.py — Unit tests for core/database.py

Strategy:
- Every test uses a temporary directory for the DB (tmp_path fixture)
- Tests are fully isolated — no shared state between test functions
- DB path is patched to use tmp_path instead of ~/.netlab/sessions/

Covers:
- init_db: tables created, idempotent
- save_session / get_session / close_session
- save_finding / get_findings / get_finding_by_id
- save_findings (batch)
- update_finding_status / update_finding_risk_score
- save_asset / get_assets
- Isolation: findings from session A are not visible from session B
- Edge cases: empty session, missing finding, empty findings list
- Invariant: risk_score in DB is only written via update_finding_risk_score
"""

import json
import pytest
from pathlib import Path
from typing import Optional
from unittest.mock import patch

from core.finding import (
    Finding,
    Evidence,
    Explanation,
    Severity,
    Category,
    Confidence,
    Exposure,
    FindingStatus,
)
import core.database as db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SESSION_A = "session-test-001"
SESSION_B = "session-test-002"


@pytest.fixture(autouse=True)
def patch_db_path(tmp_path: Path, monkeypatch):
    """Redirect all DB files to a temporary directory for each test."""
    def mock_get_db_path(session_id: str) -> Path:
        db_dir = tmp_path / ".netlab" / "sessions"
        db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir / f"{session_id}.db"

    monkeypatch.setattr(db, "get_db_path", mock_get_db_path)


def make_finding(
    session_id: str = SESSION_A,
    module: str = "tcp_scan",
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.PROBABLE,
    target_ip: str = "192.168.1.1",
    target_port: int = 445,
    evidence: Optional[Evidence] = None,
    **kwargs,
) -> Finding:
    """Return a minimal valid Finding for testing."""
    if evidence is None:
        evidence = Evidence(raw="PORT 445/tcp open", command="nmap 192.168.1.1")
    return Finding(
        session_id=session_id,
        module=module,
        severity=severity,
        confidence=confidence,
        target_ip=target_ip,
        target_port=target_port,
        evidence=evidence,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# init_db
# ---------------------------------------------------------------------------

class TestInitDb:
    def test_creates_all_five_tables(self):
        db.init_db(SESSION_A)
        conn = db.get_connection(SESSION_A)
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            conn.close()

        assert "assets" in tables
        assert "sessions" in tables
        assert "findings" in tables
        assert "baseline" in tables
        assert "events" in tables

    def test_init_db_is_idempotent(self):
        """Calling init_db twice must not raise and tables must still exist."""
        db.init_db(SESSION_A)
        db.init_db(SESSION_A)  # should not raise

        conn = db.get_connection(SESSION_A)
        try:
            count = conn.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'"
            ).fetchone()[0]
        finally:
            conn.close()

        assert count == 5


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

class TestSessions:
    def setup_method(self):
        db.init_db(SESSION_A)

    def test_save_and_get_session(self):
        db.save_session(SESSION_A, target="192.168.1.0/24", profile="normal")
        session = db.get_session(SESSION_A)

        assert session is not None
        assert session["id"] == SESSION_A
        assert session["target"] == "192.168.1.0/24"
        assert session["profile"] == "normal"
        assert session["status"] == "running"
        assert session["end_time"] is None

    def test_get_session_returns_none_when_not_found(self):
        result = db.get_session(SESSION_A)
        assert result is None

    def test_close_session_sets_end_time_and_status(self):
        db.save_session(SESSION_A, target="192.168.1.1")
        db.close_session(SESSION_A, status="completed")

        session = db.get_session(SESSION_A)
        assert session["status"] == "completed"
        assert session["end_time"] is not None

    def test_close_session_with_explicit_end_time(self):
        db.save_session(SESSION_A, target="192.168.1.1")
        db.close_session(SESSION_A, end_time="2026-09-08T12:00:00+00:00", status="failed")

        session = db.get_session(SESSION_A)
        assert session["end_time"] == "2026-09-08T12:00:00+00:00"
        assert session["status"] == "failed"

    def test_save_session_with_notes(self):
        db.save_session(SESSION_A, target="192.168.1.1", notes="Lab test run")
        session = db.get_session(SESSION_A)
        assert session["notes"] == "Lab test run"


# ---------------------------------------------------------------------------
# Findings — save and retrieve
# ---------------------------------------------------------------------------

class TestFindingsPersistence:
    def setup_method(self):
        db.init_db(SESSION_A)
        db.save_session(SESSION_A, target="192.168.1.1")

    def test_save_and_get_finding_nominal(self):
        f = make_finding()
        db.save_finding(f)

        findings = db.get_findings(SESSION_A)
        assert len(findings) == 1
        result = findings[0]

        assert result.id == f.id
        assert result.session_id == SESSION_A
        assert result.module == "tcp_scan"
        assert result.severity == Severity.HIGH
        assert result.confidence == Confidence.PROBABLE
        assert result.target_ip == "192.168.1.1"
        assert result.target_port == 445
        assert result.status == FindingStatus.OPEN

    def test_save_finding_preserves_evidence(self):
        f = make_finding(
            evidence=Evidence(
                raw="PORT 22/tcp open ssh OpenSSH 7.4",
                command="nmap -sV 192.168.1.1 -p 22",
            )
        )
        db.save_finding(f)

        result = db.get_findings(SESSION_A)[0]
        assert result.evidence.raw == "PORT 22/tcp open ssh OpenSSH 7.4"
        assert result.evidence.command == "nmap -sV 192.168.1.1 -p 22"

    def test_save_finding_with_explanation(self):
        f = make_finding(
            explanation=Explanation(
                what="SMBv1 is enabled.",
                attack="EternalBlue exploitation.",
                defense="Disable SMBv1.",
            )
        )
        db.save_finding(f)

        result = db.get_findings(SESSION_A)[0]
        assert result.explanation is not None
        assert result.explanation.what == "SMBv1 is enabled."
        assert result.explanation.attack == "EternalBlue exploitation."
        assert result.explanation.defense == "Disable SMBv1."

    def test_save_finding_with_explanation_none(self):
        """explanation=None must be stored as NULL and retrieved as None."""
        f = make_finding(explanation=None)
        db.save_finding(f)

        result = db.get_findings(SESSION_A)[0]
        assert result.explanation is None

    def test_save_finding_with_cve_refs(self):
        f = make_finding(cve_refs=["CVE-2017-0144", "CVE-2017-0145"])
        db.save_finding(f)

        result = db.get_findings(SESSION_A)[0]
        assert result.cve_refs == ["CVE-2017-0144", "CVE-2017-0145"]

    def test_save_finding_empty_cve_refs(self):
        f = make_finding()
        db.save_finding(f)

        result = db.get_findings(SESSION_A)[0]
        assert result.cve_refs == []

    def test_get_finding_by_id(self):
        f = make_finding()
        db.save_finding(f)

        result = db.get_finding_by_id(SESSION_A, f.id)
        assert result is not None
        assert result.id == f.id

    def test_get_finding_by_id_returns_none_when_not_found(self):
        result = db.get_finding_by_id(SESSION_A, "nonexistent-id")
        assert result is None

    def test_get_findings_returns_empty_list_when_none(self):
        findings = db.get_findings(SESSION_A)
        assert findings == []

    def test_save_findings_batch(self):
        findings = [
            make_finding(module="tcp_scan", severity=Severity.HIGH),
            make_finding(module="tcp_scan", severity=Severity.MEDIUM),
            make_finding(module="tcp_scan", severity=Severity.LOW),
        ]
        db.save_findings(findings)

        results = db.get_findings(SESSION_A)
        assert len(results) == 3

    def test_save_findings_empty_list_is_noop(self):
        """save_findings([]) must not raise and must leave DB unchanged."""
        db.save_findings([])
        assert db.get_findings(SESSION_A) == []

    def test_save_findings_raises_on_mixed_session_ids(self):
        db.init_db(SESSION_B)
        findings = [
            make_finding(session_id=SESSION_A),
            make_finding(session_id=SESSION_B),
        ]
        with pytest.raises(ValueError, match="same session_id"):
            db.save_findings(findings)

    def test_save_finding_raises_when_session_id_empty(self):
        f = make_finding(session_id="")
        with pytest.raises(ValueError, match="session_id"):
            db.save_finding(f)

    def test_get_findings_ordered_by_severity(self):
        """get_findings must return most severe findings first."""
        db.save_finding(make_finding(severity=Severity.LOW))
        db.save_finding(make_finding(severity=Severity.CRITICAL))
        db.save_finding(make_finding(severity=Severity.MEDIUM))

        results = db.get_findings(SESSION_A)
        severities = [f.severity for f in results]
        assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]

    def test_save_finding_is_idempotent(self):
        """Saving the same Finding twice must not create a duplicate."""
        f = make_finding()
        db.save_finding(f)
        db.save_finding(f)

        results = db.get_findings(SESSION_A)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Findings — status and risk_score updates
# ---------------------------------------------------------------------------

class TestFindingUpdates:
    def setup_method(self):
        db.init_db(SESSION_A)
        db.save_session(SESSION_A, target="192.168.1.1")

    def test_update_finding_status(self):
        f = make_finding()
        db.save_finding(f)

        updated = db.update_finding_status(SESSION_A, f.id, FindingStatus.VERIFIED)
        assert updated is True

        result = db.get_finding_by_id(SESSION_A, f.id)
        assert result.status == FindingStatus.VERIFIED

    def test_update_finding_status_returns_false_when_not_found(self):
        result = db.update_finding_status(SESSION_A, "nonexistent-id", FindingStatus.VERIFIED)
        assert result is False

    def test_update_finding_risk_score(self):
        """risk_score must be writable only via update_finding_risk_score."""
        f = make_finding()
        assert f.risk_score is None  # invariant: never set at creation

        db.save_finding(f)
        updated = db.update_finding_risk_score(SESSION_A, f.id, 72.5)
        assert updated is True

        result = db.get_finding_by_id(SESSION_A, f.id)
        assert result.risk_score == 72.5

    def test_update_finding_risk_score_returns_false_when_not_found(self):
        result = db.update_finding_risk_score(SESSION_A, "nonexistent-id", 50.0)
        assert result is False

    def test_finding_risk_score_is_none_after_save(self):
        """A freshly saved Finding must have risk_score=None in the DB.
        Only risk_scorer.py is allowed to set it via update_finding_risk_score.
        """
        f = make_finding()
        db.save_finding(f)

        result = db.get_finding_by_id(SESSION_A, f.id)
        assert result.risk_score is None


# ---------------------------------------------------------------------------
# Session isolation — critical invariant
# ---------------------------------------------------------------------------

class TestSessionIsolation:
    def setup_method(self):
        db.init_db(SESSION_A)
        db.init_db(SESSION_B)
        db.save_session(SESSION_A, target="192.168.1.1")
        db.save_session(SESSION_B, target="10.0.0.1")

    def test_findings_from_session_a_not_visible_in_session_b(self):
        """A Finding saved in session A must never appear in session B."""
        f_a = make_finding(session_id=SESSION_A, target_ip="192.168.1.1")
        db.save_finding(f_a)

        results_b = db.get_findings(SESSION_B)
        assert results_b == []

    def test_findings_from_session_b_not_visible_in_session_a(self):
        f_b = make_finding(session_id=SESSION_B, target_ip="10.0.0.1")
        db.save_finding(f_b)

        results_a = db.get_findings(SESSION_A)
        assert results_a == []

    def test_get_finding_by_id_respects_session_boundary(self):
        """A Finding from session A cannot be retrieved using session B."""
        f_a = make_finding(session_id=SESSION_A)
        db.save_finding(f_a)

        result = db.get_finding_by_id(SESSION_B, f_a.id)
        assert result is None

    def test_update_status_respects_session_boundary(self):
        """update_finding_status must not affect a Finding from another session."""
        f_a = make_finding(session_id=SESSION_A)
        db.save_finding(f_a)

        # Try to update from session B — must return False (not found)
        updated = db.update_finding_status(SESSION_B, f_a.id, FindingStatus.VERIFIED)
        assert updated is False

        # Original finding in session A must be untouched
        result = db.get_finding_by_id(SESSION_A, f_a.id)
        assert result.status == FindingStatus.OPEN


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

class TestAssets:
    def setup_method(self):
        db.init_db(SESSION_A)

    def test_save_and_get_asset(self):
        db.save_asset(
            session_id=SESSION_A,
            asset_id="asset-001",
            ip="192.168.1.10",
            first_seen="2026-09-08T10:00:00+00:00",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="lab-server",
            os="Linux",
        )

        assets = db.get_assets(SESSION_A)
        assert len(assets) == 1
        assert assets[0]["ip"] == "192.168.1.10"
        assert assets[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert assets[0]["hostname"] == "lab-server"
        assert assets[0]["active"] == 1

    def test_get_assets_returns_empty_list_when_none(self):
        assets = db.get_assets(SESSION_A)
        assert assets == []

    def test_save_asset_is_idempotent(self):
        """Saving the same asset twice must not create a duplicate."""
        for _ in range(2):
            db.save_asset(
                session_id=SESSION_A,
                asset_id="asset-001",
                ip="192.168.1.10",
                first_seen="2026-09-08T10:00:00+00:00",
            )

        assets = db.get_assets(SESSION_A)
        assert len(assets) == 1

    def test_save_asset_minimal_fields(self):
        """Only id, ip, and first_seen are required — others can be None."""
        db.save_asset(
            session_id=SESSION_A,
            asset_id="asset-002",
            ip="10.0.0.1",
            first_seen="2026-09-08T10:00:00+00:00",
        )

        assets = db.get_assets(SESSION_A)
        assert assets[0]["mac"] is None
        assert assets[0]["hostname"] is None
