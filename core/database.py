"""
core/database.py — SQLite persistence layer for SentinelX NetLab V1

This is the ONLY file authorized to import sqlite3.
No other module may import sqlite3 — this rule is enforced by grep at ticket close.

One SQLite file per session: ~/.netlab/sessions/<session_id>.db
All tables are created on first connection (init_db).

Rules enforced here:
- ONLY file that imports sqlite3
- ZERO business logic — reads and writes only
- ZERO risk_score calculation
- ZERO print() — logging via core/logger.py (not yet implemented, uses no-op for now)
- Finding objects are serialized to/from dict via Finding.to_dict() and from_row()

Tables:
    assets    — network device inventory
    sessions  — one record per audit session
    findings  — core of the system, one record per detected issue
    baseline  — Sentinel normal state per asset
    events    — Sentinel detected events
    scan_outcomes — per-machine outcome of each scan module (T20)
"""

import sqlite3
import json
import os
from pathlib import Path
from typing import List, Optional

try:
    import pwd
except ImportError:  # pragma: no cover - pwd is unavailable on Windows
    pwd = None

from core.finding import (
    Finding,
    Evidence,
    Explanation,
    Severity,
    Category,
    Confidence,
    Exposure,
    FindingStatus,
    format_finding_id,
)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _real_user_home() -> Path:
    """Return the data home for the user who invoked SentinelX.

    Under sudo, Path.home() resolves to /root even though the data belongs to
    the invoking user. Prefer SUDO_USER, then SUDO_UID. If sudo metadata is
    present but cannot be resolved, fail rather than silently writing data to
    root's home. With no sudo metadata, preserve normal Path.home() behaviour.
    """
    sudo_user = os.environ.get("SUDO_USER")
    sudo_uid = os.environ.get("SUDO_UID")

    if sudo_user and pwd is not None:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except (KeyError, TypeError):
            pass

    if sudo_uid and pwd is not None:
        try:
            return Path(pwd.getpwuid(int(sudo_uid)).pw_dir)
        except (KeyError, TypeError, ValueError):
            pass

    if sudo_user or sudo_uid:
        home = os.environ.get("HOME")
        if home and Path(home) != Path.home() and home != "/root":
            return Path(home)
        raise RuntimeError(
            "Unable to resolve the invoking user's home directory under sudo; "
            "refusing to use /root/.netlab."
        )

    return Path.home()


def _validate_session_id(session_id: str) -> str:
    """Validate that session_id is safe to use as a filesystem path component.

    Only allows alphanumeric characters, hyphens, and underscores, up to 64
    characters. Raises ValueError if the input is invalid.

    Args:
        session_id: Raw session identifier from caller.

    Returns:
        str: The validated session_id (unchanged).

    Raises:
        ValueError: If session_id contains path traversal or invalid characters.
    """
    import re
    if not session_id or not re.match(r'^[a-zA-Z0-9_-]{1,64}$', session_id):
        raise ValueError(
            f"Invalid session_id '{session_id}'. "
            "Must be 1-64 characters: letters, digits, hyphens, underscores only."
        )
    return session_id


def get_db_path(session_id: str) -> Path:
    """Return the absolute path to the SQLite file for a given session.

    Creates the parent directory if it does not exist.
    Validates session_id to prevent path traversal attacks.

    Args:
        session_id: Unique session identifier (e.g. "session-abc123").

    Returns:
        Path: ~/.netlab/sessions/<session_id>.db

    Raises:
        ValueError: If session_id contains unsafe characters.
    """
    _validate_session_id(session_id)
    db_dir = _real_user_home() / ".netlab" / "sessions"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / f"{session_id}.db"


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def get_connection(session_id: str) -> sqlite3.Connection:
    """Open and return a sqlite3 connection for a session database.

    Enables WAL mode for better concurrency and enforces foreign keys.

    Args:
        session_id: Unique session identifier.

    Returns:
        sqlite3.Connection: Open connection with row_factory set to Row.
    """
    db_path = get_db_path(session_id)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------------
# Schema initialization
# ---------------------------------------------------------------------------

def init_db(session_id: str) -> None:
    """Create all tables for a session database if they do not exist.

    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.

    Args:
        session_id: Unique session identifier.
    """
    conn = get_connection(session_id)
    try:
        cursor = conn.cursor()

        # assets — network device inventory
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id          TEXT PRIMARY KEY,
                ip          TEXT NOT NULL,
                mac         TEXT,
                hostname    TEXT,
                os          TEXT,
                first_seen  TEXT NOT NULL,
                active      INTEGER NOT NULL DEFAULT 1
            )
        """)

        # sessions — one record per audit session
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id                       TEXT PRIMARY KEY,
                start_time               TEXT NOT NULL,
                end_time                 TEXT,
                target                   TEXT NOT NULL,
                profile                  TEXT NOT NULL DEFAULT 'normal',
                status                   TEXT NOT NULL DEFAULT 'running',
                discover_status          TEXT,
                notes                    TEXT,
                sentinel_state           TEXT DEFAULT 'inactive',
                last_check_time          TEXT,
                sentinel_target_network  TEXT,
                sentinel_gateway_ip      TEXT,
                sentinel_gateway_mac     TEXT
            )
        """)

        session_columns = {
            row[1] for row in cursor.execute("PRAGMA table_info(sessions)").fetchall()
        }
        if "discover_status" not in session_columns:
            cursor.execute("ALTER TABLE sessions ADD COLUMN discover_status TEXT")

        # findings — core of the system
        # evidence and explanation are stored as JSON strings
        # cve_refs is stored as a JSON array string
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id              TEXT PRIMARY KEY,
                session_id      TEXT NOT NULL,
                asset_id        TEXT,
                module          TEXT NOT NULL,
                category        TEXT NOT NULL,
                severity        TEXT NOT NULL,
                cvss            REAL,
                confidence      REAL NOT NULL,
                exposure        TEXT NOT NULL DEFAULT 'internal',
                score           REAL,
                status          TEXT NOT NULL DEFAULT 'open',
                evidence        TEXT NOT NULL DEFAULT '{}',
                explanation     TEXT,
                remediation_cmd TEXT,
                cve_refs        TEXT NOT NULL DEFAULT '[]',
                target_ip       TEXT NOT NULL,
                target_port     INTEGER,
                target_service  TEXT,
                service_version TEXT,
                created_at      TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)

        # baseline — Sentinel normal state per asset
        # ports and services stored as JSON arrays/objects
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS baseline (
                id              TEXT PRIMARY KEY,
                asset_id        TEXT NOT NULL,
                target_network  TEXT NOT NULL DEFAULT '',
                gateway_ip      TEXT NOT NULL DEFAULT '',
                gateway_mac     TEXT NOT NULL DEFAULT '',
                ports           TEXT NOT NULL DEFAULT '[]',
                services        TEXT NOT NULL DEFAULT '{}',
                mac             TEXT,
                gateway         TEXT,
                dns             TEXT,
                last_scan       TEXT NOT NULL,
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            )
        """)

        # events — Sentinel detected changes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          TEXT PRIMARY KEY,
                timestamp   TEXT NOT NULL,
                type        TEXT NOT NULL,
                asset_id    TEXT,
                details     TEXT NOT NULL DEFAULT '{}',
                resolved    INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            )
        """)

        # scan_outcomes — one row per machine and scan module (additive, T20)
        _create_scan_outcomes_table(cursor)

        conn.commit()
    finally:
        conn.close()


def _create_scan_outcomes_table(cursor: sqlite3.Cursor) -> None:
    """Create the scan_outcomes table when it is missing.

    Additive and idempotent: existing sessions gain an empty table, and
    existing rows in other tables are untouched.

    Args:
        cursor: Open cursor on a session database.
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_outcomes (
            target_ip   TEXT,
            module      TEXT,
            outcome     TEXT,
            open_ports  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (target_ip, module)
        )
    """)


# ---------------------------------------------------------------------------
# Sessions CRUD
# ---------------------------------------------------------------------------

def save_session(
    session_id: str,
    target: str,
    profile: str = "normal",
    start_time: Optional[str] = None,
    status: str = "running",
    notes: Optional[str] = None,
) -> None:
    """Insert or replace a session record.

    Args:
        session_id: Unique session identifier.
        target:     Scan target (IP, CIDR, hostname).
        profile:    Scan profile (normal / stealth / aggressive).
        start_time: ISO 8601 datetime string. Defaults to current UTC time.
        status:     Session status (running / completed / failed).
        notes:      Optional free-text notes.
    """
    import datetime
    from datetime import timezone

    if start_time is None:
        start_time = datetime.datetime.now(timezone.utc).isoformat()

    conn = get_connection(session_id)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO sessions
                (id, start_time, target, profile, status, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, start_time, target, profile, status, notes),
        )
        conn.commit()
    finally:
        conn.close()


def close_session(
    session_id: str,
    end_time: Optional[str] = None,
    status: str = "completed",
    discover_status: Optional[str] = None,
) -> None:
    """Mark a session as closed with an end timestamp.

    Args:
        session_id: Unique session identifier.
        end_time:   ISO 8601 datetime string. Defaults to current UTC time.
        status:          Final status (completed / partial / failed).
        discover_status: Terminal DISCOVER outcome, if available.
    """
    import datetime
    from datetime import timezone

    if end_time is None:
        end_time = datetime.datetime.now(timezone.utc).isoformat()

    conn = get_connection(session_id)
    try:
        conn.execute(
            """
            UPDATE sessions
            SET end_time = ?, status = ?, discover_status = ?
            WHERE id = ?
            """,
            (end_time, status, discover_status, session_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_session(session_id: str) -> Optional[dict]:
    """Return a session record as a dict, or None if not found.

    Args:
        session_id: Unique session identifier.

    Returns:
        dict with session fields, or None.
    """
    conn = get_connection(session_id)
    try:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Findings CRUD
# ---------------------------------------------------------------------------

def _finding_to_row(finding: Finding) -> tuple:
    """Serialize a Finding to a tuple matching the findings INSERT statement.

    evidence and explanation are JSON-encoded.
    cve_refs is JSON-encoded as a list.

    Args:
        finding: Finding object to serialize.

    Returns:
        tuple: Values in column order for the INSERT statement.
    """
    evidence_json = json.dumps({
        "raw": finding.evidence.raw,
        "command": finding.evidence.command,
    })

    explanation_json: Optional[str] = None
    if finding.explanation is not None:
        explanation_json = json.dumps({
            "what": finding.explanation.what,
            "attack": finding.explanation.attack,
            "defense": finding.explanation.defense,
        })

    return (
        finding.id,
        finding.session_id,
        None,                              # asset_id — linked later by asset layer
        finding.module,
        finding.category.value,
        finding.severity.value,
        finding.cvss_score,
        float(finding.confidence),
        finding.exposure.value,
        finding.risk_score,
        finding.status.value,
        evidence_json,
        explanation_json,
        finding.remediation_cmd,
        json.dumps(finding.cve_refs),
        finding.target_ip,
        finding.target_port,
        finding.target_service,
        finding.service_version,
        finding.created_at,
    )


def _row_to_finding(row: sqlite3.Row) -> Finding:
    """Deserialize a sqlite3.Row from the findings table back to a Finding.

    Args:
        row: sqlite3.Row from a SELECT on the findings table.

    Returns:
        Finding: Fully reconstructed Finding object.
    """
    evidence_data = json.loads(row["evidence"]) if row["evidence"] else {}
    explanation_data = json.loads(row["explanation"]) if row["explanation"] else None

    return Finding(
        id=row["id"],
        session_id=row["session_id"],
        module=row["module"],
        created_at=row["created_at"],
        target_ip=row["target_ip"],
        target_port=row["target_port"],
        target_service=row["target_service"] or "",
        service_version=row["service_version"] or "",
        category=Category(row["category"]),
        severity=Severity(row["severity"]),
        confidence=Confidence(row["confidence"]),
        exposure=Exposure(row["exposure"]),
        evidence=Evidence(
            raw=evidence_data.get("raw", ""),
            command=evidence_data.get("command", ""),
        ),
        explanation=Explanation(
            what=explanation_data["what"],
            attack=explanation_data["attack"],
            defense=explanation_data["defense"],
        ) if explanation_data else None,
        cve_refs=json.loads(row["cve_refs"]) if row["cve_refs"] else [],
        cvss_score=row["cvss"],
        risk_score=row["score"],
        status=FindingStatus(row["status"]),
        remediation_cmd=row["remediation_cmd"] or "",
    )


def save_finding(finding: Finding) -> None:
    """Persist a single Finding to its session database.

    Uses INSERT OR REPLACE — safe to call on updates.
    The session database is determined by finding.session_id.

    Args:
        finding: Finding object to persist.

    Raises:
        ValueError: If finding.session_id is empty.
    """
    if not finding.session_id:
        raise ValueError("Finding.session_id must not be empty before saving to DB.")

    conn = get_connection(finding.session_id)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, session_id, asset_id, module, category, severity,
                cvss, confidence, exposure, score, status,
                evidence, explanation, remediation_cmd, cve_refs,
                target_ip, target_port, target_service, service_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            _finding_to_row(finding),
        )
        conn.commit()
    finally:
        conn.close()


def save_findings(findings: List[Finding]) -> None:
    """Persist a list of Findings in a single transaction.

    All Findings must share the same session_id.

    Args:
        findings: List of Finding objects. Must all have the same session_id.

    Raises:
        ValueError: If findings list is empty or session_ids are inconsistent.
    """
    if not findings:
        return

    session_ids = {f.session_id for f in findings}
    if len(session_ids) != 1:
        raise ValueError(
            f"All findings must share the same session_id. Got: {session_ids}"
        )

    session_id = findings[0].session_id
    if not session_id:
        raise ValueError("Finding.session_id must not be empty before saving to DB.")

    conn = get_connection(session_id)
    try:
        conn.executemany(
            """
            INSERT OR REPLACE INTO findings (
                id, session_id, asset_id, module, category, severity,
                cvss, confidence, exposure, score, status,
                evidence, explanation, remediation_cmd, cve_refs,
                target_ip, target_port, target_service, service_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [_finding_to_row(f) for f in findings],
        )
        conn.commit()
    finally:
        conn.close()


def get_findings(session_id: str) -> List[Finding]:
    """Return all Findings for a session, ordered by severity then created_at.

    Args:
        session_id: Unique session identifier.

    Returns:
        List[Finding]: All findings for the session, most severe first.
    """
    severity_order = "CASE severity " \
        "WHEN 'critical' THEN 1 " \
        "WHEN 'high' THEN 2 " \
        "WHEN 'medium' THEN 3 " \
        "WHEN 'low' THEN 4 " \
        "WHEN 'info' THEN 5 " \
        "ELSE 6 END"

    conn = get_connection(session_id)
    try:
        rows = conn.execute(
            f"SELECT * FROM findings WHERE session_id = ? ORDER BY {severity_order}, created_at",
            (session_id,),
        ).fetchall()
        return [_row_to_finding(row) for row in rows]
    finally:
        conn.close()


def resolve_finding_id(session_id: str, identifier: str) -> List[Finding]:
    """Resolve an internal or user-facing Finding ID within one session.

    A full internal ID is matched exactly. An ``FD-`` identifier is resolved
    against the stable display ID of every Finding, so short-ID collisions are
    returned to the caller instead of being selected arbitrarily.
    """
    if identifier.upper().startswith("FD-"):
        requested = identifier.upper()
        return [
            finding
            for finding in get_findings(session_id)
            if format_finding_id(finding.id) == requested
        ]

    finding = get_finding_by_id(session_id, identifier)
    return [finding] if finding is not None else []


def get_finding_by_id(session_id: str, finding_id: str) -> Optional[Finding]:
    """Return a single Finding by its internal ID within a session, or None.

    Args:
        session_id: Session the Finding belongs to.
        finding_id: UUID of the Finding.

    Returns:
        Finding or None.
    """
    conn = get_connection(session_id)
    try:
        row = conn.execute(
            "SELECT * FROM findings WHERE id = ? AND session_id = ?",
            (finding_id, session_id),
        ).fetchone()
        return _row_to_finding(row) if row else None
    finally:
        conn.close()


def update_finding_status(
    session_id: str,
    finding_id: str,
    status: FindingStatus,
) -> bool:
    """Update the status of a Finding (e.g. open → verified → remediated).

    Args:
        session_id: Session the Finding belongs to.
        finding_id: UUID of the Finding.
        status:     New FindingStatus value.

    Returns:
        bool: True if a row was updated, False if not found.
    """
    conn = get_connection(session_id)
    try:
        cursor = conn.execute(
            "UPDATE findings SET status = ? WHERE id = ? AND session_id = ?",
            (status.value, finding_id, session_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def update_finding_risk_score(
    session_id: str,
    finding_id: str,
    risk_score: float,
) -> bool:
    """Write the risk_score calculated by core/risk_scorer.py into the DB.

    This is the ONLY legitimate path for writing risk_score.
    risk_scorer.py calls this after calculating the score — it never touches
    the Finding object's risk_score field directly.

    Args:
        session_id: Session the Finding belongs to.
        finding_id: UUID of the Finding.
        risk_score: Score calculated by risk_scorer (0–100).

    Returns:
        bool: True if a row was updated, False if not found.
    """
    conn = get_connection(session_id)
    try:
        cursor = conn.execute(
            "UPDATE findings SET score = ? WHERE id = ? AND session_id = ?",
            (risk_score, finding_id, session_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Assets CRUD
# ---------------------------------------------------------------------------

def save_asset(
    session_id: str,
    asset_id: str,
    ip: str,
    first_seen: str,
    mac: Optional[str] = None,
    hostname: Optional[str] = None,
    os: Optional[str] = None,
    active: bool = True,
) -> None:
    """Insert or replace an asset record.

    Args:
        session_id: Session that discovered the asset (used to route to the DB).
        asset_id:   Unique asset identifier (UUID).
        ip:         IP address of the asset.
        first_seen: ISO 8601 datetime string.
        mac:        MAC address (optional).
        hostname:   Resolved hostname (optional).
        os:         Detected OS (optional).
        active:     Whether the asset is currently reachable.
    """
    conn = get_connection(session_id)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO assets
                (id, ip, mac, hostname, os, first_seen, active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (asset_id, ip, mac, hostname, os, first_seen, int(active)),
        )
        conn.commit()
    finally:
        conn.close()


def get_assets(session_id: str) -> List[dict]:
    """Return all assets discovered in a session.

    Args:
        session_id: Unique session identifier.

    Returns:
        List[dict]: One dict per asset row.
    """
    conn = get_connection(session_id)
    try:
        rows = conn.execute(
            "SELECT * FROM assets ORDER BY ip"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scan outcomes — how each scan module ended for each machine (T20)
# ---------------------------------------------------------------------------

SCAN_OUTCOME_COMPLETED = "completed"
SCAN_OUTCOME_FAILED = "failed"
SCAN_OUTCOME_CANCELLED = "cancelled"
SCAN_OUTCOMES = (SCAN_OUTCOME_COMPLETED, SCAN_OUTCOME_FAILED, SCAN_OUTCOME_CANCELLED)


def save_scan_outcome(
    session_id: str,
    target_ip: str,
    module: str,
    outcome: str,
    open_ports: int = 0,
) -> None:
    """Record how one scan module ended for one machine in a session.

    A later call for the same (target_ip, module) replaces the previous row,
    so a retried scan overwrites its earlier outcome within the session.
    open_ports is meaningful only for a completed scan: other outcomes store 0.

    Args:
        session_id: Unique session identifier.
        target_ip:  Machine that was scanned.
        module:     Scan module name, e.g. "tcp_scan" or "udp_scan".
        outcome:    One of SCAN_OUTCOMES.
        open_ports: Number of open ports reported by a completed scan.

    Raises:
        ValueError: If the outcome is unknown, the identity is empty,
                    or open_ports is negative.
    """
    if outcome not in SCAN_OUTCOMES:
        raise ValueError(f"Unknown scan outcome: {outcome!r}")
    if not target_ip or not module:
        raise ValueError("A scan outcome needs a target_ip and a module.")
    if open_ports < 0:
        raise ValueError("open_ports must be >= 0.")
    stored_ports = int(open_ports) if outcome == SCAN_OUTCOME_COMPLETED else 0

    conn = get_connection(session_id)
    try:
        cursor = conn.cursor()
        _create_scan_outcomes_table(cursor)
        cursor.execute(
            """
            INSERT OR REPLACE INTO scan_outcomes (target_ip, module, outcome, open_ports)
            VALUES (?, ?, ?, ?)
            """,
            (target_ip, module, outcome, stored_ports),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan_outcomes(session_id: str) -> Optional[List[dict]]:
    """Return the scan outcomes recorded for a session.

    Returns None when the session database has no scan_outcomes table, which
    is the case for sessions created before T20. Callers must treat None as
    "unknown", never as "no machine was scanned".

    Args:
        session_id: Unique session identifier.

    Returns:
        List[dict]: One dict per row with keys target_ip, module, outcome and
                    open_ports, ordered by target_ip then module; or None.
    """
    conn = get_connection(session_id)
    try:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scan_outcomes'"
        ).fetchone()
        if table is None:
            return None
        rows = conn.execute(
            "SELECT target_ip, module, outcome, open_ports FROM scan_outcomes "
            "ORDER BY target_ip, module"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Sentinel — baseline CRUD
# ---------------------------------------------------------------------------

def save_baseline_entry(
    session_id: str,
    entry_id: str,
    asset_id: str,
    target_network: str,
    gateway_ip: str,
    gateway_mac: str,
    ports: List[int],
    mac: Optional[str],
    last_scan: str,
) -> None:
    """Insert or replace a baseline entry for one asset.

    Args:
        session_id:     Session the baseline belongs to.
        entry_id:       Unique ID for this baseline entry (UUID).
        asset_id:       Asset this entry describes.
        target_network: CIDR of the network (e.g. "192.168.1.0/24").
        gateway_ip:     Gateway IP detected at baseline time.
        gateway_mac:    Gateway MAC detected at baseline time ("" if unknown).
        ports:          List of open TCP port numbers.
        mac:            MAC address of the asset (optional).
        last_scan:      ISO 8601 timestamp of the scan.
    """
    conn = get_connection(session_id)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO baseline
                (id, asset_id, target_network, gateway_ip, gateway_mac,
                 ports, services, mac, last_scan)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_id,
                asset_id,
                target_network,
                gateway_ip,
                gateway_mac,
                json.dumps(ports),
                "{}",
                mac,
                last_scan,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_baseline_entries(
    session_id: str,
    target_network: str,
    gateway_ip: str,
    gateway_mac: str,
) -> List[dict]:
    """Return all baseline entries for an exact NetworkIdentity triplet.

    Filters on (target_network, gateway_ip, gateway_mac) exactly.
    gateway_mac="" matches only entries where gateway_mac="" — never a wildcard.

    Args:
        session_id:     Session identifier.
        target_network: CIDR string.
        gateway_ip:     Gateway IP string.
        gateway_mac:    Gateway MAC string ("" if unknown).

    Returns:
        List[dict]: One dict per baseline row, ports decoded from JSON.
    """
    conn = get_connection(session_id)
    try:
        rows = conn.execute(
            """
            SELECT b.*, a.ip, a.mac as asset_mac
            FROM baseline b
            JOIN assets a ON b.asset_id = a.id
            WHERE b.target_network = ?
              AND b.gateway_ip     = ?
              AND b.gateway_mac    = ?
            ORDER BY a.ip
            """,
            (target_network, gateway_ip, gateway_mac),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["ports"] = json.loads(d.get("ports", "[]"))
            result.append(d)
        return result
    finally:
        conn.close()


def baseline_exists(
    session_id: str,
    target_network: str,
    gateway_ip: str,
    gateway_mac: str,
) -> bool:
    """Return True if at least one baseline entry exists for this NetworkIdentity.

    Args:
        session_id:     Session identifier.
        target_network: CIDR string.
        gateway_ip:     Gateway IP string.
        gateway_mac:    Gateway MAC string ("" if unknown).

    Returns:
        bool
    """
    conn = get_connection(session_id)
    try:
        count = conn.execute(
            """
            SELECT COUNT(*) FROM baseline
            WHERE target_network = ?
              AND gateway_ip     = ?
              AND gateway_mac    = ?
            """,
            (target_network, gateway_ip, gateway_mac),
        ).fetchone()[0]
        return count > 0
    finally:
        conn.close()


def delete_baseline_for_identity(
    session_id: str,
    target_network: str,
    gateway_ip: str,
    gateway_mac: str,
) -> int:
    """Delete all baseline entries for an exact NetworkIdentity.

    Used by --relearn. Never touches other network identities.

    Args:
        session_id:     Session identifier.
        target_network: CIDR string.
        gateway_ip:     Gateway IP string.
        gateway_mac:    Gateway MAC string.

    Returns:
        int: Number of rows deleted.
    """
    conn = get_connection(session_id)
    try:
        cursor = conn.execute(
            """
            DELETE FROM baseline
            WHERE target_network = ?
              AND gateway_ip     = ?
              AND gateway_mac    = ?
            """,
            (target_network, gateway_ip, gateway_mac),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Sentinel — events CRUD
# ---------------------------------------------------------------------------

def save_event(
    session_id: str,
    event_id: str,
    event_type: str,
    timestamp: str,
    asset_id: Optional[str],
    details: dict,
    resolved: bool = False,
) -> None:
    """Insert a Sentinel event into the events table.

    Args:
        session_id: Session identifier.
        event_id:   Unique event ID (UUID).
        event_type: Type string (e.g. "new_host", "new_port", "mac_change",
                    "whitelisted_change").
        timestamp:  ISO 8601 timestamp.
        asset_id:   Asset concerned (optional).
        details:    Dict with change details — stored as JSON.
        resolved:   True if the change was whitelisted (no alert raised).
    """
    conn = get_connection(session_id)
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO events
                (id, timestamp, type, asset_id, details, resolved)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                timestamp,
                event_type,
                asset_id,
                json.dumps(details),
                int(resolved),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_events(
    session_id: str,
    resolved: Optional[bool] = None,
    limit: int = 100,
) -> List[dict]:
    """Return events for a session, optionally filtered by resolved status.

    Args:
        session_id: Session identifier.
        resolved:   None = all, True = resolved only, False = unresolved only.
        limit:      Maximum number of events to return (most recent first).

    Returns:
        List[dict]: Event rows with details decoded from JSON.
    """
    conn = get_connection(session_id)
    try:
        if resolved is None:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events WHERE resolved = ? ORDER BY timestamp DESC LIMIT ?",
                (int(resolved), limit),
            ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["details"] = json.loads(d.get("details", "{}"))
            result.append(d)
        return result
    finally:
        conn.close()


def count_unresolved_events(session_id: str) -> int:
    """Return the count of unresolved (non-whitelisted) events in a session.

    Used for the 'alertes' counter in sentinel status.

    Args:
        session_id: Session identifier.

    Returns:
        int: Count of events with resolved=0.
    """
    conn = get_connection(session_id)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM events WHERE resolved = 0",
        ).fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Sentinel — session state CRUD
# ---------------------------------------------------------------------------

def update_sentinel_state(
    session_id: str,
    sentinel_state: str,
    last_check_time: Optional[str] = None,
    target_network: Optional[str] = None,
    gateway_ip: Optional[str] = None,
    gateway_mac: Optional[str] = None,
) -> None:
    """Update Sentinel-specific columns on a session record.

    last_check_time is only updated when provided (successful check only).
    A failed check must NOT pass last_check_time — pass None instead.

    Args:
        session_id:     Session identifier.
        sentinel_state: "active" | "degraded" | "inactive".
        last_check_time: ISO 8601 of last SUCCESSFUL check. None = don't update.
        target_network: CIDR being monitored (set at start, not updated after).
        gateway_ip:     Gateway IP (set at start).
        gateway_mac:    Gateway MAC (set at start).
    """
    conn = get_connection(session_id)
    try:
        if last_check_time is not None:
            conn.execute(
                """
                UPDATE sessions
                SET sentinel_state          = ?,
                    last_check_time         = ?,
                    sentinel_target_network = COALESCE(?, sentinel_target_network),
                    sentinel_gateway_ip     = COALESCE(?, sentinel_gateway_ip),
                    sentinel_gateway_mac    = COALESCE(?, sentinel_gateway_mac)
                WHERE id = ?
                """,
                (sentinel_state, last_check_time,
                 target_network, gateway_ip, gateway_mac,
                 session_id),
            )
        else:
            conn.execute(
                """
                UPDATE sessions
                SET sentinel_state          = ?,
                    sentinel_target_network = COALESCE(?, sentinel_target_network),
                    sentinel_gateway_ip     = COALESCE(?, sentinel_gateway_ip),
                    sentinel_gateway_mac    = COALESCE(?, sentinel_gateway_mac)
                WHERE id = ?
                """,
                (sentinel_state,
                 target_network, gateway_ip, gateway_mac,
                 session_id),
            )
        conn.commit()
    finally:
        conn.close()


def get_sentinel_state(session_id: str) -> dict:
    """Return Sentinel state columns for a session.

    Args:
        session_id: Session identifier.

    Returns:
        dict with sentinel_state, last_check_time, sentinel_target_network,
        sentinel_gateway_ip, sentinel_gateway_mac. Empty dict if not found.
    """
    conn = get_connection(session_id)
    try:
        row = conn.execute(
            """
            SELECT sentinel_state, last_check_time,
                   sentinel_target_network, sentinel_gateway_ip, sentinel_gateway_mac
            FROM sessions WHERE id = ?
            """,
            (session_id,),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


# ===========================================================================
# SENTINEL — Dedicated persistent DB (~/.netlab/sentinel/<network_id>.db)
#
# Baseline belongs to the network identity, not to a run session.
# These sentinel_ functions use a separate DB path that persists across
# Sentinel restarts, unlike ~/.netlab/sessions/<session_id>.db.
# ===========================================================================

def get_sentinel_db_path(network_id: str) -> Path:
    """Return path to the persistent Sentinel DB for a network identity.

    ~/.netlab/sentinel/<network_id>.db — distinct from audit session DBs.

    Args:
        network_id: Stable 12-char hex identifier from compute_network_id().

    Returns:
        Path: ~/.netlab/sentinel/<network_id>.db

    Raises:
        ValueError: If network_id is unsafe (path traversal check).
    """
    _validate_session_id(network_id)
    db_dir = _real_user_home() / ".netlab" / "sentinel"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / f"{network_id}.db"


def get_sentinel_connection(network_id: str) -> sqlite3.Connection:
    """Open a sqlite3 connection for the sentinel DB of a network."""
    db_path = get_sentinel_db_path(network_id)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_sentinel_db(network_id: str) -> None:
    """Create sentinel DB tables if they do not exist. Safe to call multiple times."""
    conn = get_sentinel_connection(network_id)
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY, ip TEXT NOT NULL, mac TEXT,
                hostname TEXT, os TEXT, first_seen TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS baseline (
                id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                target_network TEXT NOT NULL DEFAULT '',
                gateway_ip TEXT NOT NULL DEFAULT '',
                gateway_mac TEXT NOT NULL DEFAULT '',
                ports TEXT NOT NULL DEFAULT '[]',
                services TEXT NOT NULL DEFAULT '{}',
                mac TEXT, gateway TEXT, dns TEXT,
                last_scan TEXT NOT NULL,
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL, type TEXT NOT NULL,
                asset_id TEXT,
                details TEXT NOT NULL DEFAULT '{}',
                resolved INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sentinel_state (
                network_id TEXT PRIMARY KEY,
                sentinel_status TEXT NOT NULL DEFAULT 'inactive',
                last_check_time TEXT,
                target_network TEXT, gateway_ip TEXT, gateway_mac TEXT,
                updated_at TEXT
            )
        """)
        conn.commit()
    finally:
        conn.close()


# Sentinel — assets

def sentinel_save_asset(
    network_id: str, asset_id: str, ip: str, first_seen: str,
    mac: Optional[str] = None, hostname: Optional[str] = None,
    os: Optional[str] = None, active: bool = True,
) -> None:
    """Insert or replace an asset in the sentinel DB."""
    conn = get_sentinel_connection(network_id)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO assets (id,ip,mac,hostname,os,first_seen,active) VALUES (?,?,?,?,?,?,?)",
            (asset_id, ip, mac, hostname, os, first_seen, int(active)),
        )
        conn.commit()
    finally:
        conn.close()


# Sentinel — baseline

def sentinel_save_baseline_entry(
    network_id: str, entry_id: str, asset_id: str,
    target_network: str, gateway_ip: str, gateway_mac: str,
    ports: List[int], mac: Optional[str], last_scan: str,
) -> None:
    """Insert or replace a baseline entry in the sentinel DB."""
    conn = get_sentinel_connection(network_id)
    try:
        conn.execute(
            """INSERT OR REPLACE INTO baseline
               (id,asset_id,target_network,gateway_ip,gateway_mac,ports,services,mac,last_scan)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (entry_id, asset_id, target_network, gateway_ip, gateway_mac,
             json.dumps(ports), "{}", mac, last_scan),
        )
        conn.commit()
    finally:
        conn.close()


def sentinel_get_baseline_entries(
    network_id: str, target_network: str, gateway_ip: str, gateway_mac: str,
) -> List[dict]:
    """Return baseline entries for an exact NetworkIdentity from the sentinel DB."""
    conn = get_sentinel_connection(network_id)
    try:
        rows = conn.execute(
            """SELECT b.*, a.ip, a.mac as asset_mac
               FROM baseline b JOIN assets a ON b.asset_id = a.id
               WHERE b.target_network=? AND b.gateway_ip=? AND b.gateway_mac=?
               ORDER BY a.ip""",
            (target_network, gateway_ip, gateway_mac),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["ports"] = json.loads(d.get("ports", "[]"))
            result.append(d)
        return result
    finally:
        conn.close()


def sentinel_baseline_exists(
    network_id: str, target_network: str, gateway_ip: str, gateway_mac: str,
) -> bool:
    """Return True if a baseline exists for this NetworkIdentity in the sentinel DB."""
    conn = get_sentinel_connection(network_id)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM baseline WHERE target_network=? AND gateway_ip=? AND gateway_mac=?",
            (target_network, gateway_ip, gateway_mac),
        ).fetchone()[0]
        return count > 0
    finally:
        conn.close()


def sentinel_delete_baseline_for_identity(
    network_id: str, target_network: str, gateway_ip: str, gateway_mac: str,
) -> int:
    """Delete baseline entries for an exact NetworkIdentity. Returns row count."""
    conn = get_sentinel_connection(network_id)
    try:
        cursor = conn.execute(
            "DELETE FROM baseline WHERE target_network=? AND gateway_ip=? AND gateway_mac=?",
            (target_network, gateway_ip, gateway_mac),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


# Sentinel — events

def sentinel_save_event(
    network_id: str, event_id: str, event_type: str, timestamp: str,
    asset_id: Optional[str], details: dict, resolved: bool = False,
) -> None:
    """Insert a Sentinel event into the sentinel DB."""
    conn = get_sentinel_connection(network_id)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO events (id,timestamp,type,asset_id,details,resolved) VALUES (?,?,?,?,?,?)",
            (event_id, timestamp, event_type, asset_id, json.dumps(details), int(resolved)),
        )
        conn.commit()
    finally:
        conn.close()


def sentinel_get_events(
    network_id: str, resolved: Optional[bool] = None, limit: int = 100,
) -> List[dict]:
    """Return events from the sentinel DB."""
    conn = get_sentinel_connection(network_id)
    try:
        if resolved is None:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events WHERE resolved=? ORDER BY timestamp DESC LIMIT ?",
                (int(resolved), limit),
            ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["details"] = json.loads(d.get("details", "{}"))
            result.append(d)
        return result
    finally:
        conn.close()


def sentinel_count_unresolved_events(network_id: str) -> int:
    """Return count of unresolved events in the sentinel DB."""
    conn = get_sentinel_connection(network_id)
    try:
        return conn.execute("SELECT COUNT(*) FROM events WHERE resolved=0").fetchone()[0]
    finally:
        conn.close()


# Sentinel — state

def sentinel_update_state(
    network_id: str,
    sentinel_status: str,
    last_check_time: Optional[str] = None,
    target_network: Optional[str] = None,
    gateway_ip: Optional[str] = None,
    gateway_mac: Optional[str] = None,
) -> None:
    """Upsert the sentinel state for a network.

    last_check_time is only written when provided (successful check only).
    A failed check must pass None to leave last_check_time unchanged.
    """
    import datetime
    from datetime import timezone
    now = datetime.datetime.now(timezone.utc).isoformat()
    conn = get_sentinel_connection(network_id)
    try:
        existing = conn.execute(
            "SELECT network_id FROM sentinel_state WHERE network_id=?", (network_id,)
        ).fetchone()
        if existing is None:
            conn.execute(
                """INSERT INTO sentinel_state
                   (network_id,sentinel_status,last_check_time,target_network,gateway_ip,gateway_mac,updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (network_id, sentinel_status, last_check_time,
                 target_network, gateway_ip, gateway_mac, now),
            )
        elif last_check_time is not None:
            conn.execute(
                """UPDATE sentinel_state
                   SET sentinel_status=?, last_check_time=?,
                       target_network=COALESCE(?,target_network),
                       gateway_ip=COALESCE(?,gateway_ip),
                       gateway_mac=COALESCE(?,gateway_mac),
                       updated_at=?
                   WHERE network_id=?""",
                (sentinel_status, last_check_time,
                 target_network, gateway_ip, gateway_mac, now, network_id),
            )
        else:
            conn.execute(
                """UPDATE sentinel_state
                   SET sentinel_status=?,
                       target_network=COALESCE(?,target_network),
                       gateway_ip=COALESCE(?,gateway_ip),
                       gateway_mac=COALESCE(?,gateway_mac),
                       updated_at=?
                   WHERE network_id=?""",
                (sentinel_status,
                 target_network, gateway_ip, gateway_mac, now, network_id),
            )
        conn.commit()
    finally:
        conn.close()


def sentinel_get_state(network_id: str) -> dict:
    """Return the sentinel state for a network from the sentinel DB.

    Returns:
        dict with sentinel_status, last_check_time, target_network,
        gateway_ip, gateway_mac. Empty dict if not found.
    """
    conn = get_sentinel_connection(network_id)
    try:
        row = conn.execute(
            "SELECT * FROM sentinel_state WHERE network_id=?", (network_id,)
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def sentinel_get_assets(network_id: str) -> List[dict]:
    """Return assets stored in the persistent Sentinel DB for a network."""
    conn = get_sentinel_connection(network_id)
    try:
        rows = conn.execute("SELECT * FROM assets ORDER BY ip").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def list_sentinel_network_ids() -> List[str]:
    """List network IDs with an existing persistent Sentinel DB.

    This only inspects the existing per-network storage directory; it does not
    create a database or derive a new network identity.
    """
    directory = _real_user_home() / ".netlab" / "sentinel"
    if not directory.is_dir():
        return []
    return sorted(path.stem for path in directory.glob("*.db") if path.is_file())


def sentinel_has_conflicting_baseline(
    network_id: str, target_network: str, gateway_ip: str, gateway_mac: str,
) -> bool:
    """Return True if a baseline exists for this CIDR but with a different identity."""
    conn = get_sentinel_connection(network_id)
    try:
        # We need to check across ALL sentinel DBs — but since each network_id
        # maps to a unique DB, a conflict can only occur if we search by CIDR
        # in the current DB (same network_id could store multiple CIDRs in theory,
        # but in practice each DB is network-specific).
        # Conflict = same CIDR but different gateway triplet in the same DB.
        row = conn.execute(
            """SELECT COUNT(*) FROM baseline
               WHERE target_network=?
                 AND (gateway_ip != ? OR gateway_mac != ?)""",
            (target_network, gateway_ip, gateway_mac),
        ).fetchone()
        return row[0] > 0
    except Exception:
        return False
    finally:
        conn.close()
