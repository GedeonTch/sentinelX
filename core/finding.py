"""
core/finding.py — Central contract for SentinelX NetLab V1

Every scan module MUST return Finding objects.
This is the only data format accepted by Core — no exceptions.

Rules enforced here:
- ZERO import sqlite3
- ZERO import from cli
- ZERO print()
- risk_score is NEVER calculated here — set by core/risk_scorer.py only
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional
import uuid
import datetime
from datetime import timezone
import json


# ---------------------------------------------------------------------------
# Enums — typed, validated, JSON-serializable without custom logic
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Severity of a detected vulnerability.

    Inherits from str so json.dumps() serializes it as a plain string.
    Example: Severity.HIGH → "high"
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    """Type of weakness the Finding represents.

    Inherits from str — serializes natively as a JSON string.
    """
    CONFIG = "config"
    SERVICE = "service"
    NETWORK = "network"
    CREDENTIAL = "credential"
    TRACE = "trace"


class Confidence(float, Enum):
    """Confidence level in the Finding.

    Inherits from float — usable directly as a multiplier in risk_scorer.py
    without any conversion (e.g. Confidence.PROBABLE * base_severity works as-is).
    Prevents arbitrary values like 0.9 from being used.

    Rules:
        CONFIRMED (1.00) — Direct observation, tangible proof (TCP handshake)
        PROBABLE  (0.85) — Strong deduction, banner grabbing
        POSSIBLE  (0.60) — Behavioral estimate (OS via TTL)

    If confidence < 0.7 → Finding shown in grey, marked "unconfirmed",
    excluded from global score calculation.
    """
    CONFIRMED = 1.00
    PROBABLE = 0.85
    POSSIBLE = 0.60


class Exposure(str, Enum):
    """Network exposure of the target service.

    INTERNAL — service reachable only from the local network
    EXTERNAL — service reachable from outside (amplifies risk ×1.15)

    Inherits from str — serializes natively as a JSON string.
    """
    INTERNAL = "internal"
    EXTERNAL = "external"


class FindingStatus(str, Enum):
    """Lifecycle status of a Finding.

    OPEN       — detected, not yet acted on
    VERIFIED   — confirmed by a rescan
    REMEDIATED — fix applied and verified
    ACCEPTED   — risk acknowledged, no fix planned

    Inherits from str — serializes natively as a JSON string.
    """
    OPEN = "open"
    VERIFIED = "verified"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"


# ---------------------------------------------------------------------------
# Supporting dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """Raw proof that justifies a Finding.

    Never interpreted here — stored as-is for traceability.

    Attributes:
        raw     : Raw output of the command that produced the evidence.
        command : Exact command that was executed to obtain it.
    """
    raw: str = ""
    command: str = ""


@dataclass
class Explanation:
    """3-angle pedagogical explanation for a Finding.

    Populated from the local knowledge base (knowledge/vulnerabilities.json),
    indexed by detection rule (e.g. "smb_v1_active", "default_creds_router").

    If no matching rule exists in the knowledge base, explanation remains None
    on the Finding — never filled with a generic placeholder.

    Attributes:
        what    : What the vulnerability is and why it matters.
        attack  : How an attacker would exploit it.
        defense : How to detect and remediate it.
    """
    what: str = ""
    attack: str = ""
    defense: str = ""


# ---------------------------------------------------------------------------
# Finding — the central contract
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Core data object produced by every scan module.

    This is the only format accepted by Core (risk_scorer, database, reports).
    Scan modules produce Findings — they never touch SQLite, calculate scores,
    or call print().

    Key invariants:
        - risk_score is ALWAYS None here — set exclusively by core/risk_scorer.py
        - explanation is None when no knowledge base rule matches (not a placeholder)
        - evidence.raw must not be empty for any Finding with confidence >= PROBABLE
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    module: str = ""            # e.g. "smb_enum", "tcp_scan", "default_creds"
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(timezone.utc).isoformat()
    )

    # Target
    target_ip: str = ""
    target_port: Optional[int] = None
    target_service: str = ""
    service_version: str = ""

    # Classification
    category: Category = Category.CONFIG
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.PROBABLE
    exposure: Exposure = Exposure.INTERNAL

    # Proof and explanation
    evidence: Evidence = field(default_factory=Evidence)
    explanation: Optional[Explanation] = None   # None = no matching rule in knowledge base

    # CVE references
    cve_refs: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None

    # Scoring — set by core/risk_scorer.py ONLY, never here
    risk_score: Optional[float] = None

    # Lifecycle
    status: FindingStatus = FindingStatus.OPEN
    remediation_cmd: str = ""   # V2: bash command for auto-fix

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict representation of this Finding.

        Uses dataclasses.asdict() which:
        - Recursively converts nested dataclasses (Evidence, Explanation) to dicts
        - Leaves str/float/int/None values as-is

        str Enums (Severity, Category, Exposure, FindingStatus) serialize as
        plain strings because they inherit from str.
        Confidence serializes as a plain float because it inherits from float.

        No custom serialization logic needed — verified by json.dumps().

        Returns:
            dict: A flat/nested dict ready for json.dumps(), SQLite storage,
                  or report generation.
        """
        return asdict(self)
