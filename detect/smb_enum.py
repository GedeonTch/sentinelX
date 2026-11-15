"""
detect/smb_enum.py — SMB share / user / domain enumeration via enum4linux-ng

Pipeline step: DETECT
Role: Enumerate SMB shares, users, and domain information on a Windows host.
      One Finding per detected share, plus one Finding for domain info
      when a domain or workgroup name is present in the output.
      Uses enum4linux-ng (external tool, own venv) for structured JSON output.

Does not calculate risk_score. Does not write to SQLite. Does not print().

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding]
- ALWAYS ask (y/n) confirmation before sending traffic
- explanation stays None (KB lookup done by pipeline/CLI)
- evidence.raw holds only the analysed, filtered fields (JSON). It never holds
  the full enum4linux-ng output, which may contain secrets.
- A failed enumeration is reported explicitly and returns []; it is never
  presented as an empty result.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

import typer
from rich.markup import escape

from core.dependencies import ENUM4LINUX_NG_PYTHON, ENUM4LINUX_NG_SCRIPT, _resolve_tool_path
from core.finding import (
    Category,
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Severity,
)
from core.logger import display

MODULE_NAME = "smb_enum"
SMB_PORT = 445
ENUM4LINUX_TIMEOUT_SECONDS = 120
ENUM4LINUX_STDERR_EXCERPT_CHARS = 160
ENUM4LINUX_EVIDENCE_COMMAND = "enum4linux-ng -A -oJ <json-base> {target}"

_SHARE_ROW = re.compile(
    r"^\s*([A-Za-z0-9._$-]+)\s+(Disk|IPC|Printer)\b",
    re.IGNORECASE,
)
_SHARE_HEADER_NAMES = frozenset({"sharename", "---------"})
_DOMAIN_PATTERNS = (
    re.compile(r"Domain Name:\s*(\S+)", re.IGNORECASE),
    re.compile(r"Got domain/workgroup name:\s*(\S+)", re.IGNORECASE),
    re.compile(r"\[.\]\s+Got domain name:\s*(\S+)", re.IGNORECASE),
    re.compile(r"Workgroup:\s*(\S+)", re.IGNORECASE),
)


_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


@dataclass(frozen=True)
class SmbShare:
    """Normalized description of one SMB share."""
    name: str
    share_type: Optional[str] = None
    comment: Optional[str] = None
    accessible: Optional[bool] = None
    permissions: Optional[str] = None


@dataclass(frozen=True)
class SmbEnumerationResult:
    """Tool-independent SMB observations with None meaning unknown."""
    target: str
    os: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    sid: Optional[str] = None
    mac: Optional[str] = None
    dialects: Tuple[str, ...] = ()
    signing_required: Optional[bool] = None
    shares: Tuple[SmbShare, ...] = ()
    users: Tuple[str, ...] = ()
    groups: Tuple[str, ...] = ()
    anonymous_session: Optional[bool] = None
    anonymous_share_access: Optional[bool] = None
    password_policy: Optional[dict] = None   # {"min_password_length": int, "lockout_threshold": int}
    raw_output: str = ""
    smb1_imposed: bool = False   # True when smb_dialects JSON value is bool True
                                  # (enum4linux-ng enforce_smb1 succeeded). Never
                                  # used as a dialect name in .dialects.
    source_format: str = "text"


def smb_enum(target_ip: str, session_id: str) -> List[Finding]:
    """Enumerate SMB shares and domain info on a Windows host.

    Asks for (y/n) confirmation before running enum4linux-ng. Returns an
    empty list when the tool is missing, the user cancels, or the run fails.
    A failed run is displayed as an explicit error, distinct from the message
    "no shares or domain info" that is shown only after a successful, empty
    analysis. Never raises for those cases. Use run_smb_enum() when the caller
    must tell a failure apart from an empty result.

    Args:
        target_ip: IPv4 address of the Windows host.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One Finding per detected share, plus one domain
        Finding when domain information is available.
    """
    return run_smb_enum(target_ip, session_id) or []


def run_smb_enum(target_ip: str, session_id: str) -> Optional[List[Finding]]:
    """Run the SMB enumeration once and report its outcome without ambiguity.

    Args:
        target_ip: IPv4 address of the Windows host.
        session_id: Current audit session ID.

    Returns:
        None: the enumeration failed or could not start (tool missing,
            timeout, non-zero exit, unreadable export). The explicit red
            message has already been displayed.
        []: the user cancelled, or the analysis completed with no Finding.
        List[Finding]: the analysis completed with Findings.

    Never raises for those cases.
    """
    if _resolve_tool_path("enum4linux-ng") is None:
        display("[red]enum4linux-ng not found. Run 'netlab doctor'.[/red]")
        return None

    confirmed = typer.confirm(
        f"[smb_enum] Enumerate SMB shares, users and domain on {target_ip}?"
    )
    if not confirmed:
        display("[yellow]SMB enumeration cancelled.[/yellow]")
        return []

    display(f"[cyan]Starting enum4linux-ng on {target_ip}...[/cyan]")
    raw_output = _run_enum4linux_ng(target_ip)
    if raw_output is None:
        # The failure reason was already displayed by _run_enum4linux_ng.
        return None

    findings = _parse_enum4linux_output(raw_output, target_ip, session_id)
    if findings:
        display(
            f"[green]SMB enumeration complete — {len(findings)} finding(s).[/green]"
        )
    else:
        display(
            f"[yellow]SMB enumeration complete — no shares or domain info on {target_ip}.[/yellow]"
        )
    return findings


def _report_failure(target_ip: str, reason: str) -> None:
    """Display an explicit, visible SMB enumeration failure (red).

    The message states that there is no result, so it can never be read as
    an absence of shares or domain information.
    """
    display(
        f"[red]SMB enumeration FAILED on {escape(target_ip)}: {escape(reason)}. "
        "No result: this is not an absence of shares or domain info.[/red]"
    )


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|hash|token|key)\b\s*[:=]\s*\S+"
)


def _stderr_excerpt(stderr: str) -> str:
    """Return a short diagnostic excerpt of stderr.

    stderr is never parsed as data. The excerpt is one line, ANSI-free,
    truncated, and any ``password: value``-style assignment is redacted.
    """
    lines = [line.strip() for line in _strip_ansi(stderr or "").splitlines() if line.strip()]
    if not lines:
        return ""
    excerpt = _SECRET_ASSIGNMENT.sub("[redacted]", lines[-1])
    if len(excerpt) > ENUM4LINUX_STDERR_EXCERPT_CHARS:
        excerpt = excerpt[:ENUM4LINUX_STDERR_EXCERPT_CHARS] + "..."
    return excerpt


def _run_enum4linux_ng(target_ip: str) -> Optional[str]:
    """Run enum4linux-ng in JSON-export mode and return the text to analyse.

    Invokes ``ENUM4LINUX_NG_PYTHON ENUM4LINUX_NG_SCRIPT -A -oJ <base> <ip>``
    in a private temporary directory (0700). The export is read from
    ``<base>.json``. The directory is removed on every path, including
    failures.

    Decision rules (approved):
      - non-zero return code          -> explicit failure, no fallback;
      - rc 0 and valid JSON export    -> the JSON text is returned;
      - rc 0 and no JSON export       -> stdout text is returned (text fallback),
                                         or failure if stdout is empty;
      - JSON export present but bad   -> explicit failure, no fallback.

    Args:
        target_ip: IPv4 address of the Windows host.

    Returns:
        Optional[str]: Text to analyse, or None on failure. Every failure is
        displayed explicitly before None is returned.
    """
    with tempfile.TemporaryDirectory(prefix="smb_enum_") as export_dir:
        base = os.path.join(export_dir, "enum4linux")
        command = [ENUM4LINUX_NG_PYTHON, ENUM4LINUX_NG_SCRIPT, "-A", "-oJ", base, target_ip]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=ENUM4LINUX_TIMEOUT_SECONDS,
                check=False,
            )
        except FileNotFoundError:
            _report_failure(target_ip, "enum4linux-ng not found (run 'netlab doctor')")
            return None
        except subprocess.TimeoutExpired:
            _report_failure(target_ip, f"timed out after {ENUM4LINUX_TIMEOUT_SECONDS} s")
            return None
        except OSError as exc:
            _report_failure(target_ip, f"system error ({type(exc).__name__})")
            return None

        if result.returncode != 0:
            excerpt = _stderr_excerpt(result.stderr or "")
            detail = f"exit code {result.returncode}"
            if excerpt:
                detail += f" ({excerpt})"
            _report_failure(target_ip, detail)
            return None

        json_path = base + ".json"
        if os.path.isfile(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                document = json.loads(text)
            except (OSError, ValueError):
                _report_failure(target_ip, "JSON export is unreadable or malformed")
                return None
            if not isinstance(document, dict):
                _report_failure(target_ip, "JSON export is not an object")
                return None
            return text

        stdout = result.stdout or ""
        if not _strip_ansi(stdout).strip():
            _report_failure(target_ip, "no JSON export and no output")
            return None
        return stdout


def _analysis_evidence(**fields: Any) -> str:
    """Serialise only analysed fields as sorted JSON (evidence.raw).

    Never receives the full tool output: the caller passes the named,
    filtered values it actually relies on (decision Q4).
    """
    return json.dumps(fields, sort_keys=True, default=str)


def _parse_enum4linux_output(
    raw_output: str,
    target_ip: str,
    session_id: str,
) -> List[Finding]:
    """Normalize tool output, then convert justified observations to Findings."""
    result = normalize_smb_output(raw_output, target_ip)
    command = ENUM4LINUX_EVIDENCE_COMMAND.format(target=target_ip)
    findings: List[Finding] = []
    seen_services: set[str] = set()

    def add_finding(
        service: str,
        category: Category,
        severity: Severity,
        evidence_raw: str,
        confidence: Confidence = Confidence.CONFIRMED,
    ) -> None:
        """Append one Finding per service key; evidence_raw holds analysed fields only."""
        key = service.lower()
        if key in seen_services:
            return
        seen_services.add(key)
        findings.append(_make_finding(
            session_id=session_id,
            target_ip=target_ip,
            target_service=service,
            category=category,
            severity=severity,
            raw_output=evidence_raw,
            command=command,
            confidence=confidence,
        ))

    for share in result.shares:
        category, severity = _classify_share(share.name)
        add_finding(share.name, category, severity, _analysis_evidence(
            share=share.name,
            source="enum4linux-ng share listing",
        ))

    if result.domain is not None:
        add_finding(result.domain, Category.NETWORK, Severity.INFO, _analysis_evidence(
            domain=result.domain,
            source="enum4linux-ng domain information",
        ))

    # Null session explicitly refused → document the attempt as INFO.
    # This is an observation, not a vulnerability: the server is hardened.
    if result.anonymous_session is False:
        add_finding("smb_access_refused", Category.NETWORK, Severity.INFO, _analysis_evidence(
            anonymous_session=False,
            source="enum4linux-ng session check",
        ))

    # Anonymous authentication alone is an observation. Only confirmed share
    # access creates a stronger Finding with the analysed proof attached.
    if result.anonymous_session is True and result.anonymous_share_access is True:
        add_finding("smb_anonymous_share_access", Category.SERVICE, Severity.MEDIUM,
                    _analysis_evidence(
                        anonymous_session=True,
                        anonymous_share_access=True,
                        source="enum4linux-ng session and share check",
                    ))

    # SMBv1 is detected in two distinct ways:
    # 1. smb1_imposed=True : enum4linux-ng bool-True (enforce_smb1 succeeded).
    #    Evidence distinguishes this case from a named dialect.
    # 2. A named SMBv1 dialect in result.dialects (case-insensitive comparison).
    _smb1_from_name = [d for d in result.dialects
                       if d.lower() in _SMB1_DIALECT_NAMES_LOWER]
    if result.smb1_imposed or _smb1_from_name:
        if result.smb1_imposed:
            _smb1_evidence = _analysis_evidence(
                smb1_imposed=True,
                source="enum4linux-ng enforce_smb1 succeeded (smb_dialects: true)",
            )
        else:
            _smb1_evidence = _analysis_evidence(
                dialects=_smb1_from_name,
                source="enum4linux-ng dialect check",
            )
        add_finding("SMBv1", Category.SERVICE, Severity.HIGH, _smb1_evidence)

    if result.signing_required is False:
        add_finding("smb_signing_not_required", Category.CONFIG, Severity.MEDIUM,
                    _analysis_evidence(
                        signing_required=False,
                        source="enum4linux-ng signing check",
                    ))

    # ── T19 — Writable shares ─────────────────────────────────────────────────
    # Confidence is PROBABLE because enum4linux-ng uses smbclient "dir" to test
    # listing access — it does NOT perform an actual write. Writable status is
    # inferred from the permissions field, not confirmed by a write attempt.
    for share in result.shares:
        perms = (share.permissions or "").upper()
        is_writable = bool(perms) and any(
            token in perms for token in ("WRITE", "READ_WRITE", "CHANGE", "FULL")
        )
        if not is_writable:
            continue
        # Anonymous session + writable = higher risk (no credentials required)
        severity = (
            Severity.HIGH
            if result.anonymous_session is True
            else Severity.MEDIUM
        )
        evidence_raw = json.dumps({
            "share": share.name,
            "permissions": share.permissions,
            "anonymous_session": result.anonymous_session,
            "source": "enum4linux-ng permissions field",
        }, sort_keys=True)
        # Use share name as key to allow one finding per writable share
        svc_key = f"smb_share_writable:{share.name.lower()}"
        if svc_key not in seen_services:
            seen_services.add(svc_key)
            findings.append(_make_finding(
                session_id=session_id,
                target_ip=target_ip,
                target_service="smb_share_writable",
                category=Category.CONFIG,
                severity=severity,
                raw_output=evidence_raw,
                command=command,
                confidence=Confidence.PROBABLE,
            ))

    # ── T19 — Users enumerated ────────────────────────────────────────────────
    # One finding regardless of user count. List stored in evidence.raw as JSON.
    if result.users:
        evidence_raw = json.dumps({
            "users": list(result.users),
            "count": len(result.users),
            "source": "enum4linux-ng user enumeration",
        }, sort_keys=True)
        add_finding(
            "smb_users_enumerated",
            Category.NETWORK,
            Severity.INFO,
            evidence_raw,
            Confidence.CONFIRMED,
        )

    # ── T19 — Weak password policy ────────────────────────────────────────────
    # Severity: HIGH if lockout_threshold == 0, MEDIUM if min_password_length < 8.
    # When both conditions hold, HIGH takes precedence (one single finding).
    if result.password_policy:
        policy = result.password_policy
        min_len = policy.get("min_password_length")
        lockout = policy.get("lockout_threshold")

        weak_min_len = isinstance(min_len, int) and min_len < 8
        no_lockout = isinstance(lockout, int) and lockout == 0

        if weak_min_len or no_lockout:
            severity = Severity.HIGH if no_lockout else Severity.MEDIUM
            evidence_raw = json.dumps({
                "min_password_length": min_len,
                "lockout_threshold": lockout,
                "weak_min_len": weak_min_len,
                "no_lockout": no_lockout,
                "source": "enum4linux-ng password policy",
            }, sort_keys=True)
            add_finding(
                "smb_weak_password_policy",
                Category.CONFIG,
                severity,
                evidence_raw,
                Confidence.CONFIRMED,
            )

    return findings


def normalize_smb_output(raw_output: str, target_ip: str) -> SmbEnumerationResult:
    """Convert JSON or noisy text into one stable internal SMB structure."""
    clean = _strip_ansi(raw_output or "")
    try:
        document = json.loads(clean)
    except (TypeError, json.JSONDecodeError):
        return _normalize_text_output(clean, target_ip)
    if not isinstance(document, dict):
        return _normalize_text_output(clean, target_ip)
    return _normalize_json_output(document, clean, target_ip)


def _strip_ansi(value: str) -> str:
    return _ANSI_ESCAPE.sub("", value).replace("\r", "")


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _find_value(document: Any, aliases: set[str]) -> Any:
    if isinstance(document, dict):
        for key, value in document.items():
            if _normalize_key(str(key)) in aliases:
                return value
        for value in document.values():
            found = _find_value(value, aliases)
            if found is not None:
                return found
    elif isinstance(document, list):
        for value in document:
            found = _find_value(value, aliases)
            if found is not None:
                return found
    return None


def _as_text(value: Any) -> Optional[str]:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "accepted", "enabled", "required", "open"}:
            return True
        if normalized in {"false", "no", "refused", "disabled", "not required", "closed"}:
            return False
    return None


def _as_strings(value: Any) -> Tuple[str, ...]:
    if isinstance(value, dict):
        value = list(value.keys())
    if not isinstance(value, list):
        return () if value is None else (_as_text(value) or "",)
    return tuple(text for item in value if (text := _as_text(item)))


def _normalize_shares(value: Any) -> Tuple[SmbShare, ...]:
    if isinstance(value, dict):
        value = [dict(item, name=name) if isinstance(item, dict) else {"name": name, "comment": item}
                 for name, item in value.items()]
    if not isinstance(value, list):
        return ()
    shares = []
    for item in value:
        if isinstance(item, str):
            name = item.strip()
            details = {}
        elif isinstance(item, dict):
            name = _as_text(_find_value(item, {"name", "sharename", "share"}))
            details = item
        else:
            continue
        if not name:
            continue
        shares.append(SmbShare(
            name=name,
            share_type=_as_text(_find_value(details, {"type", "sharetype"})),
            comment=_as_text(_find_value(details, {"comment", "description"})),
            accessible=_as_bool(_find_value(details, {"accessible", "access", "readable"})),
            permissions=_as_text(_find_value(details, {"permissions", "perms", "accessrights"})),
        ))
    return tuple(shares)


def _policy_int(value: Any) -> Optional[int]:
    """Convert a password-policy field value to int, field by field.

    Decision rules (approved by owner, 2026-11-13, confirmed in
    enum4linux-ng 1.3.10 source l.2630-2631, 2654, 2686-2688):

    * ``None`` or ``"None"`` / ``"none"`` → 0 (zero in enum4linux-ng means
      the threshold is set to zero / unlimited).
    * ``"not set"`` → None (field is not configured; omit it).
    * Any integer-like value (int, float, or numeric string) → int(value).
    * Anything else unrecognised → None (omit the field, do NOT lose the
      other fields in the policy dict).

    Returns:
        int  — parsed value (including 0 for None/none).
        None — field absent, "not set", or unrecognised (omit this field).
    """
    if value is None:
        return 0
    if isinstance(value, bool):
        # bool is a subclass of int in Python; bool values are never valid
        # numeric policy fields — reject them so they cannot produce false positives.
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in ("none",):
            return 0
        if normalised in ("not set", "not_set", "notset", "n/a", "unknown", ""):
            return None
        try:
            return int(value.strip())
        except (ValueError, TypeError):
            return None
    return None


def _extract_password_policy(raw: Any) -> Optional[dict]:
    """Extract min_password_length and lockout_threshold from a policy dict.

    Each field is converted independently by ``_policy_int`` so that one
    unrecognised value does not discard the whole policy.  Returns None only
    when the dict is absent or both fields are absent / "not set".

    Args:
        raw: Raw value found via _find_value (may be dict, list, or None).

    Returns:
        Optional[dict]: {"min_password_length": int, "lockout_threshold": int}
        (each key present only when the value could be converted).
    """
    if not isinstance(raw, dict):
        return None
    # Use _find_key_value (not _find_value) to distinguish a key that is
    # present with JSON null (Python None → 0 by rule) from a key that is
    # simply absent (field omitted, never invented as 0).
    min_found, min_len_raw = _find_key_value(
        raw, {"minpasswdlength", "minimumpasswordlength",
              "minpasswordlength", "minlen", "minlength"}
    )
    lock_found, lockout_raw = _find_key_value(
        raw, {"lockoutthreshold", "accountlockoutthreshold",
              "lockout", "badpwdcount", "badpasswordcount"}
    )
    result: dict = {}
    if min_found:
        min_len = _policy_int(min_len_raw)
        if min_len is not None:
            result["min_password_length"] = min_len
    if lock_found:
        lockout = _policy_int(lockout_raw)
        if lockout is not None:
            result["lockout_threshold"] = lockout
    return result if result else None



# _SMB1_DIALECT_NAMES: canonical SMBv1 identifiers found in enum4linux-ng JSON
# dict-format dialect maps. Comparison is case-insensitive (see _extract_dialects).
# "NT1" is kept for backward compatibility with legacy list-format output only.
_SMB1_DIALECT_NAMES: Tuple[str, ...] = ("NT1", "SMBv1", "SMB 1.0", "SMB1")

# Normalised lower-case set for case-insensitive look-up
_SMB1_DIALECT_NAMES_LOWER: frozenset = frozenset(n.lower() for n in _SMB1_DIALECT_NAMES)


def _extract_dialects(value: Any) -> Tuple[Tuple[str, ...], bool]:
    """Extract dialect names and the SMBv1-imposed flag from a JSON dialect value.

    enum4linux-ng 1.3.10 may produce one of three formats for smb_dialects:

    * ``true`` (bool)   — SMBv1-only path: enum4linux-ng called enforce_smb1()
      and the boolean records its success.  No dialect *name* is known from
      the JSON in this case.  Returns ((), True): an empty dialect tuple and
      smb1_imposed=True.  The caller must NOT place a synthetic name ("NT1")
      into the dialect list.

    * ``false`` (bool)  — enforce_smb1 failed or SMBv1 not present.
      Returns ((), False).

    * ``{<name>: <bool>, …}`` (dict) — dialect negotiation map.  Returns
      (names_of_active_dialects, False).  A dialect is considered active only
      when its value is explicitly True according to ``_as_bool``; unknown /
      unrecognised values (None from _as_bool) are treated as inactive so that
      "0", "none", "None", "not set", "unsupported" do not trigger a Finding.
      Comparison against _SMB1_DIALECT_NAMES is case-insensitive.

    * Any other type → fallback to ``_as_strings`` with smb1_imposed=False.

    Returns:
        Tuple[Tuple[str, ...], bool]: (dialect_names, smb1_imposed)
    """
    if isinstance(value, bool):
        return (), value   # True → imposed; False → not present
    if isinstance(value, dict):
        names: List[str] = []
        for k, v in value.items():
            name = _as_text(k)
            if not name:
                continue
            enabled = _as_bool(v)
            if enabled is True:          # only explicit True; None → skip
                names.append(name)
        return tuple(dict.fromkeys(names)), False
    # list / str / int / None → original behaviour
    return _as_strings(value), False


_MISSING = object()   # sentinel — distinct from None, False, {}, []


def _find_key_value(document: Any, aliases: set[str]) -> Tuple[bool, Any]:
    """Like _find_value but distinguishes absence from a falsy value.

    Returns:
        (True, value)  — a key matching ``aliases`` was found at the top
                         level of the dict; ``value`` may be False, None,
                         [], {}, or any other falsy object.
        (False, None)  — no matching key exists in the top-level dict.

    Only the top level is searched (no recursive descent), because the
    caller needs to know that the key belongs to the root document, not
    to a nested sub-structure.
    """
    if not isinstance(document, dict):
        return False, None
    for key, value in document.items():
        if _normalize_key(str(key)) in aliases:
            return True, value
    return False, None


def _normalize_json_output(document: dict, raw: str, target_ip: str) -> SmbEnumerationResult:
    """Read common enum4linux-ng-style aliases without leaking them outward."""
    shares = _normalize_shares(_find_value(document, {"shares", "sharelist", "shareenum"}))
    anonymous = _as_bool(_find_value(document, {"anonymoussession", "anonymous", "nullsession"}))
    accessible = _as_bool(_find_value(document, {"anonymousshareaccess", "shareaccessible"}))
    if accessible is None and shares:
        accessible = any(share.accessible is True for share in shares)
    signing = _as_bool(_find_value(document, {"signingrequired", "smbsigningrequired", "signing"}))
    # ── Dialect extraction (provenance-aware) ───────────────────────────────
    # Rule: smb1_imposed=True is only valid when the JSON key is exactly
    # "smb_dialects" (alias "smbdialects") AND its value is the boolean True.
    # This matches the confirmed behaviour of enum4linux-ng 1.3.10 where a
    # boolean True in that key means enforce_smb1() succeeded.
    #
    # Algorithm:
    #   Step 1 — search the CANONICAL key ("smbdialects" / "smb_dialects").
    #     If the key IS present, use its value exclusively regardless of
    #     truthiness.  smb1_imposed may be set here.
    #   Step 2 — only if the canonical key is ABSENT, fall back to "dialects"
    #     and then to "protocol"/"smbprotocol".  These generic aliases may
    #     supply dialect names or structures but NEVER smb1_imposed=True.
    _canonical_found, _canonical_val = _find_key_value(
        document, {"smbdialects"}      # "smb_dialects" normalises to "smbdialects"
    )
    if _canonical_found:
        # Canonical key present: respect its value, even if falsy.
        # _extract_dialects handles bool/dict/list/None correctly.
        _dialects_tuple, _smb1_imposed = _extract_dialects(_canonical_val)
    else:
        # Canonical key absent: try "dialects" first, then generic aliases.
        # Boolean True from these aliases must NOT set smb1_imposed.
        _fallback_found, _fallback_val = _find_key_value(document, {"dialects"})
        if not _fallback_found:
            _fallback_val = _find_value(document, {"protocol", "smbprotocol"})
        _dialects_tuple, _raw_imposed = _extract_dialects(_fallback_val)
        # Strip smb1_imposed: generic aliases cannot guarantee enforce_smb1
        _smb1_imposed = False
    policy_raw = _find_value(document, {"passwordpolicy", "passwdpolicy", "passwordpolicies",
                                        "password_policy", "passpol"})
    return SmbEnumerationResult(
        target=target_ip,
        os=_as_text(_find_value(document, {"os", "operatingsystem", "targetos"})),
        hostname=_as_text(_find_value(document, {"hostname", "host"})),
        domain=_as_text(_find_value(document, {"domain", "workgroup", "domainname"})),
        sid=_as_text(_find_value(document, {"sid", "domainsid"})),
        mac=_as_text(_find_value(document, {"mac", "macaddress"})),
        dialects=_dialects_tuple,
        smb1_imposed=_smb1_imposed,
        signing_required=signing,
        shares=shares,
        users=_as_strings(_find_value(document, {"users", "userlist"})),
        groups=_as_strings(_find_value(document, {"groups", "grouplist"})),
        anonymous_session=anonymous,
        anonymous_share_access=accessible,
        password_policy=_extract_password_policy(policy_raw),
        raw_output=raw,
        source_format="json",
    )


def _normalize_text_output(raw: str, target_ip: str) -> SmbEnumerationResult:
    """Best-effort parser for legacy text; absent values remain unknown."""
    lower = raw.lower()
    anonymous = True if re.search(r"anonymous.*(accepted|success|allowed)", lower) else None
    if re.search(r"anonymous.*(refused|denied|rejected)", lower):
        anonymous = False
    signing = None
    if re.search(r"signing.*(required|mandatory)", lower):
        signing = True
    elif re.search(r"signing.*(not required|disabled|not mandatory)", lower):
        signing = False
    dialects = tuple(re.findall(r"\b(SMBv?1|SMB[23](?:\.\d+)?)\b", raw, re.IGNORECASE))
    access = True if re.search(r"anonymous.*(?:share|resource).*(accessible|read|write)", lower) else None
    return SmbEnumerationResult(
        target=target_ip,
        os=_text_field(raw, (r"OS(?: version)?[:.]\s*(.+)", r"OS:\s*(.+)")),
        hostname=_text_field(raw, (r"(?:NetBIOS )?Name[:.]\s*(\S+)",)),
        domain=_extract_domain_name(raw),
        sid=_text_field(raw, (r"Domain SID[:.]\s*(S-\d-[0-9-]+)",)),
        mac=_text_field(raw, (r"MAC(?: address)?[:.]\s*([0-9a-f:.-]+)",)),
        dialects=tuple(dict.fromkeys(dialects)),
        signing_required=signing,
        shares=tuple(SmbShare(name=name) for name in _extract_share_names(raw)),
        users=tuple(re.findall(r"Account:\s*(\S+)", raw, re.IGNORECASE)),
        groups=(),
        anonymous_session=anonymous,
        anonymous_share_access=access,
        password_policy=None,   # not extractable from legacy text output
        raw_output=raw,
        source_format="text",
    )


def _text_field(raw: str, patterns: Tuple[str, ...]) -> Optional[str]:
    for pattern in patterns:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def _extract_share_names(raw_output: str) -> List[str]:
    """Return share names parsed from an enum4linux share table.

    Args:
        raw_output: Full enum4linux output.

    Returns:
        List[str]: Share names in the order they appeared.
    """
    names: List[str] = []
    for line in raw_output.splitlines():
        match = _SHARE_ROW.match(line)
        if match is None:
            continue
        name = match.group(1)
        if name.lower() in _SHARE_HEADER_NAMES or set(name) <= {"-"}:
            continue
        names.append(name)
    return names


def _extract_domain_name(raw_output: str) -> Optional[str]:
    """Return a domain or workgroup name if enum4linux reported one.

    Args:
        raw_output: Full enum4linux output.

    Returns:
        Optional[str]: Domain/workgroup name, or None if not available.
    """
    for pattern in _DOMAIN_PATTERNS:
        match = pattern.search(raw_output)
        if match is None:
            continue
        name = match.group(1).strip().strip("'\"")
        if name and name.upper() not in {"(NULL)", "NULL", "UNKNOWN", "N/A"}:
            return name
    return None


def _classify_share(share_name: str) -> Tuple[Category, Severity]:
    """Return category and severity for a detected share.

    ADMIN$ is specified by the ticket: CREDENTIAL / MEDIUM.
    Other shares are reported as SERVICE / INFO (confirmed observation).

    Args:
        share_name: Share name as printed by enum4linux.

    Returns:
        Tuple[Category, Severity]: Classification for this share.
    """
    if share_name.upper() == "ADMIN$":
        return Category.CREDENTIAL, Severity.MEDIUM
    return Category.SERVICE, Severity.INFO


def _make_finding(
    session_id: str,
    target_ip: str,
    target_service: str,
    category: Category,
    severity: Severity,
    raw_output: str,
    command: str,
    confidence: Confidence = Confidence.CONFIRMED,
) -> Finding:
    """Construct a Finding for this module. risk_score and explanation stay None.

    Args:
        session_id:     Current audit session ID.
        target_ip:      Host that was enumerated.
        target_service: Share name or rule id.
        category:       Finding category.
        severity:       Finding severity.
        raw_output:     Analysed-fields JSON only (evidence.raw); never full tool output.
        command:        Exact command that produced the output.
        confidence:     Confidence level (default CONFIRMED; use PROBABLE when
                        the evidence is indirect, e.g. share writable inferred
                        from permissions field rather than a real write attempt).

    Returns:
        Finding: Populated Finding.
    """
    return Finding(
        session_id=session_id,
        module=MODULE_NAME,
        target_ip=target_ip,
        target_port=SMB_PORT,
        target_service=target_service,
        category=category,
        severity=severity,
        confidence=confidence,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(raw=raw_output, command=command),
        explanation=None,
        risk_score=None,
    )
