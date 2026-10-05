"""
detect/smb_enum.py — SMB share / user / domain enumeration via enum4linux

Pipeline step: DETECT
Role: Enumerate SMB shares, users, and domain information on a Windows host.
      One Finding per detected share, plus one Finding for domain info
      when a domain or workgroup name is present in the output.

Does not calculate risk_score. Does not write to SQLite. Does not print().

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — display via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding]
- ALWAYS ask (y/n) confirmation before sending traffic
- explanation stays None (no knowledge-base rule wired here)
- evidence.raw is the raw enum4linux stdout
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

import typer

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
    raw_output: str = ""
    source_format: str = "text"


def smb_enum(target_ip: str, session_id: str) -> List[Finding]:
    """Enumerate SMB shares and domain info on a Windows host.

    Asks for (y/n) confirmation before running enum4linux. Returns an
    empty list when the tool is missing, the user cancels, or output is
    empty — never raises for those cases.

    Args:
        target_ip: IPv4 address of the Windows host.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One Finding per detected share, plus one domain
        Finding when domain information is available.
    """
    if shutil.which("enum4linux") is None:
        display("[red]enum4linux not found. Run 'netlab doctor'.[/red]")
        return []

    confirmed = typer.confirm(
        f"[smb_enum] Enumerate SMB shares, users and domain on {target_ip}?"
    )
    if not confirmed:
        display("[yellow]SMB enumeration cancelled.[/yellow]")
        return []

    display(f"[cyan]Starting enum4linux on {target_ip}...[/cyan]")
    raw_output = _run_enum4linux(target_ip)
    if not raw_output:
        display(f"[yellow]No output from enum4linux on {target_ip}.[/yellow]")
        return []

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


def _run_enum4linux(target_ip: str) -> Optional[str]:
    """Run enum4linux and return stdout, or None on error / empty output.

    Args:
        target_ip: IPv4 address of the Windows host.

    Returns:
        Optional[str]: Raw stdout, or None.
    """
    command = ["enum4linux", "-a", target_ip]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=ENUM4LINUX_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        display("[red]enum4linux not found. Run 'netlab doctor'.[/red]")
        return None
    except subprocess.TimeoutExpired:
        display("[yellow]enum4linux timed out.[/yellow]")
        return None
    except OSError as exc:
        display(f"[red]enum4linux error: {exc}[/red]")
        return None

    combined = f"{result.stdout or ''}{result.stderr or ''}"
    stripped = combined.strip()
    if not stripped:
        return None
    return combined


def _parse_enum4linux_output(
    raw_output: str,
    target_ip: str,
    session_id: str,
) -> List[Finding]:
    """Normalize tool output, then convert justified observations to Findings."""
    result = normalize_smb_output(raw_output, target_ip)
    command = f"enum4linux -a {target_ip}"
    findings: List[Finding] = []
    seen_services: set[str] = set()

    def add_finding(service: str, category: Category, severity: Severity) -> None:
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
            raw_output=result.raw_output,
            command=command,
        ))

    for share in result.shares:
        category, severity = _classify_share(share.name)
        add_finding(share.name, category, severity)

    if result.domain is not None:
        add_finding(result.domain, Category.NETWORK, Severity.INFO)

    # Anonymous authentication alone is an observation. Only confirmed share
    # access creates a stronger Finding with the raw proof attached.
    if result.anonymous_session is True and result.anonymous_share_access is True:
        add_finding("smb_anonymous_share_access", Category.SERVICE, Severity.MEDIUM)

    if "NT1" in result.dialects or "SMBv1" in result.dialects:
        add_finding("SMBv1", Category.SERVICE, Severity.HIGH)

    if result.signing_required is False:
        add_finding("smb_signing_not_required", Category.CONFIG, Severity.MEDIUM)

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


def _normalize_json_output(document: dict, raw: str, target_ip: str) -> SmbEnumerationResult:
    """Read common enum4linux-ng-style aliases without leaking them outward."""
    shares = _normalize_shares(_find_value(document, {"shares", "sharelist", "shareenum"}))
    anonymous = _as_bool(_find_value(document, {"anonymoussession", "anonymous", "nullsession"}))
    accessible = _as_bool(_find_value(document, {"anonymousshareaccess", "shareaccessible"}))
    if accessible is None and shares:
        accessible = any(share.accessible is True for share in shares)
    signing = _as_bool(_find_value(document, {"signingrequired", "smbsigningrequired", "signing"}))
    dialect_value = _find_value(document, {"dialects", "smbdialects", "protocol", "smbprotocol"})
    return SmbEnumerationResult(
        target=target_ip,
        os=_as_text(_find_value(document, {"os", "operatingsystem", "targetos"})),
        hostname=_as_text(_find_value(document, {"hostname", "host"})),
        domain=_as_text(_find_value(document, {"domain", "workgroup", "domainname"})),
        sid=_as_text(_find_value(document, {"sid", "domainsid"})),
        mac=_as_text(_find_value(document, {"mac", "macaddress"})),
        dialects=_as_strings(dialect_value),
        signing_required=signing,
        shares=shares,
        users=_as_strings(_find_value(document, {"users", "userlist"})),
        groups=_as_strings(_find_value(document, {"groups", "grouplist"})),
        anonymous_session=anonymous,
        anonymous_share_access=accessible,
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
        users=tuple(re.findall(r"Account:\\s*(\\S+)", raw, re.IGNORECASE)),
        groups=(),
        anonymous_session=anonymous,
        anonymous_share_access=access,
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
) -> Finding:
    """Construct a Finding for this module. risk_score and explanation stay None.

    Args:
        session_id: Current audit session ID.
        target_ip: Host that was enumerated.
        target_service: Share name or domain name.
        category: Finding category.
        severity: Finding severity.
        raw_output: Full enum4linux stdout (evidence.raw).
        command: Exact command that produced the output.

    Returns:
        Finding: Populated Finding with confidence CONFIRMED.
    """
    return Finding(
        session_id=session_id,
        module=MODULE_NAME,
        target_ip=target_ip,
        target_port=SMB_PORT,
        target_service=target_service,
        category=category,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(raw=raw_output, command=command),
        explanation=None,
        risk_score=None,
    )
