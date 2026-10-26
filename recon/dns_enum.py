"""
recon/dns_enum.py — DNS enumeration and registration lookup (standalone, not in scan).

Targets:
  - IPv4 address  → PTR lookup, forward-confirmed when possible.
  - Domain        → A, MX, NS, TXT, CNAME records, PTR for every A address,
                    then the registration summary (RDAP + WHOIS, see
                    recon/registration.py).

Confidence rules for records:
  - CONFIRMED only when the answer carries the AA (authoritative) flag.
  - PROBABLE otherwise (answer from a recursive resolver, not demonstrated authoritative).

Outcomes are kept distinct: NXDOMAIN, no data (NoAnswer), timeout, resolver
unavailable, other error. A missing answer is never presented as proof that
a record does not exist, and no Finding is created for an error.

Exposure: DNS and registration data are public information, not a service
observation. No Finding is marked EXTERNAL here (no exposure is demonstrated),
and the value stays at the Exposure default. See docs/T24-RECON.md.

No raw DNS message or raw WHOIS/RDAP text is stored or returned.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple

import dns.exception
import dns.flags
import dns.resolver
import dns.reversename

from core.finding import (
    Category,
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Severity,
)
from recon.rdap import RdapClient
from recon.registration import (
    SOURCE_RDAP,
    RegistrationSummary,
    lookup_registration,
    registration_evidence,
)

DNS_LIFETIME_SECONDS: float = 5.0
DNS_RECORD_TYPES: Tuple[str, ...] = ("A", "MX", "NS", "TXT", "CNAME")
MAX_PTR_LOOKUPS: int = 8

# Outcome statuses for one DNS query.
DNS_OK = "ok"
DNS_NXDOMAIN = "nxdomain"
DNS_NODATA = "nodata"
DNS_TIMEOUT = "timeout"
DNS_UNAVAILABLE = "unavailable"
DNS_ERROR = "error"

DNS_STATUS_LABELS = {
    DNS_OK: "réponse reçue",
    DNS_NXDOMAIN: "NXDOMAIN (nom inexistant selon le résolveur)",
    DNS_NODATA: "aucune donnée pour ce type",
    DNS_TIMEOUT: "timeout (pas de réponse : inconnu, pas inexistant)",
    DNS_UNAVAILABLE: "résolveur ou serveur indisponible",
    DNS_ERROR: "erreur DNS",
}

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_TLD = r"[a-z][a-z0-9-]{0,61}[a-z0-9]"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_TLD}$")


@dataclass
class DnsOutcome:
    """Result of one DNS query. ``values`` is only filled when status is 'ok'."""

    record_type: str
    status: str
    values: List[str] = field(default_factory=list)
    authoritative: bool = False


@dataclass
class DomainReport:
    """Everything the standalone whois/dns command needs to render."""

    target: str
    kind: str  # "ip" or "domain"
    outcomes: List[DnsOutcome] = field(default_factory=list)
    ptr: List[Tuple[str, str]] = field(default_factory=list)  # (ip, hostname)
    registration: Optional[RegistrationSummary] = None
    findings: List[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

def _is_ip(target: str) -> bool:
    try:
        return ipaddress.ip_address(target).version == 4
    except ValueError:
        return False


def normalize_domain(target: str) -> str:
    """Return the lower-case domain without trailing dot, or raise ValueError."""
    candidate = target.strip().rstrip(".").lower()
    if len(candidate) > 253 or not _DOMAIN_RE.match(candidate):
        raise ValueError(f"cible invalide : {target!r} (attendu : domaine ou IPv4)")
    return candidate


def target_kind(target: str) -> str:
    """Classify a target as 'ip' (IPv4) or 'domain'. Raises ValueError otherwise."""
    if ":" in target:
        raise ValueError("IPv6 non pris en charge par cette commande")
    if _is_ip(target):
        return "ip"
    normalize_domain(target)
    return "domain"


# ---------------------------------------------------------------------------
# DNS queries
# ---------------------------------------------------------------------------

def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_LIFETIME_SECONDS
    return resolver


def _query(
    name: str,
    record_type: str,
    resolver_factory: Optional[Callable[[], Any]] = None,
) -> DnsOutcome:
    """Query one name/type and classify the outcome. Never raises."""
    try:
        resolver = (resolver_factory or _make_resolver)()
        answer = resolver.resolve(name, record_type, raise_on_no_answer=True)
    except dns.resolver.NXDOMAIN:
        return DnsOutcome(record_type, DNS_NXDOMAIN)
    except dns.resolver.NoAnswer:
        return DnsOutcome(record_type, DNS_NODATA)
    except dns.resolver.NoNameservers:
        return DnsOutcome(record_type, DNS_UNAVAILABLE)
    except dns.resolver.LifetimeTimeout:
        return DnsOutcome(record_type, DNS_TIMEOUT)
    except dns.exception.Timeout:
        return DnsOutcome(record_type, DNS_TIMEOUT)
    except dns.exception.DNSException:
        return DnsOutcome(record_type, DNS_ERROR)
    except Exception:  # defensive: an unexpected resolver failure is an error status
        return DnsOutcome(record_type, DNS_ERROR)

    values = [str(item).rstrip(".") if record_type != "TXT" else str(item) for item in answer]
    authoritative = bool(answer.response.flags & dns.flags.AA)
    return DnsOutcome(record_type, DNS_OK, values=values, authoritative=authoritative)


def _ptr_outcome(ip: str, resolver_factory: Optional[Callable[[], Any]] = None) -> DnsOutcome:
    reverse = str(dns.reversename.from_address(ip))
    return _query(reverse, "PTR", resolver_factory)


def _forward_confirm(hostname: str, original_ip: str) -> Confidence:
    """CONFIRMED when hostname resolves back to original_ip, else PROBABLE."""
    try:
        resolved_ips = {r[4][0] for r in socket.getaddrinfo(hostname, None)}
        if original_ip in resolved_ips:
            return Confidence.CONFIRMED
        return Confidence.PROBABLE
    except Exception:
        return Confidence.PROBABLE


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

_MAX_VALUE_CHARS = 300


def _record_findings(domain: str, outcomes: List[DnsOutcome], session_id: str) -> List[Finding]:
    findings: List[Finding] = []
    for outcome in outcomes:
        if outcome.status != DNS_OK or not outcome.values:
            continue
        values = [v if len(v) <= _MAX_VALUE_CHARS else v[:_MAX_VALUE_CHARS] + "…" for v in outcome.values]
        authority = "réponse autoritative (AA)" if outcome.authoritative else "réponse non autoritative"
        findings.append(Finding(
            session_id=session_id,
            module="dns_enum",
            target_ip="",
            target_port=None,
            target_service="dns",
            service_version=f"{outcome.record_type} ({len(values)})",
            category=Category.CONFIG,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED if outcome.authoritative else Confidence.PROBABLE,
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=f"{domain} {outcome.record_type} — {authority}\n" + "\n".join(values),
                command=f"dig {domain} {outcome.record_type}",
            ),
        ))
    return findings


def _ptr_findings(pairs: List[Tuple[str, str]], session_id: str,
                  confidence_for: Callable[[str, str], Confidence]) -> List[Finding]:
    """One Finding per PTR pair. target_ip is the IP the PTR belongs to, never a domain."""
    findings: List[Finding] = []
    for ip, hostname in pairs:
        findings.append(Finding(
            session_id=session_id,
            module="dns_enum",
            target_ip=ip,
            target_port=None,
            target_service="dns",
            service_version=f"PTR {hostname}",
            category=Category.CONFIG,
            severity=Severity.INFO,
            confidence=confidence_for(hostname, ip),
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=f"PTR {ip} → {hostname}",
                command=f"dig -x {ip}",
            ),
        ))
    return findings


def _registration_finding(summary: RegistrationSummary, session_id: str) -> Optional[Finding]:
    if not summary.has_data:
        return None
    registrar = summary.fields.get("registrar")
    version = f"registrar={registrar.value}" if registrar is not None and not registrar.masked else "enregistrement"
    confidence = Confidence.CONFIRMED if summary.primary_source == SOURCE_RDAP else Confidence.PROBABLE
    return Finding(
        session_id=session_id,
        module="dns_enum",
        target_ip="",
        target_port=None,
        target_service="whois",
        service_version=version,
        category=Category.CONFIG,
        severity=Severity.INFO,
        confidence=confidence,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(
            raw=registration_evidence(summary),
            command=f"RDAP {summary.domain} + whois {summary.domain}",
        ),
    )


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def dns_report(
    target: str,
    session_id: str,
    resolver_factory: Optional[Callable[[], Any]] = None,
    rdap_client: Optional[RdapClient] = None,
    whois_func: Optional[Callable[..., Any]] = None,
) -> DomainReport:
    """Run the DNS (and, for domains, registration) lookups and build the report.

    Raises:
        ValueError: when the target is neither a valid IPv4 nor a valid domain.
    """
    kind = target_kind(target)
    if kind == "ip":
        outcome = _ptr_outcome(target, resolver_factory)
        pairs = [(target, host) for host in outcome.values] if outcome.status == DNS_OK else []
        findings = _ptr_findings(
            pairs, session_id=session_id,
            confidence_for=lambda host, ip: _forward_confirm(host, ip),
        )
        return DomainReport(target=target, kind=kind, outcomes=[outcome], ptr=pairs, findings=findings)

    domain = normalize_domain(target)
    outcomes = [_query(domain, rtype, resolver_factory) for rtype in DNS_RECORD_TYPES]

    a_outcome = next(o for o in outcomes if o.record_type == "A")
    a_ips: List[str] = []
    for value in a_outcome.values if a_outcome.status == DNS_OK else []:
        try:
            if ipaddress.ip_address(value).version == 4 and value not in a_ips:
                a_ips.append(value)
        except ValueError:
            continue

    pairs: List[Tuple[str, str]] = []
    for ip in a_ips[:MAX_PTR_LOOKUPS]:
        ptr = _ptr_outcome(ip, resolver_factory)
        if ptr.status == DNS_OK:
            pairs.extend((ip, host) for host in ptr.values)

    registration = lookup_registration(domain, rdap_client=rdap_client, whois_func=whois_func)

    findings: List[Finding] = []
    findings.extend(_record_findings(domain, outcomes, session_id))
    findings.extend(_ptr_findings(
        pairs, session_id=session_id,
        confidence_for=lambda host, ip: Confidence.PROBABLE,
    ))
    registration_finding = _registration_finding(registration, session_id)
    if registration_finding is not None:
        findings.append(registration_finding)

    return DomainReport(
        target=domain,
        kind=kind,
        outcomes=outcomes,
        ptr=pairs,
        registration=registration,
        findings=findings,
    )


def dns_enum(target: str, session_id: str) -> List[Finding]:
    """Return the Findings for a target (IPv4 → PTR, domain → records + registration)."""
    return dns_report(target, session_id).findings
