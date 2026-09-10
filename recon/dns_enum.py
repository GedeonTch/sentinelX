"""
recon/dns_enum.py — DNS enumeration and WHOIS lookup

Pipeline step: DISCOVER
Role: Resolve hostnames, DNS records, and WHOIS data for discovered targets.

This module answers:
  - "What hostname does this IP have?" (reverse DNS / PTR)
  - "What DNS records exist for this domain?" (A, MX, NS, TXT, CNAME)
  - "Who registered this domain?" (WHOIS)

Designed to be called after device_fingerprint.py — it enriches the
picture of what's on the network without sending active scan traffic.

DNS queries are passive from the perspective of the target — they go to
DNS servers, not directly to the target machine.
WHOIS queries go to public WHOIS servers — also passive for the target.

Rules enforced here:
- ZERO import sqlite3
- ZERO print() — logging via core/logger.py
- ZERO risk_score calculation
- ALWAYS return List[Finding]
- No (y/n) confirmation needed — DNS/WHOIS queries are passive (no traffic
  sent to the target itself). Active confirmation is only required for
  direct network traffic to the target (Section B.6 of steering doc).

Confidence rules:
    CONFIRMED — PTR record exists and resolves back to the same IP (forward-confirmed)
    PROBABLE  — PTR record exists but forward lookup was not verified
    POSSIBLE  — hostname inferred from WHOIS or DNS A record only
"""

import socket
from typing import List, Optional, Dict

import dns.resolver
import dns.reversename
import dns.exception
import whois as whois_lib

from core.finding import (
    Finding,
    Evidence,
    Category,
    Severity,
    Confidence,
    Exposure,
)
from core.logger import display


# DNS record types to enumerate when target is a domain name
_DNS_RECORD_TYPES = ("A", "MX", "NS", "TXT", "CNAME")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def dns_enum(target: str, session_id: str) -> List[Finding]:
    """Enumerate DNS records and WHOIS data for a target.

    Handles two cases:
      - IP address  → reverse DNS (PTR) lookup only
      - Domain name → PTR + A/MX/NS/TXT/CNAME records + WHOIS

    No (y/n) confirmation — DNS/WHOIS queries are passive.
    They go to DNS servers, not directly to the target.

    Args:
        target:     IP address or domain name (e.g. "192.168.1.1" or "example.com").
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One Finding per DNS record type found + one for WHOIS if available.
                       Empty list if no DNS data found.
    """
    display(f"[cyan]Starting DNS enumeration for {target}...[/cyan]")

    findings: List[Finding] = []

    if _is_ip(target):
        # IP target — reverse DNS only
        findings.extend(_reverse_dns_findings(target, session_id))
    else:
        # Domain target — full enumeration
        findings.extend(_reverse_dns_findings(target, session_id))
        findings.extend(_dns_record_findings(target, session_id))
        whois_finding = _whois_finding(target, session_id)
        if whois_finding:
            findings.append(whois_finding)

    if findings:
        display(f"[green]DNS enumeration complete — {len(findings)} finding(s).[/green]")
    else:
        display(f"[yellow]No DNS data found for {target}.[/yellow]")

    return findings


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def _reverse_dns_findings(target: str, session_id: str) -> List[Finding]:
    """Perform reverse DNS lookup and return a Finding if a PTR record exists.

    Args:
        target:     IP address or domain name.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One Finding if PTR resolved, empty list otherwise.
    """
    hostname, confidence, raw = _reverse_dns(target)
    if not hostname:
        return []

    return [Finding(
        session_id=session_id,
        module="dns_enum",
        target_ip=target if _is_ip(target) else "",
        target_service="dns",
        service_version=f"PTR → {hostname}",
        category=Category.NETWORK,
        severity=Severity.INFO,
        confidence=confidence,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(
            raw=raw,
            command=f"dig -x {target}" if _is_ip(target) else f"dig {target} PTR",
        ),
        explanation=None,
        cve_refs=[],
    )]


def _reverse_dns(target: str) -> tuple[str, Confidence, str]:
    """Perform a reverse DNS (PTR) lookup for an IP or domain.

    For an IP: looks up the PTR record.
    For a domain: resolves A record, then does reverse lookup on the IP.

    Confidence:
        CONFIRMED — PTR resolved AND forward lookup of the hostname confirms
                    it maps back to the same IP.
        PROBABLE  — PTR resolved but forward confirmation failed or not attempted.

    Args:
        target: IP address or domain name.

    Returns:
        Tuple[str, Confidence, str]: (hostname, confidence, raw_evidence)
        Returns ("", PROBABLE, "") if lookup fails.
    """
    try:
        if _is_ip(target):
            rev_name = dns.reversename.from_address(target)
            answers = dns.resolver.resolve(rev_name, "PTR")
            hostname = str(answers[0]).rstrip(".")
            raw = f"PTR lookup for {target}:\n" + "\n".join(str(r) for r in answers)

            # Forward-confirm: does the hostname resolve back to the same IP?
            confidence = _forward_confirm(hostname, target)
            return hostname, confidence, raw
        else:
            # Domain → get A record
            answers = dns.resolver.resolve(target, "A")
            ip = str(answers[0])
            raw = f"A record for {target}: {ip}"
            # Now reverse lookup the IP
            rev_name = dns.reversename.from_address(ip)
            ptr_answers = dns.resolver.resolve(rev_name, "PTR")
            hostname = str(ptr_answers[0]).rstrip(".")
            raw += f"\nPTR for {ip}: {hostname}"
            return hostname, Confidence.PROBABLE, raw

    except (dns.exception.DNSException, Exception):
        return "", Confidence.PROBABLE, ""


def _forward_confirm(hostname: str, original_ip: str) -> Confidence:
    """Check if a hostname resolves back to the expected IP.

    Args:
        hostname:    Hostname from PTR record.
        original_ip: IP that the PTR was resolved from.

    Returns:
        Confidence.CONFIRMED if hostname → original_ip, else PROBABLE.
    """
    try:
        resolved_ips = {r[4][0] for r in socket.getaddrinfo(hostname, None)}
        if original_ip in resolved_ips:
            return Confidence.CONFIRMED
        return Confidence.PROBABLE
    except Exception:
        return Confidence.PROBABLE


# ---------------------------------------------------------------------------
# DNS records (A, MX, NS, TXT, CNAME)
# ---------------------------------------------------------------------------

def _dns_record_findings(domain: str, session_id: str) -> List[Finding]:
    """Query standard DNS record types for a domain and return Findings.

    Args:
        domain:     Domain name to query.
        session_id: Current audit session ID.

    Returns:
        List[Finding]: One Finding per record type that returns results.
    """
    findings = []
    for record_type in _DNS_RECORD_TYPES:
        records, raw = _dns_records(domain, record_type)
        if not records:
            continue

        findings.append(Finding(
            session_id=session_id,
            module="dns_enum",
            target_ip="",
            target_service="dns",
            service_version=f"{record_type} records",
            category=Category.NETWORK,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,  # DNS answer is authoritative
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=raw,
                command=f"dig {domain} {record_type}",
            ),
            explanation=None,
            cve_refs=[],
        ))

    return findings


def _dns_records(domain: str, record_type: str) -> tuple[List[str], str]:
    """Query a specific DNS record type for a domain.

    Args:
        domain:      Domain name.
        record_type: DNS record type (A, MX, NS, TXT, CNAME).

    Returns:
        Tuple[List[str], str]: (list of record values, raw evidence string)
        Returns ([], "") if no records found or on error.
    """
    try:
        answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
        records = [str(r) for r in answers]
        if not records:
            return [], ""
        raw = f"{record_type} records for {domain}:\n" + "\n".join(records)
        return records, raw
    except (dns.exception.DNSException, Exception):
        return [], ""


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def _whois_finding(domain: str, session_id: str) -> Optional[Finding]:
    """Perform a WHOIS lookup for a domain and return a Finding.

    Args:
        domain:     Domain name.
        session_id: Current audit session ID.

    Returns:
        Finding if WHOIS data found, None otherwise.
    """
    data, raw = _whois_lookup(domain)
    if not data or not raw:
        return None

    # Build a readable summary for service_version
    registrar = data.get("registrar", "")
    creation = data.get("creation_date", "")
    if isinstance(creation, list):
        creation = creation[0]
    summary = f"registrar={registrar}" if registrar else "WHOIS data available"

    return Finding(
        session_id=session_id,
        module="dns_enum",
        target_ip="",
        target_service="whois",
        service_version=summary,
        category=Category.NETWORK,
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNAL,
        evidence=Evidence(
            raw=raw,
            command=f"whois {domain}",
        ),
        explanation=None,
        cve_refs=[],
    )


def _whois_lookup(domain: str) -> tuple[Dict, str]:
    """Perform a WHOIS lookup and return parsed data and raw text.

    Args:
        domain: Domain name.

    Returns:
        Tuple[dict, str]: (parsed whois dict, raw text evidence)
        Returns ({}, "") on error.
    """
    try:
        w = whois_lib.whois(domain)
        if not w or not w.domain_name:
            return {}, ""

        data = {
            "domain_name": str(w.domain_name),
            "registrar": str(w.registrar) if w.registrar else "",
            "creation_date": str(w.creation_date) if w.creation_date else "",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "",
            "name_servers": str(w.name_servers) if w.name_servers else "",
        }
        raw = f"WHOIS for {domain}:\n"
        for k, v in data.items():
            if v:
                raw += f"  {k}: {v}\n"

        return data, raw
    except Exception:
        return {}, ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_ip(target: str) -> bool:
    """Return True if target looks like an IPv4 address (4 octets).

    Args:
        target: String to check.

    Returns:
        bool: True if IPv4, False otherwise.
    """
    parts = target.split(".")
    if len(parts) != 4:
        return False
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False
