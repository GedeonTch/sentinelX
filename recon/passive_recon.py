"""
recon/passive_recon.py — Local passive reconnaissance (standalone, not in scan).

Sources:
  - ARP / neighbour cache: ``arp -n``, or ``ip -4 neigh show`` when ``arp`` is absent.
    A cache entry is a past observation: it does not prove current presence.
  - /etc/hosts: local name mappings, read only.
  - mDNS (Bonjour/Avahi): ``avahi-browse``. This sends multicast DNS queries on
    the local network, so it runs ONLY when the caller has obtained explicit
    confirmation (see cli.py ``passive-recon``). ``passive_recon()`` never runs it
    unless ``mdns_allowed=True`` is passed.

Network filter (``--network``): an IPv4 CIDR (``192.168.1.0/24``), a single IPv4
address, or the historical octet prefix (``192.168.1`` = ``192.168.1.0/24``).
Empty means no filter. Invalid values are rejected. IPv6 entries are never
targets: they are counted and ignored, and no IPv6 scan is performed.

Each source reports its own status: ``ok``, ``unavailable`` (tool or file
missing), ``failed`` (error or timeout), or ``skipped`` (not requested).
A missing tool is never shown as an empty result.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.finding import (
    Category,
    Confidence,
    Evidence,
    Exposure,
    Finding,
    Severity,
)

HOSTS_PATH: Path = Path("/etc/hosts")
ARP_TIMEOUT_SECONDS: int = 10
MDNS_TIMEOUT_SECONDS: int = 20
MDNS_COMMAND: Tuple[str, ...] = (
    "avahi-browse", "--all", "--resolve", "--terminate", "--parsable", "--no-db-lookup",
)
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

SOURCE_ARP = "arp"
SOURCE_HOSTS = "hosts"
SOURCE_MDNS = "mdns"

STATUS_OK = "ok"
STATUS_UNAVAILABLE = "unavailable"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"

SOURCE_LABELS = {
    SOURCE_ARP: "Voisinage ARP (cache local)",
    SOURCE_HOSTS: "/etc/hosts (local)",
    SOURCE_MDNS: "mDNS / Avahi (réseau local)",
}
STATUS_LABELS = {
    STATUS_OK: "effectué",
    STATUS_UNAVAILABLE: "indisponible (outil ou fichier absent)",
    STATUS_FAILED: "échec ou timeout",
    STATUS_SKIPPED: "ignoré (non confirmé)",
}

MDNS_WARNING = (
    "mDNS envoie des requêtes multicast sur le réseau local, comme un scan léger. "
    "Ne le lancez que sur un réseau que vous êtes autorisé à observer."
)

_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_ARP_LINE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(\S+)\s+")
_IP_NEIGH_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+\S+\s+lladdr\s+(\S+)")
_ESCAPE_RE = re.compile(r"\\(\d{3})")

NetworkFilter = Optional[ipaddress.IPv4Network]


@dataclass
class SourceReport:
    name: str
    status: str
    count: int = 0
    detail: str = ""

    @property
    def label(self) -> str:
        return SOURCE_LABELS.get(self.name, self.name)

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)


@dataclass
class PassiveReport:
    network: str
    findings: List[Finding] = field(default_factory=list)
    sources: List[SourceReport] = field(default_factory=list)
    ignored_ipv6: int = 0


# ---------------------------------------------------------------------------
# Network filter
# ---------------------------------------------------------------------------

def parse_network_filter(value: str) -> NetworkFilter:
    """Parse the --network value. Returns None for no filter.

    Raises:
        ValueError: when the value is not a valid IPv4 CIDR, address, or octet prefix.
    """
    text = (value or "").strip()
    if not text:
        return None
    if ":" in text:
        raise ValueError("IPv6 non pris en charge pour le filtre réseau")
    if "/" in text:
        try:
            network = ipaddress.IPv4Network(text, strict=True)
        except ValueError as exc:
            raise ValueError(f"CIDR IPv4 invalide : {text!r} ({exc})") from None
        return network
    parts = text.split(".")
    if not 1 <= len(parts) <= 4 or not all(p.isdigit() and int(p) <= 255 for p in parts):
        raise ValueError(f"filtre réseau invalide : {text!r} (attendu : CIDR, IPv4 ou préfixe 192.168.1)")
    if len(parts) == 4:
        return ipaddress.IPv4Network(f"{text}/32")
    prefix_len = 8 * len(parts)
    padded = parts + ["0"] * (4 - len(parts))
    return ipaddress.IPv4Network(f"{'.'.join(padded)}/{prefix_len}")


def _in_filter(ip: str, network: NetworkFilter) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version != 4:
        return False
    return network is None or address in network


def _is_ipv4(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# ARP / neighbour cache
# ---------------------------------------------------------------------------

NeighborEntry = Tuple[str, str, str]  # (ip, mac, state) ; state '' for arp -n


def _parse_arp_output(output: str) -> List[NeighborEntry]:
    """Parse ``arp -n`` output. Incomplete entries and broadcast MACs are skipped."""
    entries: List[NeighborEntry] = []
    for line in output.splitlines():
        match = _ARP_LINE_RE.match(line.strip())
        if not match:
            continue
        ip, mac = match.group(1), match.group(2)
        if not _is_ipv4(ip) or not _MAC_RE.match(mac) or mac.lower() == BROADCAST_MAC:
            continue
        entries.append((ip, mac.lower(), ""))
    return entries


def _parse_ip_neigh_output(output: str) -> List[NeighborEntry]:
    """Parse ``ip -4 neigh show`` output. Entries without lladdr are skipped."""
    entries: List[NeighborEntry] = []
    for line in output.splitlines():
        match = _IP_NEIGH_RE.match(line.strip())
        if not match:
            continue
        ip, mac = match.group(1), match.group(2)
        if not _is_ipv4(ip) or not _MAC_RE.match(mac) or mac.lower() == BROADCAST_MAC:
            continue
        state = line.split()[-1].upper()
        entries.append((ip, mac.lower(), state))
    return entries


def _neighbor_entries() -> Tuple[str, Optional[List[NeighborEntry]], str, str]:
    """Return (status, entries, command, detail). Tries ``arp`` then ``ip neigh``."""
    try:
        completed = subprocess.run(
            ["arp", "-n"], capture_output=True, text=True,
            timeout=ARP_TIMEOUT_SECONDS, check=False,
        )
        return STATUS_OK, _parse_arp_output(completed.stdout), "arp -n", ""
    except FileNotFoundError:
        pass
    except (subprocess.TimeoutExpired, OSError):
        return STATUS_FAILED, None, "arp -n", "commande arp en erreur ou en timeout"

    try:
        completed = subprocess.run(
            ["ip", "-4", "neigh", "show"], capture_output=True, text=True,
            timeout=ARP_TIMEOUT_SECONDS, check=False,
        )
        return STATUS_OK, _parse_ip_neigh_output(completed.stdout), "ip -4 neigh show", "arp absent : repli sur ip neigh"
    except FileNotFoundError:
        return STATUS_UNAVAILABLE, None, "", "ni arp ni ip (iproute2) disponibles"
    except (subprocess.TimeoutExpired, OSError):
        return STATUS_FAILED, None, "ip -4 neigh show", "ip neigh en erreur ou en timeout"


def _arp_findings(network: NetworkFilter, session_id: str) -> Tuple[SourceReport, List[Finding]]:
    status, entries, command, detail = _neighbor_entries()
    if status != STATUS_OK or entries is None:
        return SourceReport(SOURCE_ARP, status, detail=detail), []

    findings: List[Finding] = []
    for ip, mac, state in entries:
        if not _in_filter(ip, network):
            continue
        state_text = f", état : {state}" if state else ""
        findings.append(Finding(
            session_id=session_id,
            module="passive_recon",
            target_ip=ip,
            target_service="arp",
            service_version=f"MAC={mac}",
            category=Category.NETWORK,
            severity=Severity.INFO,
            # A neighbour-cache entry is a past observation: presence now is not proven.
            confidence=Confidence.PROBABLE,
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=f"Entrée de cache ARP : {ip} → {mac}{state_text} (présence actuelle non prouvée)",
                command=command,
            ),
        ))
    return SourceReport(SOURCE_ARP, STATUS_OK, count=len(findings), detail=detail), findings


# ---------------------------------------------------------------------------
# /etc/hosts
# ---------------------------------------------------------------------------

def _read_hosts_file(path: Path) -> Tuple[List[Tuple[str, str]], int]:
    """Return (IPv4 (ip, hostname) pairs, count of ignored IPv6 lines).

    Only the first name of each line is kept. Repeated IPs on different lines
    are all kept. Identical (ip, name) pairs are reported once.
    """
    pairs: List[Tuple[str, str]] = []
    seen = set()
    ignored_v6 = 0
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        ip, name = fields[0], fields[1]
        if ":" in ip:
            ignored_v6 += 1
            continue
        if not _is_ipv4(ip):
            continue
        if (ip, name) in seen:
            continue
        seen.add((ip, name))
        pairs.append((ip, name))
    return pairs, ignored_v6


def _hosts_findings(
    network: NetworkFilter, session_id: str, path: Path,
) -> Tuple[SourceReport, List[Finding], int]:
    try:
        pairs, ignored_v6 = _read_hosts_file(path)
    except FileNotFoundError:
        return SourceReport(SOURCE_HOSTS, STATUS_UNAVAILABLE, detail="fichier absent"), [], 0
    except OSError:
        return SourceReport(SOURCE_HOSTS, STATUS_FAILED, detail="fichier illisible"), [], 0

    findings: List[Finding] = []
    for ip, name in pairs:
        if not _in_filter(ip, network):
            continue
        if ipaddress.ip_address(ip).is_loopback:
            continue
        findings.append(Finding(
            session_id=session_id,
            module="passive_recon",
            target_ip=ip,
            target_service="hosts",
            service_version=f"hostname={name}",
            category=Category.NETWORK,
            severity=Severity.INFO,
            confidence=Confidence.PROBABLE,
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=f"/etc/hosts : {ip} {name}",
                command="lecture /etc/hosts",
            ),
        ))
    return SourceReport(SOURCE_HOSTS, STATUS_OK, count=len(findings)), findings, ignored_v6


# ---------------------------------------------------------------------------
# mDNS (avahi-browse)
# ---------------------------------------------------------------------------

@dataclass
class MdnsRecord:
    service: str
    service_type: str
    host: str
    address: str
    port: Optional[int]


def _unescape_avahi(value: str) -> str:
    """Decode avahi's \\DDD (decimal) escapes in names."""
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1))), value)


def _parse_avahi_output(output: str) -> Tuple[List[MdnsRecord], int]:
    """Parse ``avahi-browse --parsable`` resolved lines.

    Format (avahi-utils, parsable mode):
        =;interface;protocol;service_name;service_type;domain;host_name;address;port;txt

    Only resolved lines ('=') are used. IPv4 addresses are kept; IPv6 addresses
    are counted and ignored. Returns (records, ignored_ipv6_count).
    """
    records: List[MdnsRecord] = []
    ignored_v6 = 0
    for line in output.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 9:
            continue
        address = parts[7].strip()
        if ":" in address:
            ignored_v6 += 1
            continue
        if not _is_ipv4(address):
            continue
        port = int(parts[8]) if parts[8].isdigit() else None
        records.append(MdnsRecord(
            service=_unescape_avahi(parts[3]),
            service_type=parts[4],
            host=_unescape_avahi(parts[6]).rstrip("."),
            address=address,
            port=port,
        ))
    return records, ignored_v6


def _group_mdns(records: List[MdnsRecord]) -> Dict[Tuple[str, str], List[MdnsRecord]]:
    """Group by (address, host). Several services and addresses stay separate."""
    grouped: Dict[Tuple[str, str], List[MdnsRecord]] = {}
    for record in records:
        grouped.setdefault((record.address, record.host), []).append(record)
    return grouped


def _mdns_findings(
    network: NetworkFilter, session_id: str,
) -> Tuple[SourceReport, List[Finding], int]:
    try:
        completed = subprocess.run(
            list(MDNS_COMMAND), capture_output=True, text=True,
            timeout=MDNS_TIMEOUT_SECONDS, check=False,
        )
    except FileNotFoundError:
        return SourceReport(SOURCE_MDNS, STATUS_UNAVAILABLE, detail="avahi-browse absent"), [], 0
    except (subprocess.TimeoutExpired, OSError):
        return SourceReport(SOURCE_MDNS, STATUS_FAILED, detail="avahi-browse en erreur ou en timeout"), [], 0
    if completed.returncode != 0:
        return SourceReport(SOURCE_MDNS, STATUS_FAILED, detail="avahi-browse a retourné une erreur"), [], 0

    records, ignored_v6 = _parse_avahi_output(completed.stdout)
    findings: List[Finding] = []
    for (address, host), group in _group_mdns(records).items():
        if not _in_filter(address, network):
            continue
        services = sorted({
            f"{r.service} ({r.service_type}{', port ' + str(r.port) if r.port else ''})"
            for r in group
        })
        label = host or address
        findings.append(Finding(
            session_id=session_id,
            module="passive_recon",
            target_ip=address,
            target_service="mdns",
            service_version=f"hostname={label}",
            category=Category.NETWORK,
            severity=Severity.INFO,
            confidence=Confidence.POSSIBLE,  # self-advertised, not verified
            exposure=Exposure.INTERNAL,
            evidence=Evidence(
                raw=f"mDNS {address} ({label}) : " + "; ".join(services),
                command=" ".join(MDNS_COMMAND),
            ),
        ))
    return SourceReport(SOURCE_MDNS, STATUS_OK, count=len(findings)), findings, ignored_v6


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def collect_passive(
    target_network: str,
    session_id: str,
    mdns_allowed: bool = False,
    hosts_path: Optional[Path] = None,
) -> PassiveReport:
    """Run the local sources, and mDNS only when ``mdns_allowed`` is True.

    Raises:
        ValueError: when ``target_network`` is not a valid filter.
    """
    network = parse_network_filter(target_network)
    report = PassiveReport(network=target_network.strip() or "tous")

    arp_source, arp_findings = _arp_findings(network, session_id)
    report.sources.append(arp_source)
    report.findings.extend(arp_findings)

    hosts_source, hosts_findings, hosts_v6 = _hosts_findings(network, session_id, hosts_path or HOSTS_PATH)
    report.sources.append(hosts_source)
    report.findings.extend(hosts_findings)
    report.ignored_ipv6 += hosts_v6

    if mdns_allowed:
        mdns_source, mdns_findings, mdns_v6 = _mdns_findings(network, session_id)
        report.ignored_ipv6 += mdns_v6
    else:
        mdns_source = SourceReport(SOURCE_MDNS, STATUS_SKIPPED, detail="avahi-browse non lancé")
        mdns_findings = []
    report.sources.append(mdns_source)
    report.findings.extend(mdns_findings)
    return report


def passive_recon(
    target_network: str,
    session_id: str,
    mdns_allowed: bool = False,
) -> List[Finding]:
    """Return the passive Findings. mDNS runs only when ``mdns_allowed`` is True.

    Not called by ``netlab scan`` or by the pipeline.
    """
    return collect_passive(target_network, session_id, mdns_allowed=mdns_allowed).findings
