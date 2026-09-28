"""Targeted active ARP probing for known IPv4 hosts.

This module deliberately performs one probe for one IPv4 address. It never
scans a CIDR/range, reads the ARP table, creates Findings, or writes state.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ArpProbeStatus(str, Enum):
    """Outcome of one active ARP probe."""

    PRESENT = "present"
    NOT_OBSERVED = "not_observed"
    ERROR = "error"


@dataclass(frozen=True)
class ArpProbeResult:
    """Typed result of a targeted ARP probe."""

    status: ArpProbeStatus
    ip: str
    mac: Optional[str] = None
    error: Optional[str] = None


def arp_probe(
    ip: str,
    interface: Optional[str] = None,
    timeout: float = 1.0,
) -> ArpProbeResult:
    """Send one active ARP request for one IPv4 address.

    Scapy is imported locally so its absence cannot prevent SentinelX from
    starting. Missing privileges, an unavailable interface, and other probe
    failures are returned as ERROR rather than treated as host absence.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        return ArpProbeResult(
            status=ArpProbeStatus.ERROR,
            ip=ip,
            error=f"invalid IP address: {exc}",
        )

    if address.version != 4:
        return ArpProbeResult(
            status=ArpProbeStatus.ERROR,
            ip=ip,
            error="ARP probe supports IPv4 addresses only",
        )

    if timeout <= 0:
        return ArpProbeResult(
            status=ArpProbeStatus.ERROR,
            ip=str(address),
            error="timeout must be greater than zero",
        )

    try:
        from scapy.all import ARP, Ether, srp

        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(address))
        answers, _ = srp(
            packet,
            iface=interface,
            timeout=min(timeout, 5.0),
            retry=0,
            verbose=False,
        )

        for _, received in answers:
            received_ip = getattr(received, "psrc", None)
            received_mac = getattr(received, "hwsrc", None)
            if received_ip == str(address) and received_mac:
                return ArpProbeResult(
                    status=ArpProbeStatus.PRESENT,
                    ip=str(address),
                    mac=str(received_mac).lower(),
                )

        return ArpProbeResult(
            status=ArpProbeStatus.NOT_OBSERVED,
            ip=str(address),
        )
    except ImportError as exc:
        return ArpProbeResult(
            status=ArpProbeStatus.ERROR,
            ip=str(address),
            error=f"Scapy unavailable: {exc}",
        )
    except (PermissionError, OSError) as exc:
        return ArpProbeResult(
            status=ArpProbeStatus.ERROR,
            ip=str(address),
            error=f"ARP probe failed: {exc}",
        )
    except Exception as exc:
        return ArpProbeResult(
            status=ArpProbeStatus.ERROR,
            ip=str(address),
            error=f"unexpected ARP probe error: {exc}",
        )
