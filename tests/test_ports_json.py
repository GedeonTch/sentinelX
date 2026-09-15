"""
tests/test_ports_json.py — Validation tests for knowledge/ports.json (ticket #014)

Covers:
- File loads as valid JSON
- Required schema fields per entry
- Well-known ports present (22, 80, 443, 445, 161, 3389)
- No CVE / explanation fields mixed into this identification table
"""

import json
from pathlib import Path

PORTS_PATH = Path(__file__).resolve().parent.parent / "knowledge" / "ports.json"
REQUIRED_FIELDS = {"protocol", "service", "common_products", "description"}
ALLOWED_PROTOCOLS = {"tcp", "udp", "both"}


def _load_ports() -> dict:
    with open(PORTS_PATH, encoding="utf-8") as f:
        return json.load(f)


class TestPortsJsonLoads:
    def test_file_exists(self):
        assert PORTS_PATH.is_file()

    def test_valid_json_with_ports_key(self):
        data = _load_ports()
        assert "ports" in data
        assert isinstance(data["ports"], dict)
        assert len(data["ports"]) >= 10


class TestPortsJsonSchema:
    def test_each_entry_has_required_fields(self):
        ports = _load_ports()["ports"]
        for port, entry in ports.items():
            assert port.isdigit(), f"port key must be numeric string, got {port!r}"
            missing = REQUIRED_FIELDS - set(entry.keys())
            assert not missing, f"port {port} missing fields: {missing}"
            assert entry["protocol"] in ALLOWED_PROTOCOLS
            assert isinstance(entry["service"], str) and entry["service"]
            assert isinstance(entry["common_products"], list)
            assert isinstance(entry["description"], str) and entry["description"]

    def test_well_known_ports_present(self):
        ports = _load_ports()["ports"]
        for expected in ("22", "80", "443", "445", "161", "3389", "21", "23"):
            assert expected in ports, f"missing well-known port {expected}"

    def test_ssh_and_smb_names_align_with_cve_db_style(self):
        ports = _load_ports()["ports"]
        assert ports["22"]["service"] == "ssh"
        assert ports["445"]["service"] == "microsoft-ds"
        assert ports["161"]["protocol"] == "udp"

    def test_identification_only_no_cve_fields(self):
        """ports.json must not mix CVE / explanation concerns (#014 vs #010/#015)."""
        ports = _load_ports()["ports"]
        forbidden = {"cve_refs", "cvss_score", "what", "attack", "defense", "severity"}
        for port, entry in ports.items():
            overlap = forbidden & set(entry.keys())
            assert not overlap, f"port {port} must not contain {overlap}"
