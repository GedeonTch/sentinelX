"""
tests/test_sentinel_whitelist.py — Unit tests for sentinel/whitelist.py

Covers: load_whitelist, save_whitelist, allow/unallow, is_whitelisted,
        normalize_mac, extract_port, extract_mac, missing file fallback.
"""

import pytest
from pathlib import Path

from sentinel.whitelist import (
    Whitelist,
    load_whitelist,
    save_whitelist,
    allow_port,
    unallow_port,
    allow_host,
    unallow_host,
    allow_mac,
    is_whitelisted,
    _normalize_mac,
    _extract_port,
    _extract_mac,
)


# ---------------------------------------------------------------------------
# load_whitelist
# ---------------------------------------------------------------------------

class TestLoadWhitelist:
    def test_missing_file_returns_empty_whitelist(self, tmp_path):
        wl = load_whitelist(tmp_path / "nonexistent.yaml")
        assert wl.allowed_new_hosts == []
        assert wl.allowed_new_macs == []
        assert wl.allowed_port_changes == []
        assert wl.sentinel_max_alerts_per_hour == 3

    def test_loads_valid_yaml(self, tmp_path):
        f = tmp_path / "wl.yaml"
        f.write_text(
            "allowed_new_hosts: [192.168.1.99]\n"
            "allowed_new_macs: [aa:bb:cc:dd:ee:ff]\n"
            "allowed_port_changes:\n"
            "  - host: 192.168.1.10\n"
            "    ports: [8080]\n"
            "sentinel_max_alerts_per_hour: 5\n"
        )
        wl = load_whitelist(f)
        assert "192.168.1.99" in wl.allowed_new_hosts
        assert "aa:bb:cc:dd:ee:ff" in wl.allowed_new_macs
        assert wl.sentinel_max_alerts_per_hour == 5

    def test_malformed_yaml_returns_default(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("{{{{ invalid yaml")
        wl = load_whitelist(f)
        assert wl.sentinel_max_alerts_per_hour == 3


# ---------------------------------------------------------------------------
# save_whitelist + round-trip
# ---------------------------------------------------------------------------

class TestSaveWhitelist:
    def test_save_and_reload(self, tmp_path):
        path = tmp_path / "wl.yaml"
        wl = Whitelist(
            allowed_new_hosts=["10.0.0.1"],
            sentinel_max_alerts_per_hour=5,
        )
        save_whitelist(wl, path)
        loaded = load_whitelist(path)
        assert "10.0.0.1" in loaded.allowed_new_hosts
        assert loaded.sentinel_max_alerts_per_hour == 5


# ---------------------------------------------------------------------------
# allow / unallow port
# ---------------------------------------------------------------------------

class TestAllowUnallowPort:
    def test_allow_port_writes_to_yaml(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_port("192.168.1.10", 8080, path)
        wl = load_whitelist(path)
        entry = next((e for e in wl.allowed_port_changes if e["host"] == "192.168.1.10"), None)
        assert entry is not None
        assert 8080 in entry["ports"]

    def test_allow_port_does_not_duplicate(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_port("192.168.1.10", 8080, path)
        allow_port("192.168.1.10", 8080, path)
        wl = load_whitelist(path)
        entry = next(e for e in wl.allowed_port_changes if e["host"] == "192.168.1.10")
        assert entry["ports"].count(8080) == 1

    def test_unallow_port_removes_entry(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_port("192.168.1.10", 8080, path)
        unallow_port("192.168.1.10", 8080, path)
        wl = load_whitelist(path)
        for entry in wl.allowed_port_changes:
            assert 8080 not in entry.get("ports", [])

    def test_unallow_removes_empty_host_entry(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_port("192.168.1.10", 8080, path)
        unallow_port("192.168.1.10", 8080, path)
        wl = load_whitelist(path)
        hosts = [e["host"] for e in wl.allowed_port_changes]
        assert "192.168.1.10" not in hosts


# ---------------------------------------------------------------------------
# allow / unallow host
# ---------------------------------------------------------------------------

class TestAllowUnallowHost:
    def test_allow_host(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_host("192.168.1.99", path)
        wl = load_whitelist(path)
        assert "192.168.1.99" in wl.allowed_new_hosts

    def test_allow_host_no_duplicate(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_host("192.168.1.99", path)
        allow_host("192.168.1.99", path)
        wl = load_whitelist(path)
        assert wl.allowed_new_hosts.count("192.168.1.99") == 1

    def test_unallow_host(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_host("192.168.1.99", path)
        unallow_host("192.168.1.99", path)
        wl = load_whitelist(path)
        assert "192.168.1.99" not in wl.allowed_new_hosts


# ---------------------------------------------------------------------------
# allow MAC
# ---------------------------------------------------------------------------

class TestAllowMac:
    def test_allow_mac_normalizes(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_mac("192.168.1.1", "AA:BB:CC:DD:EE:FF", path)
        wl = load_whitelist(path)
        assert "aa:bb:cc:dd:ee:ff" in wl.allowed_new_macs

    def test_allow_invalid_mac_not_stored(self, tmp_path):
        path = tmp_path / "wl.yaml"
        allow_mac("192.168.1.1", "not-a-mac", path)
        wl = load_whitelist(path)
        assert "not-a-mac" not in wl.allowed_new_macs


# ---------------------------------------------------------------------------
# is_whitelisted
# ---------------------------------------------------------------------------

class TestIsWhitelisted:
    def _wl(self):
        return Whitelist(
            allowed_new_hosts=["192.168.1.99"],
            allowed_new_macs=["aa:bb:cc:dd:ee:ff"],
            allowed_port_changes=[{"host": "192.168.1.10", "ports": [8080]}],
        )

    def test_new_host_whitelisted(self):
        assert is_whitelisted("new_host", "192.168.1.99", "new host detected", self._wl())

    def test_new_host_not_whitelisted(self):
        assert not is_whitelisted("new_host", "192.168.1.77", "new host detected", self._wl())

    def test_new_port_whitelisted(self):
        assert is_whitelisted("new_port", "192.168.1.10", "port 8080 opened", self._wl())

    def test_new_port_not_whitelisted(self):
        assert not is_whitelisted("new_port", "192.168.1.10", "port 9999 opened", self._wl())

    def test_new_port_wrong_host(self):
        assert not is_whitelisted("new_port", "192.168.1.20", "port 8080 opened", self._wl())

    def test_mac_change_whitelisted(self):
        assert is_whitelisted(
            "mac_change", "192.168.1.1",
            "mac changed from 11:22:33:44:55:66 to aa:bb:cc:dd:ee:ff",
            self._wl()
        )

    def test_mac_change_not_whitelisted(self):
        assert not is_whitelisted(
            "mac_change", "192.168.1.1",
            "mac changed from 11:22:33:44:55:66 to ff:ee:dd:cc:bb:aa",
            self._wl()
        )

    def test_unknown_change_type_returns_false(self):
        assert not is_whitelisted("unknown", "192.168.1.1", "detail", self._wl())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_normalize_mac_lowercase(self):
        assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_normalize_mac_dashes(self):
        assert _normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_normalize_mac_invalid(self):
        assert _normalize_mac("not-a-mac") == ""

    def test_normalize_mac_empty(self):
        assert _normalize_mac("") == ""

    def test_extract_port_from_detail(self):
        assert _extract_port("port 8080 opened") == 8080

    def test_extract_port_no_number(self):
        assert _extract_port("new host detected") is None

    def test_extract_mac_from_detail(self):
        mac = _extract_mac("mac changed from 11:22:33:44:55:66 to aa:bb:cc:dd:ee:ff")
        assert mac == "11:22:33:44:55:66"

    def test_extract_mac_empty(self):
        assert _extract_mac("no mac here") == ""
