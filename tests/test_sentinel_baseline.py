"""
tests/test_sentinel_baseline.py — Unit tests for sentinel/baseline.py

Covers: NetworkIdentity, detect_network_identity (mocked),
        baseline_exists, get_baseline, learn_baseline (mocked scans),
        --relearn atomicity, MAC="" never matches known MAC.
"""

import uuid
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import core.database as db
from sentinel.baseline import (
    NetworkIdentity,
    BaselineEntry,
    baseline_exists,
    get_baseline,
    learn_baseline,
    detect_network_identity,
    _get_gateway_ip,
    _get_arp_mac,
)


SESSION = "session-sentinel-test"

IDENTITY_A = NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:aa:aa:aa:aa:aa")
IDENTITY_B = NetworkIdentity("192.168.1.0/24", "192.168.1.1", "bb:bb:bb:bb:bb:bb")
IDENTITY_EMPTY_MAC = NetworkIdentity("192.168.1.0/24", "192.168.1.1", "")


@pytest.fixture(autouse=True)
def patch_db_path(tmp_path, monkeypatch):
    def mock_get_db_path(session_id: str):
        d = tmp_path / ".netlab" / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{session_id}.db"
    monkeypatch.setattr(db, "get_db_path", mock_get_db_path)
    db.init_db(SESSION)


# ---------------------------------------------------------------------------
# NetworkIdentity
# ---------------------------------------------------------------------------

class TestNetworkIdentity:
    def test_same_cidr_different_mac_are_not_equal(self):
        assert IDENTITY_A != IDENTITY_B

    def test_same_triplet_are_equal(self):
        a = NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:aa:aa:aa:aa:aa")
        b = NetworkIdentity("192.168.1.0/24", "192.168.1.1", "aa:aa:aa:aa:aa:aa")
        assert a == b

    def test_empty_mac_identity(self):
        assert IDENTITY_EMPTY_MAC != IDENTITY_A

    def test_frozen(self):
        with pytest.raises(Exception):
            IDENTITY_A.gateway_mac = "changed"


# ---------------------------------------------------------------------------
# baseline_exists
# ---------------------------------------------------------------------------

class TestBaselineExists:
    def _insert_entry(self, session_id, identity, ip="192.168.1.10"):
        asset_id = str(uuid.uuid4())
        db.save_asset(session_id, asset_id, ip, "2026-01-01T00:00:00+00:00")
        db.save_baseline_entry(
            session_id=session_id,
            entry_id=str(uuid.uuid4()),
            asset_id=asset_id,
            target_network=identity.target_network,
            gateway_ip=identity.gateway_ip,
            gateway_mac=identity.gateway_mac,
            ports=[22, 80],
            mac="aa:bb:cc:dd:ee:01",
            last_scan="2026-01-01T00:00:00+00:00",
        )

    def test_returns_true_when_entry_exists(self):
        self._insert_entry(SESSION, IDENTITY_A)
        assert baseline_exists(SESSION, IDENTITY_A) is True

    def test_returns_false_when_no_entry(self):
        assert baseline_exists(SESSION, IDENTITY_B) is False

    def test_empty_mac_does_not_match_known_mac(self):
        """MAC="" must not match a baseline with known MAC."""
        self._insert_entry(SESSION, IDENTITY_A)
        assert baseline_exists(SESSION, IDENTITY_EMPTY_MAC) is False

    def test_known_mac_does_not_match_empty_mac(self):
        """Baseline with MAC="" must not be returned when MAC is known."""
        self._insert_entry(SESSION, IDENTITY_EMPTY_MAC)
        assert baseline_exists(SESSION, IDENTITY_A) is False

    def test_same_cidr_different_mac_not_found(self):
        self._insert_entry(SESSION, IDENTITY_A)
        assert baseline_exists(SESSION, IDENTITY_B) is False


# ---------------------------------------------------------------------------
# get_baseline
# ---------------------------------------------------------------------------

class TestGetBaseline:
    def _insert(self, session_id, identity, ip, ports):
        asset_id = str(uuid.uuid4())
        db.save_asset(session_id, asset_id, ip, "2026-01-01T00:00:00+00:00")
        db.save_baseline_entry(
            session_id=session_id,
            entry_id=str(uuid.uuid4()),
            asset_id=asset_id,
            target_network=identity.target_network,
            gateway_ip=identity.gateway_ip,
            gateway_mac=identity.gateway_mac,
            ports=ports,
            mac=None,
            last_scan="2026-01-01T00:00:00+00:00",
        )

    def test_returns_entries_for_matching_identity(self):
        self._insert(SESSION, IDENTITY_A, "192.168.1.10", [22, 80])
        result = get_baseline(SESSION, IDENTITY_A)
        assert "192.168.1.10" in result
        assert result["192.168.1.10"].ports == [22, 80]

    def test_never_returns_entries_for_different_identity(self):
        self._insert(SESSION, IDENTITY_A, "192.168.1.10", [22])
        result = get_baseline(SESSION, IDENTITY_B)
        assert result == {}

    def test_empty_mac_identity_not_matched_by_known_mac(self):
        self._insert(SESSION, IDENTITY_A, "192.168.1.10", [22])
        result = get_baseline(SESSION, IDENTITY_EMPTY_MAC)
        assert result == {}

    def test_returns_empty_when_no_baseline(self):
        result = get_baseline(SESSION, IDENTITY_A)
        assert result == {}

    def test_baseline_entry_fields(self):
        self._insert(SESSION, IDENTITY_A, "192.168.1.10", [22, 443])
        result = get_baseline(SESSION, IDENTITY_A)
        entry = result["192.168.1.10"]
        assert isinstance(entry, BaselineEntry)
        assert entry.ip == "192.168.1.10"
        assert 22 in entry.ports
        assert 443 in entry.ports


# ---------------------------------------------------------------------------
# learn_baseline — mocked scans
# ---------------------------------------------------------------------------

PING_XML_ONE = """<nmaprun>
  <host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/></host>
</nmaprun>"""

PORT_XML_ONE = """<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" method="probed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestLearnBaseline:
    def test_learns_one_host(self):
        with patch("sentinel.baseline._run_nmap_ping", return_value=PING_XML_ONE), \
             patch("sentinel.baseline._run_nmap_tcp", return_value=PORT_XML_ONE), \
             patch("sentinel.baseline._get_arp_mac", return_value=""):
            ok = learn_baseline("192.168.1.0/24", SESSION, IDENTITY_A)
        assert ok is True
        assert baseline_exists(SESSION, IDENTITY_A)

    def test_no_hosts_returns_false(self):
        with patch("sentinel.baseline._run_nmap_ping", return_value="<nmaprun></nmaprun>"):
            ok = learn_baseline("192.168.1.0/24", SESSION, IDENTITY_A)
        assert ok is False

    def test_ping_failure_returns_false(self):
        with patch("sentinel.baseline._run_nmap_ping", return_value=None):
            ok = learn_baseline("192.168.1.0/24", SESSION, IDENTITY_A)
        assert ok is False

    def test_relearn_only_deletes_current_identity(self):
        """--relearn must not touch IDENTITY_B when relearning IDENTITY_A."""
        # Insert IDENTITY_B baseline first
        asset_id = str(uuid.uuid4())
        db.save_asset(SESSION, asset_id, "192.168.1.20", "2026-01-01T00:00:00+00:00")
        db.save_baseline_entry(
            session_id=SESSION,
            entry_id=str(uuid.uuid4()),
            asset_id=asset_id,
            target_network=IDENTITY_B.target_network,
            gateway_ip=IDENTITY_B.gateway_ip,
            gateway_mac=IDENTITY_B.gateway_mac,
            ports=[80],
            mac=None,
            last_scan="2026-01-01T00:00:00+00:00",
        )
        # Learn IDENTITY_A with relearn
        with patch("sentinel.baseline._run_nmap_ping", return_value=PING_XML_ONE), \
             patch("sentinel.baseline._run_nmap_tcp", return_value=PORT_XML_ONE), \
             patch("sentinel.baseline._get_arp_mac", return_value=""):
            learn_baseline("192.168.1.0/24", SESSION, IDENTITY_A, force_relearn=True)

        # IDENTITY_B must still be there
        assert baseline_exists(SESSION, IDENTITY_B)

    def test_relearn_failed_discovery_preserves_old_baseline(self):
        """If new discovery finds 0 hosts, old baseline must be preserved."""
        # First learn
        with patch("sentinel.baseline._run_nmap_ping", return_value=PING_XML_ONE), \
             patch("sentinel.baseline._run_nmap_tcp", return_value=PORT_XML_ONE), \
             patch("sentinel.baseline._get_arp_mac", return_value=""):
            learn_baseline("192.168.1.0/24", SESSION, IDENTITY_A)
        assert baseline_exists(SESSION, IDENTITY_A)

        # Relearn fails (no hosts)
        with patch("sentinel.baseline._run_nmap_ping", return_value="<nmaprun></nmaprun>"):
            ok = learn_baseline("192.168.1.0/24", SESSION, IDENTITY_A, force_relearn=True)
        assert ok is False
        # Old baseline still there
        assert baseline_exists(SESSION, IDENTITY_A)
