"""
tests/test_knowledge_base.py — Unit tests for knowledge/knowledge_base.py

Strategy:
- All tests use injected rules dict — never depend on vulnerabilities.json on disk
- Tests cover: nominal lookup, unknown rule, prefix stripping,
  resolution order, empty fields, list_rule_ids, format validation
- Format validation: every rule in the real KB has non-empty what/attack/defense
"""

import pytest
from unittest.mock import patch
from typing import Dict

from core.finding import Explanation
import knowledge.knowledge_base as kb
from knowledge.knowledge_base import (
    get_explanation,
    get_explanation_for_finding,
    list_rule_ids,
    _lookup,
    _resolution_candidates,
)


# ---------------------------------------------------------------------------
# Injected test rules
# ---------------------------------------------------------------------------

TEST_RULES: Dict[str, Dict[str, str]] = {
    "telnet_exposed": {
        "what": "Telnet transmits credentials in cleartext.",
        "attack": "Passive capture on the network segment.",
        "defense": "Replace with SSH.",
    },
    "tcp_scan": {
        "what": "An open TCP port was detected.",
        "attack": "Attacker scans for services to exploit.",
        "defense": "Close unnecessary ports.",
    },
    "smb_enum": {
        "what": "SMB share discovered.",
        "attack": "Lateral movement via share access.",
        "defense": "Disable admin shares if not needed.",
    },
    "empty_rule": {
        "what": "",
        "attack": "",
        "defense": "",
    },
}


# ---------------------------------------------------------------------------
# _lookup
# ---------------------------------------------------------------------------

class TestLookup:
    def test_returns_explanation_for_known_rule(self):
        result = _lookup("telnet_exposed", TEST_RULES)
        assert result is not None
        assert isinstance(result, Explanation)

    def test_returns_correct_what(self):
        result = _lookup("telnet_exposed", TEST_RULES)
        assert result.what == "Telnet transmits credentials in cleartext."

    def test_returns_correct_attack(self):
        result = _lookup("telnet_exposed", TEST_RULES)
        assert result.attack == "Passive capture on the network segment."

    def test_returns_correct_defense(self):
        result = _lookup("telnet_exposed", TEST_RULES)
        assert result.defense == "Replace with SSH."

    def test_returns_none_for_unknown_rule(self):
        result = _lookup("nonexistent_rule", TEST_RULES)
        assert result is None

    def test_returns_none_for_empty_string(self):
        result = _lookup("", TEST_RULES)
        assert result is None

    def test_returns_none_when_all_fields_empty(self):
        """An entry with all empty strings is treated as undocumented."""
        result = _lookup("empty_rule", TEST_RULES)
        assert result is None

    def test_returns_none_for_empty_rules_dict(self):
        result = _lookup("telnet_exposed", {})
        assert result is None


# ---------------------------------------------------------------------------
# _resolution_candidates
# ---------------------------------------------------------------------------

class TestResolutionCandidates:
    def test_target_service_first(self):
        candidates = _resolution_candidates("tcp_scan", "telnet_exposed")
        assert candidates[0] == "telnet_exposed"

    def test_module_second(self):
        candidates = _resolution_candidates("tcp_scan", "telnet_exposed")
        assert "tcp_scan" in candidates
        assert candidates.index("tcp_scan") > candidates.index("telnet_exposed")

    def test_prefix_stripped_added(self):
        """'misconfig_detection.telnet_exposed' → 'telnet_exposed' added as candidate."""
        candidates = _resolution_candidates(
            "misconfig_detection.telnet_exposed", ""
        )
        assert "telnet_exposed" in candidates

    def test_no_duplicates(self):
        """Same value should not appear twice."""
        candidates = _resolution_candidates("telnet_exposed", "telnet_exposed")
        assert len(candidates) == len(set(candidates))

    def test_empty_module_and_service(self):
        candidates = _resolution_candidates("", "")
        assert candidates == []

    def test_only_module_no_service(self):
        candidates = _resolution_candidates("tcp_scan", "")
        assert "tcp_scan" in candidates

    def test_only_service_no_module(self):
        candidates = _resolution_candidates("", "telnet_exposed")
        assert "telnet_exposed" in candidates


# ---------------------------------------------------------------------------
# get_explanation — uses injected _RULES
# ---------------------------------------------------------------------------

class TestGetExplanation:
    def test_returns_explanation_for_known_rule(self):
        with patch.object(kb, "_RULES", TEST_RULES):
            result = get_explanation("telnet_exposed")
        assert result is not None
        assert isinstance(result, Explanation)

    def test_returns_none_for_unknown_rule(self):
        with patch.object(kb, "_RULES", TEST_RULES):
            result = get_explanation("unknown_rule_xyz")
        assert result is None

    def test_returns_none_for_empty_string(self):
        with patch.object(kb, "_RULES", TEST_RULES):
            result = get_explanation("")
        assert result is None


# ---------------------------------------------------------------------------
# get_explanation_for_finding — resolution order
# ---------------------------------------------------------------------------

class TestGetExplanationForFinding:
    def test_resolves_via_target_service(self):
        """target_service takes priority over module."""
        with patch.object(kb, "_RULES", TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="telnet_exposed",
            )
        assert result is not None
        assert "cleartext" in result.what

    def test_resolves_via_module_when_no_service(self):
        with patch.object(kb, "_RULES", TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="",
            )
        assert result is not None
        assert "TCP" in result.what

    def test_resolves_prefix_stripped_module(self):
        """'misconfig_detection.telnet_exposed' → 'telnet_exposed' resolved."""
        with patch.object(kb, "_RULES", TEST_RULES):
            result = get_explanation_for_finding(
                module="misconfig_detection.telnet_exposed",
                target_service="",
            )
        assert result is not None
        assert "cleartext" in result.what

    def test_returns_none_when_nothing_matches(self):
        with patch.object(kb, "_RULES", TEST_RULES):
            result = get_explanation_for_finding(
                module="unknown_module",
                target_service="unknown_service",
            )
        assert result is None

    def test_target_service_wins_over_module(self):
        """When both match, target_service result must be returned."""
        rules = {
            "smb_enum": {"what": "SMB module", "attack": "a", "defense": "d"},
            "telnet_exposed": {"what": "Telnet service", "attack": "a", "defense": "d"},
        }
        with patch.object(kb, "_RULES", rules):
            result = get_explanation_for_finding(
                module="smb_enum",
                target_service="telnet_exposed",
            )
        assert result.what == "Telnet service"


# ---------------------------------------------------------------------------
# list_rule_ids
# ---------------------------------------------------------------------------

class TestListRuleIds:
    def test_returns_sorted_list(self):
        with patch.object(kb, "_RULES", TEST_RULES):
            ids = list_rule_ids()
        assert ids == sorted(ids)

    def test_contains_all_injected_rules(self):
        with patch.object(kb, "_RULES", TEST_RULES):
            ids = list_rule_ids()
        for rule_id in TEST_RULES:
            assert rule_id in ids

    def test_returns_empty_list_for_empty_rules(self):
        with patch.object(kb, "_RULES", {}):
            assert list_rule_ids() == []


# ---------------------------------------------------------------------------
# Format validation — real KB file must be complete
# ---------------------------------------------------------------------------

class TestRealKbFormat:
    """These tests run against the actual vulnerabilities.json on disk.
    They enforce the steering rule: no orphan Finding without explanation.
    Every rule must have non-empty what, attack, and defense.
    """

    def test_kb_loads_without_error(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        assert isinstance(rules, dict)
        assert len(rules) > 0

    def test_every_rule_has_what(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        for rule_id, entry in rules.items():
            assert entry.get("what"), f"Rule '{rule_id}' has empty 'what' field"

    def test_every_rule_has_attack(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        for rule_id, entry in rules.items():
            assert entry.get("attack"), f"Rule '{rule_id}' has empty 'attack' field"

    def test_every_rule_has_defense(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        for rule_id, entry in rules.items():
            assert entry.get("defense"), f"Rule '{rule_id}' has empty 'defense' field"

    def test_required_misconfig_rules_present(self):
        """All 7 misconfig rules from #012 must have entries."""
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        required = [
            "telnet_exposed",
            "ftp_plaintext",
            "http_no_https",
            "snmp_exposed",
            "smb_signing_missing",
            "ssh_weak_version",
            "rdp_exposed",
        ]
        for rule_id in required:
            assert rule_id in rules, f"Missing required rule: '{rule_id}'"

    def test_required_scanner_modules_present(self):
        """Core scanner modules must have entries."""
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        required = ["tcp_scan", "udp_scan", "smb_enum", "device_fingerprint"]
        for rule_id in required:
            assert rule_id in rules, f"Missing required rule: '{rule_id}'"

    def test_get_explanation_works_for_telnet(self):
        """End-to-end: real KB resolves telnet_exposed to a valid Explanation."""
        result = get_explanation("telnet_exposed")
        assert result is not None
        assert len(result.what) > 10
        assert len(result.attack) > 10
        assert len(result.defense) > 10

    def test_get_explanation_returns_none_for_unknown(self):
        result = get_explanation("this_rule_does_not_exist")
        assert result is None
