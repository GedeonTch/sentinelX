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
    _cve_to_rule_key,
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

# ---------------------------------------------------------------------------
# _cve_to_rule_key — normalisation helper
# ---------------------------------------------------------------------------

class TestCveToRuleKey:
    def test_uppercase_cve_normalised(self):
        assert _cve_to_rule_key("CVE-2011-2523") == "cve_2011_2523"

    def test_lowercase_cve_normalised(self):
        assert _cve_to_rule_key("cve-2017-0144") == "cve_2017_0144"

    def test_mixed_case_normalised(self):
        assert _cve_to_rule_key("Cve-2019-0708") == "cve_2019_0708"

    def test_strips_surrounding_whitespace(self):
        assert _cve_to_rule_key("  CVE-2011-2523  ") == "cve_2011_2523"

    def test_empty_string(self):
        assert _cve_to_rule_key("") == ""


# ---------------------------------------------------------------------------
# get_explanation_for_finding — CVE lookup priority
# ---------------------------------------------------------------------------

CVE_TEST_RULES: Dict[str, Dict[str, str]] = {
    "tcp_scan": {
        "what": "Generic TCP scan explanation.",
        "attack": "Generic attack.",
        "defense": "Generic defense.",
    },
    "cve_2011_2523": {
        "what": "vsftpd 2.3.4 backdoor specific explanation.",
        "attack": "Connect port 6200 after trigger.",
        "defense": "Upgrade vsftpd.",
    },
    "cve_2017_0144": {
        "what": "EternalBlue SMBv1 specific explanation.",
        "attack": "Unauthenticated RCE via port 445.",
        "defense": "Disable SMBv1 and apply MS17-010.",
    },
}


class TestCveLookupPriority:
    def test_cve_rule_beats_module_rule(self):
        """CVE-specific rule must win over the generic module rule."""
        with patch.object(kb, "_RULES", CVE_TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="ftp",
                cve_refs=["CVE-2011-2523"],
            )
        assert result is not None
        assert "vsftpd" in result.what

    def test_cve_2011_2523_returns_specific_explanation(self):
        with patch.object(kb, "_RULES", CVE_TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="ftp",
                cve_refs=["CVE-2011-2523"],
            )
        assert result is not None
        assert result.what != ""
        assert result.attack != ""
        assert result.defense != ""
        assert "vsftpd" in result.what

    def test_cve_2017_0144_returns_specific_explanation(self):
        with patch.object(kb, "_RULES", CVE_TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="microsoft-ds",
                cve_refs=["CVE-2017-0144"],
            )
        assert result is not None
        assert "EternalBlue" in result.what

    def test_what_attack_defense_non_empty_for_cve_2011_2523(self):
        with patch.object(kb, "_RULES", CVE_TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="ftp",
                cve_refs=["CVE-2011-2523"],
            )
        assert result is not None
        assert len(result.what) > 0
        assert len(result.attack) > 0
        assert len(result.defense) > 0

    def test_unknown_cve_falls_back_to_module(self):
        """Unknown CVE ref must fall back to module/service lookup."""
        with patch.object(kb, "_RULES", CVE_TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="",
                cve_refs=["CVE-9999-9999"],
            )
        assert result is not None
        assert "Generic" in result.what

    def test_empty_cve_refs_uses_module_fallback(self):
        """Empty cve_refs list must behave identically to no cve_refs."""
        with patch.object(kb, "_RULES", CVE_TEST_RULES):
            result_no_cve = get_explanation_for_finding(
                module="tcp_scan",
                target_service="",
            )
            result_empty_cve = get_explanation_for_finding(
                module="tcp_scan",
                target_service="",
                cve_refs=[],
            )
        assert result_no_cve is not None
        assert result_empty_cve is not None
        assert result_no_cve.what == result_empty_cve.what

    def test_none_cve_refs_uses_module_fallback(self):
        """None cve_refs must behave identically to no cve_refs."""
        with patch.object(kb, "_RULES", CVE_TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="",
                cve_refs=None,
            )
        assert result is not None
        assert "Generic" in result.what

    def test_first_matching_cve_wins(self):
        """When multiple CVE refs are passed, first match wins."""
        with patch.object(kb, "_RULES", CVE_TEST_RULES):
            result = get_explanation_for_finding(
                module="tcp_scan",
                target_service="ftp",
                cve_refs=["CVE-9999-0000", "CVE-2011-2523", "CVE-2017-0144"],
            )
        assert result is not None
        assert "vsftpd" in result.what  # CVE-2011-2523 found before CVE-2017-0144


# ---------------------------------------------------------------------------
# Real KB — CVE rules present and complete
# ---------------------------------------------------------------------------

class TestRealKbCveRules:
    """Validate that the new CVE rules in vulnerabilities.json are complete."""

    def test_cve_2011_2523_present(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        assert "cve_2011_2523" in rules, "cve_2011_2523 missing from vulnerabilities.json"

    def test_cve_2017_0144_present(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        assert "cve_2017_0144" in rules, "cve_2017_0144 missing from vulnerabilities.json"

    def test_ssh_weak_version_present(self):
        from knowledge.knowledge_base import _load_vulnerabilities
        rules = _load_vulnerabilities()
        assert "ssh_weak_version" in rules, "ssh_weak_version missing from vulnerabilities.json"

    def test_cve_2011_2523_what_non_empty(self):
        result = get_explanation("cve_2011_2523")
        assert result is not None
        assert len(result.what) > 10

    def test_cve_2011_2523_attack_non_empty(self):
        result = get_explanation("cve_2011_2523")
        assert result is not None
        assert len(result.attack) > 10

    def test_cve_2011_2523_defense_non_empty(self):
        result = get_explanation("cve_2011_2523")
        assert result is not None
        assert len(result.defense) > 10

    def test_cve_2017_0144_what_non_empty(self):
        result = get_explanation("cve_2017_0144")
        assert result is not None
        assert len(result.what) > 10

    def test_cve_2017_0144_attack_non_empty(self):
        result = get_explanation("cve_2017_0144")
        assert result is not None
        assert len(result.attack) > 10

    def test_cve_2017_0144_defense_non_empty(self):
        result = get_explanation("cve_2017_0144")
        assert result is not None
        assert len(result.defense) > 10

    def test_cve_lookup_end_to_end_vsftpd(self):
        """End-to-end: real KB returns vsftpd-specific explanation for CVE-2011-2523."""
        result = get_explanation_for_finding(
            module="tcp_scan",
            target_service="ftp",
            cve_refs=["CVE-2011-2523"],
        )
        assert result is not None
        assert len(result.what) > 10
        assert len(result.attack) > 10
        assert len(result.defense) > 10
        # Must be the CVE-specific entry, not the generic tcp_scan rule
        assert "vsftpd" in result.what.lower() or "backdoor" in result.what.lower()

    def test_cve_lookup_end_to_end_eternalblue(self):
        """End-to-end: real KB returns EternalBlue explanation for CVE-2017-0144."""
        result = get_explanation_for_finding(
            module="tcp_scan",
            target_service="microsoft-ds",
            cve_refs=["CVE-2017-0144"],
        )
        assert result is not None
        assert len(result.what) > 10
        assert len(result.attack) > 10
        assert len(result.defense) > 10
        assert "eternal" in result.what.lower() or "smb" in result.what.lower()
