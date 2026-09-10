"""
knowledge/knowledge_base.py — Local explanation lookup for SentinelX NetLab V1

Role: Load vulnerabilities.json and resolve a rule_id to an Explanation object.

This module is the bridge between:
  - detect/ modules that produce Findings with explanation=None
  - The knowledge base that contains {what, attack, defense} per rule

Usage pattern (in cli.py or a post-processing step):
    from knowledge.knowledge_base import get_explanation
    from core.finding import Finding
    import dataclasses

    explanation = get_explanation(finding.target_service or finding.module)
    if explanation:
        finding = dataclasses.replace(finding, explanation=explanation)

Rule ID resolution order:
    1. finding.target_service  (used by misconfig_detection — e.g. "telnet_exposed")
    2. finding.module          (used by scanners — e.g. "tcp_scan", "smb_enum")
    3. module prefix           (e.g. "misconfig_detection.telnet_exposed" → "telnet_exposed")

Rules enforced here:
- ZERO import sqlite3
- ZERO print()
- Returns Optional[Explanation] — never raises on unknown rule_id
- KB loaded once at import time, injectable for tests
"""

import json
from pathlib import Path
from typing import Dict, Optional

from core.finding import Explanation


# ---------------------------------------------------------------------------
# KB path and loading
# ---------------------------------------------------------------------------

_KB_PATH = Path(__file__).parent / "vulnerabilities.json"


def _load_vulnerabilities(path: Path = _KB_PATH) -> Dict[str, Dict[str, str]]:
    """Load vulnerabilities.json and return the rules dict.

    Falls back to empty dict if file is missing or malformed — never raises.

    Args:
        path: Path to vulnerabilities.json (injectable for tests).

    Returns:
        Dict[str, Dict[str, str]]: {rule_id: {what, attack, defense}}
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("rules", {})
    except Exception:
        return {}


# Module-level cache — loaded once at import time.
# Tests can override _RULES to inject custom data without touching disk.
_RULES: Dict[str, Dict[str, str]] = _load_vulnerabilities()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_explanation(rule_id: str) -> Optional[Explanation]:
    """Return an Explanation for a given rule_id, or None if not found.

    Looks up the rule_id directly, then tries stripping a module prefix
    (e.g. "misconfig_detection.telnet_exposed" → "telnet_exposed").

    Args:
        rule_id: The rule identifier to look up. Typically:
                 - finding.target_service for misconfig rules
                 - finding.module for scanner modules
                 - A dotted module.rule string

    Returns:
        Optional[Explanation]: Populated Explanation, or None if no rule matches.
                               None means: no entry in the knowledge base yet —
                               not an error, just undocumented.
    """
    return _lookup(rule_id, _RULES)


def get_explanation_for_finding(module: str, target_service: str) -> Optional[Explanation]:
    """Convenience function: resolve explanation using both module and target_service.

    Tries resolution in this order:
        1. target_service (e.g. "telnet_exposed", "smb_enum")
        2. module (e.g. "tcp_scan", "misconfig_detection.telnet_exposed")
        3. module prefix stripped (e.g. "telnet_exposed" from "misconfig_detection.telnet_exposed")

    Args:
        module:         Finding.module value.
        target_service: Finding.target_service value.

    Returns:
        Optional[Explanation]: First match found, or None.
    """
    for candidate in _resolution_candidates(module, target_service):
        result = _lookup(candidate, _RULES)
        if result is not None:
            return result
    return None


def list_rule_ids() -> list:
    """Return all rule IDs present in the knowledge base.

    Useful for auditing — checking that every detect module rule has an entry.

    Returns:
        List[str]: Sorted list of rule IDs.
    """
    return sorted(_RULES.keys())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _lookup(rule_id: str, rules: Dict[str, Dict[str, str]]) -> Optional[Explanation]:
    """Perform the actual dict lookup and build an Explanation.

    Args:
        rule_id: Key to look up.
        rules:   The rules dictionary (injectable for tests).

    Returns:
        Optional[Explanation]: Built from the entry, or None.
    """
    if not rule_id:
        return None

    entry = rules.get(rule_id)
    if entry is None:
        return None

    what = entry.get("what", "")
    attack = entry.get("attack", "")
    defense = entry.get("defense", "")

    # Return None if all fields are empty — partial entries are not useful
    if not (what or attack or defense):
        return None

    return Explanation(what=what, attack=attack, defense=defense)


def _resolution_candidates(module: str, target_service: str) -> list:
    """Build an ordered list of rule_id candidates to try.

    Args:
        module:         Finding.module.
        target_service: Finding.target_service.

    Returns:
        List[str]: Candidates in priority order, deduplicated.
    """
    candidates = []

    # 1. target_service directly
    if target_service:
        candidates.append(target_service)

    # 2. module directly
    if module:
        candidates.append(module)

    # 3. Strip module prefix (e.g. "misconfig_detection.telnet_exposed" → "telnet_exposed")
    if module and "." in module:
        suffix = module.split(".", 1)[1]
        if suffix not in candidates:
            candidates.append(suffix)

    # Deduplicate while preserving order
    seen = set()
    result = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result
