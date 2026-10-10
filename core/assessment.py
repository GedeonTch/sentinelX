"""
core/assessment.py — Pure assessment states for a session report (T20).

Two questions are kept apart on purpose:
- Discovery state: did DISCOVER complete, and with which recorded result?
- Assessment completeness: which observed machines were evaluated by a
  completed TCP scan?

Rules enforced here:
- ZERO I/O: no sqlite3, no file access, no print()
- ZERO risk_score calculation
- Inputs are plain values prepared by the caller (reports/generator.py)

A machine is evaluated when its TCP scan completed, even with zero open ports.
Zero observed machines is "not applicable": never 0 % and never 100 %.
Discovery is never inferred from TCP results, and TCP completeness is never
inferred from the discovery status.
"""

from typing import Iterable, Optional

DISCOVERY_OK = "OK"
DISCOVERY_NO_HOSTS_OBSERVED = "NO_HOSTS_OBSERVED"
DISCOVERY_UNKNOWN = "UNKNOWN"

COMPLETENESS_MEASURED = "MEASURED"
COMPLETENESS_NOT_APPLICABLE = "NOT_APPLICABLE"
COMPLETENESS_UNKNOWN = "UNKNOWN"

NOT_APPLICABLE_LABEL = "Non applicable (0 machine observée)"


def compute_discovery_state(discover_status: Optional[str]) -> dict:
    """Map the recorded DISCOVER status to a report state.

    Args:
        discover_status: "OK", "EMPTY", "CANCELLED", "FAILED", or None for a
                         session created before the status was recorded.

    Returns:
        dict: {"state": one of DISCOVERY_*, "label": explanation}.
    """
    if discover_status == "OK":
        return {
            "state": DISCOVERY_OK,
            "label": "Discovery completed with at least one machine observed.",
        }
    if discover_status == "EMPTY":
        return {
            "state": DISCOVERY_NO_HOSTS_OBSERVED,
            "label": (
                "Discovery completed with no machine observed. "
                "This does not prove that no machine is present."
            ),
        }
    if discover_status == "CANCELLED":
        return {
            "state": DISCOVERY_UNKNOWN,
            "label": "Discovery was cancelled: the machine list may be incomplete.",
        }
    if discover_status == "FAILED":
        return {
            "state": DISCOVERY_UNKNOWN,
            "label": "Discovery failed: the machine list may be incomplete.",
        }
    if discover_status is None:
        return {
            "state": DISCOVERY_UNKNOWN,
            "label": "No discovery status recorded (legacy session): state unknown.",
        }
    return {
        "state": DISCOVERY_UNKNOWN,
        "label": "Unrecognized discovery status: state unknown.",
    }


def compute_assessment_completeness(
    observed_ips: Iterable[str],
    evaluated_ips: Optional[Iterable[str]],
) -> dict:
    """Share of observed machines evaluated by a completed TCP scan.

    Args:
        observed_ips:  IPs with a device_fingerprint Finding in the session.
        evaluated_ips: IPs whose tcp_scan outcome is "completed", or None when
                       the session has no scan outcome data (legacy session).

    Returns:
        dict with:
          - "state": one of COMPLETENESS_*
          - "label": human-readable explanation
          - "observed": number of observed machines
          - "evaluated": machines evaluated among the observed ones, or None
          - "percent": integer 0-100 only when measured, otherwise None
    """
    observed_set = {ip for ip in observed_ips if ip}
    observed = len(observed_set)

    if observed == 0:
        return {
            "state": COMPLETENESS_NOT_APPLICABLE,
            "label": NOT_APPLICABLE_LABEL,
            "observed": 0,
            "evaluated": None,
            "percent": None,
        }

    if evaluated_ips is None:
        return {
            "state": COMPLETENESS_UNKNOWN,
            "label": "Unknown: legacy session without reliable scan data.",
            "observed": observed,
            "evaluated": None,
            "percent": None,
        }

    evaluated = len(observed_set & set(evaluated_ips))
    return {
        "state": COMPLETENESS_MEASURED,
        "label": f"{evaluated} / {observed} machines assessed (completed TCP scan)",
        "observed": observed,
        "evaluated": evaluated,
        "percent": (200 * evaluated + observed) // (2 * observed),  # half-up rounding
    }
