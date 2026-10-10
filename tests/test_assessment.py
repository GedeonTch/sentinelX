"""Unit tests for core/assessment.py (T20): pure discovery and completeness states.

No I/O: the module receives plain values. These tests check the labels and
state rules that the HTML report displays.
"""

import pytest

from core.assessment import (
    COMPLETENESS_MEASURED,
    COMPLETENESS_NOT_APPLICABLE,
    COMPLETENESS_UNKNOWN,
    DISCOVERY_NO_HOSTS_OBSERVED,
    DISCOVERY_OK,
    DISCOVERY_UNKNOWN,
    NOT_APPLICABLE_LABEL,
    compute_assessment_completeness,
    compute_discovery_state,
)


class TestDiscoveryState:

    @pytest.mark.parametrize(
        "discover_status, expected_state",
        [
            ("OK", DISCOVERY_OK),
            ("EMPTY", DISCOVERY_NO_HOSTS_OBSERVED),
            ("CANCELLED", DISCOVERY_UNKNOWN),
            ("FAILED", DISCOVERY_UNKNOWN),
            (None, DISCOVERY_UNKNOWN),          # legacy session: no recorded status
            ("SOMETHING_NEW", DISCOVERY_UNKNOWN),
        ],
    )
    def test_recorded_status_maps_to_a_state(self, discover_status, expected_state):
        assert compute_discovery_state(discover_status)["state"] == expected_state

    def test_empty_discovery_does_not_claim_absence_of_machines(self):
        label = compute_discovery_state("EMPTY")["label"]
        assert "does not prove" in label

    @pytest.mark.parametrize("discover_status", ["CANCELLED", "FAILED"])
    def test_interrupted_or_failed_discovery_says_the_list_may_be_incomplete(
        self, discover_status
    ):
        label = compute_discovery_state(discover_status)["label"]
        assert "may be incomplete" in label

    def test_legacy_session_is_explained_not_guessed(self):
        result = compute_discovery_state(None)
        assert result["state"] == DISCOVERY_UNKNOWN
        assert "legacy" in result["label"]

    def test_every_result_has_a_state_and_a_label(self):
        for status in ("OK", "EMPTY", "CANCELLED", "FAILED", None, "X"):
            result = compute_discovery_state(status)
            assert set(result) == {"state", "label"}
            assert result["label"]


class TestAssessmentCompleteness:

    def test_zero_observed_is_not_applicable_never_a_percentage(self):
        result = compute_assessment_completeness([], ["192.0.2.10"])
        assert result["state"] == COMPLETENESS_NOT_APPLICABLE
        assert result["percent"] is None
        assert result["observed"] == 0
        assert result["evaluated"] is None

    def test_zero_observed_with_no_evaluated_is_not_applicable_too(self):
        result = compute_assessment_completeness([], [])
        assert result["state"] == COMPLETENESS_NOT_APPLICABLE
        assert result["percent"] is None

    def test_not_applicable_label_is_the_exact_french_wording(self):
        result = compute_assessment_completeness([], [])
        assert result["label"] == "Non applicable (0 machine observée)"
        assert NOT_APPLICABLE_LABEL == "Non applicable (0 machine observée)"

    def test_legacy_session_without_scan_data_is_unknown(self):
        result = compute_assessment_completeness(["192.0.2.10"], None)
        assert result["state"] == COMPLETENESS_UNKNOWN
        assert result["percent"] is None
        assert result["evaluated"] is None
        assert result["observed"] == 1
        assert "legacy" in result["label"]

    def test_measured_counts_only_observed_machines_with_a_completed_scan(self):
        observed = ["192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40"]
        completed = ["192.0.2.10", "192.0.2.20", "192.0.2.99"]  # .99 never observed
        result = compute_assessment_completeness(observed, completed)
        assert result["state"] == COMPLETENESS_MEASURED
        assert result["observed"] == 4
        assert result["evaluated"] == 2
        assert result["percent"] == 50
        assert result["label"] == "2 / 4 machines assessed (completed TCP scan)"

    def test_observed_machine_with_no_completed_scan_is_a_measured_zero(self):
        result = compute_assessment_completeness(["192.0.2.10"], [])
        assert result["state"] == COMPLETENESS_MEASURED
        assert result["evaluated"] == 0
        assert result["percent"] == 0

    def test_all_observed_machines_evaluated_is_one_hundred_percent(self):
        result = compute_assessment_completeness(["a", "b", "c"], ["a", "b", "c"])
        assert result["percent"] == 100

    @pytest.mark.parametrize(
        "evaluated, observed, expected_percent",
        [(1, 8, 13), (1, 3, 33), (2, 3, 67), (1, 2, 50)],
    )
    def test_percentage_is_rounded_half_up(self, evaluated, observed, expected_percent):
        observed_ips = [f"10.0.0.{i}" for i in range(observed)]
        evaluated_ips = observed_ips[:evaluated]
        result = compute_assessment_completeness(observed_ips, evaluated_ips)
        assert result["percent"] == expected_percent

    def test_duplicates_and_empty_identities_are_ignored(self):
        result = compute_assessment_completeness(["a", "a", "", "b"], ["a"])
        assert result["observed"] == 2
        assert result["evaluated"] == 1
        assert result["percent"] == 50

    def test_accepts_generators(self):
        result = compute_assessment_completeness(
            (ip for ip in ["a", "b"]),
            (ip for ip in ["b"]),
        )
        assert result["observed"] == 2
        assert result["evaluated"] == 1
