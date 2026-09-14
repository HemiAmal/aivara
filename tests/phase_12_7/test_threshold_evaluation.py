"""Tests for Phase 12.7 Threshold Boundaries & Validation (REQ-12-POL-004, 005, 006)."""

import pytest

from aivara.universal.policy.enums import PolicyReasonCode, UniversalDecision
from aivara.universal.policy.exceptions import (
    ThresholdConfigurationError,
    ThresholdGapError,
    ThresholdOverlapError,
)
from aivara.universal.policy.schemas import RiskThresholdBand, UniversalPolicy


def test_standard_threshold_boundaries():
    """Verify exact boundary values against default policy risk bands."""
    policy = UniversalPolicy.get_default_policy()
    bands = policy.thresholds

    # Helper to find matching band
    def match_band(val: float) -> RiskThresholdBand:
        for b in bands:
            if b.contains(val):
                return b
        raise ValueError(f"No band for {val}")

    # 0.000000 -> ACCEPT
    b_0 = match_band(0.000000)
    assert b_0.decision == UniversalDecision.ACCEPT
    assert b_0.band_name == "ACCEPT_BAND"

    # 0.299999 -> ACCEPT
    b_299 = match_band(0.299999)
    assert b_299.decision == UniversalDecision.ACCEPT
    assert b_299.band_name == "ACCEPT_BAND"

    # 0.300000 -> REVIEW
    b_300 = match_band(0.300000)
    assert b_300.decision == UniversalDecision.REVIEW
    assert b_300.band_name == "REVIEW_BAND"

    # 0.649999 -> REVIEW
    b_649 = match_band(0.649999)
    assert b_649.decision == UniversalDecision.REVIEW
    assert b_649.band_name == "REVIEW_BAND"

    # 0.650000 -> QUARANTINE
    b_650 = match_band(0.650000)
    assert b_650.decision == UniversalDecision.QUARANTINE
    assert b_650.band_name == "QUARANTINE_BAND"

    # 0.849999 -> QUARANTINE
    b_849 = match_band(0.849999)
    assert b_849.decision == UniversalDecision.QUARANTINE
    assert b_849.band_name == "QUARANTINE_BAND"

    # 0.850000 -> REJECT
    b_850 = match_band(0.850000)
    assert b_850.decision == UniversalDecision.REJECT
    assert b_850.band_name == "REJECT_BAND"

    # 1.000000 -> REJECT
    b_100 = match_band(1.000000)
    assert b_100.decision == UniversalDecision.REJECT
    assert b_100.band_name == "REJECT_BAND"


def test_threshold_gap_rejected():
    """Threshold bands with a gap (e.g. 0.30 to 0.35 omitted) raise ThresholdGapError."""
    bands = [
        RiskThresholdBand(
            band_name="B1",
            min_score=0.0,
            max_score=0.30,
            decision=UniversalDecision.ACCEPT,
            reason_code=PolicyReasonCode.RISK_BELOW_REVIEW_THRESHOLD,
            inclusive_min=True,
            inclusive_max=False,
        ),
        RiskThresholdBand(
            band_name="B2",
            min_score=0.35,  # GAP: [0.30, 0.35) missing
            max_score=1.00,
            decision=UniversalDecision.REJECT,
            reason_code=PolicyReasonCode.RISK_ABOVE_REJECT_THRESHOLD,
            inclusive_min=True,
            inclusive_max=True,
        ),
    ]

    with pytest.raises(ThresholdGapError):
        UniversalPolicy(
            policy_id="gap_policy",
            thresholds=bands,
        )


def test_threshold_overlap_rejected():
    """Threshold bands with overlapping intervals raise ThresholdOverlapError."""
    bands = [
        RiskThresholdBand(
            band_name="B1",
            min_score=0.0,
            max_score=0.50,
            decision=UniversalDecision.ACCEPT,
            reason_code=PolicyReasonCode.RISK_BELOW_REVIEW_THRESHOLD,
            inclusive_min=True,
            inclusive_max=False,
        ),
        RiskThresholdBand(
            band_name="B2",
            min_score=0.40,  # OVERLAP: [0.40, 0.50) overlapped
            max_score=1.00,
            decision=UniversalDecision.REJECT,
            reason_code=PolicyReasonCode.RISK_ABOVE_REJECT_THRESHOLD,
            inclusive_min=True,
            inclusive_max=True,
        ),
    ]

    with pytest.raises(ThresholdOverlapError):
        UniversalPolicy(
            policy_id="overlap_policy",
            thresholds=bands,
        )


def test_threshold_boundary_point_overlap_rejected():
    """Both bands inclusive on the exact boundary point (e.g., max_score=0.3 inclusive AND min_score=0.3 inclusive) raise ThresholdOverlapError."""
    bands = [
        RiskThresholdBand(
            band_name="B1",
            min_score=0.0,
            max_score=0.30,
            decision=UniversalDecision.ACCEPT,
            reason_code=PolicyReasonCode.RISK_BELOW_REVIEW_THRESHOLD,
            inclusive_min=True,
            inclusive_max=True,  # Inclusive max
        ),
        RiskThresholdBand(
            band_name="B2",
            min_score=0.30,
            max_score=1.00,
            decision=UniversalDecision.REJECT,
            reason_code=PolicyReasonCode.RISK_ABOVE_REJECT_THRESHOLD,
            inclusive_min=True,  # Inclusive min -> double inclusion of 0.30
            inclusive_max=True,
        ),
    ]

    with pytest.raises(ThresholdOverlapError):
        UniversalPolicy(
            policy_id="boundary_overlap_policy",
            thresholds=bands,
        )


def test_threshold_not_starting_at_zero_rejected():
    """Threshold bands not starting at 0.0 raise ThresholdGapError."""
    bands = [
        RiskThresholdBand(
            band_name="B1",
            min_score=0.10,  # Does not start at 0.0
            max_score=1.00,
            decision=UniversalDecision.REJECT,
            reason_code=PolicyReasonCode.RISK_ABOVE_REJECT_THRESHOLD,
            inclusive_min=True,
            inclusive_max=True,
        ),
    ]

    with pytest.raises(ThresholdGapError):
        UniversalPolicy(
            policy_id="non_zero_start_policy",
            thresholds=bands,
        )


def test_threshold_not_ending_at_one_rejected():
    """Threshold bands not ending at 1.0 raise ThresholdGapError."""
    bands = [
        RiskThresholdBand(
            band_name="B1",
            min_score=0.0,
            max_score=0.90,  # Does not reach 1.0
            decision=UniversalDecision.ACCEPT,
            reason_code=PolicyReasonCode.RISK_BELOW_REVIEW_THRESHOLD,
            inclusive_min=True,
            inclusive_max=True,
        ),
    ]

    with pytest.raises(ThresholdGapError):
        UniversalPolicy(
            policy_id="non_one_end_policy",
            thresholds=bands,
        )
