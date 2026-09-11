"""Baseline Comparability Engine determining validity of comparative analysis (Phase 8.3)."""

from __future__ import annotations

from typing import List, Optional, Tuple
from aivara.behavioral.baselines.schemas import BehavioralBaseline, BaselineStatus


def validate_baseline_comparability(
    baseline: BehavioralBaseline,
    candidate_task_type: str,
    candidate_input_set_id: str,
    candidate_preprocessing_hash: Optional[str] = None,
    candidate_provider: Optional[str] = None,
    candidate_precision: Optional[str] = None,
) -> Tuple[bool, Optional[str], List[str]]:
    """Determine whether a candidate model observation is mathematically and logically comparable to a baseline.

    Args:
        baseline: The authoritative BehavioralBaseline reference profile.
        candidate_task_type: Candidate observation task type (classification, detection, etc.).
        candidate_input_set_id: SHA-256 digest of input set used for candidate inference.
        candidate_preprocessing_hash: Optional preprocessing contract digest.
        candidate_provider: Optional execution provider used for candidate inference.
        candidate_precision: Optional floating-point precision.

    Returns:
        Tuple of (is_comparable, summary_reason, list_of_incompatibility_codes).
    """
    incompatibility_codes: List[str] = []

    # 1. Baseline Validity Check
    if baseline.baseline_status in (BaselineStatus.INVALID, BaselineStatus.UNAVAILABLE, BaselineStatus.INCOMPATIBLE):
        incompatibility_codes.append("BASELINE_STATUS_INVALID")

    # 2. Task Type Compatibility
    if baseline.task_type.lower() != candidate_task_type.lower():
        incompatibility_codes.append("TASK_TYPE_MISMATCH")

    # 3. Input Set Identity Compatibility
    if baseline.input_set_identity != candidate_input_set_id:
        incompatibility_codes.append("INPUT_SET_MISMATCH")

    # 4. Preprocessing Contract Compatibility
    if baseline.preprocessing_hash is not None and candidate_preprocessing_hash is not None:
        if baseline.preprocessing_hash != candidate_preprocessing_hash:
            incompatibility_codes.append("PREPROCESSING_MISMATCH")

    # 5. Runtime Hardware Provider Discrepancy Notice (Non-fatal warning / code)
    if candidate_provider is not None and baseline.execution_provider != candidate_provider:
        incompatibility_codes.append("RUNTIME_PROVIDER_DIFFERENTIAL")

    if incompatibility_codes:
        reason = f"Baseline is incompatible with candidate observation: {', '.join(incompatibility_codes)}"
        return False, reason, incompatibility_codes

    return True, None, []
