"""Deterministic multi-tier drift classification and attribution engine (Phase 7.5).

Evaluates the 8-state drift matrix across structure, weights, and contracts,
resolves reference trust boundaries, and synthesizes granular deterministic reason codes.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from aivara.model_integrity.comparison.schemas import (
    ArtifactComparisonStatus,
    ComparisonStatus,
    ContractComparisonStatus,
    DriftClassification,
    StructuralComparisonStatus,
    WeightComparisonStatus,
)

PROHIBITED_INTENT_PATTERN = re.compile(
    r"\b(malicious|maliciously|collusion|culpable|intentional|attacker|compromised)\b",
    re.IGNORECASE,
)


def classify_drift(
    structural_status: StructuralComparisonStatus,
    weight_status: WeightComparisonStatus,
    contract_status: ContractComparisonStatus,
) -> DriftClassification:
    """Classify model drift according to the formal eight-state multi-tier matrix.

    State Matrix:
      (Structure, Weight, Contract)
      (0, 0, 0) -> EXACT_INTEGRITY_MATCH
      (0, 1, 0) -> WEIGHT_ONLY_DRIFT
      (1, 0, 0) -> STRUCTURAL_ONLY_DRIFT
      (0, 0, 1) -> CONTRACT_ONLY_DRIFT
      (1, 1, 0) -> STRUCTURAL_AND_WEIGHT_DRIFT
      (1, 0, 1) -> STRUCTURAL_AND_CONTRACT_DRIFT
      (0, 1, 1) -> WEIGHT_AND_CONTRACT_DRIFT
      (1, 1, 1) -> STRUCTURAL_WEIGHT_CONTRACT_DRIFT

    Returns:
        DriftClassification enum value.
    """
    s_avail = structural_status != StructuralComparisonStatus.STRUCTURE_UNAVAILABLE
    w_avail = weight_status != WeightComparisonStatus.WEIGHT_COMPARISON_UNAVAILABLE
    c_avail = contract_status != ContractComparisonStatus.CONTRACT_COMPARISON_UNAVAILABLE

    if not s_avail and not w_avail and not c_avail:
        return DriftClassification.DRIFT_UNAVAILABLE

    s_drift = structural_status == StructuralComparisonStatus.STRUCTURAL_DRIFT
    w_drift = weight_status == WeightComparisonStatus.WEIGHT_DRIFT
    c_drift = contract_status == ContractComparisonStatus.CONTRACT_DRIFT

    if not s_drift and not w_drift and not c_drift:
        return DriftClassification.EXACT_INTEGRITY_MATCH

    if not s_drift and w_drift and not c_drift:
        return DriftClassification.WEIGHT_ONLY_DRIFT

    if s_drift and not w_drift and not c_drift:
        return DriftClassification.STRUCTURAL_ONLY_DRIFT

    if not s_drift and not w_drift and c_drift:
        return DriftClassification.CONTRACT_ONLY_DRIFT

    if s_drift and w_drift and not c_drift:
        return DriftClassification.STRUCTURAL_AND_WEIGHT_DRIFT

    if s_drift and not w_drift and c_drift:
        return DriftClassification.STRUCTURAL_AND_CONTRACT_DRIFT

    if not s_drift and w_drift and c_drift:
        return DriftClassification.WEIGHT_AND_CONTRACT_DRIFT

    return DriftClassification.STRUCTURAL_WEIGHT_CONTRACT_DRIFT


def determine_comparison_status(
    reference_trust: str,
    candidate_trust: str,
    artifact_status: ArtifactComparisonStatus,
    structural_status: StructuralComparisonStatus,
    weight_status: WeightComparisonStatus,
    contract_status: ContractComparisonStatus,
) -> ComparisonStatus:
    """Determine the overarching comparison feasibility and validity status.

    Precedence:
      1. INVALID_REFERENCE if reference trust is invalid.
      2. INVALID_CANDIDATE if candidate trust is invalid.
      3. REFERENCE_UNVERIFIABLE if reference trust is unverifiable.
      4. CANDIDATE_UNVERIFIABLE if candidate trust is unverifiable.
      5. UNCOMPARABLE if all comparison tiers are unavailable.
      6. PARTIALLY_COMPARABLE if only a subset of tiers are available.
      7. COMPARABLE if all comparison tiers are available.
    """
    ref_upper = reference_trust.strip().upper()
    cand_upper = candidate_trust.strip().upper()

    if ref_upper in ("INVALID", "CORRUPTED"):
        return ComparisonStatus.INVALID_REFERENCE

    if cand_upper in ("INVALID", "CORRUPTED"):
        return ComparisonStatus.INVALID_CANDIDATE

    if ref_upper in ("UNVERIFIABLE", "UNTRUSTED"):
        return ComparisonStatus.REFERENCE_UNVERIFIABLE

    if cand_upper in ("UNVERIFIABLE", "UNTRUSTED"):
        return ComparisonStatus.CANDIDATE_UNVERIFIABLE

    available_count = 0
    total_count = 4

    if artifact_status != ArtifactComparisonStatus.ARTIFACT_UNAVAILABLE:
        available_count += 1
    if structural_status != StructuralComparisonStatus.STRUCTURE_UNAVAILABLE:
        available_count += 1
    if weight_status != WeightComparisonStatus.WEIGHT_COMPARISON_UNAVAILABLE:
        available_count += 1
    if contract_status != ContractComparisonStatus.CONTRACT_COMPARISON_UNAVAILABLE:
        available_count += 1

    if available_count == 0:
        return ComparisonStatus.UNCOMPARABLE

    if available_count < total_count:
        return ComparisonStatus.PARTIALLY_COMPARABLE

    return ComparisonStatus.COMPARABLE


def synthesize_reason_codes(
    comparison_status: ComparisonStatus,
    drift_classification: DriftClassification,
    is_exact_artifact_match: bool,
    is_exact_master_match: bool,
    structural_status: StructuralComparisonStatus,
    weight_status: WeightComparisonStatus,
    contract_status: ContractComparisonStatus,
) -> List[str]:
    """Generate deterministic, standardized reason codes for model comparison results."""
    codes: List[str] = [comparison_status.value, drift_classification.value]

    if is_exact_artifact_match:
        codes.append("EXACT_ARTIFACT_MATCH")
    else:
        codes.append("ARTIFACT_BYTES_DIFFER")

    if is_exact_master_match:
        codes.append("MASTER_FINGERPRINT_MATCH")
    else:
        codes.append("MASTER_FINGERPRINT_MISMATCH")

    codes.append(structural_status.value)
    codes.append(weight_status.value)
    codes.append(contract_status.value)

    # Validate semantic safety on generated reason codes
    for code in codes:
        if PROHIBITED_INTENT_PATTERN.search(code):
            raise RuntimeError(
                f"Semantic safety violation: Prohibited intent vocabulary detected in reason code: '{code}'"
            )

    return sorted(list(set(codes)))
