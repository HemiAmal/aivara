"""Operational I/O contract and preprocessing comparison (Phase 7.5).

Compares Tier 3 contract identity digests and performs deterministic diffing
across input/output interfaces, shapes, dtypes, and preprocessing declarations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aivara.model_integrity.comparison.schemas import (
    ContractComparisonStatus,
    ContractDifferenceRecord,
)
from aivara.model_integrity.contract_verification.schemas import ContractVerificationResult


def compare_contract_hashes(
    reference_hash: Optional[str],
    candidate_hash: Optional[str],
) -> ContractComparisonStatus:
    """Compare Tier 3 Operational Contract identity digests (H_contract).

    Args:
        reference_hash: 64-char lowercase hex contract hash of reference.
        candidate_hash: 64-char lowercase hex contract hash of candidate.

    Returns:
        ContractComparisonStatus (CONTRACT_MATCH, CONTRACT_DRIFT, or CONTRACT_COMPARISON_UNAVAILABLE).
    """
    if not reference_hash or not candidate_hash:
        return ContractComparisonStatus.CONTRACT_COMPARISON_UNAVAILABLE

    if reference_hash.strip().lower() == candidate_hash.strip().lower():
        return ContractComparisonStatus.CONTRACT_MATCH

    return ContractComparisonStatus.CONTRACT_DRIFT


def diff_contract_metadata(
    reference_contract: Optional[ContractVerificationResult],
    candidate_contract: Optional[ContractVerificationResult],
) -> List[ContractDifferenceRecord]:
    """Perform granular deterministic field-by-field contract diffing.

    Args:
        reference_contract: ContractVerificationResult of reference model if available.
        candidate_contract: ContractVerificationResult of candidate model if available.

    Returns:
        Deterministically sorted list of ContractDifferenceRecord objects.
    """
    if reference_contract is None or candidate_contract is None:
        return []

    diffs: List[ContractDifferenceRecord] = []

    # 1. Input count comparison
    if len(reference_contract.inputs) != len(candidate_contract.inputs):
        diffs.append(
            ContractDifferenceRecord(
                category="input_count",
                path="inputs.count",
                reference_value=len(reference_contract.inputs),
                candidate_value=len(candidate_contract.inputs),
                severity="HIGH",
                reason_code="INPUT_COUNT_MISMATCH",
            )
        )

    # 2. Output count comparison
    if len(reference_contract.outputs) != len(candidate_contract.outputs):
        diffs.append(
            ContractDifferenceRecord(
                category="output_count",
                path="outputs.count",
                reference_value=len(reference_contract.outputs),
                candidate_value=len(candidate_contract.outputs),
                severity="HIGH",
                reason_code="OUTPUT_COUNT_MISMATCH",
            )
        )

    # 3. Input descriptor diffing
    ref_in_map = {inp.name: inp for inp in reference_contract.inputs}
    cand_in_map = {inp.name: inp for inp in candidate_contract.inputs}

    all_in_names = sorted(set(ref_in_map.keys()).union(cand_in_map.keys()))
    for in_name in all_in_names:
        r_in = ref_in_map.get(in_name)
        c_in = cand_in_map.get(in_name)

        if r_in is None:
            diffs.append(
                ContractDifferenceRecord(
                    category="input_descriptor",
                    path=f"inputs.{in_name}",
                    reference_value=None,
                    candidate_value={"shape": c_in.shape, "dtype": c_in.dtype},  # type: ignore
                    severity="HIGH",
                    reason_code="ADDED_INPUT_CONTRACT",
                )
            )
        elif c_in is None:
            diffs.append(
                ContractDifferenceRecord(
                    category="input_descriptor",
                    path=f"inputs.{in_name}",
                    reference_value={"shape": r_in.shape, "dtype": r_in.dtype},
                    candidate_value=None,
                    severity="HIGH",
                    reason_code="REMOVED_INPUT_CONTRACT",
                )
            )
        else:
            if r_in.shape != c_in.shape:
                diffs.append(
                    ContractDifferenceRecord(
                        category="input_descriptor",
                        path=f"inputs.{in_name}.shape",
                        reference_value=r_in.shape,
                        candidate_value=c_in.shape,
                        severity="HIGH",
                        reason_code="INPUT_SHAPE_MUTATION",
                    )
                )
            if r_in.dtype.upper() != c_in.dtype.upper():
                diffs.append(
                    ContractDifferenceRecord(
                        category="input_descriptor",
                        path=f"inputs.{in_name}.dtype",
                        reference_value=r_in.dtype,
                        candidate_value=c_in.dtype,
                        severity="HIGH",
                        reason_code="INPUT_DTYPE_MUTATION",
                    )
                )
            if r_in.layout != c_in.layout:
                diffs.append(
                    ContractDifferenceRecord(
                        category="input_descriptor",
                        path=f"inputs.{in_name}.layout",
                        reference_value=r_in.layout,
                        candidate_value=c_in.layout,
                        severity="MEDIUM",
                        reason_code="INPUT_LAYOUT_MUTATION",
                    )
                )

    # 4. Output descriptor diffing
    ref_out_map = {out.name: out for out in reference_contract.outputs}
    cand_out_map = {out.name: out for out in candidate_contract.outputs}

    all_out_names = sorted(set(ref_out_map.keys()).union(cand_out_map.keys()))
    for out_name in all_out_names:
        r_out = ref_out_map.get(out_name)
        c_out = cand_out_map.get(out_name)

        if r_out is None:
            diffs.append(
                ContractDifferenceRecord(
                    category="output_descriptor",
                    path=f"outputs.{out_name}",
                    reference_value=None,
                    candidate_value={"shape": c_out.shape, "dtype": c_out.dtype},  # type: ignore
                    severity="HIGH",
                    reason_code="ADDED_OUTPUT_CONTRACT",
                )
            )
        elif c_out is None:
            diffs.append(
                ContractDifferenceRecord(
                    category="output_descriptor",
                    path=f"outputs.{out_name}",
                    reference_value={"shape": r_out.shape, "dtype": r_out.dtype},
                    candidate_value=None,
                    severity="HIGH",
                    reason_code="REMOVED_OUTPUT_CONTRACT",
                )
            )
        else:
            if r_out.shape != c_out.shape:
                diffs.append(
                    ContractDifferenceRecord(
                        category="output_descriptor",
                        path=f"outputs.{out_name}.shape",
                        reference_value=r_out.shape,
                        candidate_value=c_out.shape,
                        severity="HIGH",
                        reason_code="OUTPUT_SHAPE_MUTATION",
                    )
                )
            if r_out.dtype.upper() != c_out.dtype.upper():
                diffs.append(
                    ContractDifferenceRecord(
                        category="output_descriptor",
                        path=f"outputs.{out_name}.dtype",
                        reference_value=r_out.dtype,
                        candidate_value=c_out.dtype,
                        severity="HIGH",
                        reason_code="OUTPUT_DTYPE_MUTATION",
                    )
                )

    # 5. Preprocessing diffing
    r_prep = reference_contract.preprocessing
    c_prep = candidate_contract.preprocessing
    if r_prep is not None and c_prep is not None:
        if r_prep.resize_shape != c_prep.resize_shape:
            diffs.append(
                ContractDifferenceRecord(
                    category="preprocessing",
                    path="preprocessing.resize_shape",
                    reference_value=r_prep.resize_shape,
                    candidate_value=c_prep.resize_shape,
                    severity="HIGH",
                    reason_code="PREPROCESSING_RESIZE_MUTATION",
                )
            )
        if r_prep.normalization_mean != c_prep.normalization_mean:
            diffs.append(
                ContractDifferenceRecord(
                    category="preprocessing",
                    path="preprocessing.normalization_mean",
                    reference_value=r_prep.normalization_mean,
                    candidate_value=c_prep.normalization_mean,
                    severity="HIGH",
                    reason_code="PREPROCESSING_MEAN_MUTATION",
                )
            )
        if r_prep.normalization_std != c_prep.normalization_std:
            diffs.append(
                ContractDifferenceRecord(
                    category="preprocessing",
                    path="preprocessing.normalization_std",
                    reference_value=r_prep.normalization_std,
                    candidate_value=c_prep.normalization_std,
                    severity="HIGH",
                    reason_code="PREPROCESSING_STD_MUTATION",
                )
            )

    return sorted(diffs, key=lambda d: (d.category, d.path))
