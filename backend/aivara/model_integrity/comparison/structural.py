"""Structural architecture and graph metadata comparison (Phase 7.5).

Evaluates structural identity hash equality and produces detailed, deterministically
ordered structural difference records across operators, tensor schemas, and parameters.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aivara.model_integrity.comparison.schemas import (
    StructuralComparisonStatus,
    StructuralDifferenceRecord,
)
from aivara.model_integrity.schemas import NormalizedModelMetadata


def compare_structural_hashes(
    reference_hash: Optional[str],
    candidate_hash: Optional[str],
) -> StructuralComparisonStatus:
    """Compare Tier 2 structural identity digests (H_structural).

    Args:
        reference_hash: 64-char lowercase hex structural hash of reference.
        candidate_hash: 64-char lowercase hex structural hash of candidate.

    Returns:
        StructuralComparisonStatus (STRUCTURE_MATCH, STRUCTURAL_DRIFT, or STRUCTURE_UNAVAILABLE).
    """
    if not reference_hash or not candidate_hash:
        return StructuralComparisonStatus.STRUCTURE_UNAVAILABLE

    if reference_hash.strip().lower() == candidate_hash.strip().lower():
        return StructuralComparisonStatus.STRUCTURE_MATCH

    return StructuralComparisonStatus.STRUCTURAL_DRIFT


def diff_structural_metadata(
    reference_metadata: Optional[NormalizedModelMetadata],
    candidate_metadata: Optional[NormalizedModelMetadata],
) -> List[StructuralDifferenceRecord]:
    """Perform granular deterministic field-by-field structural diffing between models.

    Args:
        reference_metadata: NormalizedModelMetadata of reference model if available.
        candidate_metadata: NormalizedModelMetadata of candidate model if available.

    Returns:
        Deterministically sorted list of StructuralDifferenceRecord objects.
    """
    if reference_metadata is None or candidate_metadata is None:
        return []

    diffs: List[StructuralDifferenceRecord] = []

    # 1. Format comparison
    if reference_metadata.format != candidate_metadata.format:
        diffs.append(
            StructuralDifferenceRecord(
                category="format",
                path="format",
                reference_value=reference_metadata.format.value,
                candidate_value=candidate_metadata.format.value,
                severity="HIGH",
                reason_code="MODEL_FORMAT_MISMATCH",
            )
        )

    # 2. Tensor count comparison
    if reference_metadata.tensor_count != candidate_metadata.tensor_count:
        diffs.append(
            StructuralDifferenceRecord(
                category="tensor_count",
                path="tensor_count",
                reference_value=reference_metadata.tensor_count,
                candidate_value=candidate_metadata.tensor_count,
                severity="HIGH",
                reason_code="TENSOR_COUNT_MISMATCH",
            )
        )

    # 3. Parameter count comparison
    if reference_metadata.parameter_count != candidate_metadata.parameter_count:
        diffs.append(
            StructuralDifferenceRecord(
                category="parameter_count",
                path="parameter_count",
                reference_value=reference_metadata.parameter_count,
                candidate_value=candidate_metadata.parameter_count,
                severity="HIGH",
                reason_code="PARAMETER_COUNT_MISMATCH",
            )
        )

    # 4. Operator comparison
    ref_ops = {(op.op_type, op.domain): op.count for op in reference_metadata.operators}
    cand_ops = {(op.op_type, op.domain): op.count for op in candidate_metadata.operators}

    all_op_keys = sorted(set(ref_ops.keys()).union(cand_ops.keys()))
    for op_type, domain in all_op_keys:
        ref_count = ref_ops.get((op_type, domain))
        cand_count = cand_ops.get((op_type, domain))
        op_name = f"{domain}::{op_type}" if domain else op_type

        if ref_count != cand_count:
            diffs.append(
                StructuralDifferenceRecord(
                    category="operator",
                    path=f"operators.{op_name}",
                    reference_value=ref_count,
                    candidate_value=cand_count,
                    severity="HIGH" if ref_count is None or cand_count is None else "MEDIUM",
                    reason_code="OPERATOR_COUNT_MISMATCH" if ref_count and cand_count else "OPERATOR_PRESENCE_MISMATCH",
                )
            )

    # 5. Tensor schema comparison (names, shapes, dtypes)
    ref_tensors = {t.name: t for t in reference_metadata.tensors}
    cand_tensors = {t.name: t for t in candidate_metadata.tensors}

    all_tensor_names = sorted(set(ref_tensors.keys()).union(cand_tensors.keys()))
    for name in all_tensor_names:
        t_ref = ref_tensors.get(name)
        t_cand = cand_tensors.get(name)

        if t_ref is None:
            diffs.append(
                StructuralDifferenceRecord(
                    category="tensor_schema",
                    path=f"tensors.{name}",
                    reference_value=None,
                    candidate_value={"shape": t_cand.shape, "dtype": t_cand.dtype},  # type: ignore
                    severity="HIGH",
                    reason_code="ADDED_TENSOR_DETECTED",
                )
            )
        elif t_cand is None:
            diffs.append(
                StructuralDifferenceRecord(
                    category="tensor_schema",
                    path=f"tensors.{name}",
                    reference_value={"shape": t_ref.shape, "dtype": t_ref.dtype},
                    candidate_value=None,
                    severity="HIGH",
                    reason_code="REMOVED_TENSOR_DETECTED",
                )
            )
        else:
            if t_ref.shape != t_cand.shape:
                diffs.append(
                    StructuralDifferenceRecord(
                        category="tensor_schema",
                        path=f"tensors.{name}.shape",
                        reference_value=t_ref.shape,
                        candidate_value=t_cand.shape,
                        severity="HIGH",
                        reason_code="TENSOR_SHAPE_MUTATION",
                    )
                )
            if t_ref.dtype.upper() != t_cand.dtype.upper():
                diffs.append(
                    StructuralDifferenceRecord(
                        category="tensor_schema",
                        path=f"tensors.{name}.dtype",
                        reference_value=t_ref.dtype,
                        candidate_value=t_cand.dtype,
                        severity="HIGH",
                        reason_code="TENSOR_DTYPE_MUTATION",
                    )
                )

    # Sort deterministically by (category, path)
    return sorted(diffs, key=lambda d: (d.category, d.path))
