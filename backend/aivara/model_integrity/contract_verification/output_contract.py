"""Static inspection and validation of model output contracts (Phase 7.4).

Performs bounded shape validation, rank checking, dtype canonicalization,
and activation metadata extraction without runtime execution or semantic inference.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from aivara.model_integrity.contract_verification.normalization import (
    normalize_dtype,
    normalize_shape_entry,
)
from aivara.model_integrity.contract_verification.schemas import (
    ContractFinding,
    ContractFindingCode,
    FindingSeverity,
    ValidatedOutputContract,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import OutputContractDescriptor


def inspect_output_contract(
    raw_output: OutputContractDescriptor,
    index: int = 0,
    limits: ModelIngestionLimits = DEFAULT_LIMITS,
) -> Tuple[ValidatedOutputContract, List[ContractFinding]]:
    """Statically validate and normalize a single output contract descriptor.

    Args:
        raw_output: Raw OutputContractDescriptor from parser/metadata.
        index: Sequential 0-based order index in model interface.
        limits: Enforced resource and structural limits.

    Returns:
        Tuple of (ValidatedOutputContract, List[ContractFinding]).
    """
    findings: List[ContractFinding] = []

    # 1. Name validation
    name = str(raw_output.name).strip()
    if not name:
        findings.append(
            ContractFinding(
                code=ContractFindingCode.INVALID_CONTRACT_METADATA,
                message=f"Output contract at index {index} has an empty or whitespace name.",
                severity=FindingSeverity.HIGH,
                target_field="name",
                details={"index": index},
            )
        )
        name = f"unnamed_output_{index}"

    if len(name) > limits.max_string_length:
        findings.append(
            ContractFinding(
                code=ContractFindingCode.INVALID_CONTRACT_METADATA,
                message=f"Output name '{name[:30]}...' exceeds maximum allowed string length.",
                severity=FindingSeverity.HIGH,
                target_field="name",
                details={"length": len(name), "max_allowed": limits.max_string_length},
            )
        )

    # 2. Dtype canonicalization
    canonical_dtype, is_recognized_dtype = normalize_dtype(raw_output.dtype)
    if not is_recognized_dtype:
        findings.append(
            ContractFinding(
                code=ContractFindingCode.UNSUPPORTED_DTYPE,
                message=f"Output '{name}' declares unrecognized or unsupported data type '{raw_output.dtype}'.",
                severity=FindingSeverity.MEDIUM,
                target_field="dtype",
                details={"raw_dtype": raw_output.dtype, "normalized": canonical_dtype},
            )
        )

    # 3. Rank & Shape Validation
    raw_shape = raw_output.shape or []
    rank = len(raw_shape)

    if rank > limits.max_tensor_dimensions:
        findings.append(
            ContractFinding(
                code=ContractFindingCode.RANK_MISMATCH,
                message=f"Output '{name}' rank {rank} exceeds maximum allowed tensor rank {limits.max_tensor_dimensions}.",
                severity=FindingSeverity.HIGH,
                target_field="shape",
                details={"rank": rank, "max_rank": limits.max_tensor_dimensions},
            )
        )

    normalized_shape: List[Optional[int]] = []
    symbolic_dims: List[Optional[str]] = []
    dynamic_dims: List[int] = []
    max_dim_size = 100_000_000

    for dim_idx, dim_val in enumerate(raw_shape):
        norm_dim, sym_name = normalize_shape_entry(dim_val)

        if norm_dim is not None:
            if norm_dim < 0:
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.INVALID_DIMENSION,
                        message=f"Output '{name}' dimension at index {dim_idx} has invalid negative value {norm_dim}.",
                        severity=FindingSeverity.HIGH,
                        target_field="shape",
                        details={"dim_idx": dim_idx, "dim_value": norm_dim},
                    )
                )
            elif norm_dim > max_dim_size:
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.INVALID_DIMENSION,
                        message=f"Output '{name}' dimension at index {dim_idx} ({norm_dim}) exceeds maximum size limit.",
                        severity=FindingSeverity.HIGH,
                        target_field="shape",
                        details={"dim_idx": dim_idx, "dim_value": norm_dim, "max_dim": max_dim_size},
                    )
                )
            normalized_shape.append(norm_dim)
            symbolic_dims.append(None)
        else:
            normalized_shape.append(None)
            symbolic_dims.append(sym_name)
            dynamic_dims.append(dim_idx)

    is_dynamic = len(dynamic_dims) > 0

    # 4. Activation type & semantic descriptors
    activation = raw_output.activation_type.strip() if raw_output.activation_type else None

    # Track name-derived hints as declared metadata descriptors only (not verified runtime proof)
    semantic_descriptors: List[str] = []
    lower_name = name.lower()
    for hint in ("logits", "probabilities", "boxes", "labels", "scores", "embeddings", "features"):
        if hint in lower_name:
            semantic_descriptors.append(hint)

    validated = ValidatedOutputContract(
        name=name,
        index=index,
        dtype=canonical_dtype,
        rank=rank,
        shape=normalized_shape,
        symbolic_dimensions=symbolic_dims,
        dynamic_dimensions=dynamic_dims,
        dimension_constraints={},
        activation_type=activation,
        semantic_descriptors=semantic_descriptors,
        is_dynamic=is_dynamic,
    )

    return validated, findings
