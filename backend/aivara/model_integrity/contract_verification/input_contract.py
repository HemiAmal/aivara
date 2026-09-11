"""Static inspection and validation of model input contracts (Phase 7.4).

Performs bounded shape validation, rank checking, dtype canonicalization,
symbolic dimension extraction, and safe layout determination without model execution.
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
    ValidatedInputContract,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import InputContractDescriptor


def inspect_input_contract(
    raw_input: InputContractDescriptor,
    index: int = 0,
    limits: ModelIngestionLimits = DEFAULT_LIMITS,
) -> Tuple[ValidatedInputContract, List[ContractFinding]]:
    """Statically validate and normalize a single input contract descriptor.

    Args:
        raw_input: Raw InputContractDescriptor from parser/metadata.
        index: Sequential 0-based order index in model interface.
        limits: Enforced resource and structural limits.

    Returns:
        Tuple of (ValidatedInputContract, List[ContractFinding]).
    """
    findings: List[ContractFinding] = []

    # 1. Name validation
    name = str(raw_input.name).strip()
    if not name:
        findings.append(
            ContractFinding(
                code=ContractFindingCode.INVALID_CONTRACT_METADATA,
                message=f"Input contract at index {index} has an empty or whitespace name.",
                severity=FindingSeverity.HIGH,
                target_field="name",
                details={"index": index},
            )
        )
        name = f"unnamed_input_{index}"

    if len(name) > limits.max_string_length:
        findings.append(
            ContractFinding(
                code=ContractFindingCode.INVALID_CONTRACT_METADATA,
                message=f"Input name '{name[:30]}...' exceeds maximum allowed string length.",
                severity=FindingSeverity.HIGH,
                target_field="name",
                details={"length": len(name), "max_allowed": limits.max_string_length},
            )
        )

    # 2. Dtype canonicalization
    canonical_dtype, is_recognized_dtype = normalize_dtype(raw_input.dtype)
    if not is_recognized_dtype:
        findings.append(
            ContractFinding(
                code=ContractFindingCode.UNSUPPORTED_DTYPE,
                message=f"Input '{name}' declares unrecognized or unsupported data type '{raw_input.dtype}'.",
                severity=FindingSeverity.MEDIUM,
                target_field="dtype",
                details={"raw_dtype": raw_input.dtype, "normalized": canonical_dtype},
            )
        )

    # 3. Rank & Shape Validation
    raw_shape = raw_input.shape or []
    rank = len(raw_shape)

    if rank > limits.max_tensor_dimensions:
        findings.append(
            ContractFinding(
                code=ContractFindingCode.RANK_MISMATCH,
                message=f"Input '{name}' rank {rank} exceeds maximum allowed tensor rank {limits.max_tensor_dimensions}.",
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
                        message=f"Input '{name}' dimension at index {dim_idx} has invalid negative value {norm_dim}.",
                        severity=FindingSeverity.HIGH,
                        target_field="shape",
                        details={"dim_idx": dim_idx, "dim_value": norm_dim},
                    )
                )
            elif norm_dim > max_dim_size:
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.INVALID_DIMENSION,
                        message=f"Input '{name}' dimension at index {dim_idx} ({norm_dim}) exceeds maximum size limit.",
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

    is_dynamic = raw_input.is_dynamic or len(dynamic_dims) > 0

    # 4. Safe Layout and Channel Extraction (NO GUESSING)
    layout: Optional[str] = None
    channel_count: Optional[int] = None
    channel_ordering: Optional[str] = None

    declared_ch_order = raw_input.channel_order
    if declared_ch_order:
        cleaned_order = declared_ch_order.strip().upper()
        if cleaned_order in ("NCHW", "CHW"):
            layout = cleaned_order
            # In NCHW / CHW, channel dimension is index 1 or 0
            ch_idx = 1 if cleaned_order == "NCHW" else 0
            if rank > ch_idx and normalized_shape[ch_idx] is not None and normalized_shape[ch_idx] >= 1:
                channel_count = normalized_shape[ch_idx]
        elif cleaned_order in ("NHWC", "HWC"):
            layout = cleaned_order
            ch_idx = 3 if cleaned_order == "NHWC" else 2
            if rank > ch_idx and normalized_shape[ch_idx] is not None and normalized_shape[ch_idx] >= 1:
                channel_count = normalized_shape[ch_idx]
        elif cleaned_order in ("RGB", "BGR", "GRAYSCALE", "RGBA", "BGRA"):
            channel_ordering = cleaned_order
            if cleaned_order == "GRAYSCALE":
                channel_count = 1
            elif cleaned_order in ("RGB", "BGR"):
                channel_count = 3
            elif cleaned_order in ("RGBA", "BGRA"):
                channel_count = 4
        else:
            layout = cleaned_order

    validated = ValidatedInputContract(
        name=name,
        index=index,
        dtype=canonical_dtype,
        rank=rank,
        shape=normalized_shape,
        symbolic_dimensions=symbolic_dims,
        dynamic_dimensions=dynamic_dims,
        dimension_constraints={},
        layout=layout,
        channel_count=channel_count,
        channel_ordering=channel_ordering,
        color_space=None,
        value_range=None,
        normalization_mean=None,
        normalization_std=None,
        batch_dimension_semantics=None,
        sequence_dimension_semantics=None,
        is_dynamic=is_dynamic,
    )

    return validated, findings
