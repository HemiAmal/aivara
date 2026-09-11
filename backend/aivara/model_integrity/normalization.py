"""Deterministic normalization for model descriptors and metadata representations.

Transforms format-specific parsed outputs into a canonically ordered, schema-versioned,
reproducible metadata structure.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from aivara.crypto.canonical import canonicalize
from aivara.model_integrity.parsers.base import ParsedModelData
from aivara.model_integrity.schemas import (
    InputContractDescriptor,
    InspectionStatus,
    ModelFormat,
    NormalizedModelMetadata,
    OperatorDescriptor,
    OutputContractDescriptor,
    ReasonCode,
    TensorDescriptor,
)


def build_normalized_metadata(
    parsed_data: ParsedModelData,
    artifact_size_bytes: int,
    artifact_hash_sha256: str,
    inspection_status: InspectionStatus = InspectionStatus.SUCCESS,
    extra_reason_codes: Optional[List[ReasonCode]] = None,
    extra_warnings: Optional[List[str]] = None,
) -> NormalizedModelMetadata:
    """Construct a deterministically sorted NormalizedModelMetadata object.

    Guarantees:
      - Tensors sorted strictly lexicographically by tensor name.
      - Inputs sorted strictly lexicographically by input name.
      - Outputs sorted strictly lexicographically by output name.
      - Operators sorted strictly by (op_type, domain).
      - Metadata properties sorted by key.
      - Reason codes and warnings deduplicated and deterministically ordered.
      - Parameter count calculated as sum of tensor element counts.
    """
    # 1. Canonical sort for tensors
    sorted_tensors: List[TensorDescriptor] = sorted(
        parsed_data.tensors,
        key=lambda t: t.name,
    )

    # 2. Canonical sort for inputs and outputs
    sorted_inputs: List[InputContractDescriptor] = sorted(
        parsed_data.inputs,
        key=lambda i: i.name,
    )
    sorted_outputs: List[OutputContractDescriptor] = sorted(
        parsed_data.outputs,
        key=lambda o: o.name,
    )

    # 3. Canonical sort for operators
    sorted_operators: List[OperatorDescriptor] = sorted(
        parsed_data.operators,
        key=lambda op: (op.op_type, op.domain),
    )

    # 4. Canonical sort for metadata properties
    sorted_props: Dict[str, str] = {
        k: parsed_data.metadata_props[k]
        for k in sorted(parsed_data.metadata_props.keys())
    }

    # 5. Parameter count
    param_count = sum(t.element_count for t in sorted_tensors)

    # 6. Combined reason codes and warnings
    all_reasons = list(parsed_data.reason_codes)
    if extra_reason_codes:
        all_reasons.extend(extra_reason_codes)
    # Deduplicate while preserving deterministic order
    seen_reasons = set()
    deduped_reasons: List[ReasonCode] = []
    for r in all_reasons:
        if r not in seen_reasons:
            seen_reasons.add(r)
            deduped_reasons.append(r)

    all_warnings = list(parsed_data.warnings)
    if extra_warnings:
        all_warnings.extend(extra_warnings)
    deduped_warnings = sorted(list(set(all_warnings)))

    return NormalizedModelMetadata(
        schema_version="1.0",
        format=parsed_data.format,
        inspection_status=inspection_status,
        artifact_size_bytes=artifact_size_bytes,
        artifact_hash_sha256=artifact_hash_sha256,
        tensor_count=len(sorted_tensors),
        parameter_count=param_count,
        inputs=sorted_inputs,
        outputs=sorted_outputs,
        operators=sorted_operators,
        tensors=sorted_tensors,
        metadata_props=sorted_props,
        warnings=deduped_warnings,
        reason_codes=deduped_reasons,
    )


def canonicalize_normalized_metadata(metadata: NormalizedModelMetadata) -> bytes:
    """Serialize normalized metadata to RFC 8785 JSON Canonicalization Scheme (JCS) bytes."""
    return canonicalize(metadata.model_dump())
