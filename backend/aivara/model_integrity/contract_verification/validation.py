"""Static graph contract integrity checks and completeness categorization (Phase 7.4).

Evaluates cross-consistency between tensor metadata, graph interface descriptors,
and preprocessing parameters, assigning deterministic status codes and technical findings.
"""

from __future__ import annotations

import re
from typing import List, Set, Tuple

from aivara.model_integrity.contract_verification.schemas import (
    ContractCompleteness,
    ContractFinding,
    ContractFindingCode,
    ContractStatus,
    FindingSeverity,
    PreprocessingDeclaration,
    ValidatedInputContract,
    ValidatedOutputContract,
)
from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import ModelFormat, NormalizedModelMetadata

PROHIBITED_INTENT_PATTERN = re.compile(
    r"\b(malicious|maliciously|collusion|culpable|intentional|attacker|compromised)\b",
    re.IGNORECASE,
)


def validate_contract_integrity(
    metadata: NormalizedModelMetadata,
    inputs: List[ValidatedInputContract],
    outputs: List[ValidatedOutputContract],
    preprocessing: PreprocessingDeclaration | None = None,
    limits: ModelIngestionLimits = DEFAULT_LIMITS,
) -> Tuple[List[ContractFinding], ContractCompleteness, ContractStatus]:
    """Perform deterministic cross-checks across inputs, outputs, tensors, and preprocessing.

    Returns:
        Tuple of (findings_list, completeness_enum, status_enum).
    """
    findings: List[ContractFinding] = []

    # 1. Duplicate input names check
    seen_inputs: Set[str] = set()
    for inp in inputs:
        if inp.name in seen_inputs:
            findings.append(
                ContractFinding(
                    code=ContractFindingCode.DUPLICATE_INTERFACE_NAME,
                    message=f"Duplicate input contract name '{inp.name}' detected in model interface.",
                    severity=FindingSeverity.HIGH,
                    target_field="inputs",
                    details={"input_name": inp.name},
                )
            )
        seen_inputs.add(inp.name)

    # 2. Duplicate output names check
    seen_outputs: Set[str] = set()
    for out in outputs:
        if out.name in seen_outputs:
            findings.append(
                ContractFinding(
                    code=ContractFindingCode.DUPLICATE_INTERFACE_NAME,
                    message=f"Duplicate output contract name '{out.name}' detected in model interface.",
                    severity=FindingSeverity.HIGH,
                    target_field="outputs",
                    details={"output_name": out.name},
                )
            )
        seen_outputs.add(out.name)

    # 3. Input / Output name collision check
    io_collisions = seen_inputs.intersection(seen_outputs)
    for col_name in sorted(io_collisions):
        findings.append(
            ContractFinding(
                code=ContractFindingCode.INVALID_CONTRACT_METADATA,
                message=f"Name collision: '{col_name}' is declared simultaneously as both input and output.",
                severity=FindingSeverity.MEDIUM,
                target_field="interface",
                details={"colliding_name": col_name},
            )
        )

    # 4. Initializer / Interface collision check
    tensor_map = {t.name: t for t in metadata.tensors}
    for inp in inputs:
        if inp.name in tensor_map:
            findings.append(
                ContractFinding(
                    code=ContractFindingCode.INITIALIZER_INTERFACE_COLLISION,
                    message=(
                        f"Input interface '{inp.name}' conflicts with existing weight initializer parameter."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    target_field="inputs",
                    details={"tensor_name": inp.name},
                )
            )
            # Check dtype consistency between tensor and input
            t = tensor_map[inp.name]
            if t.dtype.upper() != inp.dtype.upper():
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.INTERFACE_TENSOR_TYPE_CONFLICT,
                        message=(
                            f"Input '{inp.name}' dtype '{inp.dtype}' contradicts underlying tensor dtype '{t.dtype}'."
                        ),
                        severity=FindingSeverity.HIGH,
                        target_field="inputs.dtype",
                        details={"input_dtype": inp.dtype, "tensor_dtype": t.dtype},
                    )
                )

    # 5. Determine Completeness & Status
    has_inputs = len(inputs) > 0
    has_outputs = len(outputs) > 0

    has_critical_or_high_structural_error = any(
        f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        and f.code in (
            ContractFindingCode.INVALID_DIMENSION,
            ContractFindingCode.RANK_MISMATCH,
            ContractFindingCode.DUPLICATE_INTERFACE_NAME,
            ContractFindingCode.INVALID_CONTRACT_METADATA,
            ContractFindingCode.INTERFACE_TENSOR_TYPE_CONFLICT,
        )
        for f in findings
    )

    has_mismatch = any(
        f.code in (
            ContractFindingCode.CHANNEL_COUNT_MISMATCH,
            ContractFindingCode.LAYOUT_MISMATCH,
            ContractFindingCode.PREPROCESSING_MISMATCH,
            ContractFindingCode.PREPROCESSING_INCONSISTENT_WITH_INPUT,
            ContractFindingCode.NORMALIZATION_PARAMETER_MISMATCH,
            ContractFindingCode.NORMALIZATION_LENGTH_MISMATCH,
            ContractFindingCode.RESIZE_SHAPE_MISMATCH,
            ContractFindingCode.DTYPE_MISMATCH,
            ContractFindingCode.VALUE_RANGE_INVALID,
        )
        for f in findings
    )

    if not has_inputs and not has_outputs:
        if metadata.format in (
            ModelFormat.SAFETENSORS,
            ModelFormat.PYTORCH_STATE_DICT,
            ModelFormat.TORCHSCRIPT,
        ):
            completeness = ContractCompleteness.UNAVAILABLE
            status = ContractStatus.UNAVAILABLE
            findings.append(
                ContractFinding(
                    code=ContractFindingCode.SHAPE_METADATA_UNAVAILABLE,
                    message=(
                        f"Operational input/output contract metadata is statically unavailable for format "
                        f"'{metadata.format.value}' without external configuration."
                    ),
                    severity=FindingSeverity.INFO,
                    target_field="interface",
                    details={"format": metadata.format.value},
                )
            )
        else:
            completeness = ContractCompleteness.UNKNOWN
            status = ContractStatus.MISSING
            findings.append(
                ContractFinding(
                    code=ContractFindingCode.CONTRACT_METADATA_MISSING,
                    message="Model artifact does not declare input or output interface contracts.",
                    severity=FindingSeverity.INFO,
                    target_field="interface",
                    details={"format": metadata.format.value},
                )
            )
    elif has_critical_or_high_structural_error:
        completeness = ContractCompleteness.INVALID
        status = ContractStatus.INVALID
    elif has_mismatch:
        is_dynamic = any(i.is_dynamic for i in inputs) or any(o.is_dynamic for o in outputs)
        completeness = ContractCompleteness.PARTIAL if is_dynamic else ContractCompleteness.COMPLETE
        status = ContractStatus.MISMATCHED
    else:
        is_dynamic = any(i.is_dynamic for i in inputs) or any(o.is_dynamic for o in outputs)
        if not has_inputs or not has_outputs:
            completeness = ContractCompleteness.PARTIAL
            status = ContractStatus.PARTIAL
        elif is_dynamic:
            completeness = ContractCompleteness.PARTIAL
            status = ContractStatus.VERIFIED
        else:
            completeness = ContractCompleteness.COMPLETE
            status = ContractStatus.VERIFIED

    # 6. Semantic safety guard: enforce zero prohibited intent words in findings
    for f in findings:
        if PROHIBITED_INTENT_PATTERN.search(f.message):
            raise RuntimeError(
                f"Semantic safety violation: Prohibited intent vocabulary detected in finding: '{f.message}'"
            )

    return findings, completeness, status
