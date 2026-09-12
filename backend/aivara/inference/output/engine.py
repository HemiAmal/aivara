"""Core validation and deterministic identity engine for Phase 10.6 Output Schema & Numerical Integrity."""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
)
from aivara.inference.exceptions import (
    OutputContractMismatchError,
    OutputContractUnavailableError,
    OutputContractUnverifiableError,
    OutputIntegrityError,
    OutputNumericalIntegrityError,
    OutputResourceLimitError,
    OutputSchemaValidationError,
)
from aivara.inference.execution.models import (
    InferenceExecution,
    RawExecutionOutput,
    RawOutputTensor,
)
from aivara.inference.input.models import InputFinding
from aivara.inference.output.enums import (
    NumericalSanityStatus,
    OutputKind,
    OutputStructuralStatus,
    TaskType,
)
from aivara.inference.output.models import (
    ModelOutputContract,
    OutputIntegrityAssessment,
    OutputIntegrityPolicy,
    OutputTensorContract,
    ValidatedTensorSummary,
)

HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")

SUPPORTED_NUMPY_DTYPES = {
    "float32",
    "float64",
    "float16",
    "int32",
    "int64",
    "int16",
    "int8",
    "uint8",
    "bool",
    "bool_",
}


def compute_output_contract_hash(contract: ModelOutputContract) -> str:
    """Compute deterministic SHA-256 digest over the canonical RFC 8785 JCS output contract descriptor."""
    outputs_desc = [
        {
            "activation_type": o.activation_type,
            "dtype": str(o.dtype).lower(),
            "max_value": float(o.max_value) if o.max_value is not None else None,
            "min_value": float(o.min_value) if o.min_value is not None else None,
            "name": str(o.name),
            "normalized_coordinates": bool(o.normalized_coordinates),
            "output_kind": o.output_kind.value if o.output_kind else None,
            "shape": list(o.shape),
            "unit_norm_required": bool(o.unit_norm_required),
        }
        for o in contract.outputs
    ]

    descriptor = {
        "class_count": contract.class_count,
        "contract_version": str(contract.contract_version),
        "expected_output_count": contract.expected_output_count,
        "outputs": outputs_desc,
        "probability_normalization_tolerance": float(contract.probability_normalization_tolerance),
        "require_finite": bool(contract.require_finite),
        "require_probability_normalization": bool(contract.require_probability_normalization),
        "strict_names": bool(contract.strict_names),
        "strict_ordering": bool(contract.strict_ordering),
        "task_type": contract.task_type.value if hasattr(contract.task_type, "value") else str(contract.task_type),
    }

    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_validated_output_identity(
    raw_output_hash: str,
    task_type: Union[TaskType, str],
    output_contract_hash: Optional[str],
    validation_status: Union[InferenceIntegrityStatus, str],
    numerical_status: Union[NumericalSanityStatus, str],
    output_count: int,
    structural_summaries: List[ValidatedTensorSummary],
    schema_version: str = "1.0",
) -> str:
    """Compute deterministic SHA-256 digest over the canonical validated output descriptor."""
    task_str = task_type.value if hasattr(task_type, "value") else str(task_type)
    val_status_str = validation_status.value if hasattr(validation_status, "value") else str(validation_status)
    num_status_str = numerical_status.value if hasattr(numerical_status, "value") else str(numerical_status)

    summaries_desc = [
        {
            "byte_size": int(s.byte_size),
            "c_contiguous_byte_hash": str(s.c_contiguous_byte_hash),
            "domain_valid": bool(s.domain_valid),
            "dtype": str(s.dtype).lower(),
            "element_count": int(s.element_count),
            "has_nan": bool(s.has_nan),
            "has_neg_inf": bool(s.has_neg_inf),
            "has_pos_inf": bool(s.has_pos_inf),
            "index": int(s.index),
            "is_finite": bool(s.is_finite),
            "name": str(s.name),
            "rank": int(s.rank),
            "shape": list(s.shape),
        }
        for s in sorted(structural_summaries, key=lambda x: x.index)
    ]

    descriptor = {
        "numerical_status": num_status_str,
        "output_contract_hash": str(output_contract_hash) if output_contract_hash else "",
        "output_count": int(output_count),
        "raw_output_hash": str(raw_output_hash),
        "schema_version": str(schema_version),
        "structural_summary": summaries_desc,
        "task_type": task_str.lower(),
        "validation_status": val_status_str,
    }

    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def build_tensor_summary(
    tensor_data: np.ndarray,
    name: str,
    index: int,
    contract: Optional[OutputTensorContract] = None,
    policy: Optional[OutputIntegrityPolicy] = None,
) -> ValidatedTensorSummary:
    """Extract structural, numerical, and cryptographic metadata from a single output tensor without mutating it."""
    pol = policy or OutputIntegrityPolicy()
    dtype_str = str(tensor_data.dtype)
    shape_list = list(tensor_data.shape)
    rank = int(tensor_data.ndim)
    element_count = int(tensor_data.size)
    byte_size = int(tensor_data.nbytes)

    # Contiguous byte digest
    c_bytes = np.ascontiguousarray(tensor_data).tobytes()
    c_byte_hash = hashlib.sha256(c_bytes).hexdigest()

    # Numerical finiteness checks
    has_nan = False
    has_pos_inf = False
    has_neg_inf = False
    is_finite = True
    min_val: Optional[float] = None
    max_val: Optional[float] = None

    if np.issubdtype(tensor_data.dtype, np.number):
        if np.issubdtype(tensor_data.dtype, np.floating):
            isnan_mask = np.isnan(tensor_data)
            isposinf_mask = np.isposinf(tensor_data)
            isneginf_mask = np.isneginf(tensor_data)

            has_nan = bool(np.any(isnan_mask))
            has_pos_inf = bool(np.any(isposinf_mask))
            has_neg_inf = bool(np.any(isneginf_mask))
            is_finite = not (has_nan or has_pos_inf or has_neg_inf)

            if is_finite and element_count > 0:
                min_val = float(np.min(tensor_data))
                max_val = float(np.max(tensor_data))
            elif element_count > 0:
                finite_vals = tensor_data[np.isfinite(tensor_data)]
                if finite_vals.size > 0:
                    min_val = float(np.min(finite_vals))
                    max_val = float(np.max(finite_vals))
        else:
            is_finite = True
            if element_count > 0:
                min_val = float(np.min(tensor_data))
                max_val = float(np.max(tensor_data))

    domain_valid = True
    if contract:
        if contract.min_value is not None and min_val is not None:
            if min_val < contract.min_value:
                domain_valid = False
        if contract.max_value is not None and max_val is not None:
            if max_val > contract.max_value:
                domain_valid = False

    return ValidatedTensorSummary(
        name=str(name),
        index=int(index),
        dtype=dtype_str,
        shape=shape_list,
        rank=rank,
        element_count=element_count,
        byte_size=byte_size,
        is_finite=is_finite,
        has_nan=has_nan,
        has_pos_inf=has_pos_inf,
        has_neg_inf=has_neg_inf,
        min_value=min_val,
        max_value=max_val,
        domain_valid=domain_valid,
        c_contiguous_byte_hash=c_byte_hash,
    )


def validate_classification_output(
    summary: ValidatedTensorSummary,
    tensor_data: Optional[np.ndarray],
    contract: Optional[ModelOutputContract],
    tensor_contract: Optional[OutputTensorContract],
    policy: OutputIntegrityPolicy,
    findings: List[InputFinding],
) -> None:
    """Evaluate classification task output constraints."""
    # Rank check: classification output is typically 1D [C] or 2D [B, C]
    if summary.rank not in (1, 2):
        findings.append(
            InputFinding(
                code=InferenceFindingCode.OUTPUT_RANK_MISMATCH.value,
                message=f"Classification output tensor '{summary.name}' expected rank 1 or 2, got rank {summary.rank}.",
                details={"tensor": summary.name, "rank": summary.rank},
            )
        )

    # Class dimension check
    class_dim = summary.shape[-1] if summary.shape else 0
    if contract and contract.class_count is not None:
        if class_dim != contract.class_count:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_SHAPE_MISMATCH.value,
                    message=f"Classification class dimension ({class_dim}) does not match contract class count ({contract.class_count}).",
                    details={"observed": class_dim, "expected": contract.class_count},
                )
            )

    # Probabilities vs. Logits checks
    is_probability = False
    if tensor_contract and tensor_contract.output_kind == OutputKind.PROBABILITIES:
        is_probability = True
    elif tensor_contract and tensor_contract.activation_type in ("softmax", "sigmoid"):
        is_probability = True

    if is_probability:
        if summary.min_value is not None and summary.min_value < 0.0:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value,
                    message=f"Probability output '{summary.name}' contains negative values (min: {summary.min_value}).",
                    details={"min_value": summary.min_value},
                )
            )
        if summary.max_value is not None and summary.max_value > 1.0 + policy.probability_sum_tolerance:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value,
                    message=f"Probability output '{summary.name}' contains values exceeding 1.0 (max: {summary.max_value}).",
                    details={"max_value": summary.max_value},
                )
            )

        # Normalization check if required
        if contract and contract.require_probability_normalization and tensor_data is not None and summary.is_finite:
            tol = contract.probability_normalization_tolerance or policy.probability_sum_tolerance
            if summary.rank == 1:
                prob_sum = float(np.sum(tensor_data))
                if abs(prob_sum - 1.0) > tol:
                    findings.append(
                        InputFinding(
                            code=InferenceFindingCode.OUTPUT_PROBABILITY_SUM_INVALID.value,
                            message=f"Probability sum {prob_sum} deviates from 1.0 by more than tolerance {tol}.",
                            details={"prob_sum": prob_sum, "tolerance": tol},
                        )
                    )
            elif summary.rank == 2:
                row_sums = np.sum(tensor_data, axis=-1)
                deviations = np.abs(row_sums - 1.0)
                max_dev = float(np.max(deviations))
                if max_dev > tol:
                    findings.append(
                        InputFinding(
                            code=InferenceFindingCode.OUTPUT_PROBABILITY_SUM_INVALID.value,
                            message=f"Batched probability row sums deviate from 1.0 by max {max_dev} (tolerance: {tol}).",
                            details={"max_deviation": max_dev, "tolerance": tol},
                        )
                    )


def validate_detection_output(
    summary: ValidatedTensorSummary,
    tensor_data: Optional[np.ndarray],
    contract: Optional[ModelOutputContract],
    tensor_contract: Optional[OutputTensorContract],
    policy: OutputIntegrityPolicy,
    findings: List[InputFinding],
) -> None:
    """Evaluate object detection task output constraints."""
    if tensor_data is None:
        return

    # Detection output can be bounding boxes [N, 4], [B, N, 4], scores [N], class_ids [N], or combined [N, 6]
    is_box_tensor = False
    if tensor_contract and tensor_contract.output_kind == OutputKind.BOUNDING_BOXES:
        is_box_tensor = True
    elif "box" in summary.name.lower() or (summary.shape and summary.shape[-1] == 4):
        is_box_tensor = True

    if is_box_tensor and summary.is_finite and tensor_data.size > 0:
        # Reshape to [-1, 4] for box evaluation
        boxes = tensor_data.reshape(-1, 4)
        x1 = boxes[:, 0]
        y1 = boxes[:, 1]
        x2 = boxes[:, 2]
        y2 = boxes[:, 3]

        # Geometry check: x1 <= x2, y1 <= y2
        invalid_x = np.any(x1 > x2)
        invalid_y = np.any(y1 > y2)
        if invalid_x or invalid_y:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_BOX_INVALID.value,
                    message=f"Detection bounding boxes in '{summary.name}' have inverted coordinates (x1 > x2 or y1 > y2).",
                    details={"tensor": summary.name},
                )
            )

        # Coordinate bounds check for normalized coordinates
        normalized = True
        if tensor_contract is not None:
            normalized = tensor_contract.normalized_coordinates

        if normalized:
            tol = policy.box_coordinate_tolerance
            out_of_bounds = (
                np.any(x1 < -tol)
                or np.any(y1 < -tol)
                or np.any(x2 > 1.0 + tol)
                or np.any(y2 > 1.0 + tol)
            )
            if out_of_bounds:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_BOX_INVALID.value,
                        message=f"Normalized detection box coordinates in '{summary.name}' exceed [0.0, 1.0] domain.",
                        details={"tensor": summary.name, "tolerance": tol},
                    )
                )

    # Score tensor validation
    is_score_tensor = (
        (tensor_contract and tensor_contract.output_kind == OutputKind.CLASS_SCORES)
        or "score" in summary.name.lower()
        or "conf" in summary.name.lower()
    )
    if is_score_tensor and summary.is_finite and tensor_data.size > 0:
        if summary.min_value is not None and summary.min_value < 0.0:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value,
                    message=f"Detection confidence scores in '{summary.name}' contain negative values ({summary.min_value}).",
                    details={"min_value": summary.min_value},
                )
            )
        if summary.max_value is not None and summary.max_value > 1.0 + policy.probability_sum_tolerance:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value,
                    message=f"Detection confidence scores in '{summary.name}' exceed 1.0 ({summary.max_value}).",
                    details={"max_value": summary.max_value},
                )
            )

    # Class ID tensor validation
    is_class_tensor = "class" in summary.name.lower() or "label" in summary.name.lower()
    if is_class_tensor and summary.is_finite and tensor_data.size > 0:
        if np.issubdtype(tensor_data.dtype, np.integer):
            if summary.min_value is not None and summary.min_value < 0:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_CLASS_ID_INVALID.value,
                        message=f"Detection class IDs in '{summary.name}' contain negative indices ({summary.min_value}).",
                        details={"min_value": summary.min_value},
                    )
                )
            if contract and contract.class_count is not None and summary.max_value is not None:
                if summary.max_value >= contract.class_count:
                    findings.append(
                        InputFinding(
                            code=InferenceFindingCode.OUTPUT_CLASS_ID_INVALID.value,
                            message=f"Detection class ID ({summary.max_value}) exceeds contract class count ({contract.class_count}).",
                            details={"max_class_id": summary.max_value, "class_count": contract.class_count},
                        )
                    )


def validate_segmentation_output(
    summary: ValidatedTensorSummary,
    tensor_data: Optional[np.ndarray],
    contract: Optional[ModelOutputContract],
    tensor_contract: Optional[OutputTensorContract],
    policy: OutputIntegrityPolicy,
    findings: List[InputFinding],
) -> None:
    """Evaluate semantic segmentation task output constraints."""
    # Segmentation outputs are spatial: rank 2 [H, W], rank 3 [C, H, W] or [B, H, W], rank 4 [B, C, H, W]
    if summary.rank not in (2, 3, 4):
        findings.append(
            InputFinding(
                code=InferenceFindingCode.OUTPUT_RANK_MISMATCH.value,
                message=f"Segmentation output '{summary.name}' expected spatial rank 2, 3, or 4, got rank {summary.rank}.",
                details={"tensor": summary.name, "rank": summary.rank},
            )
        )

    # If discrete integer class map
    if tensor_data is not None and np.issubdtype(tensor_data.dtype, np.integer):
        if summary.min_value is not None and summary.min_value < 0:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_CLASS_ID_INVALID.value,
                    message=f"Segmentation class mask '{summary.name}' contains negative class indices.",
                    details={"min_value": summary.min_value},
                )
            )
        if contract and contract.class_count is not None and summary.max_value is not None:
            if summary.max_value >= contract.class_count:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_CLASS_ID_INVALID.value,
                        message=f"Segmentation mask class ID ({summary.max_value}) exceeds contract class count ({contract.class_count}).",
                        details={"max_class_id": summary.max_value, "class_count": contract.class_count},
                    )
                )


def validate_embedding_output(
    summary: ValidatedTensorSummary,
    tensor_data: Optional[np.ndarray],
    contract: Optional[ModelOutputContract],
    tensor_contract: Optional[OutputTensorContract],
    policy: OutputIntegrityPolicy,
    findings: List[InputFinding],
) -> None:
    """Evaluate embedding / feature vector output constraints."""
    if summary.rank not in (1, 2):
        findings.append(
            InputFinding(
                code=InferenceFindingCode.OUTPUT_RANK_MISMATCH.value,
                message=f"Embedding output '{summary.name}' expected vector rank 1 or 2, got rank {summary.rank}.",
                details={"tensor": summary.name, "rank": summary.rank},
            )
        )

    # Unit norm check if explicitly requested
    unit_norm = False
    if tensor_contract and tensor_contract.unit_norm_required:
        unit_norm = True

    if unit_norm and tensor_data is not None and summary.is_finite and tensor_data.size > 0:
        if summary.rank == 1:
            norm = float(np.linalg.norm(tensor_data))
            if abs(norm - 1.0) > 1e-3:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value,
                        message=f"Embedding vector '{summary.name}' norm ({norm:.4f}) violates required unit norm.",
                        details={"norm": norm},
                    )
                )
        elif summary.rank == 2:
            norms = np.linalg.norm(tensor_data, axis=-1)
            deviations = np.abs(norms - 1.0)
            max_dev = float(np.max(deviations))
            if max_dev > 1e-3:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value,
                        message=f"Batched embedding vectors in '{summary.name}' deviate from unit norm by max {max_dev:.4f}.",
                        details={"max_deviation": max_dev},
                    )
                )


def validate_structured_object(
    data: Any,
    current_depth: int,
    max_depth: int,
    max_string_len: int,
    path: str = "$",
) -> None:
    """Recursively validate structured output data types and nesting limits."""
    if current_depth > max_depth:
        raise OutputResourceLimitError(
            f"Structured output exceeded maximum nesting depth of {max_depth} at {path}.",
            details={"path": path, "depth": current_depth, "max_depth": max_depth},
        )

    if data is None or isinstance(data, (bool, int, float)):
        if isinstance(data, float) and (math.isnan(data) or math.isinf(data)):
            raise OutputNumericalIntegrityError(
                f"Non-finite float value '{data}' detected in structured output at {path}.",
                details={"path": path, "value": str(data)},
            )
        return

    if isinstance(data, str):
        if len(data) > max_string_len:
            raise OutputResourceLimitError(
                f"String length {len(data)} at {path} exceeds maximum limit of {max_string_len}.",
                details={"path": path, "length": len(data), "max_length": max_string_len},
            )
        return

    if isinstance(data, (list, tuple)):
        for idx, item in enumerate(data):
            validate_structured_object(
                item,
                current_depth=current_depth + 1,
                max_depth=max_depth,
                max_string_len=max_string_len,
                path=f"{path}[{idx}]",
            )
        return

    if isinstance(data, dict):
        for key, value in data.items():
            if not isinstance(key, str):
                raise OutputSchemaValidationError(
                    f"Dictionary key at {path} must be a string, got '{type(key).__name__}'.",
                    details={"path": path, "key_type": type(key).__name__},
                )
            if len(key) > max_string_len:
                raise OutputResourceLimitError(
                    f"Dictionary key length {len(key)} at {path} exceeds limit {max_string_len}.",
                    details={"path": path, "key": key},
                )
            validate_structured_object(
                value,
                current_depth=current_depth + 1,
                max_depth=max_depth,
                max_string_len=max_string_len,
                path=f"{path}.{key}",
            )
        return

    # Any other arbitrary Python type is strictly prohibited
    raise OutputSchemaValidationError(
        f"Unsupported data type '{type(data).__name__}' detected in structured output at {path}.",
        details={"path": path, "unsupported_type": type(data).__name__},
    )


def validate_output_integrity(
    raw_output: Union[RawExecutionOutput, InferenceExecution, Dict[str, Any], List[np.ndarray], np.ndarray],
    contract: Optional[Union[ModelOutputContract, Dict[str, Any], str]] = None,
    policy: Optional[OutputIntegrityPolicy] = None,
    expected_raw_output_hash: Optional[str] = None,
) -> OutputIntegrityAssessment:
    """Authoritative Phase 10.6 evaluation of model output schema and numerical integrity.

    Evaluates raw outputs from Phase 10.5 against model-declared contracts and task domains,
    producing an immutable OutputIntegrityAssessment with a canonical validated_output_identity.
    """
    pol = policy or OutputIntegrityPolicy()
    findings: List[InputFinding] = []
    details: Dict[str, Any] = {}

    # Extract target raw output tensors and recorded hash
    raw_hash = ""
    raw_tensors_map: Dict[str, np.ndarray] = {}
    ordered_tensor_names: List[str] = []

    if isinstance(raw_output, InferenceExecution):
        if raw_output.raw_output is None:
            raise OutputSchemaValidationError("InferenceExecution record does not contain raw_output envelope.")
        raw_hash = raw_output.raw_output_hash or raw_output.raw_output.raw_output_hash
        # Map raw output tensors if numpy arrays exist in details or rebuild placeholders
        for rot in raw_output.raw_output.outputs:
            ordered_tensor_names.append(rot.name)
            # Check if actual tensor array was stored in details or execution
            if "raw_arrays" in raw_output.details and rot.name in raw_output.details["raw_arrays"]:
                raw_tensors_map[rot.name] = raw_output.details["raw_arrays"][rot.name]

    elif isinstance(raw_output, RawExecutionOutput):
        raw_hash = raw_output.raw_output_hash
        for rot in raw_output.outputs:
            ordered_tensor_names.append(rot.name)

    elif isinstance(raw_output, dict):
        if "outputs" in raw_output and "raw_output_hash" in raw_output:
            # Serialized RawExecutionOutput dictionary
            raw_hash = str(raw_output["raw_output_hash"])
            for item in raw_output["outputs"]:
                name = item.get("name", "output")
                ordered_tensor_names.append(name)
        else:
            # Map of tensor names to ndarrays
            for k, v in raw_output.items():
                if isinstance(v, np.ndarray):
                    raw_tensors_map[str(k)] = v
                    ordered_tensor_names.append(str(k))
                else:
                    # Structured output
                    validate_structured_object(
                        v,
                        current_depth=1,
                        max_depth=pol.max_structured_nesting_depth,
                        max_string_len=pol.max_string_length,
                    )
            if not raw_hash and raw_tensors_map:
                # Compute raw output hash
                desc = [
                    {
                        "byte_size": int(v.nbytes),
                        "c_contiguous_byte_hash": hashlib.sha256(np.ascontiguousarray(v).tobytes()).hexdigest(),
                        "dtype": str(v.dtype),
                        "element_count": int(v.size),
                        "index": idx,
                        "is_finite": bool(np.all(np.isfinite(v))) if np.issubdtype(v.dtype, np.number) else True,
                        "name": k,
                        "shape": list(v.shape),
                    }
                    for idx, (k, v) in enumerate(raw_tensors_map.items())
                ]
                raw_hash = hashlib.sha256(canonicalize(desc)).hexdigest()

    elif isinstance(raw_output, list):
        for idx, item in enumerate(raw_output):
            if isinstance(item, np.ndarray):
                name = f"output_{idx}"
                raw_tensors_map[name] = item
                ordered_tensor_names.append(name)
        if not raw_hash and raw_tensors_map:
            desc = [
                {
                    "byte_size": int(v.nbytes),
                    "c_contiguous_byte_hash": hashlib.sha256(np.ascontiguousarray(v).tobytes()).hexdigest(),
                    "dtype": str(v.dtype),
                    "element_count": int(v.size),
                    "index": idx,
                    "is_finite": bool(np.all(np.isfinite(v))) if np.issubdtype(v.dtype, np.number) else True,
                    "name": k,
                    "shape": list(v.shape),
                }
                for idx, (k, v) in enumerate(raw_tensors_map.items())
            ]
            raw_hash = hashlib.sha256(canonicalize(desc)).hexdigest()

    elif isinstance(raw_output, np.ndarray):
        name = "output_0"
        raw_tensors_map[name] = raw_output
        ordered_tensor_names.append(name)
        c_hash = hashlib.sha256(np.ascontiguousarray(raw_output).tobytes()).hexdigest()
        is_fin = bool(np.all(np.isfinite(raw_output))) if np.issubdtype(raw_output.dtype, np.number) else True
        desc = [
            {
                "byte_size": int(raw_output.nbytes),
                "c_contiguous_byte_hash": c_hash,
                "dtype": str(raw_output.dtype),
                "element_count": int(raw_output.size),
                "index": 0,
                "is_finite": is_fin,
                "name": name,
                "shape": list(raw_output.shape),
            }
        ]
        raw_hash = hashlib.sha256(canonicalize(desc)).hexdigest()

    if expected_raw_output_hash:
        if raw_hash and raw_hash != expected_raw_output_hash:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_HASH_MISMATCH.value,
                    message=f"Observed raw output hash '{raw_hash}' does not match expected '{expected_raw_output_hash}'.",
                    details={"observed": raw_hash, "expected": expected_raw_output_hash},
                )
            )

    # Resource limit check on output count
    output_count = len(ordered_tensor_names)
    if output_count > pol.max_outputs:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.OUTPUT_RESOURCE_LIMIT_EXCEEDED.value,
                message=f"Output count {output_count} exceeds maximum policy limit {pol.max_outputs}.",
                details={"output_count": output_count, "limit": pol.max_outputs},
            )
        )

    # Contract parsing & resolution
    parsed_contract: Optional[ModelOutputContract] = None
    contract_hash: Optional[str] = None
    contract_status = OutputStructuralStatus.VALID
    task_type = TaskType.GENERIC

    if isinstance(contract, str):
        if contract.upper() == "UNAVAILABLE":
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_CONTRACT_UNAVAILABLE.value,
                    message="Model output contract is unavailable for this inference transaction.",
                    details={"contract": contract},
                )
            )
            contract_status = OutputStructuralStatus.UNAVAILABLE
        elif contract.upper() == "UNVERIFIABLE":
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_CONTRACT_UNVERIFIABLE.value,
                    message="Model output contract cannot be verified deterministically.",
                    details={"contract": contract},
                )
            )
            contract_status = OutputStructuralStatus.UNVERIFIABLE

    elif isinstance(contract, dict):
        try:
            parsed_contract = ModelOutputContract(**contract)
            contract_hash = compute_output_contract_hash(parsed_contract)
            task_type = parsed_contract.task_type
        except Exception as e:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_SCHEMA_INVALID.value,
                    message=f"Failed to parse model output contract dictionary: {str(e)}",
                    details={"error": str(e)},
                )
            )
            contract_status = OutputStructuralStatus.INVALID

    elif isinstance(contract, ModelOutputContract):
        parsed_contract = contract
        contract_hash = compute_output_contract_hash(parsed_contract)
        task_type = parsed_contract.task_type

    elif contract is not None and hasattr(contract, "outputs"):
        # NormalizedModelMetadata from Phase 7
        try:
            tensor_contracts: List[OutputTensorContract] = []
            for out_desc in contract.outputs:
                tensor_contracts.append(
                    OutputTensorContract(
                        name=out_desc.name,
                        shape=out_desc.shape,
                        dtype=out_desc.dtype,
                        activation_type=out_desc.activation_type,
                    )
                )
            parsed_contract = ModelOutputContract(
                outputs=tensor_contracts,
                expected_output_count=len(tensor_contracts),
            )
            contract_hash = compute_output_contract_hash(parsed_contract)
            task_type = parsed_contract.task_type
        except Exception as e:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_SCHEMA_INVALID.value,
                    message=f"Failed to adapt Phase 7 model metadata to output contract: {str(e)}",
                    details={"error": str(e)},
                )
            )
            contract_status = OutputStructuralStatus.INVALID

    # Contract output count check
    if parsed_contract and parsed_contract.expected_output_count is not None:
        if output_count != parsed_contract.expected_output_count:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_COUNT_MISMATCH.value,
                    message=f"Observed output count {output_count} does not match contract expected {parsed_contract.expected_output_count}.",
                    details={"observed": output_count, "expected": parsed_contract.expected_output_count},
                )
            )

    # Build validated tensor summaries
    summaries: List[ValidatedTensorSummary] = []
    total_elements = 0
    overall_finite = True
    any_nan = False
    any_pos_inf = False
    any_neg_inf = False
    all_domains_valid = True

    # Build contract map by name and by index
    contract_by_name = {o.name: o for o in parsed_contract.outputs} if parsed_contract else {}

    for idx, name in enumerate(ordered_tensor_names):
        tensor_contract = contract_by_name.get(name)
        if parsed_contract and not tensor_contract and parsed_contract.strict_names:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_NAME_MISMATCH.value,
                    message=f"Output tensor name '{name}' not found in model contract.",
                    details={"tensor": name},
                )
            )

        # If strict ordering is enabled
        if parsed_contract and parsed_contract.strict_ordering and idx < len(parsed_contract.outputs):
            expected_name_at_idx = parsed_contract.outputs[idx].name
            if name != expected_name_at_idx:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_ORDER_MISMATCH.value,
                        message=f"Output tensor at index {idx} is '{name}', expected '{expected_name_at_idx}'.",
                        details={"index": idx, "observed": name, "expected": expected_name_at_idx},
                    )
                )

        arr = raw_tensors_map.get(name)
        if arr is not None:
            summary = build_tensor_summary(arr, name=name, index=idx, contract=tensor_contract, policy=pol)
            summaries.append(summary)

            total_elements += summary.element_count
            if not summary.is_finite:
                overall_finite = False
            if summary.has_nan:
                any_nan = True
            if summary.has_pos_inf:
                any_pos_inf = True
            if summary.has_neg_inf:
                any_neg_inf = True
            if not summary.domain_valid:
                all_domains_valid = False

            # DType check
            if summary.dtype not in SUPPORTED_NUMPY_DTYPES:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_DTYPE_MISMATCH.value,
                        message=f"Output tensor '{name}' has unsupported dtype '{summary.dtype}'.",
                        details={"tensor": name, "dtype": summary.dtype},
                    )
                )
            if tensor_contract and tensor_contract.dtype.lower() != summary.dtype.lower():
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_DTYPE_MISMATCH.value,
                        message=f"Output tensor '{name}' dtype '{summary.dtype}' contradicts contract '{tensor_contract.dtype}'.",
                        details={"tensor": name, "observed": summary.dtype, "expected": tensor_contract.dtype},
                    )
                )

            # Rank & Dimension limits
            if summary.rank > pol.max_rank:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.OUTPUT_RANK_MISMATCH.value,
                        message=f"Output tensor '{name}' rank {summary.rank} exceeds policy max {pol.max_rank}.",
                        details={"tensor": name, "rank": summary.rank, "limit": pol.max_rank},
                    )
                )
            for dim_idx, d in enumerate(summary.shape):
                if d < 0 or d > pol.max_dimension_size:
                    findings.append(
                        InputFinding(
                            code=InferenceFindingCode.OUTPUT_DIMENSION_INVALID.value,
                            message=f"Output tensor '{name}' dimension {dim_idx} ({d}) exceeds limits.",
                            details={"tensor": name, "dim_index": dim_idx, "dim_size": d},
                        )
                    )

            # Shape check against contract
            if tensor_contract and tensor_contract.shape:
                if len(tensor_contract.shape) != summary.rank:
                    findings.append(
                        InputFinding(
                            code=InferenceFindingCode.OUTPUT_RANK_MISMATCH.value,
                            message=f"Output tensor '{name}' rank {summary.rank} contradicts contract rank {len(tensor_contract.shape)}.",
                            details={"observed_rank": summary.rank, "expected_rank": len(tensor_contract.shape)},
                        )
                    )
                else:
                    for s_idx, (exp_dim, obs_dim) in enumerate(zip(tensor_contract.shape, summary.shape)):
                        if exp_dim is not None and exp_dim != -1 and exp_dim != obs_dim:
                            findings.append(
                                InputFinding(
                                    code=InferenceFindingCode.OUTPUT_SHAPE_MISMATCH.value,
                                    message=f"Output tensor '{name}' dimension {s_idx} ({obs_dim}) does not match contract ({exp_dim}).",
                                    details={"tensor": name, "dimension": s_idx, "observed": obs_dim, "expected": exp_dim},
                                )
                            )

            # Task-specific validation rules
            if task_type == TaskType.CLASSIFICATION:
                validate_classification_output(summary, arr, parsed_contract, tensor_contract, pol, findings)
            elif task_type == TaskType.OBJECT_DETECTION:
                validate_detection_output(summary, arr, parsed_contract, tensor_contract, pol, findings)
            elif task_type == TaskType.SEGMENTATION:
                validate_segmentation_output(summary, arr, parsed_contract, tensor_contract, pol, findings)
            elif task_type == TaskType.EMBEDDING:
                validate_embedding_output(summary, arr, parsed_contract, tensor_contract, pol, findings)

        elif isinstance(raw_output, (RawExecutionOutput, InferenceExecution)):
            # Tensors were summarized in Phase 10.5 RawOutputTensor
            rot_list = raw_output.raw_output.outputs if isinstance(raw_output, InferenceExecution) else raw_output.outputs
            if idx < len(rot_list):
                rot = rot_list[idx]
                s = ValidatedTensorSummary(
                    name=rot.name,
                    index=rot.index,
                    dtype=rot.dtype,
                    shape=list(rot.shape),
                    rank=len(rot.shape),
                    element_count=rot.element_count,
                    byte_size=rot.byte_size,
                    is_finite=rot.is_finite,
                    has_nan=not rot.is_finite,
                    has_pos_inf=False,
                    has_neg_inf=False,
                    min_value=None,
                    max_value=None,
                    domain_valid=True,
                    c_contiguous_byte_hash=rot.c_contiguous_byte_hash,
                )
                summaries.append(s)
                total_elements += s.element_count
                if not s.is_finite:
                    overall_finite = False
                    any_nan = True

    # Total elements limit check
    if total_elements > pol.max_tensor_elements:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.OUTPUT_RESOURCE_LIMIT_EXCEEDED.value,
                message=f"Total output elements {total_elements} exceeds limit {pol.max_tensor_elements}.",
                details={"total_elements": total_elements, "limit": pol.max_tensor_elements},
            )
        )

    # Numerical Sanity Status classification
    if not overall_finite:
        numerical_status = NumericalSanityStatus.NONFINITE
        if any_nan:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_NAN.value,
                    message="Output tensors contain NaN (Not a Number) values.",
                    details={"has_nan": True},
                )
            )
        if any_pos_inf or any_neg_inf:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.OUTPUT_INFINITY.value,
                    message="Output tensors contain Infinity (+Inf or -Inf) values.",
                    details={"has_pos_inf": any_pos_inf, "has_neg_inf": any_neg_inf},
                )
            )
    elif not all_domains_valid:
        numerical_status = NumericalSanityStatus.DOMAIN_INVALID
    else:
        numerical_status = NumericalSanityStatus.DOMAIN_VALID if parsed_contract else NumericalSanityStatus.FINITE

    # Structural Status classification
    has_structural_mismatch = any(
        f.code in (
            InferenceFindingCode.OUTPUT_COUNT_MISMATCH.value,
            InferenceFindingCode.OUTPUT_ORDER_MISMATCH.value,
            InferenceFindingCode.OUTPUT_NAME_MISMATCH.value,
            InferenceFindingCode.OUTPUT_DTYPE_MISMATCH.value,
            InferenceFindingCode.OUTPUT_RANK_MISMATCH.value,
            InferenceFindingCode.OUTPUT_SHAPE_MISMATCH.value,
            InferenceFindingCode.OUTPUT_DIMENSION_INVALID.value,
            InferenceFindingCode.OUTPUT_SCHEMA_INVALID.value,
            InferenceFindingCode.OUTPUT_RESOURCE_LIMIT_EXCEEDED.value,
        )
        for f in findings
    )

    if contract_status == OutputStructuralStatus.UNAVAILABLE:
        structural_status = OutputStructuralStatus.UNAVAILABLE
    elif contract_status == OutputStructuralStatus.UNVERIFIABLE:
        structural_status = OutputStructuralStatus.UNVERIFIABLE
    elif has_structural_mismatch:
        structural_status = OutputStructuralStatus.MISMATCHED
    else:
        structural_status = OutputStructuralStatus.VALID

    # Final Overall Integrity Status
    if contract_status == OutputStructuralStatus.UNAVAILABLE:
        integrity_status = InferenceIntegrityStatus.UNAVAILABLE
    elif contract_status == OutputStructuralStatus.UNVERIFIABLE:
        integrity_status = InferenceIntegrityStatus.UNVERIFIABLE
    elif not overall_finite:
        integrity_status = InferenceIntegrityStatus.INVALID
    elif any(f.code == InferenceFindingCode.OUTPUT_HASH_MISMATCH.value for f in findings):
        integrity_status = InferenceIntegrityStatus.MISMATCHED
    elif has_structural_mismatch:
        integrity_status = InferenceIntegrityStatus.MISMATCHED
    elif any(
        f.code in (
            InferenceFindingCode.OUTPUT_DOMAIN_INVALID.value,
            InferenceFindingCode.OUTPUT_BOX_INVALID.value,
            InferenceFindingCode.OUTPUT_CLASS_ID_INVALID.value,
            InferenceFindingCode.OUTPUT_PROBABILITY_SUM_INVALID.value,
        )
        for f in findings
    ):
        integrity_status = InferenceIntegrityStatus.INVALID
    else:
        integrity_status = InferenceIntegrityStatus.VERIFIED

    # Compute deterministic validated output identity
    validated_output_identity: Optional[str] = None
    if raw_hash:
        validated_output_identity = compute_validated_output_identity(
            raw_output_hash=raw_hash,
            task_type=task_type,
            output_contract_hash=contract_hash,
            validation_status=integrity_status,
            numerical_status=numerical_status,
            output_count=output_count,
            structural_summaries=summaries,
            schema_version="1.0",
        )

    details["total_elements"] = total_elements
    details["output_count"] = output_count
    details["overall_finite"] = overall_finite
    details["task_type"] = task_type.value if hasattr(task_type, "value") else str(task_type)

    return OutputIntegrityAssessment(
        schema_version="1.0",
        task_type=task_type,
        raw_output_hash=raw_hash or ("0" * 64),
        output_contract_hash=contract_hash,
        output_count=output_count,
        output_metadata=summaries,
        numerical_status=numerical_status,
        structural_status=structural_status,
        integrity_status=integrity_status,
        validated_output_identity=validated_output_identity,
        findings=findings,
        details=details,
    )


def verify_validated_output_identity(assessment: OutputIntegrityAssessment) -> bool:
    """Pure cryptographic verification confirming assessment's validated_output_identity matches recomputation."""
    if not assessment.validated_output_identity:
        return False

    recomputed = compute_validated_output_identity(
        raw_output_hash=assessment.raw_output_hash,
        task_type=assessment.task_type,
        output_contract_hash=assessment.output_contract_hash,
        validation_status=assessment.integrity_status,
        numerical_status=assessment.numerical_status,
        output_count=assessment.output_count,
        structural_summaries=assessment.output_metadata,
        schema_version=assessment.schema_version,
    )

    return hmac.compare_digest(assessment.validated_output_identity, recomputed)
