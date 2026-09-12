"""Core deterministic execution and verification engine for Preprocessing & Contract Integrity (Phase 10.4)."""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from pydantic import ValidationError

from aivara.crypto.canonical import canonicalize
from aivara.inference.binding.models import InputModelBinding
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
)
from aivara.inference.exceptions import (
    ContractCompatibilityError,
    InvalidHashFormatError,
    InvalidPreprocessingContractError,
    PreprocessingExecutionError,
    PreprocessingResourceLimitError,
    UnsupportedPreprocessingOpError,
)
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.preprocessing.enums import (
    AspectRatioPolicy,
    ClippingPolicy,
    ColorSpace,
    InterpolationMode,
    PaddingMode,
    PreprocessingOpType,
    RoundingPolicy,
)
from aivara.inference.preprocessing.models import (
    ChannelConvertParams,
    CompatibilityAssessment,
    ContractVerificationResult,
    CropParams,
    DtypeConvertParams,
    InputAssumption,
    NormalizeParams,
    OutputGuarantee,
    PadParams,
    PreprocessingContract,
    PreprocessingOperation,
    ResizeParams,
    TransformedInputIdentity,
    ValueRangeScaleParams,
)

HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_PREPROCESSING_OPERATIONS = 32
MAX_SPATIAL_DIMENSION = 8192
MAX_PREPROCESSING_ELEMENTS = 50_000_000


def validate_operation_parameters(
    op_type: PreprocessingOpType,
    parameters: Dict[str, Any],
) -> Dict[str, Any]:
    """Validate and sanitize operation parameters against domain schemas.

    Raises:
        InvalidPreprocessingContractError: If parameter schema is violated.
        UnsupportedPreprocessingOpError: If op_type is unsupported.
    """
    if not isinstance(parameters, dict):
        raise InvalidPreprocessingContractError(
            f"Operation parameters must be a dictionary, got {type(parameters).__name__}.",
            details={"op_type": op_type.value},
        )

    try:
        if op_type == PreprocessingOpType.RESIZE:
            validated = ResizeParams(**parameters)
            return {
                "aspect_ratio_policy": validated.aspect_ratio_policy.value,
                "interpolation": validated.interpolation.value,
                "target_height": validated.target_height,
                "target_width": validated.target_width,
            }
        elif op_type == PreprocessingOpType.CROP:
            validated = CropParams(**parameters)
            return {
                "height": validated.height,
                "normalized": validated.normalized,
                "width": validated.width,
                "x": validated.x,
                "y": validated.y,
            }
        elif op_type == PreprocessingOpType.PAD:
            validated = PadParams(**parameters)
            return {
                "bottom": validated.bottom,
                "left": validated.left,
                "mode": validated.mode.value,
                "right": validated.right,
                "top": validated.top,
                "value": float(validated.value),
            }
        elif op_type == PreprocessingOpType.CHANNEL_CONVERT:
            validated = ChannelConvertParams(**parameters)
            return {
                "source_space": validated.source_space.value,
                "target_space": validated.target_space.value,
            }
        elif op_type == PreprocessingOpType.DTYPE_CONVERT:
            validated = DtypeConvertParams(**parameters)
            return {
                "clipping_policy": validated.clipping_policy.value,
                "rounding_policy": validated.rounding_policy.value,
                "source_dtype": validated.source_dtype,
                "target_dtype": validated.target_dtype,
            }
        elif op_type == PreprocessingOpType.NORMALIZE:
            validated = NormalizeParams(**parameters)
            res: Dict[str, Any] = {
                "mean": [float(m) for m in validated.mean],
                "std": [float(s) for s in validated.std],
            }
            if validated.scale is not None:
                res["scale"] = float(validated.scale)
            if validated.clip_min is not None:
                res["clip_min"] = float(validated.clip_min)
            if validated.clip_max is not None:
                res["clip_max"] = float(validated.clip_max)
            return res
        elif op_type == PreprocessingOpType.VALUE_RANGE_SCALE:
            validated = ValueRangeScaleParams(**parameters)
            if validated.source_max <= validated.source_min:
                raise InvalidPreprocessingContractError(
                    f"source_max ({validated.source_max}) must be greater than source_min ({validated.source_min}).",
                    details={"source_min": validated.source_min, "source_max": validated.source_max},
                )
            if validated.target_max <= validated.target_min:
                raise InvalidPreprocessingContractError(
                    f"target_max ({validated.target_max}) must be greater than target_min ({validated.target_min}).",
                    details={"target_min": validated.target_min, "target_max": validated.target_max},
                )
            return {
                "clip": validated.clip,
                "source_max": float(validated.source_max),
                "source_min": float(validated.source_min),
                "target_max": float(validated.target_max),
                "target_min": float(validated.target_min),
            }
        elif op_type == PreprocessingOpType.NO_OP:
            return {}
        else:
            raise UnsupportedPreprocessingOpError(
                f"Unsupported preprocessing operation type '{op_type}'.",
                details={"op_type": str(op_type)},
            )
    except ValidationError as err:
        raise InvalidPreprocessingContractError(
            f"Invalid parameters for operation '{op_type.value}': {err}",
            details={"op_type": op_type.value, "errors": err.errors()},
        ) from err
    except ValueError as err:
        raise InvalidPreprocessingContractError(
            f"Validation error for operation '{op_type.value}': {err}",
            details={"op_type": op_type.value, "error": str(err)},
        ) from err


def build_canonical_preprocessing_descriptor(
    contract_version: str,
    name: str,
    input_assumption: Union[InputAssumption, Dict[str, Any]],
    operations: List[Union[PreprocessingOperation, Dict[str, Any]]],
    output_guarantee: Union[OutputGuarantee, Dict[str, Any]],
    schema_version: str = "1.0",
) -> Dict[str, Any]:
    """Construct the deterministic dictionary descriptor for RFC 8785 JCS canonicalization.

    List ordering of operations is preserved.
    Dictionary keys are sorted by JCS.
    """
    # Normalize input assumption
    if isinstance(input_assumption, InputAssumption):
        raw_ia = input_assumption.model_dump(exclude_none=True)
    else:
        raw_ia = {k: v for k, v in input_assumption.items() if v is not None}

    canonical_ia: Dict[str, Any] = {}
    if "expected_channels" in raw_ia:
        canonical_ia["expected_channels"] = int(raw_ia["expected_channels"])
    if "expected_dtype" in raw_ia:
        canonical_ia["expected_dtype"] = str(raw_ia["expected_dtype"])
    if "expected_layout" in raw_ia:
        layout_val = raw_ia["expected_layout"]
        canonical_ia["expected_layout"] = layout_val.value if isinstance(layout_val, InputLayout) else str(layout_val)
    if "expected_rank" in raw_ia:
        canonical_ia["expected_rank"] = int(raw_ia["expected_rank"])
    if "expected_shape" in raw_ia:
        canonical_ia["expected_shape"] = list(raw_ia["expected_shape"])
    if "expected_value_range" in raw_ia:
        canonical_ia["expected_value_range"] = [float(v) for v in raw_ia["expected_value_range"]]

    # Normalize output guarantee
    if isinstance(output_guarantee, OutputGuarantee):
        raw_og = output_guarantee.model_dump(exclude_none=True)
    else:
        raw_og = {k: v for k, v in output_guarantee.items() if v is not None}

    canonical_og: Dict[str, Any] = {}
    if "target_channels" in raw_og:
        canonical_og["target_channels"] = int(raw_og["target_channels"])
    if "target_dtype" in raw_og:
        canonical_og["target_dtype"] = str(raw_og["target_dtype"])
    if "target_layout" in raw_og:
        layout_val = raw_og["target_layout"]
        canonical_og["target_layout"] = layout_val.value if isinstance(layout_val, InputLayout) else str(layout_val)
    if "target_shape" in raw_og:
        canonical_og["target_shape"] = list(raw_og["target_shape"])
    if "target_value_range" in raw_og:
        canonical_og["target_value_range"] = [float(v) for v in raw_og["target_value_range"]]

    # Normalize operations sequence (preserving order)
    canonical_ops: List[Dict[str, Any]] = []
    for op in operations:
        if isinstance(op, PreprocessingOperation):
            op_type_enum = op.op_type
            op_version = op.op_version
            desc = op.description
            params = op.parameters
        else:
            op_type_raw = op["op_type"]
            op_type_enum = PreprocessingOpType(op_type_raw) if isinstance(op_type_raw, str) else op_type_raw
            op_version = op.get("op_version", "1.0")
            desc = op.get("description")
            params = op.get("parameters", {})

        validated_params = validate_operation_parameters(op_type_enum, params)
        op_dict: Dict[str, Any] = {
            "op_type": op_type_enum.value,
            "op_version": str(op_version),
            "parameters": validated_params,
        }
        if desc is not None:
            op_dict["description"] = str(desc)
        canonical_ops.append(op_dict)

    return {
        "contract_version": str(contract_version),
        "input_assumption": canonical_ia,
        "name": str(name),
        "operations": canonical_ops,
        "output_guarantee": canonical_og,
        "schema_version": str(schema_version),
    }


def compute_preprocessing_contract_hash(descriptor: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash over RFC 8785 canonical JSON bytes."""
    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def create_preprocessing_contract(
    name: str,
    operations: Optional[List[PreprocessingOperation]] = None,
    input_assumption: Optional[InputAssumption] = None,
    output_guarantee: Optional[OutputGuarantee] = None,
    contract_version: str = "1.0",
    schema_version: str = "1.0",
    details: Optional[Dict[str, Any]] = None,
) -> PreprocessingContract:
    """Construct an immutable, validated PreprocessingContract with deterministic hash."""
    if not name or not isinstance(name, str) or len(name) > 255:
        raise InvalidPreprocessingContractError(
            "Contract name must be a non-empty string with maximum 255 characters.",
            details={"name": name},
        )

    ops = operations or []
    if len(ops) > MAX_PREPROCESSING_OPERATIONS:
        raise PreprocessingResourceLimitError(
            f"Operation count ({len(ops)}) exceeds maximum allowed ({MAX_PREPROCESSING_OPERATIONS}).",
            details={"count": len(ops), "max": MAX_PREPROCESSING_OPERATIONS},
        )

    ia = input_assumption or InputAssumption()
    og = output_guarantee or OutputGuarantee()

    # Build canonical descriptor
    descriptor = build_canonical_preprocessing_descriptor(
        contract_version=contract_version,
        name=name,
        input_assumption=ia,
        operations=ops,
        output_guarantee=og,
        schema_version=schema_version,
    )

    contract_hash = compute_preprocessing_contract_hash(descriptor)

    # Convert sanitized operations back to list of PreprocessingOperation
    sanitized_ops: List[PreprocessingOperation] = []
    for raw_op in descriptor["operations"]:
        sanitized_ops.append(
            PreprocessingOperation(
                op_type=PreprocessingOpType(raw_op["op_type"]),
                op_version=raw_op["op_version"],
                parameters=raw_op["parameters"],
                description=raw_op.get("description"),
            )
        )

    return PreprocessingContract(
        schema_version=schema_version,
        contract_version=contract_version,
        name=name,
        input_assumption=ia,
        operations=sanitized_ops,
        output_guarantee=og,
        contract_hash=contract_hash,
        findings=[],
        details=details or {},
    )


def verify_preprocessing_contract(contract: PreprocessingContract) -> ContractVerificationResult:
    """Pure, side-effect-free recomputation and cryptographic verification of a PreprocessingContract."""
    findings: List[InputFinding] = []

    if not HEX64_PATTERN.match(contract.contract_hash):
        findings.append(
            InputFinding(
                code=InferenceFindingCode.PREPROCESSING_HASH_MISMATCH.value,
                message="Recorded contract_hash is not a valid 64-character lowercase hexadecimal SHA-256 digest.",
                details={"contract_hash": contract.contract_hash},
            )
        )
        return ContractVerificationResult(
            is_valid=False,
            status=InferenceIntegrityStatus.INVALID,
            computed_hash="",
            expected_hash=contract.contract_hash,
            findings=findings,
            details={"error": "Malformed contract hash"},
        )

    if contract.schema_version != "1.0":
        findings.append(
            InputFinding(
                code=InferenceFindingCode.PREPROCESSING_CONTRACT_INVALID.value,
                message=f"Unsupported schema_version '{contract.schema_version}'. Expected '1.0'.",
                details={"schema_version": contract.schema_version},
            )
        )
        return ContractVerificationResult(
            is_valid=False,
            status=InferenceIntegrityStatus.INVALID,
            computed_hash="",
            expected_hash=contract.contract_hash,
            findings=findings,
            details={"error": "Unsupported schema version"},
        )

    try:
        descriptor = build_canonical_preprocessing_descriptor(
            contract_version=contract.contract_version,
            name=contract.name,
            input_assumption=contract.input_assumption,
            operations=contract.operations,
            output_guarantee=contract.output_guarantee,
            schema_version=contract.schema_version,
        )
        computed_hash = compute_preprocessing_contract_hash(descriptor)
    except (InvalidPreprocessingContractError, UnsupportedPreprocessingOpError, PreprocessingResourceLimitError) as err:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.PREPROCESSING_CONTRACT_INVALID.value,
                message=f"Contract validation failure: {err}",
                details={"error": str(err)},
            )
        )
        return ContractVerificationResult(
            is_valid=False,
            status=InferenceIntegrityStatus.INVALID,
            computed_hash="",
            expected_hash=contract.contract_hash,
            findings=findings,
            details={"error": str(err)},
        )

    is_match = hmac.compare_digest(computed_hash, contract.contract_hash)
    if not is_match:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.PREPROCESSING_HASH_MISMATCH.value,
                message=f"Cryptographic hash mismatch. Computed '{computed_hash}', recorded '{contract.contract_hash}'.",
                details={"computed_hash": computed_hash, "expected_hash": contract.contract_hash},
            )
        )
        return ContractVerificationResult(
            is_valid=False,
            status=InferenceIntegrityStatus.MISMATCHED,
            computed_hash=computed_hash,
            expected_hash=contract.contract_hash,
            findings=findings,
            details={"mismatch": True},
        )

    return ContractVerificationResult(
        is_valid=True,
        status=InferenceIntegrityStatus.VERIFIED,
        computed_hash=computed_hash,
        expected_hash=contract.contract_hash,
        findings=findings,
        details={"algorithm": "SHA-256", "canonicalization": "RFC 8785 JCS"},
    )


def check_contract_compatibility(
    contract: PreprocessingContract,
    input_identity: InputIdentity,
    model_contract: Optional[Any] = None,
) -> CompatibilityAssessment:
    """Validate compatibility across InputIdentity, PreprocessingContract, and Model Contract."""
    findings: List[InputFinding] = []
    input_compatible = True
    model_compatible = True

    # 1. Check Input vs Preprocessing Contract Assumptions
    ia = contract.input_assumption
    if ia.expected_layout is not None and input_identity.layout != InputLayout.UNKNOWN:
        if input_identity.layout != ia.expected_layout:
            input_compatible = False
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.PREPROCESSING_LAYOUT_MISMATCH.value,
                    message=f"Input layout '{input_identity.layout.value}' does not match expected layout '{ia.expected_layout.value}'.",
                    details={"actual": input_identity.layout.value, "expected": ia.expected_layout.value},
                )
            )

    if ia.expected_dtype is not None and input_identity.dtype is not None:
        if input_identity.dtype.lower() != ia.expected_dtype.lower():
            input_compatible = False
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.PREPROCESSING_DTYPE_MISMATCH.value,
                    message=f"Input dtype '{input_identity.dtype}' does not match expected dtype '{ia.expected_dtype}'.",
                    details={"actual": input_identity.dtype, "expected": ia.expected_dtype},
                )
            )

    if ia.expected_channels is not None and input_identity.channels is not None:
        if input_identity.channels != ia.expected_channels:
            input_compatible = False
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.PREPROCESSING_CHANNEL_MISMATCH.value,
                    message=f"Input channels '{input_identity.channels}' does not match expected channels '{ia.expected_channels}'.",
                    details={"actual": input_identity.channels, "expected": ia.expected_channels},
                )
            )

    if ia.expected_rank is not None and input_identity.rank is not None:
        if input_identity.rank != ia.expected_rank:
            input_compatible = False
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.PREPROCESSING_DIMENSION_INVALID.value,
                    message=f"Input rank '{input_identity.rank}' does not match expected rank '{ia.expected_rank}'.",
                    details={"actual": input_identity.rank, "expected": ia.expected_rank},
                )
            )

    # 2. Check Preprocessing Output Guarantees vs Model Contract
    og = contract.output_guarantee
    if model_contract is None:
        model_compatible = False
        findings.append(
            InputFinding(
                code=InferenceFindingCode.PREPROCESSING_MODEL_CONTRACT_UNAVAILABLE.value,
                message="Model contract metadata is unavailable for compatibility verification.",
                details={"model_contract": None},
            )
        )
        return CompatibilityAssessment(
            is_compatible=False,
            status=InferenceIntegrityStatus.UNAVAILABLE,
            input_compatible=input_compatible,
            model_compatible=False,
            findings=findings,
            details={"reason": "Model contract unavailable"},
        )

    # Inspect model contract structure (supports ValidatedInputContract, dict, or Phase 7 schemas)
    model_status = getattr(model_contract, "status", None)
    if model_status in ("unverifiable", InferenceIntegrityStatus.UNVERIFIABLE):
        model_compatible = False
        findings.append(
            InputFinding(
                code=InferenceFindingCode.PREPROCESSING_MODEL_CONTRACT_UNVERIFIABLE.value,
                message="Model contract is unverifiable; compatibility cannot be established statically.",
                details={"status": "unverifiable"},
            )
        )
        return CompatibilityAssessment(
            is_compatible=False,
            status=InferenceIntegrityStatus.UNVERIFIABLE,
            input_compatible=input_compatible,
            model_compatible=False,
            findings=findings,
            details={"reason": "Model contract unverifiable"},
        )

    # Extract target model inputs
    model_inputs = getattr(model_contract, "inputs", None)
    if isinstance(model_inputs, list) and len(model_inputs) > 0:
        primary_input = model_inputs[0]
        m_layout = getattr(primary_input, "layout", None)
        m_dtype = getattr(primary_input, "dtype", None)
        m_channels = getattr(primary_input, "channel_count", None)

        if m_layout and og.target_layout:
            og_layout_str = og.target_layout.value if isinstance(og.target_layout, InputLayout) else str(og.target_layout)
            if str(m_layout).upper() != og_layout_str.upper():
                model_compatible = False
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.PREPROCESSING_LAYOUT_MISMATCH.value,
                        message=f"Preprocessing target layout '{og_layout_str}' contradicts model input layout '{m_layout}'.",
                        details={"preprocessing_layout": og_layout_str, "model_layout": str(m_layout)},
                    )
                )

        if m_dtype and og.target_dtype:
            # Map common dtype names (F32 -> float32)
            d_map = {"f32": "float32", "f64": "float64", "i32": "int32", "i64": "int64", "u8": "uint8"}
            norm_m_dtype = d_map.get(str(m_dtype).lower(), str(m_dtype).lower())
            norm_og_dtype = d_map.get(str(og.target_dtype).lower(), str(og.target_dtype).lower())
            if norm_m_dtype != norm_og_dtype:
                model_compatible = False
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.PREPROCESSING_DTYPE_MISMATCH.value,
                        message=f"Preprocessing target dtype '{og.target_dtype}' contradicts model input dtype '{m_dtype}'.",
                        details={"preprocessing_dtype": og.target_dtype, "model_dtype": str(m_dtype)},
                    )
                )

        if m_channels and og.target_channels:
            if int(m_channels) != int(og.target_channels):
                model_compatible = False
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.PREPROCESSING_CHANNEL_MISMATCH.value,
                        message=f"Preprocessing target channels '{og.target_channels}' contradicts model input channels '{m_channels}'.",
                        details={"preprocessing_channels": og.target_channels, "model_channels": m_channels},
                    )
                )

    overall_compatible = input_compatible and model_compatible
    overall_status = InferenceIntegrityStatus.VERIFIED if overall_compatible else InferenceIntegrityStatus.MISMATCHED

    return CompatibilityAssessment(
        is_compatible=overall_compatible,
        status=overall_status,
        input_compatible=input_compatible,
        model_compatible=model_compatible,
        findings=findings,
        details={"input_checks_passed": input_compatible, "model_checks_passed": model_compatible},
    )


def _resize_nearest_2d(arr: np.ndarray, target_h: int, target_w: int) -> np.ndarray:
    """Pure deterministic 2D nearest-neighbor spatial resize."""
    src_h, src_w = arr.shape[:2]
    y_indices = (np.floor(np.arange(target_h) * (src_h / target_h))).astype(int)
    x_indices = (np.floor(np.arange(target_w) * (src_w / target_w))).astype(int)
    y_indices = np.clip(y_indices, 0, src_h - 1)
    x_indices = np.clip(x_indices, 0, src_w - 1)
    return arr[y_indices[:, None], x_indices]


def _resize_bilinear_2d(arr: np.ndarray, target_h: int, target_w: int) -> np.ndarray:
    """Pure deterministic 2D bilinear interpolation spatial resize."""
    src_h, src_w = arr.shape[:2]
    if src_h == target_h and src_w == target_w:
        return arr

    orig_dtype = arr.dtype
    work_arr = arr.astype(np.float64)

    # Continuous coordinate mapping
    y = (np.arange(target_h) + 0.5) * (src_h / target_h) - 0.5
    x = (np.arange(target_w) + 0.5) * (src_w / target_w) - 0.5

    y = np.clip(y, 0, src_h - 1)
    x = np.clip(x, 0, src_w - 1)

    y0 = np.floor(y).astype(int)
    y1 = np.clip(y0 + 1, 0, src_h - 1)
    x0 = np.floor(x).astype(int)
    x1 = np.clip(x0 + 1, 0, src_w - 1)

    wy1 = y - y0
    wy0 = 1.0 - wy1
    wx1 = x - x0
    wx0 = 1.0 - wx1

    # Reshape weights for broadcasting
    wy0 = wy0[:, None]
    wy1 = wy1[:, None]
    wx0 = wx0[None, :]
    wx1 = wx1[None, :]

    if work_arr.ndim == 2:
        top = wx0 * work_arr[y0[:, None], x0] + wx1 * work_arr[y0[:, None], x1]
        bot = wx0 * work_arr[y1[:, None], x0] + wx1 * work_arr[y1[:, None], x1]
        out = wy0 * top + wy1 * bot
    elif work_arr.ndim == 3:
        top = wx0[:, :, None] * work_arr[y0[:, None], x0] + wx1[:, :, None] * work_arr[y0[:, None], x1]
        bot = wx0[:, :, None] * work_arr[y1[:, None], x0] + wx1[:, :, None] * work_arr[y1[:, None], x1]
        out = wy0[:, :, None] * top + wy1[:, :, None] * bot
    else:
        raise PreprocessingExecutionError(f"Unsupported array dimensions for bilinear resize: {work_arr.ndim}")

    if np.issubdtype(orig_dtype, np.integer):
        return np.round(out).astype(orig_dtype)
    return out.astype(orig_dtype)


def execute_preprocessing_pipeline(
    contract: PreprocessingContract,
    input_array: np.ndarray,
    input_identity: InputIdentity,
    binding: InputModelBinding,
) -> Tuple[np.ndarray, TransformedInputIdentity]:
    """Execute deterministic preprocessing sequence on input array without in-place mutation.

    Returns:
        Tuple of (preprocessed_array, TransformedInputIdentity).

    Raises:
        PreprocessingExecutionError: On execution failure.
        PreprocessingResourceLimitError: If output exceeds resource limits.
    """
    if not isinstance(input_array, np.ndarray):
        raise PreprocessingExecutionError(
            f"Expected numpy ndarray input, got '{type(input_array).__name__}'.",
            details={"type": type(input_array).__name__},
        )

    # Defensive copy to guarantee caller immutability
    arr = np.copy(input_array)

    findings: List[InputFinding] = []

    for idx, op in enumerate(contract.operations):
        op_type = op.op_type
        params = op.parameters

        if op_type == PreprocessingOpType.NO_OP:
            continue

        elif op_type == PreprocessingOpType.RESIZE:
            target_w = int(params["target_width"])
            target_h = int(params["target_height"])
            interp = InterpolationMode(params.get("interpolation", InterpolationMode.BILINEAR))

            if arr.ndim == 2:
                if interp == InterpolationMode.NEAREST:
                    arr = _resize_nearest_2d(arr, target_h, target_w)
                else:
                    arr = _resize_bilinear_2d(arr, target_h, target_w)
            elif arr.ndim == 3:
                # Assuming HWC
                if interp == InterpolationMode.NEAREST:
                    arr = _resize_nearest_2d(arr, target_h, target_w)
                else:
                    arr = _resize_bilinear_2d(arr, target_h, target_w)
            elif arr.ndim == 4:
                # Batched NHWC or NCHW
                # Apply per batch item
                resized_list = []
                for b in range(arr.shape[0]):
                    if interp == InterpolationMode.NEAREST:
                        resized_list.append(_resize_nearest_2d(arr[b], target_h, target_w))
                    else:
                        resized_list.append(_resize_bilinear_2d(arr[b], target_h, target_w))
                arr = np.stack(resized_list, axis=0)

        elif op_type == PreprocessingOpType.CROP:
            x = int(params["x"])
            y = int(params["y"])
            w = int(params["width"])
            h = int(params["height"])

            src_h, src_w = arr.shape[:2] if arr.ndim in (2, 3) else arr.shape[1:3]
            if x + w > src_w or y + h > src_h or x < 0 or y < 0:
                raise PreprocessingExecutionError(
                    f"Crop window ({x}, {y}, {w}, {h}) exceeds spatial dimensions ({src_w}, {src_h}).",
                    details={"crop": [x, y, w, h], "image_shape": [src_w, src_h]},
                )

            if arr.ndim == 2:
                arr = arr[y : y + h, x : x + w]
            elif arr.ndim == 3:
                arr = arr[y : y + h, x : x + w, :]
            elif arr.ndim == 4:
                arr = arr[:, y : y + h, x : x + w, :]

        elif op_type == PreprocessingOpType.PAD:
            top = int(params["top"])
            bottom = int(params["bottom"])
            left = int(params["left"])
            right = int(params["right"])
            mode_str = params.get("mode", "CONSTANT")
            fill_val = float(params.get("value", 0.0))

            np_mode_map = {
                "CONSTANT": "constant",
                "REFLECT": "reflect",
                "SYMMETRIC": "symmetric",
                "REPLICATE": "edge",
            }
            np_mode = np_mode_map.get(mode_str, "constant")

            if arr.ndim == 2:
                pad_width = ((top, bottom), (left, right))
                kwargs = {"constant_values": fill_val} if np_mode == "constant" else {}
                arr = np.pad(arr, pad_width, mode=np_mode, **kwargs)
            elif arr.ndim == 3:
                pad_width = ((top, bottom), (left, right), (0, 0))
                kwargs = {"constant_values": fill_val} if np_mode == "constant" else {}
                arr = np.pad(arr, pad_width, mode=np_mode, **kwargs)
            elif arr.ndim == 4:
                pad_width = ((0, 0), (top, bottom), (left, right), (0, 0))
                kwargs = {"constant_values": fill_val} if np_mode == "constant" else {}
                arr = np.pad(arr, pad_width, mode=np_mode, **kwargs)

        elif op_type == PreprocessingOpType.CHANNEL_CONVERT:
            src_sp = ColorSpace(params["source_space"])
            tgt_sp = ColorSpace(params["target_space"])

            if src_sp == ColorSpace.RGB and tgt_sp == ColorSpace.BGR:
                arr = arr[..., [2, 1, 0]]
            elif src_sp == ColorSpace.BGR and tgt_sp == ColorSpace.RGB:
                arr = arr[..., [2, 1, 0]]
            elif src_sp == ColorSpace.RGB and tgt_sp == ColorSpace.GRAYSCALE:
                # ITU-R BT.601 standard luminance weights
                arr = 0.299 * arr[..., 0] + 0.587 * arr[..., 1] + 0.114 * arr[..., 2]
                if arr.ndim == 2:
                    arr = arr[..., None]
            elif src_sp == ColorSpace.RGBA and tgt_sp == ColorSpace.RGB:
                arr = arr[..., :3]

        elif op_type == PreprocessingOpType.DTYPE_CONVERT:
            tgt_dtype_str = str(params["target_dtype"]).lower()
            try:
                tgt_np_dtype = np.dtype(tgt_dtype_str)
            except TypeError as err:
                raise PreprocessingExecutionError(f"Unknown destination dtype '{tgt_dtype_str}': {err}") from err

            clip_policy = ClippingPolicy(params.get("clipping_policy", ClippingPolicy.CLIP_TO_RANGE))
            if clip_policy == ClippingPolicy.CLIP_TO_RANGE and np.issubdtype(tgt_np_dtype, np.integer):
                info = np.iinfo(tgt_np_dtype)
                arr = np.clip(arr, info.min, info.max)

            arr = arr.astype(tgt_np_dtype)

        elif op_type == PreprocessingOpType.NORMALIZE:
            mean = np.array(params["mean"], dtype=np.float64)
            std = np.array(params["std"], dtype=np.float64)
            scale = params.get("scale")
            clip_min = params.get("clip_min")
            clip_max = params.get("clip_max")

            if not np.issubdtype(arr.dtype, np.floating):
                arr = arr.astype(np.float64)

            if scale is not None:
                arr = arr * float(scale)

            # Broadcast normalization across channel axis
            if arr.ndim == 3 and arr.shape[2] == len(mean):
                arr = (arr - mean[None, None, :]) / std[None, None, :]
            elif arr.ndim == 4 and arr.shape[3] == len(mean):
                arr = (arr - mean[None, None, None, :]) / std[None, None, None, :]
            elif arr.ndim == 4 and arr.shape[1] == len(mean):
                arr = (arr - mean[None, :, None, None]) / std[None, :, None, None]
            else:
                arr = (arr - mean) / std

            if clip_min is not None or clip_max is not None:
                c_min = float(clip_min) if clip_min is not None else -np.inf
                c_max = float(clip_max) if clip_max is not None else np.inf
                arr = np.clip(arr, c_min, c_max)

        elif op_type == PreprocessingOpType.VALUE_RANGE_SCALE:
            s_min = float(params["source_min"])
            s_max = float(params["source_max"])
            t_min = float(params["target_min"])
            t_max = float(params["target_max"])
            do_clip = bool(params.get("clip", True))

            if not np.issubdtype(arr.dtype, np.floating):
                arr = arr.astype(np.float64)

            arr = t_min + ((arr - s_min) / (s_max - s_min)) * (t_max - t_min)
            if do_clip:
                arr = np.clip(arr, t_min, t_max)

    # 3. Post-execution checks
    total_elements = int(np.prod(arr.shape))
    if total_elements > MAX_PREPROCESSING_ELEMENTS:
        raise PreprocessingResourceLimitError(
            f"Preprocessed tensor element count ({total_elements}) exceeds limit ({MAX_PREPROCESSING_ELEMENTS}).",
            details={"element_count": total_elements, "max": MAX_PREPROCESSING_ELEMENTS},
        )

    is_finite = True
    if np.issubdtype(arr.dtype, np.floating):
        is_finite = bool(np.isfinite(arr).all())
        if not is_finite:
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.PREPROCESSING_PARAMETER_NONFINITE.value,
                    message="Preprocessed array contains non-finite values (NaN/Inf).",
                    details={"shape": list(arr.shape)},
                )
            )

    # 4. Deterministic transformed bytes and SHA-256
    c_bytes = np.ascontiguousarray(arr).tobytes()
    transformed_canonical_hash = hashlib.sha256(c_bytes).hexdigest()

    layout = contract.output_guarantee.target_layout or input_identity.layout

    identity = TransformedInputIdentity(
        schema_version="1.0",
        input_id=input_identity.input_id,
        binding_hash=binding.binding_hash,
        contract_hash=contract.contract_hash,
        transformed_canonical_hash=transformed_canonical_hash,
        dtype=str(arr.dtype),
        shape=list(arr.shape),
        layout=layout,
        byte_size=len(c_bytes),
        element_count=total_elements,
        finite=is_finite,
        transformation_status=InferenceIntegrityStatus.VERIFIED if is_finite else InferenceIntegrityStatus.INVALID,
        findings=findings,
        details={"op_count": len(contract.operations)},
    )

    return arr, identity
