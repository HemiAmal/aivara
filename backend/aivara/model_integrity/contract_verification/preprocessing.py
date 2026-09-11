"""Static preprocessing contract extraction and cross-consistency validation (Phase 7.4).

Verifies declared or inferred image/tensor preprocessing parameters against model input
contracts without executing pipelines or generating runtime tensors.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from aivara.model_integrity.contract_verification.normalization import normalize_dtype
from aivara.model_integrity.contract_verification.schemas import (
    ContractFinding,
    ContractFindingCode,
    FindingSeverity,
    PreprocessingDeclaration,
    PreprocessingSource,
    ValidatedInputContract,
)
from aivara.model_integrity.schemas import NormalizedModelMetadata


def _parse_float_list(value: Any) -> Optional[List[float]]:
    """Safely parse a list of floats from a JSON array, list, or comma-separated string."""
    if value is None:
        return None
    if isinstance(value, list):
        try:
            return [float(x) for x in value]
        except (ValueError, TypeError):
            return None
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned.startswith("[") and cleaned.endswith("]"):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, list):
                    return [float(x) for x in parsed]
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        try:
            return [float(x.strip()) for x in cleaned.split(",") if x.strip()]
        except (ValueError, TypeError):
            return None
    return None


def _parse_int_list(value: Any) -> Optional[List[int]]:
    """Safely parse a list of integers from a JSON array, list, or string."""
    if value is None:
        return None
    if isinstance(value, list):
        try:
            return [int(x) for x in value]
        except (ValueError, TypeError):
            return None
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned.startswith("[") and cleaned.endswith("]"):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, list):
                    return [int(x) for x in parsed]
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        try:
            return [int(x.strip()) for x in cleaned.split(",") if x.strip()]
        except (ValueError, TypeError):
            return None
    return None


def extract_preprocessing_from_metadata(
    metadata: NormalizedModelMetadata,
) -> Optional[PreprocessingDeclaration]:
    """Statically extract preprocessing declarations from metadata properties if present."""
    props = metadata.metadata_props
    if not props:
        return None

    # Search for standard preprocessor keys (e.g. HuggingFace preprocessor_config or ONNX metadata)
    mean = _parse_float_list(props.get("image_mean") or props.get("mean") or props.get("normalization_mean"))
    std = _parse_float_list(props.get("image_std") or props.get("std") or props.get("normalization_std"))

    resize = _parse_int_list(props.get("resize_shape") or props.get("size") or props.get("input_size"))
    crop = _parse_int_list(props.get("crop_size"))

    channel_order = props.get("channel_order") or props.get("color_space")
    channels_str = props.get("channels") or props.get("channel_count")
    channels = int(channels_str) if channels_str and channels_str.isdigit() else (len(mean) if mean else None)

    scaling_str = props.get("rescale_factor") or props.get("scaling_factor")
    scaling = float(scaling_str) if scaling_str else None

    interpolation = props.get("interpolation")
    color_conv = props.get("color_conversion")
    target_layout = props.get("target_layout") or props.get("layout")
    target_dtype = props.get("target_dtype") or props.get("dtype")

    # If any property was found, construct declaration
    if any(
        x is not None
        for x in (
            mean,
            std,
            resize,
            crop,
            channel_order,
            channels,
            scaling,
            interpolation,
            color_conv,
            target_layout,
            target_dtype,
        )
    ):
        return PreprocessingDeclaration(
            source=PreprocessingSource.INFERRED_FROM_STATIC_STRUCTURE,
            resize_shape=resize,
            crop_size=crop,
            padding=None,
            interpolation=interpolation,
            color_conversion=color_conv,
            channel_order=channel_order,
            channels=channels,
            normalization_mean=mean,
            normalization_std=std,
            scaling_factor=scaling,
            value_range=None,
            target_dtype=target_dtype,
            target_layout=target_layout,
            quantization_params={},
            image_orientation=None,
        )

    return None


def validate_preprocessing_consistency(
    preprocessing: PreprocessingDeclaration,
    inputs: List[ValidatedInputContract],
) -> List[ContractFinding]:
    """Validate preprocessing parameters for internal consistency and input contract compatibility."""
    findings: List[ContractFinding] = []

    # 1. Internal consistency checks
    if preprocessing.normalization_mean is not None and preprocessing.normalization_std is not None:
        if len(preprocessing.normalization_mean) != len(preprocessing.normalization_std):
            findings.append(
                ContractFinding(
                    code=ContractFindingCode.NORMALIZATION_PARAMETER_MISMATCH,
                    message=(
                        f"Normalization mean length ({len(preprocessing.normalization_mean)}) "
                        f"does not match std length ({len(preprocessing.normalization_std)})."
                    ),
                    severity=FindingSeverity.HIGH,
                    target_field="preprocessing.normalization",
                    details={
                        "mean_len": len(preprocessing.normalization_mean),
                        "std_len": len(preprocessing.normalization_std),
                    },
                )
            )

    if preprocessing.value_range is not None:
        if len(preprocessing.value_range) == 2:
            min_v, max_v = preprocessing.value_range[0], preprocessing.value_range[1]
            if min_v >= max_v:
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.VALUE_RANGE_INVALID,
                        message=f"Declared preprocessing value range [{min_v}, {max_v}] has min >= max.",
                        severity=FindingSeverity.HIGH,
                        target_field="preprocessing.value_range",
                        details={"min": min_v, "max": max_v},
                    )
                )

    if not inputs:
        return findings

    # 2. Cross-consistency checks against input contracts
    for inp in inputs:
        # Check channel count
        if preprocessing.channels is not None and inp.channel_count is not None:
            if preprocessing.channels != inp.channel_count:
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.CHANNEL_COUNT_MISMATCH,
                        message=(
                            f"Preprocessing declares {preprocessing.channels} channels but "
                            f"input '{inp.name}' has {inp.channel_count} channels."
                        ),
                        severity=FindingSeverity.HIGH,
                        target_field="preprocessing.channels",
                        details={
                            "input_name": inp.name,
                            "expected_channels": inp.channel_count,
                            "preprocessing_channels": preprocessing.channels,
                        },
                    )
                )

        # Check normalization vector length against input channels
        if preprocessing.normalization_mean is not None and inp.channel_count is not None:
            if len(preprocessing.normalization_mean) != inp.channel_count:
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.NORMALIZATION_LENGTH_MISMATCH,
                        message=(
                            f"Normalization mean vector length ({len(preprocessing.normalization_mean)}) "
                            f"does not match input '{inp.name}' channel count ({inp.channel_count})."
                        ),
                        severity=FindingSeverity.HIGH,
                        target_field="preprocessing.normalization_mean",
                        details={
                            "input_name": inp.name,
                            "input_channels": inp.channel_count,
                            "mean_len": len(preprocessing.normalization_mean),
                        },
                    )
                )

        # Check resize dimensions against fixed input spatial dimensions
        if preprocessing.resize_shape is not None and inp.rank >= 2:
            target_h, target_w = None, None
            if len(preprocessing.resize_shape) == 2:
                target_h, target_w = preprocessing.resize_shape[0], preprocessing.resize_shape[1]
            elif len(preprocessing.resize_shape) == 4 and inp.layout == "NCHW":
                target_h, target_w = preprocessing.resize_shape[2], preprocessing.resize_shape[3]

            if target_h is not None and target_w is not None:
                inp_h, inp_w = None, None
                if inp.layout == "NCHW" and inp.rank == 4:
                    inp_h, inp_w = inp.shape[2], inp.shape[3]
                elif inp.layout == "NHWC" and inp.rank == 4:
                    inp_h, inp_w = inp.shape[1], inp.shape[2]
                elif inp.layout == "CHW" and inp.rank == 3:
                    inp_h, inp_w = inp.shape[1], inp.shape[2]
                elif inp.layout == "HWC" and inp.rank == 3:
                    inp_h, inp_w = inp.shape[0], inp.shape[1]

                if inp_h is not None and inp_w is not None:
                    if (target_h, target_w) != (inp_h, inp_w):
                        findings.append(
                            ContractFinding(
                                code=ContractFindingCode.RESIZE_SHAPE_MISMATCH,
                                message=(
                                    f"Preprocessing resize shape [{target_h}, {target_w}] does not match "
                                    f"input '{inp.name}' spatial dimensions [{inp_h}, {inp_w}]."
                                ),
                                severity=FindingSeverity.HIGH,
                                target_field="preprocessing.resize_shape",
                                details={
                                    "input_name": inp.name,
                                    "input_spatial": [inp_h, inp_w],
                                    "preprocessing_resize": [target_h, target_w],
                                },
                            )
                        )

        # Check layout consistency
        if preprocessing.target_layout is not None and inp.layout is not None:
            if preprocessing.target_layout.upper() != inp.layout.upper():
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.LAYOUT_MISMATCH,
                        message=(
                            f"Preprocessing target layout '{preprocessing.target_layout}' does not match "
                            f"input '{inp.name}' layout '{inp.layout}'."
                        ),
                        severity=FindingSeverity.HIGH,
                        target_field="preprocessing.target_layout",
                        details={
                            "input_name": inp.name,
                            "input_layout": inp.layout,
                            "target_layout": preprocessing.target_layout,
                        },
                    )
                )

        # Check dtype consistency
        if preprocessing.target_dtype is not None:
            canonical_target, _ = normalize_dtype(preprocessing.target_dtype)
            if canonical_target != inp.dtype:
                findings.append(
                    ContractFinding(
                        code=ContractFindingCode.DTYPE_MISMATCH,
                        message=(
                            f"Preprocessing target dtype '{canonical_target}' does not match "
                            f"input '{inp.name}' data type '{inp.dtype}'."
                        ),
                        severity=FindingSeverity.HIGH,
                        target_field="preprocessing.target_dtype",
                        details={
                            "input_name": inp.name,
                            "input_dtype": inp.dtype,
                            "target_dtype": canonical_target,
                        },
                    )
                )

    return findings
