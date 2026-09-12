"""Safe Inference Input Boundary: Unified validation, sandboxing, and identity engine."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from aivara.inference.config import DEFAULT_INFERENCE_LIMITS, InferenceInputLimits
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
    ValueRangeKind,
)
from aivara.inference.exceptions import (
    AmbiguousLayoutError,
    ImageDecodingError,
    InferenceError,
    InferenceInputError,
    InferencePathSecurityError,
    InputContractMismatchError,
    InputFileNotFoundError,
    InputFileUnreadableError,
    MalformedInputError,
    NonFiniteValueError,
    ResourceLimitExceededError,
    UnsupportedDtypeError,
    UnsupportedImageFormatError,
    UnsupportedInputTypeError,
    ValueRangeMismatchError,
)
from aivara.inference.input.image import validate_image_file_input
from aivara.inference.input.models import (
    ImageFileMetadata,
    InputFinding,
    InputIdentity,
    StructuredInputMetadata,
    TensorMetadata,
)
from aivara.inference.input.structured import validate_structured_input
from aivara.inference.input.tensor import validate_tensor_input

logger = logging.getLogger(__name__)


def validate_inference_input(
    data: Any,
    kind: Optional[Union[str, InputKind]] = None,
    declared_layout: Optional[Union[str, InputLayout]] = None,
    declared_range: Optional[Union[str, ValueRangeKind]] = None,
    root_dir: Optional[Union[str, Path]] = None,
    limits: Optional[InferenceInputLimits] = None,
    raise_on_error: bool = True,
) -> InputIdentity:
    """Validate an inference input against all safety, structural, and identity constraints.

    Args:
        data: The input payload (Path/str for image, ndarray for tensor, dict/list for structured).
        kind: Optional explicit input kind. If omitted, kind is automatically determined.
        declared_layout: Optional expected tensor layout.
        declared_range: Optional expected value range.
        root_dir: Optional sandboxing root directory for file inputs.
        limits: Configured resource constraints.
        raise_on_error: If True, raises typed exceptions on validation failure.
                        If False, returns InputIdentity with failure status and findings.

    Returns:
        Deterministic InputIdentity envelope.
    """
    active_limits = limits or DEFAULT_INFERENCE_LIMITS
    findings: List[InputFinding] = []

    # 1. Handle Missing Input
    if data is None:
        finding = InputFinding(
            code=InferenceFindingCode.INPUT_FILE_NOT_FOUND.value,
            message="Inference input data is None.",
        )
        if raise_on_error:
            raise MalformedInputError("Inference input data is None.")
        return InputIdentity(
            input_id="",
            input_kind=InputKind.TENSOR,
            canonical_hash="",
            validation_status=InferenceIntegrityStatus.MISSING,
            findings=[finding],
        )

    # 2. Determine / Validate Input Kind
    resolved_kind: InputKind
    if kind is not None:
        if isinstance(kind, str):
            try:
                resolved_kind = InputKind(kind)
            except ValueError as err:
                if raise_on_error:
                    raise UnsupportedInputTypeError(f"Unknown input kind '{kind}'.") from err
                return InputIdentity(
                    input_id="",
                    input_kind=InputKind.TENSOR,
                    canonical_hash="",
                    validation_status=InferenceIntegrityStatus.INVALID,
                    findings=[InputFinding(code=InferenceFindingCode.INPUT_UNSUPPORTED_DTYPE.value, message=str(err))],
                )
        else:
            resolved_kind = kind
    else:
        # Automatic Kind Inference
        if isinstance(data, (str, Path)):
            resolved_kind = InputKind.IMAGE_FILE
        elif isinstance(data, np.ndarray):
            if len(data.shape) >= 2 and data.shape[0] > 1:
                resolved_kind = InputKind.BATCHED_TENSOR
            else:
                resolved_kind = InputKind.TENSOR
        elif isinstance(data, (dict, list)):
            # Distinguish list of numbers (tensor) vs structured dict/list
            if isinstance(data, list) and data and all(isinstance(x, (int, float, bool)) for x in data):
                resolved_kind = InputKind.TENSOR
            else:
                resolved_kind = InputKind.STRUCTURED
        else:
            if raise_on_error:
                raise UnsupportedInputTypeError(
                    f"Unsupported inference input data type '{type(data).__name__}'."
                )
            return InputIdentity(
                input_id="",
                input_kind=InputKind.TENSOR,
                canonical_hash="",
                validation_status=InferenceIntegrityStatus.INVALID,
                findings=[InputFinding(
                    code=InferenceFindingCode.INPUT_UNSUPPORTED_DTYPE.value,
                    message=f"Unsupported input type '{type(data).__name__}'."
                )],
            )

    # 3. Dispatch to Domain Validators
    try:
        if resolved_kind in (InputKind.TENSOR, InputKind.BATCHED_TENSOR):
            tensor_meta, canonical_hash = validate_tensor_input(
                tensor=data,
                declared_layout=declared_layout,
                declared_range=declared_range,
                limits=active_limits,
            )

            # Check if batched
            actual_kind = InputKind.BATCHED_TENSOR if (tensor_meta.rank >= 2 and tensor_meta.shape[0] > 1 and tensor_meta.layout in (InputLayout.NHWC, InputLayout.NCHW, InputLayout.BATCH_VECTOR_2D)) else InputKind.TENSOR

            batch_size = tensor_meta.shape[0] if actual_kind == InputKind.BATCHED_TENSOR else None
            channels = None
            width = None
            height = None

            if tensor_meta.layout == InputLayout.HWC:
                height, width, channels = tensor_meta.shape[0], tensor_meta.shape[1], tensor_meta.shape[2]
            elif tensor_meta.layout == InputLayout.CHW:
                channels, height, width = tensor_meta.shape[0], tensor_meta.shape[1], tensor_meta.shape[2]
            elif tensor_meta.layout == InputLayout.NHWC:
                height, width, channels = tensor_meta.shape[1], tensor_meta.shape[2], tensor_meta.shape[3]
            elif tensor_meta.layout == InputLayout.NCHW:
                channels, height, width = tensor_meta.shape[1], tensor_meta.shape[2], tensor_meta.shape[3]

            return InputIdentity(
                input_id=canonical_hash,
                input_kind=actual_kind,
                canonical_hash=canonical_hash,
                dtype=tensor_meta.dtype,
                shape=tensor_meta.shape,
                layout=tensor_meta.layout,
                rank=tensor_meta.rank,
                batch_size=batch_size,
                channels=channels,
                width=width,
                height=height,
                value_range=tensor_meta.value_range,
                finite=tensor_meta.finite,
                byte_size=tensor_meta.byte_size,
                element_count=tensor_meta.element_count,
                validation_status=InferenceIntegrityStatus.VERIFIED,
                findings=[],
                details={
                    "min_value": tensor_meta.min_value,
                    "max_value": tensor_meta.max_value,
                    "c_contiguous_byte_hash": tensor_meta.c_contiguous_byte_hash,
                },
            )

        elif resolved_kind == InputKind.IMAGE_FILE:
            img_meta, input_id = validate_image_file_input(
                file_path=data,
                limits=active_limits,
                root_dir=root_dir,
            )

            layout = InputLayout.HWC if img_meta.channels in (3, 4) else InputLayout.GRAYSCALE_2D

            return InputIdentity(
                input_id=input_id,
                input_kind=InputKind.IMAGE_FILE,
                canonical_hash=input_id,
                raw_file_hash=img_meta.raw_file_hash,
                canonical_pixel_hash=img_meta.canonical_pixel_hash,
                dtype="uint8",
                shape=(img_meta.height, img_meta.width, img_meta.channels),
                layout=layout,
                rank=3,
                batch_size=None,
                channels=img_meta.channels,
                width=img_meta.width,
                height=img_meta.height,
                value_range=ValueRangeKind.BYTE_INTEGER,
                finite=True,
                byte_size=img_meta.file_size_bytes,
                element_count=img_meta.width * img_meta.height * img_meta.channels,
                validation_status=InferenceIntegrityStatus.VERIFIED,
                findings=[],
                details={
                    "format": img_meta.format_name,
                    "color_space": img_meta.color_space,
                    "file_path": img_meta.file_path,
                },
            )

        elif resolved_kind == InputKind.STRUCTURED:
            struct_meta, input_id = validate_structured_input(
                data=data,
                limits=active_limits,
            )

            return InputIdentity(
                input_id=input_id,
                input_kind=InputKind.STRUCTURED,
                canonical_hash=struct_meta.canonical_hash,
                layout=InputLayout.STRUCTURED,
                value_range=ValueRangeKind.UNKNOWN,
                finite=True,
                byte_size=struct_meta.canonical_byte_size,
                element_count=struct_meta.element_count,
                validation_status=InferenceIntegrityStatus.VERIFIED,
                findings=[],
                details={
                    "top_level_type": struct_meta.top_level_type,
                },
            )

        else:
            raise UnsupportedInputTypeError(f"Unsupported input kind '{resolved_kind}'.")

    except InputFileNotFoundError as err:
        if raise_on_error:
            raise
        return InputIdentity(
            input_id="",
            input_kind=resolved_kind,
            canonical_hash="",
            validation_status=InferenceIntegrityStatus.MISSING,
            findings=[InputFinding(code=InferenceFindingCode.INPUT_FILE_NOT_FOUND.value, message=str(err), details=err.details)],
        )
    except InputFileUnreadableError as err:
        if raise_on_error:
            raise
        return InputIdentity(
            input_id="",
            input_kind=resolved_kind,
            canonical_hash="",
            validation_status=InferenceIntegrityStatus.UNAVAILABLE,
            findings=[InputFinding(code=InferenceFindingCode.INPUT_FILE_UNREADABLE.value, message=str(err), details=err.details)],
        )
    except (InferencePathSecurityError, ResourceLimitExceededError, MalformedInputError, UnsupportedDtypeError, NonFiniteValueError, UnsupportedImageFormatError, ImageDecodingError) as err:
        if raise_on_error:
            raise
        return InputIdentity(
            input_id="",
            input_kind=resolved_kind,
            canonical_hash="",
            validation_status=InferenceIntegrityStatus.INVALID,
            findings=[InputFinding(code=err.code, message=str(err), details=err.details)],
        )
    except (ValueRangeMismatchError, InputContractMismatchError) as err:
        if raise_on_error:
            raise
        return InputIdentity(
            input_id="",
            input_kind=resolved_kind,
            canonical_hash="",
            validation_status=InferenceIntegrityStatus.MISMATCHED,
            findings=[InputFinding(code=err.code, message=str(err), details=err.details)],
        )
    except AmbiguousLayoutError as err:
        if raise_on_error:
            raise
        return InputIdentity(
            input_id="",
            input_kind=resolved_kind,
            canonical_hash="",
            validation_status=InferenceIntegrityStatus.UNVERIFIABLE,
            findings=[InputFinding(code=err.code, message=str(err), details=err.details)],
        )
    except Exception as err:
        if raise_on_error:
            raise MalformedInputError(f"Unexpected validation failure: {err}") from err
        return InputIdentity(
            input_id="",
            input_kind=resolved_kind,
            canonical_hash="",
            validation_status=InferenceIntegrityStatus.INVALID,
            findings=[InputFinding(code="INTERNAL_VALIDATION_ERROR", message=str(err))],
        )


class SafeInferenceInputBoundary:
    """Encapsulated boundary service for sandboxed inference input validation."""

    def __init__(
        self,
        limits: Optional[InferenceInputLimits] = None,
        root_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        self.limits = limits or DEFAULT_INFERENCE_LIMITS
        self.root_dir = Path(root_dir).resolve() if root_dir is not None else None

    def validate(
        self,
        data: Any,
        kind: Optional[Union[str, InputKind]] = None,
        declared_layout: Optional[Union[str, InputLayout]] = None,
        declared_range: Optional[Union[str, ValueRangeKind]] = None,
        raise_on_error: bool = True,
    ) -> InputIdentity:
        """Validate an inference input within this boundary instance."""
        return validate_inference_input(
            data=data,
            kind=kind,
            declared_layout=declared_layout,
            declared_range=declared_range,
            root_dir=self.root_dir,
            limits=self.limits,
            raise_on_error=raise_on_error,
        )
