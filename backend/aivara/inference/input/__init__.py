"""Input boundary subpackage for AIVARA Phase 10 Inference Integrity."""

from aivara.inference.input.boundary import (
    SafeInferenceInputBoundary,
    validate_inference_input,
)
from aivara.inference.input.image import (
    compute_canonical_pixel_sha256,
    compute_raw_file_sha256,
    validate_image_file_input,
)
from aivara.inference.input.models import (
    ImageFileMetadata,
    InputFinding,
    InputIdentity,
    StructuredInputMetadata,
    TensorMetadata,
)
from aivara.inference.input.path_security import validate_safe_input_path
from aivara.inference.input.structured import validate_structured_input
from aivara.inference.input.tensor import (
    classify_value_range,
    resolve_tensor_layout,
    validate_tensor_input,
)

__all__ = [
    "SafeInferenceInputBoundary",
    "validate_inference_input",
    "validate_tensor_input",
    "validate_image_file_input",
    "validate_structured_input",
    "validate_safe_input_path",
    "resolve_tensor_layout",
    "classify_value_range",
    "compute_raw_file_sha256",
    "compute_canonical_pixel_sha256",
    "InputIdentity",
    "TensorMetadata",
    "ImageFileMetadata",
    "StructuredInputMetadata",
    "InputFinding",
]
