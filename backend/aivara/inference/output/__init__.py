"""AIVARA Phase 10.6 — Output Schema & Numerical Integrity Subsystem."""

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
from aivara.inference.output.engine import (
    build_tensor_summary,
    compute_output_contract_hash,
    compute_validated_output_identity,
    validate_classification_output,
    validate_detection_output,
    validate_embedding_output,
    validate_output_integrity,
    validate_segmentation_output,
    validate_structured_object,
    verify_validated_output_identity,
)

__all__ = [
    "TaskType",
    "OutputKind",
    "NumericalSanityStatus",
    "OutputStructuralStatus",
    "OutputTensorContract",
    "ModelOutputContract",
    "OutputIntegrityPolicy",
    "ValidatedTensorSummary",
    "OutputIntegrityAssessment",
    "build_tensor_summary",
    "compute_output_contract_hash",
    "compute_validated_output_identity",
    "validate_classification_output",
    "validate_detection_output",
    "validate_segmentation_output",
    "validate_embedding_output",
    "validate_structured_object",
    "validate_output_integrity",
    "verify_validated_output_identity",
]
