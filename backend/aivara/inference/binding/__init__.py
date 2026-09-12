"""Input / Model Binding subpackage for AIVARA Phase 10 Inference Integrity."""

from aivara.inference.binding.engine import (
    build_canonical_binding_descriptor,
    compute_binding_hash,
    create_input_model_binding,
    validate_sha256_hex_format,
    verify_input_model_binding,
    verify_master_fingerprint_consistency,
)
from aivara.inference.binding.models import (
    BindingVerificationResult,
    InputModelBinding,
    ModelIdentityEnvelope,
)

__all__ = [
    "InputModelBinding",
    "ModelIdentityEnvelope",
    "BindingVerificationResult",
    "create_input_model_binding",
    "verify_input_model_binding",
    "compute_binding_hash",
    "build_canonical_binding_descriptor",
    "verify_master_fingerprint_consistency",
    "validate_sha256_hex_format",
]
