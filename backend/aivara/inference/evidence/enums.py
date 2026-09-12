"""Enums for Phase 10.10 Evidence & Provenance Binding subsystem."""

from enum import Enum


class InferenceEvidenceType(str, Enum):
    """Taxonomy of inference evidence types connecting Phase 10 with Phase 5."""

    INFERENCE_INTEGRITY_VERIFICATION = "inference_integrity_verification"
    INPUT_INTEGRITY = "input_integrity"
    MODEL_BINDING_INTEGRITY = "model_binding_integrity"
    PREPROCESSING_INTEGRITY = "preprocessing_integrity"
    EXECUTION_INTEGRITY = "execution_integrity"
    OUTPUT_INTEGRITY = "output_integrity"
    INPUT_OUTPUT_BINDING = "input_output_binding"
    INFERENCE_RECORD_INTEGRITY = "inference_record_integrity"
    REPLAY_CONSISTENCY = "replay_consistency"
    PROVENANCE_INTEGRITY = "provenance_integrity"
    END_TO_END_INFERENCE_INTEGRITY = "end_to_end_inference_integrity"


class InferenceFindingType(str, Enum):
    """Taxonomy of inference findings for assurance observations."""

    INFERENCE_INTEGRITY_VERIFIED = "INFERENCE_INTEGRITY_VERIFIED"
    INPUT_IDENTITY_MISMATCH = "INPUT_IDENTITY_MISMATCH"
    MODEL_IDENTITY_MISMATCH = "MODEL_IDENTITY_MISMATCH"
    PREPROCESSING_IDENTITY_MISMATCH = "PREPROCESSING_IDENTITY_MISMATCH"
    EXECUTION_IDENTITY_MISMATCH = "EXECUTION_IDENTITY_MISMATCH"
    RAW_OUTPUT_MISMATCH = "RAW_OUTPUT_MISMATCH"
    OUTPUT_CONTRACT_MISMATCH = "OUTPUT_CONTRACT_MISMATCH"
    INFERENCE_BINDING_MISMATCH = "INFERENCE_BINDING_MISMATCH"
    INFERENCE_RECORD_TAMPERED = "INFERENCE_RECORD_TAMPERED"
    REPLAY_DIVERGENCE = "REPLAY_DIVERGENCE"
    PROVENANCE_MISMATCH = "PROVENANCE_MISMATCH"
    PROJECT_MISMATCH = "PROJECT_MISMATCH"
    CROSS_COMPONENT_INCONSISTENCY = "CROSS_COMPONENT_INCONSISTENCY"
    INFERENCE_EVIDENCE_TAMPERED = "INFERENCE_EVIDENCE_TAMPERED"


class InferenceEvidenceStatus(str, Enum):
    """Overall cryptographic verification status of inference evidence."""

    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    TAMPERED = "TAMPERED"
    PROJECT_MISMATCH = "PROJECT_MISMATCH"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"
    UNVERIFIABLE = "UNVERIFIABLE"
