"""Domain models for Phase 10.10 Evidence & Provenance Binding subsystem."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.evidence.schemas import ProvenanceStatus
from aivara.inference.evidence.enums import (
    InferenceEvidenceStatus,
    InferenceEvidenceType,
    InferenceFindingType,
)


class InferenceEvidence(BaseModel):
    """Immutable, cryptographically verifiable domain model for inference evidence.

    Binds the full Phase 10.1–10.9 inference transaction (input, model, preprocessing,
    execution, output, composite binding, persistent record, and replay consistency)
    into AIVARA's Phase 5 evidence and Phase 4 cryptographic provenance systems.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", max_length=16, description="Schema specification version")
    evidence_version: str = Field("1.0", max_length=16, description="Evidence format version")
    evidence_id: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Deterministic SHA-256 digest of canonical RFC 8785 evidence descriptor",
    )
    project_id: str = Field(..., min_length=1, max_length=255, description="Tenant project identifier")

    # Phase 10.8: Persistent Record Identity
    record_id: str = Field(..., min_length=1, max_length=64, description="Phase 10.8 InferenceRecord identifier")
    record_integrity_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.8 record integrity canonical SHA-256 hash",
    )

    # Phase 10.7: Composite Binding Identity
    inference_binding_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.7 canonical composite inference binding SHA-256 hash",
    )

    # Phase 10.2: Safe Input Boundary
    input_id: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.2 validated input identifier",
    )
    input_canonical_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.2 canonical input tensor SHA-256 hash",
    )
    input_raw_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.2 raw input file SHA-256 hash if applicable",
    )

    # Phase 7 & Phase 10.3: Model & Binding Identity
    model_id: str = Field(..., min_length=1, max_length=255, description="Target AI model identifier")
    model_master_fingerprint: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 7 master model fingerprint (H_master)",
    )
    model_artifact_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 7 raw model artifact SHA-256 hash",
    )
    model_structural_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 7 canonical structural representation SHA-256 hash",
    )
    model_contract_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 7 canonical contract representation SHA-256 hash",
    )

    # Phase 10.4: Preprocessing & Contract Integrity
    preprocessing_contract_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.4 PreprocessingContract canonical SHA-256 hash",
    )
    transformed_input_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.4 transformed input C-contiguous byte SHA-256 hash",
    )

    # Phase 10.5: Inference Execution Integrity
    execution_identity_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.5 InferenceExecution canonical execution descriptor SHA-256 hash",
    )
    raw_output_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.5 raw output tensors canonical SHA-256 hash",
    )

    # Phase 10.6: Output Schema & Numerical Integrity
    validated_output_identity: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.6 ValidatedOutputIdentity canonical SHA-256 hash",
    )
    output_contract_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.6 ModelOutputContract canonical SHA-256 hash if available",
    )

    # Phase 10.9: Replay Verification State
    replay_status: Optional[str] = Field(
        None,
        description="Phase 10.9 replay consistency status (e.g. CONSISTENT_EXACT, CONSISTENT_TOLERANT)",
    )
    replay_mode: Optional[str] = Field(
        None,
        description="Phase 10.9 replay execution mode (e.g. DETERMINISTIC, NUMERICALLY_TOLERANT)",
    )

    # Phase 5: Evidence & Finding Taxonomy
    evidence_type: InferenceEvidenceType = Field(
        InferenceEvidenceType.INFERENCE_INTEGRITY_VERIFICATION,
        description="Assurance evidence taxonomy classification",
    )
    evidence_layer: EvidenceLayer = Field(
        EvidenceLayer.PROOF,
        description="Assurance layer classification (proof vs detection)",
    )
    finding_type: str = Field(
        InferenceFindingType.INFERENCE_INTEGRITY_VERIFIED.value,
        description="Categorical finding type identifier",
    )
    finding_status: str = Field("VERIFIED", description="Observational finding status")
    confidence: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Assurance confidence score (1.0 for proof layer per ADR-028)",
    )
    severity: Severity = Field(Severity.INFO, description="Assurance severity level")
    disposition: Disposition = Field(Disposition.ACCEPT, description="Recommended governance disposition")

    # Phase 4: Cryptographic Provenance Linkage
    provenance_record_id: Optional[str] = Field(
        None,
        description="Linked Phase 4 ProvenanceRecord database identifier",
    )
    provenance_record_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Linked Phase 4 ProvenanceRecord canonical SHA-256 record hash",
    )

    # Persistence / Audit Metadata (Non-Identity)
    created_at: Optional[str] = Field(
        None,
        description="ISO 8601 UTC timestamp string (persistence metadata)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Diagnostic telemetry and non-identity operational metadata",
    )


class InferenceProvenanceBindingPayload(BaseModel):
    """Canonical descriptor payload committed into Phase 4 ProvenanceRecord metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", max_length=16)
    evidence_version: str = Field("1.0", max_length=16)
    project_id: str = Field(..., min_length=1, max_length=255)
    evidence_id: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    record_id: str = Field(..., min_length=1, max_length=64)
    record_integrity_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    inference_binding_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    input_canonical_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    model_master_fingerprint: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    preprocessing_contract_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    execution_identity_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    raw_output_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    validated_output_identity: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    output_contract_hash: Optional[str] = Field(None, pattern=r"^[0-9a-f]{64}$")
    replay_status: Optional[str] = None


class InferenceEvidenceVerificationResult(BaseModel):
    """Immutable result of verifying the complete inference evidence and provenance chain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool = Field(..., description="Whether complete end-to-end chain verification succeeded")
    status: InferenceEvidenceStatus = Field(..., description="Overall verification outcome status")
    evidence_id: str = Field(..., description="Target evidence identifier")
    computed_evidence_hash: str = Field(..., description="Locally recomputed evidence SHA-256 hash")
    record_verified: bool = Field(..., description="Whether Phase 10.8 InferenceRecord integrity succeeded")
    binding_verified: bool = Field(..., description="Whether Phase 10.7 composite binding integrity succeeded")
    replay_verified: bool = Field(..., description="Whether Phase 10.9 replay state matches if evaluated")
    provenance_verified: bool = Field(..., description="Whether Phase 4 provenance record matches if linked")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Observational verification findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic telemetry and layer results")
