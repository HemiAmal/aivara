"""Domain models for Phase 10.12 Comprehensive Inference Verification."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.inference.enums import InferenceFindingCode, InferenceIntegrityStatus
from aivara.inference.evidence.enums import InferenceEvidenceStatus
from aivara.inference.input.models import InputFinding
from aivara.inference.records.enums import InferenceRecordStatus


class ComprehensiveInferenceVerificationResult(BaseModel):
    """Authoritative, multi-layer verification assessment across the entire Phase 10 inference chain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: str = Field(..., min_length=1, max_length=255, description="Tenant project identifier")
    record_id: Optional[str] = Field(None, description="Phase 10.8 InferenceRecord identifier if evaluated")
    inference_binding_hash: Optional[str] = Field(None, description="Phase 10.7 composite binding hash")
    record_integrity_hash: Optional[str] = Field(None, description="Phase 10.8 record integrity hash")

    # Layer statuses
    input_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.UNVERIFIABLE,
        description="Phase 10.2 Input boundary integrity status",
    )
    model_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.UNVERIFIABLE,
        description="Phase 7 / Phase 10.3 Model identity integrity status",
    )
    input_model_binding_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.UNVERIFIABLE,
        description="Phase 10.3 Input-Model binding integrity status",
    )
    preprocessing_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.UNVERIFIABLE,
        description="Phase 10.4 Preprocessing contract integrity status",
    )
    execution_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.UNVERIFIABLE,
        description="Phase 10.5 Controlled execution integrity status",
    )
    output_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.UNVERIFIABLE,
        description="Phase 10.6 Output schema and numerical integrity status",
    )
    binding_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.UNVERIFIABLE,
        description="Phase 10.7 Composite input-output binding status",
    )
    record_status: Optional[InferenceRecordStatus] = Field(
        None,
        description="Phase 10.8 Inference record persistence & integrity status",
    )
    replay_status: Optional[str] = Field(
        None,
        description="Phase 10.9 Replay consistency status (e.g. CONSISTENT_EXACT, DIVERGENT)",
    )
    evidence_status: Optional[InferenceEvidenceStatus] = Field(
        None,
        description="Phase 10.10 Evidence synthesis integrity status",
    )
    provenance_status: Optional[str] = Field(
        None,
        description="Phase 4 / Phase 10.10 Cryptographic provenance status",
    )

    # Aggregated outcome
    overall_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.UNVERIFIABLE,
        description="Deterministic multi-layer aggregated verification outcome",
    )
    is_verified: bool = Field(
        False,
        description="Strict boolean assertion: True only when every mandatory proof layer is VERIFIED and mutually consistent",
    )

    # Findings & Assurance metrics
    findings: List[InputFinding] = Field(
        default_factory=list,
        description="Observational findings collected across all pipeline layers",
    )
    confidence: float = Field(
        1.0,
        ge=0.0,
        le=1.0,
        description="Assurance confidence score (1.0 for proof layer per ADR-028)",
    )
    severity: Severity = Field(
        Severity.INFO,
        description="Aggregated finding severity level",
    )
    disposition: Disposition = Field(
        Disposition.ACCEPT,
        description="Recommended assurance disposition",
    )

    # Machine-readable summary & layer telemetry
    verification_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Concise machine-readable status summary across all 18 verification checkpoints",
    )
    layer_details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Diagnostic layer-specific verification telemetry",
    )
