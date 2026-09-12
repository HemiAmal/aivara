"""Domain models for Phase 10.7 Cryptographic Input-to-Output Binding."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.inference.enums import InferenceIntegrityStatus
from aivara.inference.input.models import InputFinding


class InferenceBinding(BaseModel):
    """Deterministic, immutable cryptographic binding representing a complete end-to-end inference transaction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", max_length=16, description="Schema specification version")
    binding_version: str = Field("1.0", max_length=16, description="Composite binding algorithm version")
    project_id: str = Field(..., min_length=1, max_length=255, description="Tenant project identifier")

    # Phase 10.2: Safe Input Boundary
    input_id: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.2 validated input identifier",
    )
    input_canonical_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.2 canonical input data SHA-256 hash",
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
    input_model_binding_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Phase 10.3 InputModelBinding canonical SHA-256 hash",
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

    # Composite Binding Result
    binding_status: InferenceIntegrityStatus = Field(
        InferenceIntegrityStatus.VERIFIED,
        description="Overall composite transaction verification status",
    )
    inference_binding_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Deterministic SHA-256 digest of canonical RFC 8785 inference binding descriptor",
    )
    findings: List[InputFinding] = Field(
        default_factory=list,
        description="Observational validation findings",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Bounded audit telemetry details",
    )


class InferenceBindingVerificationResult(BaseModel):
    """Result of pure cryptographic verification of an InferenceBinding object."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_valid: bool = Field(..., description="Whether inference binding hash matches recomputed value")
    status: InferenceIntegrityStatus = Field(..., description="Overall verification outcome status")
    computed_binding_hash: str = Field(..., description="Locally recomputed inference binding SHA-256 hash")
    expected_binding_hash: str = Field(..., description="Recorded inference binding SHA-256 hash")
    findings: List[InputFinding] = Field(default_factory=list, description="Observational verification findings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic telemetry")
