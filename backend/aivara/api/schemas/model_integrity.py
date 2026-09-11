"""Model Integrity REST API Schemas (Phase 7.7).

Request and response contracts for Model Ingestion, Hierarchical Fingerprinting,
Contract Verification, Reference Model Comparison, Evidence Retrieval,
Finding Resolution, and Cryptographic Provenance Verification.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.api.schemas.evidence import EvidenceItemRead, FindingDetailRead
from aivara.domain.schemas import ProvenanceRecordRead


# =====================================================================
# 1. Model Inspection Schemas
# =====================================================================

class ModelInspectRequest(BaseModel):
    """Optional payload for inspecting a model artifact."""

    model_config = ConfigDict(extra="forbid")

    file_path: Optional[str] = Field(None, description="Optional custom artifact path to inspect")
    allowed_base_dir: Optional[str] = Field(None, description="Optional confinement directory boundary")


class ModelInspectResponse(BaseModel):
    """Structured response from safe static model inspection."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Inspection status code (SUCCESS, RESTRICTED, PROHIBITED, INVALID_ARTIFACT, UNSUPPORTED_FORMAT)")
    format: str = Field(..., description="Detected model format (SAFETENSORS, ONNX, PYTORCH_STATE_DICT, TORCHSCRIPT, etc.)")
    policy: str = Field(..., description="Inspection policy (SAFE_INSPECTION, RESTRICTED_STATIC, PROHIBITED, etc.)")
    artifact_path: str = Field(..., description="Sanitized file path of the artifact")
    artifact_size_bytes: int = Field(..., ge=0, description="File size in bytes")
    artifact_hash_sha256: Optional[str] = Field(None, description="Streaming SHA-256 digest of the raw artifact")
    tensor_count: Optional[int] = Field(None, ge=0, description="Number of parsed tensor weights")
    input_count: Optional[int] = Field(None, ge=0, description="Number of declared input contract entries")
    output_count: Optional[int] = Field(None, ge=0, description="Number of declared output contract entries")
    operator_count: Optional[int] = Field(None, ge=0, description="Number of parsed operators in compute graph")
    reason_codes: List[str] = Field(default_factory=list, description="Machine-readable observation and reason codes")
    warnings: List[str] = Field(default_factory=list, description="Human-readable inspection warnings")
    details: Dict[str, Any] = Field(default_factory=dict, description="Detailed metadata parameters")


# =====================================================================
# 2. Model Fingerprinting Schemas
# =====================================================================

class ModelFingerprintRequest(BaseModel):
    """Request parameters for model fingerprint computation."""

    model_config = ConfigDict(extra="forbid")

    allow_idempotent_reuse: bool = Field(True, description="Whether to reuse pre-computed fingerprint if available")
    compute_weight_merkle: bool = Field(True, description="Whether to construct the full weight Merkle tree root")


class ModelFingerprintResponse(BaseModel):
    """Hierarchical cryptographic fingerprint summary."""

    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(..., description="AI model entity identifier")
    project_id: str = Field(..., description="Project entity identifier")
    artifact_hash: str = Field(..., description="SHA-256 hash of the complete raw artifact file")
    structural_hash: str = Field(..., description="Canonical RFC 8785 JCS SHA-256 of the model graph structure")
    weight_merkle_root: str = Field(..., description="Merkle tree root of all tensor weights")
    contract_hash: str = Field(..., description="Canonical RFC 8785 JCS SHA-256 of the I/O & preprocessing contract")
    master_fingerprint: str = Field(..., description="Deterministic master composite fingerprint (ADR-040)")
    tensor_count: int = Field(..., ge=0, description="Number of tensor leaves in weight Merkle tree")
    inspection_status: str = Field(..., description="Static inspection outcome status")
    details: Dict[str, Any] = Field(default_factory=dict, description="Fingerprint metadata details")


# =====================================================================
# 3. Contract Verification Schemas
# =====================================================================

class ModelContractVerifyRequest(BaseModel):
    """Request payload for model contract verification."""

    model_config = ConfigDict(extra="forbid")

    preprocessing_declaration: Optional[Dict[str, Any]] = Field(
        None, description="Optional explicit preprocessing declaration to verify against model metadata"
    )


class ModelContractVerifyResponse(BaseModel):
    """Contract verification outcome and integrity findings."""

    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(..., description="AI model entity identifier")
    project_id: str = Field(..., description="Project entity identifier")
    contract_status: str = Field(..., description="Contract verification status (VALID, DEFECTIVE, INCOMPLETE, UNVERIFIABLE)")
    completeness: str = Field(..., description="Contract completeness level (FULL, PARTIAL, MINIMAL, EMPTY)")
    contract_hash: str = Field(..., description="Canonical RFC 8785 SHA-256 digest of the contract representation")
    input_contract: Optional[List[Dict[str, Any]]] = Field(None, description="Validated input contract specifications")
    output_contract: Optional[List[Dict[str, Any]]] = Field(None, description="Validated output contract specifications")
    preprocessing_contract: Optional[Dict[str, Any]] = Field(None, description="Validated preprocessing contract specification")
    finding_count: int = Field(..., ge=0, description="Number of contract integrity findings")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Contract integrity observation findings")
    limitations: List[str] = Field(default_factory=list, description="Technical limitations or unverified dimensions")


# =====================================================================
# 4. Reference Comparison Schemas
# =====================================================================

class ModelCompareRequest(BaseModel):
    """Request payload for candidate vs reference model comparison."""

    model_config = ConfigDict(extra="forbid")

    reference_model_id: str = Field(..., min_length=1, description="Entity identifier of the trusted reference model")
    tolerance: float = Field(0.0, ge=0.0, description="Numerical weight comparison tolerance")
    structural_only: bool = Field(False, description="Whether to compare only structural topology without tensor contents")
    max_tensor_changes: int = Field(1000, ge=1, le=10000, description="Maximum tensor differences to return in attribution")


class ModelCompareResponse(BaseModel):
    """Deterministic 8-state reference comparison and drift attribution."""

    model_config = ConfigDict(extra="forbid")

    candidate_model_id: str = Field(..., description="Candidate model entity identifier")
    reference_model_id: str = Field(..., description="Reference model entity identifier")
    project_id: str = Field(..., description="Project entity identifier")
    comparison_status: str = Field(..., description="Comparison outcome status")
    drift_classification: str = Field(..., description="Exact 8-state drift classification (e.g. EXACT_INTEGRITY_MATCH, WEIGHT_ONLY_DRIFT)")
    is_exact_match: bool = Field(..., description="True if candidate is an identical cryptographic match to reference")
    structural_differences: List[Dict[str, Any]] = Field(default_factory=list, description="List of structural topology differences")
    contract_differences: List[Dict[str, Any]] = Field(default_factory=list, description="List of contract differences")
    weight_differences: List[Dict[str, Any]] = Field(default_factory=list, description="List of tensor weight differences")
    tensor_changes_summary: Dict[str, Any] = Field(default_factory=dict, description="Summary counts of added, removed, and modified tensors")
    attribution_records: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed tensor-level attribution records")


# =====================================================================
# 5. Integrated Assessment Schemas
# =====================================================================

class ModelIntegrityAssessmentRequest(BaseModel):
    """Request payload for running an integrated model integrity assessment."""

    model_config = ConfigDict(extra="forbid")

    reference_model_id: Optional[str] = Field(None, description="Optional reference model ID for comparative integrity audit")
    preprocessing_declaration: Optional[Dict[str, Any]] = Field(None, description="Optional declared preprocessing parameters")
    allow_idempotent_reuse: bool = Field(True, description="Whether to return cached results for identical execution context")
    seal_provenance: bool = Field(True, description="Whether to seal the findings into the Phase 4 cryptographic provenance chain")
    signer_key_id: Optional[str] = Field(None, description="Optional Ed25519 signing key identifier")
    signer_passphrase: Optional[str] = Field(None, description="Optional passphrase for encrypted private signing key")
    actor: str = Field("system:model_integrity_orchestrator", description="Audit actor string")
    extra_metadata: Optional[Dict[str, Any]] = Field(None, description="Optional additional audit metadata")


class ModelIntegrityAssessmentResponse(BaseModel):
    """Complete integrated model integrity assessment result."""

    model_config = ConfigDict(extra="forbid")

    assessment_status: str = Field(..., description="Execution status (COMPLETED, IDEMPOTENT_HIT, etc.)")
    project_id: str = Field(..., description="Project entity identifier")
    model_id: str = Field(..., description="Candidate AI model entity identifier")
    reference_model_id: Optional[str] = Field(None, description="Reference AI model entity identifier if provided")
    execution_identity_hash: str = Field(..., description="Canonical SHA-256 execution identity hash")
    idempotent: bool = Field(..., description="True if result was returned from an idempotent hit without duplicate records")
    fingerprint: Optional[ModelFingerprintResponse] = Field(None, description="Hierarchical fingerprint summary")
    contract: Optional[ModelContractVerifyResponse] = Field(None, description="Contract verification summary")
    comparison: Optional[ModelCompareResponse] = Field(None, description="Reference comparison summary if reference provided")
    findings_count: int = Field(..., ge=0, description="Total number of findings generated")
    findings: List[FindingDetailRead] = Field(default_factory=list, description="Synthesized and persisted findings")
    provenance: Optional[ProvenanceRecordRead] = Field(None, description="Sealed cryptographic provenance ledger record")
    limitations: List[str] = Field(default_factory=list, description="Technical scope and analysis limitations")


# =====================================================================
# 6. Provenance Verification Response
# =====================================================================

class ModelProvenanceVerificationResponse(BaseModel):
    """Cryptographic provenance verification for model integrity commitments."""

    model_config = ConfigDict(extra="forbid")

    is_valid: bool = Field(..., description="Whether cryptographic verification succeeded")
    status: str = Field(..., description="Provenance verification status (VERIFIED, INVALID, MISSING, UNAVAILABLE, etc.)")
    provenance_record_id: Optional[str] = Field(None, description="Primary key of verified provenance record")
    project_id: str = Field(..., description="Project entity identifier")
    model_id: str = Field(..., description="AI model entity identifier")
    target_type_logical: str = Field("model", description="Logical entity type representation")
    target_type_recorded: str = Field("dataset_version", description="Physical ledger target_type representation (Phase 5.9 compatibility mapping)")
    signature_valid: bool = Field(..., description="Whether Ed25519 digital signature is valid")
    chain_valid: bool = Field(..., description="Whether hash chain integrity is valid")
    signer_key_id: Optional[str] = Field(None, description="Public key identifier of the signer")
    sequence_number: Optional[int] = Field(None, description="Ledger sequence number")
    record_hash: Optional[str] = Field(None, description="Canonical SHA-256 digest of the ledger record")
    details: Dict[str, Any] = Field(default_factory=dict, description="Verification diagnostics and compatibility explanation")
