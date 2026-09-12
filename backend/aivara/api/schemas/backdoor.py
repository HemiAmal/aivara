"""Pydantic API Schemas for Backdoor / Trigger Analysis (Phase 9.10).

Provides structured request and response models for:
  - Task submission and lifecycle management
  - Cooperative cancellation
  - Server-Sent Events (SSE) progress broadcasting
  - Fine-grained result querying across candidate, activation, output-shift, localization,
    statistical, evidence, and cryptographic provenance layers.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.backdoor.candidates.enums import TriggerFamilyEnum
from aivara.backdoor.evidence import BackdoorEvidenceLifecycleState
from aivara.backdoor.statistics.enums import (
    MultipleTestingMethodEnum,
    StatisticalResultTaxonomyEnum,
    StatisticalStatusEnum,
)
from aivara.domain.schemas import EvidenceLayer, Severity, Disposition
from aivara.evidence.schemas import ProvenanceStatus


# =====================================================================
# Task Lifecycle & Progress Enums
# =====================================================================

class BackdoorTaskStageEnum(str, Enum):
    """Controlled sequence of execution stages for backdoor analysis."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    CANDIDATES_GENERATED = "CANDIDATES_GENERATED"
    TRANSFORMING = "TRANSFORMING"
    COMPARING = "COMPARING"
    ACTIVATION_ANALYSIS = "ACTIVATION_ANALYSIS"
    OUTPUT_SHIFT_ANALYSIS = "OUTPUT_SHIFT_ANALYSIS"
    LOCALIZATION = "LOCALIZATION"
    STATISTICS = "STATISTICS"
    EVIDENCE_BINDING = "EVIDENCE_BINDING"
    SEALING = "SEALING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


# =====================================================================
# Request Schemas
# =====================================================================

class BackdoorAnalysisRequest(BaseModel):
    """Request payload to initiate a backdoor / trigger analysis scan."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36, description="Tenant project identifier")
    model_id: str = Field(..., min_length=1, max_length=255, description="Target model identifier")
    model_fingerprint: Optional[str] = Field(None, max_length=64, description="Target model weight fingerprint")
    sample_set_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 hash of clean input sample set")
    target_class: Optional[Union[int, str]] = Field(None, description="Target class to evaluate (int index or class name)")
    
    # Candidate generation & screening parameters
    candidate_family: Optional[TriggerFamilyEnum] = Field(None, description="Optional trigger family filter")
    candidate_count_stage1: int = Field(default=16, ge=1, le=16, description="Number of candidates in Stage 1 screening")
    candidate_count_stage2: int = Field(default=2, ge=1, le=2, description="Number of promoted candidates in Stage 2")
    
    # Sample limits
    sample_count_stage1: int = Field(default=50, ge=10, le=100, description="Clean samples evaluated in Stage 1")
    sample_count_stage2: int = Field(default=200, ge=50, le=500, description="Clean samples evaluated in Stage 2")
    localization_sample_count: int = Field(default=50, ge=10, le=100, description="Samples evaluated for spatial localization")
    
    # Statistical parameters
    permutation_count: int = Field(default=1000, ge=100, le=5000, description="Permutation test iterations B")
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0, description="Statistical significance threshold alpha")
    confidence_level: float = Field(default=0.95, gt=0.0, lt=1.0, description="Confidence interval level")
    multiple_testing_method: MultipleTestingMethodEnum = Field(
        default=MultipleTestingMethodEnum.BENJAMINI_HOCHBERG,
        description="Multiple testing adjustment method",
    )
    
    # Spatial localization
    enable_localization: bool = Field(default=True, description="Whether to perform spatial grid localization")
    
    # Cryptographic provenance options
    key_alias: Optional[str] = Field(None, description="Optional key ID or alias for Ed25519 signing")
    signer_passphrase: Optional[str] = Field(None, description="Optional passphrase for key decryption")
    actor: str = Field(default="AIVARA_BACKDOOR_SERVICE", description="Actor identity for provenance record")

    @field_validator("project_id", "model_id")
    @classmethod
    def validate_non_empty_identifiers(cls, v: str, info: Any) -> str:
        if not v or not v.strip():
            raise ValueError(f"{info.field_name} must not be empty or whitespace only")
        return v.strip()

    @model_validator(mode="after")
    def validate_budget_ceiling(self) -> BackdoorAnalysisRequest:
        """Enforce strict inference budget ceiling <= 16,000 inferences (ADR-090)."""
        stage1_inf = self.sample_count_stage1 * (1 + self.candidate_count_stage1 * 3)
        stage2_inf = self.sample_count_stage2 * (1 + self.candidate_count_stage2 * 3)
        loc_inf = (self.localization_sample_count * self.candidate_count_stage2 * 64) if self.enable_localization else 0
        total_inf = stage1_inf + stage2_inf + loc_inf
        
        if total_inf > 16000:
            raise ValueError(
                f"Requested configuration consumes {total_inf} total inferences, exceeding "
                f"the hard ceiling limit of 16,000 inferences. Reduce sample counts or candidates."
            )
        return self


class BackdoorTaskCancelRequest(BaseModel):
    """Request payload to request cooperative cancellation of a task."""
    model_config = ConfigDict(extra="forbid")
    reason: Optional[str] = Field(None, max_length=255, description="Reason for cancellation request")


# =====================================================================
# Response Schemas
# =====================================================================

class BackdoorTaskReadResponse(BaseModel):
    """Response representing the state and progress of an analysis task."""

    model_config = ConfigDict(extra="ignore")

    task_id: str = Field(..., description="Unique task identifier")
    project_id: str = Field(..., description="Project identifier")
    model_id: str = Field(..., description="Model identifier")
    status: BackdoorTaskStageEnum = Field(..., description="Current execution state")
    progress_percent: float = Field(..., ge=0.0, le=100.0, description="Overall progress percentage")
    current_stage: str = Field(..., description="Human-readable current execution stage")
    execution_identity_hash: Optional[str] = Field(None, description="Deterministic execution identity hash")
    statistical_analysis_id: Optional[str] = Field(None, description="Deterministic statistical assessment ID")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    started_at: Optional[str] = Field(None, description="ISO-8601 start timestamp")
    completed_at: Optional[str] = Field(None, description="ISO-8601 completion timestamp")


class BackdoorProgressEvent(BaseModel):
    """Server-Sent Event payload for real-time progress broadcasting."""

    task_id: str = Field(..., description="Task identifier")
    stage: BackdoorTaskStageEnum = Field(..., description="Current task stage")
    progress_percent: float = Field(..., ge=0.0, le=100.0, description="Progress percentage")
    message: str = Field(..., description="Diagnostic status message")
    timestamp: str = Field(..., description="RFC 3339 UTC timestamp")
    payload: Optional[Dict[str, Any]] = Field(None, description="Optional stage-specific summary payload")


class BackdoorCandidateSummaryResponse(BaseModel):
    """Response model for a single evaluated trigger candidate."""

    model_config = ConfigDict(extra="ignore")

    candidate_hash: str = Field(..., description="Candidate identity hash")
    target_class: Optional[Union[int, str]] = Field(None, description="Evaluated target class")
    sample_count: int = Field(..., description="Sample count")
    eligible_sample_count: int = Field(..., description="Eligible sample count")
    tar: Optional[float] = Field(None, description="Trigger Activation Rate")
    tsr: Optional[float] = Field(None, description="Trigger Success Rate")
    raw_tsr_shuffled: Optional[float] = Field(None, description="TSR under location-shuffled control")
    raw_tsr_noise: Optional[float] = Field(None, description="TSR under magnitude-matched noise control")
    control_baseline_tsr: Optional[float] = Field(None, description="Control baseline TSR")
    sample_envelope_tsr: Optional[float] = Field(None, description="Sample envelope TSR")
    delta_separation: Optional[float] = Field(None, description="Delta separation over control")
    ci_lower: Optional[float] = Field(None, description="Clopper-Pearson 95% CI lower bound")
    ci_upper: Optional[float] = Field(None, description="Clopper-Pearson 95% CI upper bound")
    raw_p_value: Optional[float] = Field(None, description="Unadjusted permutation p-value")
    adjusted_p_value: Optional[float] = Field(None, description="BH-FDR adjusted p-value")
    fdr_rank: Optional[int] = Field(None, description="FDR candidate rank")
    is_significant_after_fdr: bool = Field(False, description="Whether significant after FDR adjustment")
    taxonomy_classification: str = Field(..., description="Observational result taxonomy classification")
    status: str = Field(..., description="Evaluation status")


class BackdoorActivationResponse(BaseModel):
    """Response model for clean-vs-triggered activation and behavioral comparison."""

    model_config = ConfigDict(extra="ignore")

    statistical_analysis_id: str = Field(..., description="Statistical analysis ID")
    model_id: str = Field(..., description="Evaluated model ID")
    total_candidates_evaluated: int = Field(..., description="Total candidates evaluated")
    candidate_activations: List[Dict[str, Any]] = Field(default_factory=list, description="Per-candidate activation summaries")


class BackdoorOutputShiftResponse(BaseModel):
    """Response model for targeted misclassification and output-shift metrics."""

    model_config = ConfigDict(extra="ignore")

    statistical_analysis_id: str = Field(..., description="Statistical analysis ID")
    model_id: str = Field(..., description="Evaluated model ID")
    target_class: Optional[Union[int, str]] = Field(None, description="Evaluated target class")
    output_shift_summaries: List[Dict[str, Any]] = Field(default_factory=list, description="Output shift summaries")


class BackdoorLocalizationResponse(BaseModel):
    """Response model for spatial localization and attribution analysis."""

    model_config = ConfigDict(extra="ignore")

    statistical_analysis_id: str = Field(..., description="Statistical analysis ID")
    model_id: str = Field(..., description="Evaluated model ID")
    promoted_candidate_count: int = Field(..., description="Number of promoted candidates localized")
    localizations: List[Dict[str, Any]] = Field(default_factory=list, description="Spatial localization results")


class BackdoorStatisticalSummaryResponse(BaseModel):
    """Response model for aggregate statistical significance evaluation."""

    model_config = ConfigDict(extra="ignore")

    statistical_analysis_id: str = Field(..., description="Statistical analysis ID")
    project_id: str = Field(..., description="Project identifier")
    model_id: str = Field(..., description="Model identifier")
    sample_set_hash: str = Field(..., description="Sample set hash")
    permutation_count: int = Field(..., description="Permutation iterations")
    alpha: float = Field(..., description="Significance alpha")
    multiple_testing_method: str = Field(..., description="Multiplicity correction method")
    total_inferences_consumed: int = Field(..., description="Total inferences consumed")
    candidates: List[BackdoorCandidateSummaryResponse] = Field(default_factory=list, description="Candidate statistical summaries")


class BackdoorEvidenceResponse(BaseModel):
    """Response model for sealed backdoor evidence items."""

    model_config = ConfigDict(extra="ignore")

    evidence_id: str = Field(..., description="Content-addressed evidence hash")
    execution_id: str = Field(..., description="Execution identity hash")
    lifecycle_state: str = Field(..., description="Evidence lifecycle state (DRAFT / SEALED)")
    evidence_layer: str = Field(..., description="Assurance layer")
    evidence_type: str = Field(..., description="Backdoor evidence type")
    created_at: str = Field(..., description="Creation timestamp")
    sealed_at: Optional[str] = Field(None, description="Sealing timestamp")
    content: Dict[str, Any] = Field(default_factory=dict, description="Canonical evidence content dictionary")


class BackdoorProvenanceResponse(BaseModel):
    """Response model for cryptographic provenance records bound to backdoor findings."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(..., description="Finding identifier")
    project_id: str = Field(..., description="Project identifier")
    provenance_record_id: Optional[str] = Field(None, description="Provenance record identifier")
    provenance_status: str = Field(..., description="Provenance verification state (VERIFIED, etc.)")
    cryptographic_validity: bool = Field(..., description="Cryptographic validity status")
    record_hash: Optional[str] = Field(None, description="SHA-256 record hash")
    signature: Optional[str] = Field(None, description="Ed25519 digital signature")
    sequence_number: Optional[int] = Field(None, description="Monotonic sequence number")
    nonce: Optional[str] = Field(None, description="Cryptographic nonce")


class BackdoorOverallAnalysisResponse(BaseModel):
    """Comprehensive rollup of complete backdoor analysis scan."""

    model_config = ConfigDict(extra="ignore")

    statistical_analysis_id: str = Field(..., description="Statistical analysis identifier")
    project_id: str = Field(..., description="Project identifier")
    model_id: str = Field(..., description="Target model identifier")
    execution_identity_hash: str = Field(..., description="Deterministic execution identity hash")
    primary_taxonomy_classification: str = Field(..., description="Primary non-accusatory result taxonomy")
    significant_candidate_count: int = Field(..., description="Number of candidates significant after FDR")
    total_candidates_evaluated: int = Field(..., description="Total candidates evaluated")
    total_inferences_consumed: int = Field(..., description="Total inferences consumed")
    provenance_status: str = Field(..., description="Cryptographic provenance status")
    candidates: List[BackdoorCandidateSummaryResponse] = Field(default_factory=list, description="Evaluated candidates")
