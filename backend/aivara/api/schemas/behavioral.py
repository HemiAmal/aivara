"""Pydantic request and response schemas for Behavioral Analysis REST API (Phase 8.8).

Defines stable, typed contracts for:
  - Baseline creation, retrieval, and comparison.
  - Controlled input perturbation experiments.
  - Repeatability, sensitivity, and reference stability analysis.
  - Statistical anomaly detection.
  - Evidence synthesis and cryptographic provenance verification.
  - Integrated assessment pipelines, in-memory tasks, and SSE progress events.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator


# =====================================================================
# 1. Behavioral Baseline Schemas
# =====================================================================

class BaselineCreateRequest(BaseModel):
    """Request payload for creating / computing a behavioral baseline."""
    model_id: str = Field(..., description="ID of the model to baseline")
    task_type: str = Field(
        ...,
        description="Task type: 'classification', 'detection', 'segmentation', 'generic_tensor'",
    )
    input_set_id: Optional[str] = Field(None, description="Identifier of the input reference dataset")
    baseline_type: str = Field(
        default="REFERENCE_EXECUTION_PROFILE",
        description="Type of baseline (e.g., 'REFERENCE_EXECUTION_PROFILE', 'HISTORICAL_PROFILE')",
    )
    observations: List[Dict[str, Any]] = Field(
        ...,
        min_length=1,
        description="List of raw model execution observation dictionaries to baseline",
    )
    execution_provider: str = Field(
        default="CPUExecutionProvider",
        description="Execution provider used (e.g. CPUExecutionProvider, CUDAExecutionProvider)",
    )
    preprocessing_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional preprocessing configuration metadata",
    )
    allow_idempotent_reuse: bool = Field(
        default=True,
        description="Whether to reuse existing baseline if hash matches",
    )


class BaselineReadResponse(BaseModel):
    """Response payload representing a stored behavioral baseline."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    baseline_id: str = Field(..., description="Unique deterministic baseline identifier")
    project_id: str = Field(..., description="Project ID owning this baseline")
    model_id: str = Field(..., description="Target model ID")
    model_fingerprint: str = Field(..., description="SHA-256 model weight/architecture fingerprint")
    task_type: str = Field(..., description="Task type")
    baseline_type: str = Field(..., description="Baseline type")
    baseline_status: str = Field(..., description="Baseline validity status")
    support_status: str = Field(..., description="Baseline sample support status")
    trust_status: str = Field(..., description="Baseline trust level")
    observation_count: int = Field(..., description="Total observation count in baseline")
    profiles: Dict[str, Any] = Field(..., description="Normalized task-specific metric profiles")
    limitations: List[str] = Field(default_factory=list, description="Known analytical limitations")
    created_at: str = Field(..., description="ISO-8601 creation timestamp")


class BaselineCompareRequest(BaseModel):
    """Request payload for comparing an observation against a baseline."""
    observation: Dict[str, Any] = Field(..., description="Observed measurement dictionary")
    tolerance_threshold: Optional[float] = Field(None, ge=0.0, description="Optional custom threshold")


class BaselineCompareResponse(BaseModel):
    """Response payload for baseline observation comparison."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    baseline_id: str = Field(..., description="Baseline identifier")
    project_id: str = Field(..., description="Project identifier")
    comparability_status: str = Field(..., description="Comparability evaluation status")
    metric_differences: Dict[str, Any] = Field(..., description="Detailed metric comparison deltas")
    is_compatible: bool = Field(..., description="Whether the observation is structurally compatible")
    warnings: List[str] = Field(default_factory=list, description="Comparison warnings")


# =====================================================================
# 2. Controlled Perturbation Schemas
# =====================================================================

class PerturbationExperimentRequest(BaseModel):
    """Request payload for running a deterministic perturbation experiment."""
    model_id: str = Field(..., description="Model ID")
    input_data: List[Any] = Field(..., description="Input tensor or image pixel values (nested list)")
    perturbation_type: str = Field(
        ...,
        description=(
            "Type of perturbation: 'gaussian_noise', 'uniform_noise', 'brightness', "
            "'contrast', 'gaussian_blur', 'jpeg_compression', 'spatial_translation'"
        ),
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Perturbation specific parameters (e.g. sigma, factor, quality, kernel_size)",
    )
    random_seed: int = Field(default=42, description="PCG64 deterministic integer seed")
    execution_provider: str = Field(default="CPUExecutionProvider", description="Execution provider")


class PerturbationExperimentResponse(BaseModel):
    """Response payload for a perturbation experiment."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    experiment_id: str = Field(..., description="Deterministic experiment hash")
    perturbation_id: str = Field(..., description="Deterministic perturbation specification hash")
    perturbation_type: str = Field(..., description="Applied perturbation type")
    status: str = Field(..., description="Experiment status")
    original_input_hash: str = Field(..., description="SHA-256 of original input array")
    perturbed_input_hash: str = Field(..., description="SHA-256 of perturbed input array")
    input_distance: float = Field(..., description="Normalized L2/Frobenius distance between inputs")
    execution_result: Optional[Dict[str, Any]] = Field(None, description="Model execution outputs if executed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic experiment metadata")


# =====================================================================
# 3. Output Consistency & Stability Schemas
# =====================================================================

class RepeatabilityAnalysisRequest(BaseModel):
    """Request payload for evaluating repeatability across identical runs."""
    model_id: str = Field(..., description="Model ID")
    outputs: List[Dict[str, Any]] = Field(
        ...,
        min_length=2,
        description="List of 2 or more execution output dictionaries from identical inputs",
    )
    task_type: str = Field(
        default="classification",
        description="Task type: 'classification', 'detection', 'segmentation', 'generic_tensor'",
    )


class RepeatabilityAnalysisResponse(BaseModel):
    """Response payload for repeatability analysis."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    analysis_id: str = Field(..., description="Deterministic repeatability analysis ID")
    is_fully_deterministic: bool = Field(..., description="Whether all outputs were bitwise identical")
    run_count: int = Field(..., description="Number of runs evaluated")
    metrics: Dict[str, Any] = Field(..., description="Detailed stability metric measurements")
    validity_status: str = Field(..., description="Metric validity status")


class SensitivityAnalysisRequest(BaseModel):
    """Request payload for evaluating perturbation sensitivity ratio."""
    model_id: str = Field(..., description="Model ID")
    task_type: str = Field(default="classification", description="Task type")
    original_input: List[Any] = Field(..., description="Original input array/tensor")
    perturbed_input: List[Any] = Field(..., description="Perturbed input array/tensor")
    original_output: Dict[str, Any] = Field(..., description="Model output on original input")
    perturbed_output: Dict[str, Any] = Field(..., description="Model output on perturbed input")


class SensitivityAnalysisResponse(BaseModel):
    """Response payload for perturbation sensitivity analysis."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    sensitivity_id: str = Field(..., description="Deterministic sensitivity analysis ID")
    input_distance: float = Field(..., description="Normalized input distance")
    output_distance: float = Field(..., description="Normalized output distance")
    sensitivity_ratio: Optional[float] = Field(
        None,
        description="Sensitivity ratio (null/undefined if input_distance == 0)",
    )
    ratio_status: str = Field(..., description="Status of sensitivity ratio computation")
    metrics: Dict[str, Any] = Field(..., description="Detailed task stability metrics")


class StabilityCompareRequest(BaseModel):
    """Request payload for evaluating consistency against a reference model output."""
    candidate_model_id: str = Field(..., description="Candidate model ID")
    reference_model_id: str = Field(..., description="Reference model ID")
    task_type: str = Field(default="classification", description="Task type")
    candidate_output: Dict[str, Any] = Field(..., description="Candidate model output")
    reference_output: Dict[str, Any] = Field(..., description="Reference model output")


class StabilityCompareResponse(BaseModel):
    """Response payload for reference consistency comparison."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    comparison_id: str = Field(..., description="Deterministic comparison ID")
    task_type: str = Field(..., description="Task type")
    metrics: Dict[str, Any] = Field(..., description="Consistency metrics deltas")
    validity_status: str = Field(..., description="Metric validity status")


# =====================================================================
# 4. Behavioral Anomaly Detection Schemas
# =====================================================================

class AnomalyDetectionRequest(BaseModel):
    """Request payload for statistical behavioral anomaly detection."""
    model_id: str = Field(..., description="Model ID being evaluated")
    task_type: str = Field(
        ...,
        description="Task type: 'classification', 'detection', 'segmentation', 'generic_tensor'",
    )
    observed_metrics: Dict[str, float] = Field(
        ...,
        description="Dictionary mapping metric names to observed numeric values",
    )
    baseline_id: Optional[str] = Field(
        None,
        description="Optional ID of existing registered baseline profile",
    )
    reference_dataset: Optional[Dict[str, List[float]]] = Field(
        None,
        description="Optional ad-hoc dictionary mapping metric names to reference values",
    )
    observation_id: Optional[str] = Field(
        None,
        description="Optional observation identity hash",
    )
    threshold_policy: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional custom threshold policy overrides",
    )

    @field_validator("observed_metrics")
    @classmethod
    def validate_finite_floats(cls, v: Dict[str, float]) -> Dict[str, float]:
        import math
        for k, val in v.items():
            if not isinstance(val, (int, float)) or math.isnan(val) or math.isinf(val):
                raise ValueError(f"Metric '{k}' has non-finite value '{val}'.")
        return v


class AnomalyDetectionResponse(BaseModel):
    """Response payload for behavioral anomaly detection."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    analysis_id: str = Field(..., description="Deterministic anomaly analysis ID")
    project_id: str = Field(..., description="Project ID")
    model_id: str = Field(..., description="Model ID")
    model_fingerprint: str = Field(..., description="Model fingerprint")
    task_type: str = Field(..., description="Task type")
    overall_status: str = Field(..., description="Overall anomaly status: 'NORMAL', 'ANOMALOUS', etc.")
    support_status: str = Field(..., description="Baseline sample support status")
    anomalous_metric_count: int = Field(..., description="Number of anomalous metrics")
    total_metric_count: int = Field(..., description="Total metrics evaluated")
    families: Dict[str, Any] = Field(..., description="Family-level aggregated anomaly summaries")
    metrics: Dict[str, Any] = Field(..., description="Detailed metric-level evaluations")
    overall_explanation: str = Field(..., description="Non-adversarial explanation of result")
    limitations: List[str] = Field(default_factory=list, description="Known analytical limitations")


# =====================================================================
# 5. Evidence & Provenance Binding Schemas
# =====================================================================

class BehavioralEvidenceBindRequest(BaseModel):
    """Request payload for synthesizing findings and binding cryptographic evidence."""
    model_id: str = Field(..., description="Target model ID")
    anomaly_analysis_id: str = Field(..., description="Anomaly analysis ID to bind")
    observation_id: str = Field(..., description="Observation ID")
    baseline_id: str = Field(..., description="Baseline ID")
    comparison_id: Optional[str] = Field(None, description="Optional comparison ID")
    sensitivity_id: Optional[str] = Field(None, description="Optional sensitivity ID")
    task_type: str = Field(default="classification", description="Task type")
    overall_status: str = Field(..., description="Anomaly overall status (e.g. 'NORMAL', 'ANOMALOUS')")
    support_status: str = Field(default="ADEQUATE", description="Baseline support status")
    comparability_status: str = Field(default="COMPARABLE", description="Comparability status")
    metric_results: Dict[str, Any] = Field(..., description="Metric-level evaluation dictionary")
    family_results: Dict[str, Any] = Field(..., description="Family-level evaluation dictionary")
    limitations: List[str] = Field(default_factory=list, description="Limitations list")
    seal_provenance: bool = Field(default=True, description="Whether to seal provenance in Phase 4 ledger")
    signer_key_id: Optional[str] = Field(None, description="Signer key ID for Ed25519 signature")
    signer_passphrase: Optional[str] = Field(None, description="Passphrase for encrypted signer key")
    actor: str = Field(default="aivara-behavioral-service", description="Provenance actor identity")


class BehavioralEvidenceBindResponse(BaseModel):
    """Response payload for evidence binding."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    evidence_id: str = Field(..., description="Deterministic RFC 8785 JCS + SHA-256 evidence ID")
    evidence_type: str = Field(..., description="Behavioral evidence type")
    lifecycle_state: str = Field(..., description="Evidence lifecycle state ('SEALED' or 'DRAFT')")
    finding_id: Optional[str] = Field(None, description="Synthesized finding ID in database")
    provenance_record_id: Optional[str] = Field(None, description="Bound Phase 4 provenance record ID")
    execution_identity_hash: str = Field(..., description="Deterministic execution identity hash")
    project_id: str = Field(..., description="Project ID")
    model_id: str = Field(..., description="Model ID")
    created_at: str = Field(..., description="Creation timestamp")


class BehavioralEvidenceReadResponse(BaseModel):
    """Response payload for retrieving a sealed evidence item."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    evidence_id: str = Field(..., description="Evidence ID")
    evidence_type: str = Field(..., description="Evidence type")
    lifecycle_state: str = Field(..., description="Lifecycle state")
    project_id: str = Field(..., description="Project ID")
    model_id: str = Field(..., description="Model ID")
    model_fingerprint: str = Field(..., description="Model fingerprint")
    content: Dict[str, Any] = Field(..., description="Full immutable evidence content dictionary")
    created_at: str = Field(..., description="Creation timestamp")


# =====================================================================
# 6. Provenance Verification Schemas
# =====================================================================

class BehavioralProvenanceVerificationResponse(BaseModel):
    """Response payload for cryptographic verification of behavioral provenance."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    is_valid: bool = Field(..., description="Whether cryptographic verification fully succeeded")
    status: str = Field(..., description="Provenance status: 'VERIFIED', 'INVALID', 'MISSING', etc.")
    provenance_record_id: Optional[str] = Field(None, description="Provenance record ID")
    project_id: str = Field(..., description="Project ID")
    target_id: str = Field(..., description="Target asset ID (model or finding)")
    signature_valid: bool = Field(..., description="Whether Ed25519 detached signature verified")
    chain_valid: bool = Field(..., description="Whether hash-linked chain and previous hash verified")
    sequence_valid: bool = Field(default=True, description="Whether sequence number is monotonic")
    nonce_valid: bool = Field(default=True, description="Whether replay nonce is valid and unique")
    signer_key_id: Optional[str] = Field(None, description="Signer key ID")
    sequence_number: Optional[int] = Field(None, description="Ledger sequence number")
    record_hash: Optional[str] = Field(None, description="SHA-256 record hash")
    verification_vector: Optional[Dict[str, Any]] = Field(
        None,
        description="14-point detailed diagnostic verification vector",
    )
    failures: List[str] = Field(default_factory=list, description="List of verification failure reasons")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional verification metadata")


# =====================================================================
# 7. Integrated Assessment & Tasks Schemas
# =====================================================================

class BehavioralAssessmentRequest(BaseModel):
    """Request payload for running full integrated behavioral assessment pipeline."""
    model_id: str = Field(..., description="Target model ID")
    task_type: str = Field(
        default="classification",
        description="Task type: 'classification', 'detection', 'segmentation', 'generic_tensor'",
    )
    observations: List[Dict[str, Any]] = Field(
        ...,
        min_length=1,
        description="Execution observations or test inputs for baseline/anomaly evaluation",
    )
    baseline_id: Optional[str] = Field(None, description="Optional existing baseline ID to compare against")
    perturbation_type: Optional[str] = Field(None, description="Optional perturbation type to evaluate")
    perturbation_params: Optional[Dict[str, Any]] = Field(None, description="Optional perturbation params")
    seal_provenance: bool = Field(default=True, description="Whether to seal findings into Phase 4 ledger")
    signer_key_id: Optional[str] = Field(None, description="Signer key ID")
    signer_passphrase: Optional[str] = Field(None, description="Signer passphrase")
    allow_idempotent_reuse: bool = Field(default=True, description="Whether to reuse existing sealed results")
    actor: str = Field(default="aivara-behavioral-pipeline", description="Actor identity")


class BehavioralAssessmentResponse(BaseModel):
    """Response payload for full integrated behavioral assessment."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    assessment_status: str = Field(..., description="Assessment status ('COMPLETED', 'PARTIAL', 'IDEMPOTENT_HIT')")
    project_id: str = Field(..., description="Project ID")
    model_id: str = Field(..., description="Model ID")
    execution_identity_hash: str = Field(..., description="Execution identity hash")
    idempotent: bool = Field(..., description="Whether result was resolved via idempotent hit")
    anomaly_status: str = Field(..., description="Overall anomaly status ('NORMAL', 'ANOMALOUS', etc.)")
    finding_id: Optional[str] = Field(None, description="Synthesized finding ID")
    evidence_id: Optional[str] = Field(None, description="Sealed evidence ID")
    provenance_record_id: Optional[str] = Field(None, description="Sealed provenance record ID")
    anomalous_metric_count: int = Field(0, description="Count of anomalous metrics detected")
    total_metric_count: int = Field(0, description="Total metrics analyzed")
    explanation: str = Field(..., description="Non-adversarial explanation of result")
    limitations: List[str] = Field(default_factory=list, description="Analytical limitations")


class BehavioralTaskReadResponse(BaseModel):
    """Response payload for in-memory behavioral task state."""
    schema_version: str = Field(default="1.0.0", description="Schema version")
    task_id: str = Field(..., description="Task unique ID")
    project_id: str = Field(..., description="Project ID")
    model_id: str = Field(..., description="Model ID")
    status: str = Field(..., description="Task status ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')")
    progress_percent: float = Field(..., ge=0.0, le=100.0, description="Progress percentage (0-100)")
    current_stage: str = Field(..., description="Current pipeline execution stage")
    result: Optional[BehavioralAssessmentResponse] = Field(None, description="Assessment result if completed")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    started_at: Optional[str] = Field(None, description="ISO-8601 start timestamp")
    completed_at: Optional[str] = Field(None, description="ISO-8601 completion timestamp")


class BehavioralProgressEvent(BaseModel):
    """SSE real-time progress broadcast event model."""
    task_id: str = Field(..., description="Task ID")
    event_type: str = Field(
        ...,
        description="Event type: 'task.started', 'task.progress', 'task.completed', 'task.failed', 'task.cancelled'",
    )
    progress_percent: float = Field(..., ge=0.0, le=100.0, description="Progress percentage")
    stage: str = Field(..., description="Current stage")
    message: str = Field(..., description="User-friendly status message")
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    data: Optional[Dict[str, Any]] = Field(None, description="Optional stage payload")
