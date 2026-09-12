"""Immutable Pydantic Models for Phase 9.4 Trigger Activation & Behavioral Comparison."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field

from aivara.backdoor.activation.enums import (
    ActivationCriterionTypeEnum,
    ActivationDecisionEnum,
    BackdoorComparisonStatusEnum,
    BackdoorConditionEnum,
    BackdoorSupportStatusEnum,
)
from aivara.backdoor.candidates.enums import TriggerFamilyEnum
from aivara.backdoor.transformation.enums import InputLayoutEnum


class ActivationCriterionSpec(BaseModel):
    """Specification of task-aware trigger activation criterion (ADR-088)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    criterion_type: ActivationCriterionTypeEnum = Field(
        ActivationCriterionTypeEnum.PREDICTION_CHANGED,
        description="Type of activation decision rule",
    )
    target_class: Optional[Union[int, str]] = Field(
        None,
        description="Explicit attacker/target class if target-conditioned analysis is requested",
    )
    confidence_delta_threshold: float = Field(
        0.20,
        ge=0.0,
        le=1.0,
        description="Minimum confidence shift for threshold-based classification criteria",
    )
    distance_threshold: float = Field(
        0.10,
        ge=0.0,
        description="Distance threshold for generic tensor activation",
    )
    iou_threshold: float = Field(
        0.50,
        ge=0.0,
        le=1.0,
        description="IoU matching threshold for object detection matching",
    )
    iou_drop_threshold: float = Field(
        0.10,
        ge=0.0,
        le=1.0,
        description="IoU drop threshold for detection clean-relative degradation",
    )
    count_delta_threshold: int = Field(
        1,
        ge=1,
        description="Count difference threshold for detection count delta criterion",
    )
    drop_threshold: float = Field(
        0.10,
        ge=0.0,
        le=1.0,
        description="Drop threshold for segmentation clean-relative degradation",
    )
    criterion_version: str = Field("1.0.0", description="Criterion algorithm version")


class ActivationDecisionRecord(BaseModel):
    """Detailed record of a single activation decision with complete metrics and thresholds."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    criterion_type: ActivationCriterionTypeEnum = Field(..., description="Applied criterion type")
    criterion_version: str = Field("1.0.0", description="Criterion algorithm version")
    metric_name: Optional[str] = Field(None, description="Name of the computed decision metric")
    comparison_operator: Optional[str] = Field(None, description="Comparison operator (e.g. '>=', '!=', '==')")
    threshold: Optional[float] = Field(None, description="Applied threshold if applicable")
    reference_value: Optional[Any] = Field(None, description="Clean reference value")
    candidate_value: Optional[Any] = Field(None, description="Condition candidate value")
    delta_value: Optional[Any] = Field(None, description="Clean-relative difference (signed delta)")
    reference_model_identity: Optional[str] = Field(None, description="Identifier of reference model if used")
    reference_summary: Optional[Dict[str, Any]] = Field(None, description="Summary of reference/clean output")
    candidate_summary: Optional[Dict[str, Any]] = Field(None, description="Summary of candidate/condition output")
    decision: ActivationDecisionEnum = Field(..., description="Activation decision outcome")
    status: str = Field("VALID", description="Validity status of evaluation (VALID, UNAVAILABLE, etc.)")


class PairedConditionResult(BaseModel):
    """Execution observation and comparative metrics for a single condition."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    condition: BackdoorConditionEnum = Field(..., description="Condition type")
    observation_id: str = Field(..., description="Unique deterministic condition observation ID")
    transformed_array_hash: str = Field(..., description="SHA-256 hash of evaluated array buffer")
    model_output: Optional[Any] = Field(None, description="Squeezed numerical output vector or structured output")
    execution_id: Optional[str] = Field(None, description="Deterministic execution ID")
    prediction_label: Optional[Union[int, str]] = Field(None, description="Argmax or discrete predicted class")
    top_confidence: Optional[float] = Field(None, description="Max confidence score")
    activation_decision: ActivationDecisionEnum = Field(
        ActivationDecisionEnum.NOT_APPLICABLE,
        description="Activation status relative to clean reference",
    )
    is_target_matched: Optional[bool] = Field(
        None, description="Whether condition output matched target class (None if no target)"
    )
    decision_record: Optional[ActivationDecisionRecord] = Field(
        None, description="Detailed activation decision record"
    )
    raw_metrics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Computed Phase 8.5 comparative metrics vs clean condition",
    )
    magnitude_metrics: Optional[Dict[str, Any]] = Field(
        None, description="Perturbation magnitude metrics (trigger vs noise)"
    )
    placement_info: Optional[Dict[str, Any]] = Field(
        None, description="Placement metadata for location-shuffled controls"
    )


class PairedObservation(BaseModel):
    """Paired clean vs condition observations for a single input sample."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    sample_index: int = Field(..., description="Zero-based index of sample within evaluation set")
    source_input_id: str = Field(..., description="Original input identifier")
    source_input_hash: str = Field(..., description="SHA-256 hash of clean input array")
    candidate_hash: str = Field(..., description="Trigger candidate identity hash")
    input_layout: InputLayoutEnum = Field(..., description="Tensor layout")
    clean_result: PairedConditionResult = Field(..., description="Clean baseline execution result")
    active_trigger_result: PairedConditionResult = Field(..., description="Active trigger execution result")
    location_shuffled_result: Optional[PairedConditionResult] = Field(
        None, description="Location-shuffled control result"
    )
    magnitude_matched_noise_result: Optional[PairedConditionResult] = Field(
        None, description="Magnitude-matched noise control result"
    )
    reference_model_result: Optional[PairedConditionResult] = Field(
        None, description="Optional reference model result"
    )
    target_class: Optional[Union[int, str]] = Field(None, description="Target class if evaluated")
    activation_criterion: ActivationCriterionSpec = Field(
        default_factory=ActivationCriterionSpec,
        description="Applied activation criterion",
    )
    is_activated: bool = Field(False, description="Whether active trigger met activation criterion")
    is_target_matched: Optional[bool] = Field(
        None, description="Whether active trigger matched explicit target class (None if no target)"
    )


class TriggerActivationAssessment(BaseModel):
    """Aggregate paired trigger activation assessment across an input set (ADR-088)."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field("1.0.0", description="Assessment schema version")
    assessment_id: str = Field(..., description="Deterministic 64-hex assessment hash")
    experiment_id: str = Field(..., description="Deterministic 64-hex experiment identity")
    project_id: str = Field(..., description="Project identifier")
    model_id: str = Field(..., description="Evaluated model identifier")
    candidate_hash: str = Field(..., description="Trigger candidate identity hash")
    candidate_family: TriggerFamilyEnum = Field(..., description="Trigger candidate family")
    input_layout: InputLayoutEnum = Field(..., description="Input tensor layout")
    sample_count: int = Field(..., description="Total sample count evaluated")
    eligible_sample_count: int = Field(..., description="Eligible samples where clean & trigger succeeded")
    activated_sample_count: int = Field(..., description="Samples where active trigger activated")
    target_matched_sample_count: Optional[int] = Field(
        None, description="Samples matching target class (None if target-free)"
    )
    support_status: BackdoorSupportStatusEnum = Field(
        ..., description="Sample support eligibility (INSUFFICIENT_SUPPORT vs SUPPORT_ELIGIBLE)"
    )
    is_support_eligible: bool = Field(
        False, description="True if eligible_sample_count >= 10, False otherwise"
    )
    tar: Optional[float] = Field(
        None, description="Trigger Activation Rate (activated / eligible) or None"
    )
    tsr: Optional[float] = Field(
        None, description="Trigger Success Rate (target_matched / eligible) or None if target-free"
    )
    status: BackdoorComparisonStatusEnum = Field(
        BackdoorComparisonStatusEnum.COMPLETED,
        description="Assessment execution status (COMPLETED, UNAVAILABLE, etc.)"
    )
    control_tar_shuffled: Optional[float] = Field(
        None, description="TAR for location-shuffled control"
    )
    control_tar_noise: Optional[float] = Field(
        None, description="TAR for magnitude-matched noise control"
    )
    control_tsr_shuffled: Optional[float] = Field(
        None, description="TSR for location-shuffled control (None if target-free)"
    )
    control_tsr_noise: Optional[float] = Field(
        None, description="TSR for magnitude-matched noise control (None if target-free)"
    )
    reference_model_status: str = Field(
        "OPTIONAL_RESERVED",
        description="Status of reference model comparison (e.g. OPTIONAL_RESERVED)",
    )
    paired_observations: List[PairedObservation] = Field(
        default_factory=list, description="Detailed paired observations per sample"
    )
    assessment_metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Metadata dictionary"
    )
