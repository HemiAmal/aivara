"""Domain models and schemas for Label Anomaly & Confident Learning Engine (Phase 5.5).

All schemas are strictly immutable (frozen=True) and enforce observational semantics:
LABEL ANOMALY != MALICIOUSNESS.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator


class ModelState(str, Enum):
    """Offline inference model availability states."""
    MODEL_AVAILABLE = "model_available"
    MODEL_UNAVAILABLE = "model_unavailable"
    MODEL_INCOMPATIBLE = "model_incompatible"
    MODEL_LOAD_FAILED = "model_load_failed"


class LabelAnomalyCategory(str, Enum):
    """Taxonomy of statistical label anomalies."""
    POSSIBLE_LABEL_MISMATCH = "possible_label_mismatch"
    HIGH_CONFIDENCE_ALTERNATIVE_CLASS = "high_confidence_alternative_class"
    CLASS_SYSTEMATIC_ANOMALY = "class_systematic_anomaly"
    RARE_CLASS_ANOMALY = "rare_class_anomaly"
    MODEL_DISAGREEMENT = "model_disagreement"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    MODEL_UNAVAILABLE = "model_unavailable"


class LabelAnomalyConfig(BaseModel):
    """Configuration parameters for label anomaly detection and confident learning."""

    model_config = ConfigDict(frozen=True)

    k_folds: int = Field(default=5, ge=2, le=20, description="Number of stratified cross-validation folds")
    min_total_samples: int = Field(default=25, ge=2, description="Minimum total samples required for confident learning")
    min_class_samples: int = Field(default=5, ge=1, description="Minimum class count required to avoid rare-class discount")
    rare_class_confidence_discount: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence discount factor for rare classes (<5 samples)")
    high_confidence_prob_threshold: float = Field(default=0.85, ge=0.5, le=1.0, description="Probability threshold for high-confidence alternative class")
    observed_prob_upper_threshold: float = Field(default=0.15, ge=0.0, le=0.5, description="Maximum observed class probability for high-confidence alternative class")
    systematic_anomaly_ratio_threshold: float = Field(default=0.15, ge=0.01, le=1.0, description="Proportion of class confusion to qualify as systematic anomaly")
    random_seed: int = Field(default=42, description="Deterministic integer seed for stratified fold assignment")


class LabelPrediction(BaseModel):
    """Immutable record of out-of-fold model class probability predictions for an analytical unit."""

    model_config = ConfigDict(frozen=True)

    sample_id: str = Field(..., min_length=1)
    relative_path: str = Field(..., min_length=1)
    annotation_id: Optional[str] = Field(default=None, description="Optional bounding-box annotation ID for object detection")
    observed_category_id: int = Field(..., ge=0, description="Observed label y_tilde")
    observed_category_name: str = Field(..., min_length=1)
    predicted_category_id: int = Field(..., ge=0, description="Highest probability predicted class")
    predicted_category_name: str = Field(..., min_length=1)
    probabilities: Dict[int, float] = Field(..., description="Full out-of-fold probability distribution P_hat(y | x)")
    is_out_of_fold: bool = Field(default=True, description="Strict guarantee that prediction was generated out-of-fold")


class LabelAnomalyEvidence(BaseModel):
    """Supporting statistical evidence metrics for a label anomaly finding."""

    model_config = ConfigDict(frozen=True)

    observed_category_id: int
    observed_category_name: str
    estimated_latent_category_id: Optional[int] = None
    estimated_latent_category_name: Optional[str] = None
    observed_prob: float = Field(..., ge=0.0, le=1.0, description="Predicted probability of observed label P_hat(y = y_tilde | x)")
    latent_prob: float = Field(..., ge=0.0, le=1.0, description="Predicted probability of estimated latent label P_hat(y = y_star_hat | x)")
    class_threshold: float = Field(..., ge=0.0, le=1.0, description="Empirical confident threshold t_j for estimated class")
    margin: float = Field(..., description="Threshold-normalized prediction margin")
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Sigmoidal normalized anomaly score in [0.0, 1.0]")
    raw_confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence metric before guardrail discounts")
    guardrails_applied: List[str] = Field(default_factory=list, description="List of guardrails applied (e.g. rare_class_discount)")
    final_confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated evidence confidence after all guardrails")


class LabelAnomalyFinding(BaseModel):
    """Immutable assurance observation for a suspected label anomaly under ADR-028."""

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(..., min_length=1, description="Deterministic unique finding identifier")
    sample_id: str = Field(..., min_length=1)
    relative_path: str = Field(..., min_length=1)
    annotation_id: Optional[str] = Field(default=None, description="Optional bounding-box annotation ID")
    observed_category_id: int = Field(..., ge=0)
    observed_category_name: str = Field(..., min_length=1)
    suggested_category_id: Optional[int] = Field(default=None, description="Estimated latent label y_star_hat")
    suggested_category_name: Optional[str] = Field(default=None)
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Degree of statistical inconsistency")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Statistical certainty of the finding")
    category: LabelAnomalyCategory
    margin: float
    evidence_layer: str = Field(default="detection", description="ADR-028 compliance: strictly 'detection'")
    model_id: Optional[str] = None
    model_hash: Optional[str] = None
    contributors: Tuple[str, ...] = Field(default_factory=tuple)
    limitations: List[str] = Field(default_factory=list)
    evidence_data: Optional[LabelAnomalyEvidence] = None

    @field_validator("contributors", mode="before")
    @classmethod
    def _coerce_contributors(cls, v: Any) -> Tuple[str, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(str(x) for x in v)
        return v


class LabelAnomalyScanResult(BaseModel):
    """Complete, immutable result of a dataset label anomaly audit."""

    model_config = ConfigDict(frozen=True)

    total_samples: int = Field(..., ge=0)
    evaluated_samples: int = Field(..., ge=0)
    anomalous_samples_count: int = Field(..., ge=0)
    joint_distribution_matrix: List[List[float]] = Field(default_factory=list, description="K x K joint distribution matrix Q(y_tilde, y_star)")
    class_thresholds: Dict[int, float] = Field(default_factory=dict, description="Class-specific confident thresholds t_j")
    findings: Tuple[LabelAnomalyFinding, ...] = Field(default_factory=tuple)
    model_state: ModelState = Field(default=ModelState.MODEL_AVAILABLE)
    warnings: List[str] = Field(default_factory=list)
    capability_info: Dict[str, Any] = Field(default_factory=dict)
