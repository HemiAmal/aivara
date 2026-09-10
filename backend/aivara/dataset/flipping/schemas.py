"""Immutable domain models and schemas for Label-Flipping Detection Engine (Phase 5.6).

All models enforce ADR-028 compliance (evidence_layer="detection") and the invariant:
LABEL-FLIPPING EVIDENCE != MALICIOUSNESS.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aivara.dataset.anomalies.schemas import ModelState


class LabelFlipCategory(str, Enum):
    """Taxonomy of statistical label transition and flipping patterns."""
    POSSIBLE_LABEL_FLIP = "possible_label_flip"
    DIRECTIONAL_LABEL_TRANSITION = "directional_label_transition"
    SYSTEMATIC_CLASS_TRANSITION = "systematic_class_transition"
    RECIPROCAL_CLASS_CONFUSION = "reciprocal_class_confusion"
    MANY_TO_ONE_COLLAPSE = "many_to_one_collapse"
    CONTRIBUTOR_ASSOCIATED_LABEL_TRANSITION = "contributor_associated_label_transition"
    INSUFFICIENT_SUPPORT = "insufficient_support"
    MODEL_UNAVAILABLE = "model_unavailable"


class LabelFlipConfig(BaseModel):
    """Configuration parameters for label-flipping detection policies."""

    model_config = ConfigDict(frozen=True)

    min_total_samples: int = Field(default=25, ge=2, description="Minimum dataset size required for analysis")
    min_class_samples: int = Field(default=5, ge=1, description="Minimum class count required to evaluate as transition source")
    min_transition_count: int = Field(default=3, ge=1, description="Minimum pair count N_{i,j} required to flag directional transitions")
    reciprocal_asym_threshold: float = Field(default=0.35, ge=0.0, le=1.0, description="Maximum |Asym| for symmetric reciprocal confusion")
    directional_asym_threshold: float = Field(default=0.40, ge=0.0, le=1.0, description="Minimum Asym for directional label transition")
    targeted_asym_threshold: float = Field(default=0.50, ge=0.0, le=1.0, description="Minimum Asym for targeted label flip")
    targeted_nci_threshold: float = Field(default=0.50, ge=0.0, le=1.0, description="Minimum Noise Concentration Index for targeted flip")
    targeted_tfs_threshold: float = Field(default=0.40, ge=0.0, le=1.0, description="Minimum Targeted Flipping Score for possible label flip")
    systematic_rate_threshold: float = Field(default=0.20, ge=0.01, le=1.0, description="Minimum transition rate for systematic class transition")
    contributor_diff_threshold: float = Field(default=0.25, ge=0.01, le=1.0, description="Minimum contributor delta rate above dataset baseline")
    min_contributor_samples: int = Field(default=5, ge=1, description="Minimum samples contributed to class i to evaluate contributor delta")
    min_contributor_transition_count: int = Field(default=3, ge=1, description="Minimum contributor transition count to flag finding")
    min_latent_margin_threshold: float = Field(default=0.20, description="Minimum average margin before applying 50% discount")
    support_target_n: float = Field(default=6.0, description="Target sample size for support discount sigmoid midpoint")
    random_seed: int = Field(default=42, description="Deterministic seed for reproducibility")


class LabelTransitionPair(BaseModel):
    """Statistical transition metrics between observed class i and estimated latent class j."""

    model_config = ConfigDict(frozen=True)

    source_category_id: int
    source_category_name: str
    target_category_id: int
    target_category_name: str
    transition_count: int = Field(..., ge=0, description="Count N_{i, j} observed as i but estimated as j")
    reverse_transition_count: int = Field(..., ge=0, description="Count N_{j, i} observed as j but estimated as i")
    source_total_samples: int = Field(..., ge=0, description="Total observed samples |X_{y_tilde=i}|")
    transition_rate: float = Field(..., ge=0.0, le=1.0, description="Conditional rate T_{i -> j} = N_{i,j} / |X_i|")
    reverse_transition_rate: float = Field(..., ge=0.0, le=1.0, description="Reverse conditional rate T_{j -> i}")
    asymmetry_index: float = Field(..., ge=-1.0, le=1.0, description="Asym(i, j) in [-1.0, 1.0]")
    noise_concentration_index: float = Field(..., ge=0.0, le=1.0, description="Proportion of source noise targeting j")
    targeted_flip_score: float = Field(..., ge=0.0, le=1.0, description="Composite discounted score TFS_{i -> j}")
    average_margin: float = Field(..., description="Mean prediction margin across transition samples")
    wilson_lower_bound: float = Field(..., ge=0.0, le=1.0, description="95% Wilson CI lower bound for transition rate")
    support_discount: float = Field(..., ge=0.0, le=1.0, description="Asymptotic support multiplier in [0.0, 1.0]")
    is_targeted: bool = Field(default=False, description="True if satisfies targeted flipping criteria")
    is_reciprocal: bool = Field(default=False, description="True if symmetric confusion")


class ContributorTransitionSummary(BaseModel):
    """Statistical transition differential for a specific contributor on class pair (i, j)."""

    model_config = ConfigDict(frozen=True)

    contributor_id: str
    source_category_id: int
    source_category_name: str
    target_category_id: int
    target_category_name: str
    contributor_transition_count: int = Field(..., ge=0)
    contributor_source_total: int = Field(..., ge=0)
    contributor_transition_rate: float = Field(..., ge=0.0, le=1.0)
    dataset_baseline_rate: float = Field(..., ge=0.0, le=1.0)
    rate_differential: float = Field(..., description="Delta T = T_{contributor} - T_{baseline}")
    support_adequate: bool = Field(default=True, description="True if contributor sample support meets minimum")


class LabelFlipFinding(BaseModel):
    """Immutable assurance finding for a detected label transition pattern under ADR-028."""

    model_config = ConfigDict(frozen=True)

    finding_id: str = Field(..., min_length=1, description="Deterministic unique finding identifier")
    source_category_id: int
    source_category_name: str
    target_category_id: Optional[int] = None
    target_category_name: Optional[str] = None
    category: LabelFlipCategory
    targeted_flip_score: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated statistical confidence")
    evidence_layer: str = Field(default="detection", description="ADR-028 compliance: strictly 'detection'")
    affected_sample_ids: Tuple[str, ...] = Field(default_factory=tuple)
    affected_annotation_ids: Tuple[str, ...] = Field(default_factory=tuple)
    contributor_summaries: Tuple[ContributorTransitionSummary, ...] = Field(default_factory=tuple)
    transition_metrics: Optional[LabelTransitionPair] = None
    limitations: List[str] = Field(default_factory=list)

    @field_validator("affected_sample_ids", "affected_annotation_ids", mode="before")
    @classmethod
    def _coerce_tuples(cls, v: Any) -> Tuple[str, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(str(x) for x in v)
        return v

    @field_validator("contributor_summaries", mode="before")
    @classmethod
    def _coerce_contributor_summaries(cls, v: Any) -> Tuple[ContributorTransitionSummary, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(v)
        return v


class LabelFlipScanResult(BaseModel):
    """Complete, immutable result of a dataset label-flipping audit."""

    model_config = ConfigDict(frozen=True)

    total_samples: int = Field(..., ge=0)
    evaluated_samples: int = Field(..., ge=0)
    transition_matrix: List[List[float]] = Field(default_factory=list, description="K x K row-normalized transition rate matrix T_{i -> j}")
    raw_count_matrix: List[List[int]] = Field(default_factory=list, description="K x K integer transition count matrix N_{i, j}")
    findings: Tuple[LabelFlipFinding, ...] = Field(default_factory=tuple)
    model_state: ModelState = Field(default=ModelState.MODEL_AVAILABLE)
    warnings: List[str] = Field(default_factory=list)
    capability_info: Dict[str, Any] = Field(default_factory=dict)
