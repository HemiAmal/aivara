"""Pydantic schemas and descriptors for Phase 11 Distribution Shift Boundaries."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    CompatibilityStatus,
    DataModality,
    DriftImpactLevel,
    FeatureDriftCategory,
    FeatureType,
    MultipleTestingCorrectionMethod,
    PopulationType,
    SamplingMethod,
    ShiftDecisionState,
    StatisticalMethod,
    TemporalComparisonTopology,
    TemporalTrajectoryState,
    TemporalWindowStrategy,
    TimestampSource,
)




class SamplingConfig(BaseModel):
    """Configuration for deterministic population downsampling."""
    model_config = ConfigDict(frozen=True)

    method: SamplingMethod = Field(
        default=SamplingMethod.DETERMINISTIC_SEEDED,
        description="Sampling method used when N > max_samples.",
    )
    max_samples: int = Field(
        default=5000,
        ge=1,
        le=5000,
        description="Maximum sample evaluation budget (frozen upper bound N <= 5000).",
    )
    seed: int = Field(
        default=42,
        description="Deterministic PRNG seed for reproducible subsampling.",
    )
    preserve_class_balance: bool = Field(
        default=True,
        description="Whether to perform stratified sampling across class labels if available.",
    )


class PopulationSelector(BaseModel):
    """Specification for selecting a reference or target population subset."""
    model_config = ConfigDict(frozen=True)

    population_type: PopulationType = Field(
        default=PopulationType.COMPLETE_DATASET,
        description="Category of population selection.",
    )
    dataset_id: str = Field(..., min_length=1, max_length=64, description="Target dataset ID.")
    dataset_version_id: Optional[str] = Field(None, max_length=64, description="Dataset version ID if specified.")
    contributor_id: Optional[str] = Field(None, max_length=64, description="Contributor filter ID.")
    time_start: Optional[str] = Field(None, description="ISO 8601 UTC start timestamp.")
    time_end: Optional[str] = Field(None, description="ISO 8601 UTC end timestamp.")
    class_filter: Optional[List[str]] = Field(None, description="Class label whitelist filter.")
    sample_ids: Optional[List[str]] = Field(None, description="Explicit sample ID list.")

    @field_validator("class_filter", "sample_ids")
    @classmethod
    def validate_unique_sorted_lists(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            if len(v) != len(set(v)):
                raise ValueError("List must contain unique elements.")
        return v


class FeatureSchemaDescriptor(BaseModel):
    """Descriptor for continuous tabular/numeric feature vectors."""
    model_config = ConfigDict(frozen=True)

    feature_names: List[str] = Field(..., min_length=1, max_length=4096)
    feature_types: Dict[str, str] = Field(default_factory=dict)
    dimensions: int = Field(..., ge=1, le=4096)

    @model_validator(mode="after")
    def check_dimensions(self) -> FeatureSchemaDescriptor:
        if len(self.feature_names) != self.dimensions:
            raise ValueError(f"feature_names length ({len(self.feature_names)}) != dimensions ({self.dimensions}).")
        return self


class LabelSchemaDescriptor(BaseModel):
    """Descriptor for categorical class labels."""
    model_config = ConfigDict(frozen=True)

    class_names: List[str] = Field(..., min_length=1, max_length=10000)
    label_format: str = Field(default="classification", max_length=50)
    num_classes: int = Field(..., ge=1)

    @model_validator(mode="after")
    def check_num_classes(self) -> LabelSchemaDescriptor:
        if len(self.class_names) != len(set(self.class_names)):
            raise ValueError("class_names must contain unique elements.")
        if len(self.class_names) != self.num_classes:
            raise ValueError(f"class_names length ({len(self.class_names)}) != num_classes ({self.num_classes}).")
        return self


class ImageSchemaDescriptor(BaseModel):
    """Descriptor for image datasets under comparison."""
    model_config = ConfigDict(frozen=True)

    allowed_formats: List[str] = Field(default_factory=lambda: ["jpg", "jpeg", "png", "bmp", "webp"])
    min_resolution: Tuple[int, int] = Field(default=(1, 1))
    max_resolution: Tuple[int, int] = Field(default=(10000, 10000))
    channels: int = Field(default=3, ge=1, le=4)
    color_space: str = Field(default="RGB", max_length=20)


class RepresentationDescriptor(BaseModel):
    """Descriptor for latent representation / embedding comparison."""
    model_config = ConfigDict(frozen=True)

    modality: DataModality = Field(default=DataModality.IMAGE)
    model_id: Optional[str] = Field(None, max_length=64)
    model_master_fingerprint: Optional[str] = Field(None, max_length=64)
    feature_extractor_version: Optional[str] = Field(None, max_length=50)
    embedding_dim: Optional[int] = Field(None, ge=1, le=4096)


class PopulationIdentity(BaseModel):
    """Cryptographic identity descriptor for a resolved population."""
    model_config = ConfigDict(frozen=True)

    dataset_id: str
    dataset_version_id: Optional[str] = None
    population_type: PopulationType
    total_available_samples: int
    selected_sample_count: int
    sampling_applied: bool
    sample_ids_hash: str = Field(..., min_length=64, max_length=64)
    population_selection_hash: str = Field(..., min_length=64, max_length=64)


class ComparisonContract(BaseModel):
    """Canonical, immutable comparison contract for distribution shift evaluation."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    analysis_version: str = Field(default="1.0", max_length=20)
    project_id: str = Field(..., min_length=1, max_length=64)
    reference_dataset_id: str = Field(..., min_length=1, max_length=64)
    reference_dataset_version_id: Optional[str] = Field(None, max_length=64)
    target_dataset_id: str = Field(..., min_length=1, max_length=64)
    target_dataset_version_id: Optional[str] = Field(None, max_length=64)
    modality: DataModality
    reference_population_hash: str = Field(..., min_length=64, max_length=64)
    target_population_hash: str = Field(..., min_length=64, max_length=64)
    reference_sample_count: int = Field(..., ge=0)
    target_sample_count: int = Field(..., ge=0)
    sampling_method: str = Field(default="none", max_length=50)
    max_samples_budget: int = Field(default=5000, ge=1, le=5000)
    sampling_seed: Optional[int] = None
    feature_descriptor_hash: Optional[str] = Field(None, max_length=64)
    label_descriptor_hash: Optional[str] = Field(None, max_length=64)
    representation_descriptor_hash: Optional[str] = Field(None, max_length=64)
    resource_policy_version: str = Field(default="1.0", max_length=20)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "analysis_version": self.analysis_version,
            "feature_descriptor_hash": self.feature_descriptor_hash or "",
            "label_descriptor_hash": self.label_descriptor_hash or "",
            "max_samples_budget": self.max_samples_budget,
            "modality": self.modality.value,
            "project_id": self.project_id,
            "reference_dataset_id": self.reference_dataset_id,
            "reference_dataset_version_id": self.reference_dataset_version_id or "",
            "reference_population_hash": self.reference_population_hash,
            "reference_sample_count": self.reference_sample_count,
            "representation_descriptor_hash": self.representation_descriptor_hash or "",
            "resource_policy_version": self.resource_policy_version,
            "sampling_method": self.sampling_method,
            "sampling_seed": self.sampling_seed if self.sampling_seed is not None else -1,
            "schema_version": self.schema_version,
            "target_dataset_id": self.target_dataset_id,
            "target_dataset_version_id": self.target_dataset_version_id or "",
            "target_population_hash": self.target_population_hash,
            "target_sample_count": self.target_sample_count,
        }


class ComparisonBoundaryResult(BaseModel):
    """Result of boundary construction and compatibility validation."""
    model_config = ConfigDict(frozen=True)

    contract: ComparisonContract
    comparison_boundary_hash: str = Field(..., min_length=64, max_length=64)
    reference_population: PopulationIdentity
    target_population: PopulationIdentity
    status: BoundaryEvaluationStatus
    compatibility_status: CompatibilityStatus
    warnings: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 11.3 Statistical Engine Schemas
# ---------------------------------------------------------------------------

class StatisticalAnalysisConfig(BaseModel):
    """Canonical configuration for statistical distribution shift evaluation."""
    model_config = ConfigDict(frozen=True)

    analysis_version: str = Field(default="1.0", max_length=20)
    significance_level: float = Field(default=0.05, gt=0.0, lt=1.0)
    fdr_q_star: float = Field(default=0.05, gt=0.0, lt=1.0)
    psi_moderate_threshold: float = Field(default=0.10, gt=0.0)
    psi_material_threshold: float = Field(default=0.25, gt=0.0)
    tvd_material_threshold: float = Field(default=0.05, gt=0.0, le=1.0)
    jsd_material_threshold: float = Field(default=0.02, gt=0.0)
    mmd_material_threshold: float = Field(default=0.02, gt=0.0)
    energy_material_threshold: float = Field(default=1.0, gt=0.0)
    wasserstein_std_threshold: float = Field(default=0.10, gt=0.0)
    correction_method: MultipleTestingCorrectionMethod = Field(
        default=MultipleTestingCorrectionMethod.BENJAMINI_HOCHBERG_FDR
    )
    num_permutations: int = Field(default=100, ge=10, le=1000)
    seed: int = Field(default=42)
    min_sample_size: int = Field(default=30, ge=5)
    max_sample_size: int = Field(default=5000, le=5000)
    max_features: int = Field(default=4096, le=4096)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "analysis_version": self.analysis_version,
            "correction_method": self.correction_method.value,
            "energy_material_threshold": float(self.energy_material_threshold),
            "fdr_q_star": float(self.fdr_q_star),
            "jsd_material_threshold": float(self.jsd_material_threshold),
            "max_features": int(self.max_features),
            "max_sample_size": int(self.max_sample_size),
            "min_sample_size": int(self.min_sample_size),
            "mmd_material_threshold": float(self.mmd_material_threshold),
            "num_permutations": int(self.num_permutations),
            "psi_material_threshold": float(self.psi_material_threshold),
            "psi_moderate_threshold": float(self.psi_moderate_threshold),
            "seed": int(self.seed),
            "significance_level": float(self.significance_level),
            "tvd_material_threshold": float(self.tvd_material_threshold),
            "wasserstein_std_threshold": float(self.wasserstein_std_threshold),
        }


class FeatureDriftResult(BaseModel):
    """Statistical evaluation result for a single 1D continuous feature."""
    model_config = ConfigDict(frozen=True)

    feature_name: str
    method: StatisticalMethod
    statistic_value: float
    raw_p_value: Optional[float] = None
    adjusted_p_value: Optional[float] = None
    effect_size: float
    effect_size_metric: str
    reference_sample_count: int
    target_sample_count: int
    is_statistically_significant: bool
    is_practically_significant: bool
    status: ShiftDecisionState
    details: Dict[str, Any] = Field(default_factory=dict)


class CategoricalDriftResult(BaseModel):
    """Statistical evaluation result for categorical / label distributions."""
    model_config = ConfigDict(frozen=True)

    attribute_name: str
    chi_square_statistic: Optional[float] = None
    chi_square_p_value: Optional[float] = None
    degrees_of_freedom: Optional[int] = None
    tvd: float
    jsd: float
    reference_proportions: Dict[str, float]
    target_proportions: Dict[str, float]
    unseen_target_classes: List[str] = Field(default_factory=list)
    missing_target_classes: List[str] = Field(default_factory=list)
    is_statistically_significant: bool
    is_practically_significant: bool
    status: ShiftDecisionState
    details: Dict[str, Any] = Field(default_factory=dict)


class MultivariateDriftResult(BaseModel):
    """Statistical evaluation result for multivariate / embedding distributions."""
    model_config = ConfigDict(frozen=True)

    modality: DataModality
    method: StatisticalMethod
    statistic_value: float
    permutation_p_value: Optional[float] = None
    num_permutations: int = 100
    bandwidth: Optional[float] = None
    is_statistically_significant: bool
    is_practically_significant: bool
    status: ShiftDecisionState
    details: Dict[str, Any] = Field(default_factory=dict)


class StatisticalAnalysisResult(BaseModel):
    """Global statistical distribution shift evaluation result."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    analysis_version: str = Field(default="1.0", max_length=20)
    comparison_boundary_hash: str = Field(..., min_length=64, max_length=64)
    analysis_result_hash: str = Field(..., min_length=64, max_length=64)
    config: StatisticalAnalysisConfig
    global_status: ShiftDecisionState
    total_features_tested: int = Field(default=0, ge=0)
    statistically_significant_count: int = Field(default=0, ge=0)
    materially_shifted_count: int = Field(default=0, ge=0)
    feature_results: Dict[str, FeatureDriftResult] = Field(default_factory=dict)
    categorical_results: Dict[str, CategoricalDriftResult] = Field(default_factory=dict)
    multivariate_results: Optional[MultivariateDriftResult] = None
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "analysis_version": self.analysis_version,
            "comparison_boundary_hash": self.comparison_boundary_hash,
            "config": self.config.to_canonical_dict(),
            "global_status": self.global_status.value,
            "materially_shifted_count": self.materially_shifted_count,
            "schema_version": self.schema_version,
            "statistically_significant_count": self.statistically_significant_count,
            "total_features_tested": self.total_features_tested,
        }


# ---------------------------------------------------------------------------
# Phase 11.4 Feature & Dataset Drift Schemas
# ---------------------------------------------------------------------------

class FeatureDriftProfile(BaseModel):
    """Detailed drift profile for an individual numerical or categorical feature."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    feature_id: str = Field(..., min_length=1, max_length=100)
    feature_name: str = Field(..., min_length=1, max_length=100)
    feature_type: FeatureType
    category: FeatureDriftCategory
    method: StatisticalMethod
    statistic_value: float
    raw_p_value: Optional[float] = None
    adjusted_p_value: Optional[float] = None
    effect_size: float
    effect_size_metric: str
    significance_status: bool
    practical_significance_status: bool
    shift_status: ShiftDecisionState
    impact_level: DriftImpactLevel
    rank: int = Field(default=1, ge=1)
    reference_count: int = Field(default=0, ge=0)
    target_count: int = Field(default=0, ge=0)
    details: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "adjusted_p_value": self.adjusted_p_value if self.adjusted_p_value is not None else -1.0,
            "category": self.category.value,
            "effect_size": float(self.effect_size),
            "effect_size_metric": self.effect_size_metric,
            "feature_id": self.feature_id,
            "feature_name": self.feature_name,
            "feature_type": self.feature_type.value,
            "impact_level": self.impact_level.value,
            "method": self.method.value,
            "practical_significance_status": self.practical_significance_status,
            "rank": self.rank,
            "raw_p_value": self.raw_p_value if self.raw_p_value is not None else -1.0,
            "reference_count": self.reference_count,
            "schema_version": self.schema_version,
            "shift_status": self.shift_status.value,
            "significance_status": self.significance_status,
            "statistic_value": float(self.statistic_value),
            "target_count": self.target_count,
        }


class LabelDriftProfile(BaseModel):
    """Detailed class label distribution drift profile."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    attribute_name: str = Field(default="class_labels", max_length=100)
    chi_square_statistic: Optional[float] = None
    chi_square_p_value: Optional[float] = None
    degrees_of_freedom: Optional[int] = None
    tvd: float = Field(..., ge=0.0, le=1.0)
    jsd: float = Field(..., ge=0.0, le=1.0)
    reference_proportions: Dict[str, float] = Field(default_factory=dict)
    target_proportions: Dict[str, float] = Field(default_factory=dict)
    unseen_classes: List[str] = Field(default_factory=list)
    missing_classes: List[str] = Field(default_factory=list)
    is_imbalanced: bool = False
    imbalance_ratio: Optional[float] = None
    shift_status: ShiftDecisionState
    impact_level: DriftImpactLevel
    details: Dict[str, Any] = Field(default_factory=dict)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "attribute_name": self.attribute_name,
            "chi_square_p_value": self.chi_square_p_value if self.chi_square_p_value is not None else -1.0,
            "chi_square_statistic": float(self.chi_square_statistic) if self.chi_square_statistic is not None else -1.0,
            "degrees_of_freedom": self.degrees_of_freedom if self.degrees_of_freedom is not None else -1,
            "impact_level": self.impact_level.value,
            "is_imbalanced": self.is_imbalanced,
            "jsd": float(self.jsd),
            "missing_classes": sorted(self.missing_classes),
            "schema_version": self.schema_version,
            "shift_status": self.shift_status.value,
            "tvd": float(self.tvd),
            "unseen_classes": sorted(self.unseen_classes),
        }


class DatasetDriftProfile(BaseModel):
    """Dataset-level synthesized drift profile and localization summary."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    analysis_version: str = Field(default="1.0", max_length=20)
    comparison_boundary_hash: str = Field(..., min_length=64, max_length=64)
    statistical_analysis_hash: str = Field(..., min_length=64, max_length=64)
    dataset_drift_profile_hash: str = Field(..., min_length=64, max_length=64)
    project_id: str = Field(..., min_length=1, max_length=64)
    reference_dataset_id: str = Field(..., min_length=1, max_length=64)
    target_dataset_id: str = Field(..., min_length=1, max_length=64)
    global_status: ShiftDecisionState
    total_features_evaluated: int = Field(default=0, ge=0)
    total_numerical_features: int = Field(default=0, ge=0)
    total_categorical_features: int = Field(default=0, ge=0)
    statistically_significant_feature_count: int = Field(default=0, ge=0)
    materially_shifted_feature_count: int = Field(default=0, ge=0)
    untestable_feature_count: int = Field(default=0, ge=0)
    affected_numerical_features: List[str] = Field(default_factory=list)
    affected_categorical_features: List[str] = Field(default_factory=list)
    top_shifted_features: List[FeatureDriftProfile] = Field(default_factory=list)
    all_feature_profiles: Dict[str, FeatureDriftProfile] = Field(default_factory=dict)
    label_drift_profile: Optional[LabelDriftProfile] = None
    untestable_features: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "affected_categorical_features": sorted(self.affected_categorical_features),
            "affected_numerical_features": sorted(self.affected_numerical_features),
            "analysis_version": self.analysis_version,
            "comparison_boundary_hash": self.comparison_boundary_hash,
            "global_status": self.global_status.value,
            "materially_shifted_feature_count": self.materially_shifted_feature_count,
            "project_id": self.project_id,
            "reference_dataset_id": self.reference_dataset_id,
            "schema_version": self.schema_version,
            "statistical_analysis_hash": self.statistical_analysis_hash,
            "statistically_significant_feature_count": self.statistically_significant_feature_count,
            "target_dataset_id": self.target_dataset_id,
            "total_categorical_features": self.total_categorical_features,
            "total_features_evaluated": self.total_features_evaluated,
            "total_numerical_features": self.total_numerical_features,
            "untestable_feature_count": self.untestable_feature_count,
            "untestable_features": sorted(self.untestable_features),
        }


# ---------------------------------------------------------------------------
# Phase 11.5 Image Distribution Shift Schemas
# ---------------------------------------------------------------------------

class ImagePopulationAccounting(BaseModel):
    """Detailed sample and error accounting for image population processing."""
    model_config = ConfigDict(frozen=True)

    reference_total_images: int = Field(default=0, ge=0)
    reference_analyzable_images: int = Field(default=0, ge=0)
    reference_corrupt_images: int = Field(default=0, ge=0)
    reference_unsupported_images: int = Field(default=0, ge=0)
    reference_missing_images: int = Field(default=0, ge=0)

    target_total_images: int = Field(default=0, ge=0)
    target_analyzable_images: int = Field(default=0, ge=0)
    target_corrupt_images: int = Field(default=0, ge=0)
    target_unsupported_images: int = Field(default=0, ge=0)
    target_missing_images: int = Field(default=0, ge=0)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "reference_analyzable_images": self.reference_analyzable_images,
            "reference_corrupt_images": self.reference_corrupt_images,
            "reference_missing_images": self.reference_missing_images,
            "reference_total_images": self.reference_total_images,
            "reference_unsupported_images": self.reference_unsupported_images,
            "target_analyzable_images": self.target_analyzable_images,
            "target_corrupt_images": self.target_corrupt_images,
            "target_missing_images": self.target_missing_images,
            "target_total_images": self.target_total_images,
            "target_unsupported_images": self.target_unsupported_images,
        }


class ImageDriftProfile(BaseModel):
    """Image-level synthesized drift profile, localization summary, and population accounting."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    analysis_version: str = Field(default="1.0", max_length=20)
    comparison_boundary_hash: str = Field(..., min_length=64, max_length=64)
    statistical_analysis_hash: str = Field(..., min_length=64, max_length=64)
    image_drift_profile_hash: str = Field(..., min_length=64, max_length=64)
    project_id: str = Field(..., min_length=1, max_length=64)
    reference_dataset_id: str = Field(..., min_length=1, max_length=64)
    target_dataset_id: str = Field(..., min_length=1, max_length=64)
    global_status: ShiftDecisionState
    accounting: ImagePopulationAccounting
    format_drift: Optional[CategoricalDriftResult] = None
    dimension_drift: Dict[str, FeatureDriftProfile] = Field(default_factory=dict)
    pixel_drift: Dict[str, FeatureDriftProfile] = Field(default_factory=dict)
    quality_drift: Dict[str, FeatureDriftProfile] = Field(default_factory=dict)
    all_descriptor_profiles: Dict[str, FeatureDriftProfile] = Field(default_factory=dict)
    top_shifted_descriptors: List[FeatureDriftProfile] = Field(default_factory=list)
    materially_shifted_descriptor_count: int = Field(default=0, ge=0)
    statistically_significant_descriptor_count: int = Field(default=0, ge=0)
    total_descriptors_evaluated: int = Field(default=0, ge=0)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "accounting": self.accounting.to_canonical_dict(),
            "analysis_version": self.analysis_version,
            "comparison_boundary_hash": self.comparison_boundary_hash,
            "dimension_drift_keys": sorted(self.dimension_drift.keys()),
            "format_drift_present": self.format_drift is not None,
            "global_status": self.global_status.value,
            "materially_shifted_descriptor_count": self.materially_shifted_descriptor_count,
            "pixel_drift_keys": sorted(self.pixel_drift.keys()),
            "project_id": self.project_id,
            "quality_drift_keys": sorted(self.quality_drift.keys()),
            "reference_dataset_id": self.reference_dataset_id,
            "schema_version": self.schema_version,
            "statistical_analysis_hash": self.statistical_analysis_hash,
            "statistically_significant_descriptor_count": self.statistically_significant_descriptor_count,
            "target_dataset_id": self.target_dataset_id,
            "total_descriptors_evaluated": self.total_descriptors_evaluated,
        }


# ---------------------------------------------------------------------------
# Phase 11.6 Representation & Embedding Distribution Shift Schemas
# ---------------------------------------------------------------------------

class RepresentationContract(BaseModel):
    """Canonical, immutable specification of the learned representation pipeline."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    contract_version: str = Field(default="1.0", max_length=20)
    representation_id: str = Field(..., min_length=1, max_length=100)
    modality: DataModality = Field(default=DataModality.IMAGE)
    model_id: str = Field(..., min_length=1, max_length=100)
    model_master_fingerprint: str = Field(default="", max_length=64)
    model_artifact_hash: str = Field(default="", max_length=64)
    model_format: str = Field(default="ONNX", max_length=32)
    runtime_framework: str = Field(default="onnxruntime", max_length=32)
    representation_layer: str = Field(default="norm", max_length=100)
    embedding_dimension: int = Field(default=384, ge=1, le=4096)
    preprocessing_contract_hash: str = Field(default="", max_length=64)
    normalization_policy: str = Field(default="L2", max_length=32)
    numerical_precision: str = Field(default="float32", max_length=32)
    execution_device_policy: str = Field(default="CPU", max_length=32)
    batch_size: int = Field(default=32, ge=1, le=1024)
    representation_contract_hash: str = Field(default="", max_length=64)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "batch_size": self.batch_size,
            "contract_version": self.contract_version,
            "embedding_dimension": self.embedding_dimension,
            "execution_device_policy": self.execution_device_policy,
            "modality": self.modality.value,
            "model_artifact_hash": self.model_artifact_hash,
            "model_format": self.model_format,
            "model_id": self.model_id,
            "model_master_fingerprint": self.model_master_fingerprint,
            "normalization_policy": self.normalization_policy,
            "numerical_precision": self.numerical_precision,
            "preprocessing_contract_hash": self.preprocessing_contract_hash,
            "representation_id": self.representation_id,
            "representation_layer": self.representation_layer,
            "runtime_framework": self.runtime_framework,
            "schema_version": self.schema_version,
        }


class RepresentationPopulationAccounting(BaseModel):
    """Detailed sample and error accounting for representation extraction and evaluation."""
    model_config = ConfigDict(frozen=True)

    reference_total_images: int = Field(default=0, ge=0)
    reference_valid_embeddings: int = Field(default=0, ge=0)
    reference_extraction_failures: int = Field(default=0, ge=0)
    reference_invalid_embeddings: int = Field(default=0, ge=0)

    target_total_images: int = Field(default=0, ge=0)
    target_valid_embeddings: int = Field(default=0, ge=0)
    target_extraction_failures: int = Field(default=0, ge=0)
    target_invalid_embeddings: int = Field(default=0, ge=0)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "reference_extraction_failures": self.reference_extraction_failures,
            "reference_invalid_embeddings": self.reference_invalid_embeddings,
            "reference_total_images": self.reference_total_images,
            "reference_valid_embeddings": self.reference_valid_embeddings,
            "target_extraction_failures": self.target_extraction_failures,
            "target_invalid_embeddings": self.target_invalid_embeddings,
            "target_total_images": self.target_total_images,
            "target_valid_embeddings": self.target_valid_embeddings,
        }


class RepresentationDriftProfile(BaseModel):
    """High-dimensional representation and embedding distribution shift profile."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    analysis_version: str = Field(default="1.0", max_length=20)
    comparison_boundary_hash: str = Field(..., min_length=64, max_length=64)
    representation_contract_hash: str = Field(..., min_length=64, max_length=64)
    statistical_analysis_hash: str = Field(..., min_length=64, max_length=64)
    representation_drift_profile_hash: str = Field(..., min_length=64, max_length=64)
    project_id: str = Field(..., min_length=1, max_length=64)
    reference_dataset_id: str = Field(..., min_length=1, max_length=64)
    target_dataset_id: str = Field(..., min_length=1, max_length=64)
    global_status: ShiftDecisionState
    accounting: RepresentationPopulationAccounting
    multivariate_result: Optional[MultivariateDriftResult] = None
    embedding_dimension: int = Field(..., ge=1, le=4096)
    normalization_policy: str = Field(default="L2", max_length=32)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "accounting": self.accounting.to_canonical_dict(),
            "analysis_version": self.analysis_version,
            "comparison_boundary_hash": self.comparison_boundary_hash,
            "embedding_dimension": self.embedding_dimension,
            "global_status": self.global_status.value,
            "multivariate_statistic_present": self.multivariate_result is not None,
            "normalization_policy": self.normalization_policy,
            "project_id": self.project_id,
            "reference_dataset_id": self.reference_dataset_id,
            "representation_contract_hash": self.representation_contract_hash,
            "schema_version": self.schema_version,
            "statistical_analysis_hash": self.statistical_analysis_hash,
            "target_dataset_id": self.target_dataset_id,
        }


# ---------------------------------------------------------------------------
# Phase 11.7 Temporal & Windowed Distribution Shift Schemas
# ---------------------------------------------------------------------------

class TemporalObservation(BaseModel):
    """Abstraction for a time-indexed observation within a population dataset."""
    model_config = ConfigDict(frozen=True)

    sample_id: str = Field(..., min_length=1, max_length=128)
    timestamp_raw: Any = Field(..., description="Raw timestamp input (ISO string, datetime, float/int seconds).")
    normalized_timestamp_utc: str = Field(..., min_length=20, max_length=40, description="ISO 8601 UTC string.")
    payload: Any = Field(default=None, description="Observation payload (feature vector, image, or precomputed embedding).")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TemporalAnalysisContract(BaseModel):
    """Canonical, immutable specification for temporal and windowed distribution-shift evaluation."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    contract_version: str = Field(default="1.0", max_length=20)
    temporal_analysis_id: str = Field(..., min_length=1, max_length=100)
    timestamp_field: TimestampSource = Field(default=TimestampSource.EVENT_TIME)
    timezone_policy: str = Field(default="UTC", max_length=32)
    window_strategy: TemporalWindowStrategy = Field(default=TemporalWindowStrategy.FIXED_INTERVAL)
    window_size_seconds: float = Field(default=86400.0, gt=0.0, description="Window time duration in seconds (default: 1 day).")
    step_size_seconds: Optional[float] = Field(default=None, gt=0.0, description="Step size for sliding window (must be >= window_size/2).")
    max_windows: int = Field(default=50, ge=2, le=50)
    min_window_samples: int = Field(default=30, ge=5, le=5000)
    max_window_samples: int = Field(default=5000, ge=30, le=5000)
    baseline_policy: str = Field(default="first_window", max_length=64)
    comparison_topology: TemporalComparisonTopology = Field(default=TemporalComparisonTopology.DUAL_TOPOLOGY)
    declared_seasonality_period_seconds: Optional[float] = Field(default=None, gt=0.0)
    temporal_contract_hash: str = Field(default="", max_length=64)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "baseline_policy": self.baseline_policy,
            "comparison_topology": self.comparison_topology.value,
            "contract_version": self.contract_version,
            "declared_seasonality_period_seconds": float(self.declared_seasonality_period_seconds) if self.declared_seasonality_period_seconds is not None else -1.0,
            "max_window_samples": int(self.max_window_samples),
            "max_windows": int(self.max_windows),
            "min_window_samples": int(self.min_window_samples),
            "schema_version": self.schema_version,
            "step_size_seconds": float(self.step_size_seconds) if self.step_size_seconds is not None else -1.0,
            "temporal_analysis_id": self.temporal_analysis_id,
            "timestamp_field": self.timestamp_field.value,
            "timezone_policy": self.timezone_policy,
            "window_size_seconds": float(self.window_size_seconds),
            "window_strategy": self.window_strategy.value,
        }


class TemporalWindowAccounting(BaseModel):
    """Detailed sample and window error accounting for temporal analysis."""
    model_config = ConfigDict(frozen=True)

    total_observations: int = Field(default=0, ge=0)
    valid_timestamp_observations: int = Field(default=0, ge=0)
    missing_timestamp_observations: int = Field(default=0, ge=0)
    invalid_timestamp_observations: int = Field(default=0, ge=0)
    total_windows_generated: int = Field(default=0, ge=0)
    valid_windows_count: int = Field(default=0, ge=0)
    sparse_windows_count: int = Field(default=0, ge=0)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "invalid_timestamp_observations": self.invalid_timestamp_observations,
            "missing_timestamp_observations": self.missing_timestamp_observations,
            "sparse_windows_count": self.sparse_windows_count,
            "total_observations": self.total_observations,
            "total_windows_generated": self.total_windows_generated,
            "valid_timestamp_observations": self.valid_timestamp_observations,
            "valid_windows_count": self.valid_windows_count,
        }


class TemporalWindowDescriptor(BaseModel):
    """Deterministic cryptographic identity descriptor for an individual temporal observation window."""
    model_config = ConfigDict(frozen=True)

    window_index: int = Field(..., ge=0)
    window_id: str = Field(..., min_length=1, max_length=100)
    start_time_utc: str = Field(..., min_length=20, max_length=40)
    end_time_utc: str = Field(..., min_length=20, max_length=40)
    sample_count: int = Field(..., ge=0)
    is_valid: bool = Field(default=True)
    window_hash: str = Field(..., min_length=64, max_length=64)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "end_time_utc": self.end_time_utc,
            "is_valid": self.is_valid,
            "sample_count": self.sample_count,
            "start_time_utc": self.start_time_utc,
            "window_id": self.window_id,
            "window_index": self.window_index,
        }


class TemporalComparisonResult(BaseModel):
    """Evaluation result for a pairwise temporal window comparison (Baseline-to-Window or Adjacent)."""
    model_config = ConfigDict(frozen=True)

    comparison_id: str = Field(..., min_length=1, max_length=100)
    comparison_type: str = Field(..., description="'baseline_to_window' or 'adjacent_window'")
    reference_window_index: int = Field(..., ge=0)
    target_window_index: int = Field(..., ge=0)
    reference_window_id: str = Field(..., min_length=1, max_length=100)
    target_window_id: str = Field(..., min_length=1, max_length=100)
    reference_sample_count: int = Field(..., ge=0)
    target_sample_count: int = Field(..., ge=0)
    statistical_analysis_hash: str = Field(default="", max_length=64)
    statistic_method: str = Field(default="kernel_mmd", max_length=64)
    statistic_value: float = Field(default=0.0)
    raw_p_value: Optional[float] = None
    adjusted_p_value: Optional[float] = None
    effect_size: float = Field(default=0.0)
    is_statistically_significant: bool = False
    is_practically_significant: bool = False
    status: ShiftDecisionState = ShiftDecisionState.NO_SHIFT_DETECTED
    details: Dict[str, Any] = Field(default_factory=dict)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "adjusted_p_value": self.adjusted_p_value if self.adjusted_p_value is not None else -1.0,
            "comparison_id": self.comparison_id,
            "comparison_type": self.comparison_type,
            "effect_size": float(self.effect_size),
            "is_practically_significant": self.is_practically_significant,
            "is_statistically_significant": self.is_statistically_significant,
            "raw_p_value": self.raw_p_value if self.raw_p_value is not None else -1.0,
            "reference_sample_count": self.reference_sample_count,
            "reference_window_id": self.reference_window_id,
            "reference_window_index": self.reference_window_index,
            "statistic_method": self.statistic_method,
            "statistic_value": float(self.statistic_value),
            "status": self.status.value,
            "target_sample_count": self.target_sample_count,
            "target_window_id": self.target_window_id,
            "target_window_index": self.target_window_index,
        }


class ChangePointCandidate(BaseModel):
    """Candidate distribution regime shift point identified along the temporal horizon."""
    model_config = ConfigDict(frozen=True)

    window_boundary_index: int = Field(..., ge=0)
    candidate_timestamp_utc: str = Field(..., min_length=20, max_length=40)
    adjacent_discrepancy: float = Field(..., ge=0.0)
    permutation_p_value: Optional[float] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    supporting_evidence: str = Field(..., min_length=1)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "adjacent_discrepancy": float(self.adjacent_discrepancy),
            "candidate_timestamp_utc": self.candidate_timestamp_utc,
            "confidence": float(self.confidence),
            "permutation_p_value": self.permutation_p_value if self.permutation_p_value is not None else -1.0,
            "supporting_evidence": self.supporting_evidence,
            "window_boundary_index": self.window_boundary_index,
        }


class TemporalAnalysisProfile(BaseModel):
    """Comprehensive temporal and windowed distribution-shift evaluation profile."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default="1.0", max_length=20)
    analysis_version: str = Field(default="1.0", max_length=20)
    comparison_boundary_hash: str = Field(..., min_length=64, max_length=64)
    temporal_contract_hash: str = Field(..., min_length=64, max_length=64)
    temporal_analysis_profile_hash: str = Field(..., min_length=64, max_length=64)
    project_id: str = Field(..., min_length=1, max_length=64)
    reference_dataset_id: str = Field(..., min_length=1, max_length=64)
    target_dataset_id: str = Field(..., min_length=1, max_length=64)
    global_trajectory_status: TemporalTrajectoryState
    accounting: TemporalWindowAccounting
    baseline_window: Optional[TemporalWindowDescriptor] = None
    windows: List[TemporalWindowDescriptor] = Field(default_factory=list)
    baseline_comparisons: List[TemporalComparisonResult] = Field(default_factory=list)
    adjacent_comparisons: List[TemporalComparisonResult] = Field(default_factory=list)
    change_points: List[ChangePointCandidate] = Field(default_factory=list)
    earliest_timestamp_utc: Optional[str] = None
    latest_timestamp_utc: Optional[str] = None
    total_temporal_span_seconds: float = Field(default=0.0, ge=0.0)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_records: List[Dict[str, Any]] = Field(default_factory=list)

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to strictly sorted canonical dictionary for RFC 8785 JCS hashing."""
        return {
            "accounting": self.accounting.to_canonical_dict(),
            "adjacent_comparisons_count": len(self.adjacent_comparisons),
            "analysis_version": self.analysis_version,
            "baseline_comparisons_count": len(self.baseline_comparisons),
            "change_points_count": len(self.change_points),
            "comparison_boundary_hash": self.comparison_boundary_hash,
            "earliest_timestamp_utc": self.earliest_timestamp_utc or "",
            "global_trajectory_status": self.global_trajectory_status.value,
            "latest_timestamp_utc": self.latest_timestamp_utc or "",
            "project_id": self.project_id,
            "reference_dataset_id": self.reference_dataset_id,
            "schema_version": self.schema_version,
            "target_dataset_id": self.target_dataset_id,
            "temporal_contract_hash": self.temporal_contract_hash,
            "total_temporal_span_seconds": float(self.total_temporal_span_seconds),
            "windows_count": len(self.windows),
        }





