"""Enums for Phase 11 Distribution Shift and Population Boundaries."""

from enum import Enum


class PopulationType(str, Enum):
    """Type of population selection for reference and target datasets."""
    COMPLETE_DATASET = "complete_dataset"
    DATASET_VERSION = "dataset_version"
    CONTRIBUTOR_SUBSET = "contributor_subset"
    TEMPORAL_WINDOW = "temporal_window"
    CLASS_SUBSET = "class_subset"
    EXPLICIT_SAMPLES = "explicit_samples"


class SamplingMethod(str, Enum):
    """Deterministic subsampling algorithms."""
    NONE = "none"
    DETERMINISTIC_SEEDED = "deterministic_seeded"
    HASH_RANKING = "hash_ranking"


class DataModality(str, Enum):
    """Data modality under evaluation."""
    IMAGE = "image"
    TABULAR_FEATURE = "tabular_feature"
    LATENT_EMBEDDING = "latent_embedding"
    CATEGORICAL_LABEL = "categorical_label"


class CompatibilityStatus(str, Enum):
    """Evaluation status of schema/representation compatibility."""
    COMPATIBLE = "compatible"
    INCOMPATIBLE_SCHEMA = "incompatible_schema"
    INCOMPATIBLE_DIMENSIONS = "incompatible_dimensions"
    INCOMPATIBLE_MODALITY = "incompatible_modality"
    INCOMPATIBLE_REPRESENTATION = "incompatible_representation"
    UNSEEN_CLASSES_PRESENT = "unseen_classes_present"


class BoundaryEvaluationStatus(str, Enum):
    """Overall status of comparison boundary construction and validation."""
    VALID = "valid"
    INSUFFICIENT_DATA = "insufficient_data"
    PROJECT_MISMATCH = "project_mismatch"
    INVALID_REFERENCE = "invalid_reference"
    INVALID_TARGET = "invalid_target"
    INCOMPATIBLE_INPUTS = "incompatible_inputs"
    REPRESENTATION_UNAVAILABLE = "representation_unavailable"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"


class StatisticalMethod(str, Enum):
    """Supported statistical testing and distance methods."""
    KOLMOGOROV_SMIRNOV_2SAMPLE = "kolmogorov_smirnov_2sample"
    WASSERSTEIN_1D = "wasserstein_1d"
    POPULATION_STABILITY_INDEX = "population_stability_index"
    CHI_SQUARE_TEST = "chi_square_test"
    TOTAL_VARIATION_DISTANCE = "total_variation_distance"
    JENSEN_SHANNON_DIVERGENCE = "jensen_shannon_divergence"
    KERNEL_MMD = "kernel_mmd"
    ENERGY_DISTANCE = "energy_distance"
    PERMUTATION_TEST = "permutation_test"


class ShiftDecisionState(str, Enum):
    """Dual-gate decision state for distribution shift evaluation."""
    NO_SHIFT_DETECTED = "no_shift_detected"
    SHIFT_DETECTED = "shift_detected"
    SIGNIFICANT_SHIFT = "significant_shift"
    MATERIAL_SHIFT = "material_shift"
    INSUFFICIENT_DATA = "insufficient_data"
    UNVERIFIABLE = "unverifiable"
    INVALID = "invalid"


class MultipleTestingCorrectionMethod(str, Enum):
    """Multiple hypothesis testing error control algorithms."""
    BENJAMINI_HOCHBERG_FDR = "benjamini_hochberg_fdr"
    HOLM_BONFERRONI_FWER = "holm_bonferroni_fwer"
    BONFERRONI = "bonferroni"
    NONE = "none"


class FeatureType(str, Enum):
    """Data type of an individual evaluated feature."""
    NUMERICAL = "numerical"
    CATEGORICAL = "categorical"
    EMBEDDING = "embedding"
    UNKNOWN = "unknown"


class DriftImpactLevel(str, Enum):
    """Severity / operational impact level of localized feature or label drift."""
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FeatureDriftCategory(str, Enum):
    """Taxonomic category of feature or distribution shift."""
    COVARIATE_NUMERICAL = "covariate_numerical"
    COVARIATE_CATEGORICAL = "covariate_categorical"
    LABEL_DISTRIBUTION = "label_distribution"
    LATENT_EMBEDDING = "latent_embedding"


class TemporalWindowStrategy(str, Enum):
    """Partitioning strategy for chronological observations."""
    FIXED_INTERVAL = "fixed_interval"
    SLIDING_WINDOW = "sliding_window"


class TemporalComparisonTopology(str, Enum):
    """Evaluation topology for sequential temporal windows."""
    BASELINE_TO_WINDOWS = "baseline_to_windows"
    ADJACENT_WINDOWS = "adjacent_windows"
    DUAL_TOPOLOGY = "dual_topology"


class TemporalTrajectoryState(str, Enum):
    """Trajectory classification of temporal distribution shift."""
    NO_MATERIAL_SHIFT = "no_material_shift"
    TRANSIENT_SHIFT = "transient_shift"
    PERSISTENT_SHIFT = "persistent_shift"
    GRADUAL_DRIFT = "gradual_drift"
    ABRUPT_SHIFT = "abrupt_shift"
    INSUFFICIENT_DATA = "insufficient_data"
    INSUFFICIENT_TEMPORAL_COVERAGE = "insufficient_temporal_coverage"
    INVALID = "invalid"


class TimestampSource(str, Enum):
    """Authoritative source field for temporal indexing."""
    EVENT_TIME = "event_time"
    INGESTION_TIME = "ingestion_time"


class SourceType(str, Enum):
    """Supported source attribute dimensions."""
    CONTRIBUTOR = "contributor"
    ACQUISITION_CHANNEL = "acquisition_channel"
    COLLECTION_SITE = "collection_site"
    DEVICE_HARDWARE = "device_hardware"
    PIPELINE_VERSION = "pipeline_version"
    CUSTOM = "custom"


class SourceTrustState(str, Enum):
    """Evaluation trust state of claimed vs verified source identity."""
    CLAIMED = "claimed"
    VERIFIED = "verified"
    ASSERTED = "asserted"
    UNVERIFIED = "unverified"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class SourceComparisonTopology(str, Enum):
    """Comparison topology for source groups."""
    SOURCE_VS_REFERENCE = "source_vs_reference"
    SOURCE_VS_BASELINE_POPULATION = "source_vs_baseline_population"


class SourceGroupStatus(str, Enum):
    """Operational eligibility status of a source partition group."""
    ELIGIBLE = "eligible"
    INSUFFICIENT_DATA = "insufficient_data"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    EXCLUDED = "excluded"


class SourceAttributeFallbackPolicy(str, Enum):
    """Fallback handling policy for missing or malformed source metadata."""
    FAIL_CLOSED = "fail_closed"
    ASSIGN_UNKNOWN = "assign_unknown"
    ASSIGN_MISSING = "assign_missing"




