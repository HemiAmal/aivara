"""Phase 5.7: Out-of-Distribution (OOD) & Image Quality Analysis Engine (OQAE)."""

from aivara.dataset.ood.detector import (
    OODQualityDetector,
    compute_knn_distance,
    compute_mad_threshold,
    detect_ood_and_quality,
)
from aivara.dataset.ood.drift import (
    compute_energy_distance,
    compute_mmd,
    compute_rbf_kernel_matrix,
    evaluate_distribution_shift,
)
from aivara.dataset.ood.exceptions import (
    FeatureExtractionError,
    ImageQualityError,
    InsufficientReferenceSupportError,
    InvalidReferenceDistributionError,
    OODQualityError,
)
from aivara.dataset.ood.features import (
    VisualFeatureExtractor,
    extract_tier1_statistical_descriptor,
)
from aivara.dataset.ood.quality import (
    compute_color_cast_and_saturation,
    compute_composite_quality_score,
    compute_immerkaer_noise_and_snr,
    compute_jpeg_blockiness,
    compute_luminance_and_exposure,
    compute_tenengrad_sharpness,
    compute_uniform_region_ratio,
    compute_variance_of_laplacian,
    extract_image_quality_metrics,
)
from aivara.dataset.ood.schemas import (
    DistributionShiftEvidence,
    FeatureExtractionStatus,
    ImageQualityConfig,
    ImageQualityMetrics,
    OODCategory,
    OODConfig,
    OODScanFinding,
    OODScanResult,
    OODScore,
    ReferenceDistribution,
    ReferenceMode,
)

__all__ = [
    "OODQualityDetector",
    "detect_ood_and_quality",
    "compute_knn_distance",
    "compute_mad_threshold",
    "compute_energy_distance",
    "compute_mmd",
    "compute_rbf_kernel_matrix",
    "evaluate_distribution_shift",
    "OODQualityError",
    "InsufficientReferenceSupportError",
    "FeatureExtractionError",
    "ImageQualityError",
    "InvalidReferenceDistributionError",
    "VisualFeatureExtractor",
    "extract_tier1_statistical_descriptor",
    "compute_color_cast_and_saturation",
    "compute_composite_quality_score",
    "compute_immerkaer_noise_and_snr",
    "compute_jpeg_blockiness",
    "compute_luminance_and_exposure",
    "compute_tenengrad_sharpness",
    "compute_uniform_region_ratio",
    "compute_variance_of_laplacian",
    "extract_image_quality_metrics",
    "DistributionShiftEvidence",
    "FeatureExtractionStatus",
    "ImageQualityConfig",
    "ImageQualityMetrics",
    "OODCategory",
    "OODConfig",
    "OODScanFinding",
    "OODScanResult",
    "OODScore",
    "ReferenceDistribution",
    "ReferenceMode",
]
