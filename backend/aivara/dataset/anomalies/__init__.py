"""Label Anomaly & Confident Learning Detection Engine (Phase 5.5).

Implements statistical label noise estimation and predictive disagreement auditing
strictly under the invariant: LABEL ANOMALY != MALICIOUSNESS.
"""

from aivara.dataset.anomalies.confident_learning import (
    compute_class_thresholds,
    compute_confident_count_matrix,
    compute_joint_distribution_matrix,
    compute_sample_anomaly_metrics,
    identify_systematic_anomalies,
)
from aivara.dataset.anomalies.detector import (
    LabelAnomalyDetector,
    detect_label_anomalies,
)
from aivara.dataset.anomalies.estimator import (
    DetectorSideCentroidEstimator,
    compute_out_of_fold_probabilities,
)
from aivara.dataset.anomalies.exceptions import (
    InsufficientDataError,
    InvalidFoldSplitError,
    LabelAnomalyError,
    ModelIncompatibleError,
    ModelLoadFailedError,
    ModelUnavailableError,
    UnsupportedModalityError,
)
from aivara.dataset.anomalies.folds import (
    deterministic_stratified_kfold_split,
    generate_deterministic_seed,
)
from aivara.dataset.anomalies.schemas import (
    LabelAnomalyCategory,
    LabelAnomalyConfig,
    LabelAnomalyEvidence,
    LabelAnomalyFinding,
    LabelAnomalyScanResult,
    LabelPrediction,
    ModelState,
)

__all__ = [
    # Schemas
    "ModelState",
    "LabelAnomalyCategory",
    "LabelAnomalyConfig",
    "LabelPrediction",
    "LabelAnomalyEvidence",
    "LabelAnomalyFinding",
    "LabelAnomalyScanResult",
    # Exceptions
    "LabelAnomalyError",
    "ModelUnavailableError",
    "ModelIncompatibleError",
    "ModelLoadFailedError",
    "InsufficientDataError",
    "InvalidFoldSplitError",
    "UnsupportedModalityError",
    # Folds
    "deterministic_stratified_kfold_split",
    "generate_deterministic_seed",
    # Estimator
    "DetectorSideCentroidEstimator",
    "compute_out_of_fold_probabilities",
    # Confident Learning Core
    "compute_class_thresholds",
    "compute_confident_count_matrix",
    "compute_joint_distribution_matrix",
    "compute_sample_anomaly_metrics",
    "identify_systematic_anomalies",
    # Detector & API
    "LabelAnomalyDetector",
    "detect_label_anomalies",
]
