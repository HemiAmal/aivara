"""Label-Flipping Detection Engine (Phase 5.6).

Detects directional, asymmetric, and targeted label transition patterns in computer vision datasets.
MANDATORY INVARIANT: LABEL-FLIPPING EVIDENCE != MALICIOUSNESS.
"""

from aivara.dataset.flipping.detector import (
    LabelFlipDetector,
    detect_label_flipping,
)
from aivara.dataset.flipping.exceptions import (
    InsufficientSupportError,
    InvalidTransitionMatrixError,
    LabelFlippingError,
)
from aivara.dataset.flipping.metrics import (
    compute_directional_asymmetry,
    compute_noise_concentration_index,
    compute_row_normalized_transition_rates,
    compute_support_discount,
    compute_targeted_flip_score,
    compute_transition_count_matrix,
    compute_wilson_lower_bound,
)
from aivara.dataset.flipping.schemas import (
    ContributorTransitionSummary,
    LabelFlipCategory,
    LabelFlipConfig,
    LabelFlipFinding,
    LabelFlipScanResult,
    LabelTransitionPair,
)

__all__ = [
    # Schemas
    "LabelFlipCategory",
    "LabelFlipConfig",
    "LabelTransitionPair",
    "ContributorTransitionSummary",
    "LabelFlipFinding",
    "LabelFlipScanResult",
    # Exceptions
    "LabelFlippingError",
    "InsufficientSupportError",
    "InvalidTransitionMatrixError",
    # Metrics
    "compute_transition_count_matrix",
    "compute_row_normalized_transition_rates",
    "compute_directional_asymmetry",
    "compute_noise_concentration_index",
    "compute_support_discount",
    "compute_targeted_flip_score",
    "compute_wilson_lower_bound",
    # Detector
    "LabelFlipDetector",
    "detect_label_flipping",
]
