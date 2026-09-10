"""AIVARA Near-Duplicate Detection Engine (Phase 5.4)."""

from aivara.dataset.duplicates.bktree import (
    BKTree,
    BKTreeItem,
    BKTreeNode,
)
from aivara.dataset.duplicates.detector import (
    NearDuplicateDetector,
    detect_near_duplicates,
)
from aivara.dataset.duplicates.distance import (
    hamming_distance,
    hamming_distance_uint64,
    hex_to_uint64,
    uint64_to_hex,
)
from aivara.dataset.duplicates.exceptions import (
    BKTreeError,
    DuplicateDetectionError,
    EmptyIndexError,
    InvalidPerceptualHashError,
    InvalidThresholdError,
    MultiIndexHashError,
)
from aivara.dataset.duplicates.mih import (
    MIHItem,
    MultiIndexHash,
)
from aivara.dataset.duplicates.perceptual import (
    compute_dhash,
    compute_dhash_uint64,
    compute_phash,
    compute_phash_uint64,
)
from aivara.dataset.duplicates.schemas import (
    NearDuplicateCluster,
    NearDuplicateConfig,
    NearDuplicateRelationship,
    NearDuplicateScanResult,
    NearDuplicateStrategy,
    PerceptualFingerprint,
)

__all__ = [
    # Algorithms & Distance
    "compute_phash",
    "compute_phash_uint64",
    "compute_dhash",
    "compute_dhash_uint64",
    "hamming_distance",
    "hamming_distance_uint64",
    "hex_to_uint64",
    "uint64_to_hex",
    # Indexes
    "BKTree",
    "BKTreeItem",
    "BKTreeNode",
    "MultiIndexHash",
    "MIHItem",
    # Detector & Orchestrator
    "NearDuplicateDetector",
    "detect_near_duplicates",
    # Schemas
    "NearDuplicateConfig",
    "NearDuplicateStrategy",
    "PerceptualFingerprint",
    "NearDuplicateRelationship",
    "NearDuplicateCluster",
    "NearDuplicateScanResult",
    # Exceptions
    "DuplicateDetectionError",
    "InvalidPerceptualHashError",
    "InvalidThresholdError",
    "EmptyIndexError",
    "BKTreeError",
    "MultiIndexHashError",
]
