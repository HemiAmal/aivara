"""Domain models and schemas for Near-Duplicate Detection Engine (Phase 5.4).

All schemas are strictly immutable (frozen=True) and deterministic.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, field_validator


class NearDuplicateStrategy(str, Enum):
    """Strategy for evaluating dual-hash perceptual similarity."""
    MATCH_BOTH = "match_both"  # Both pHash and dHash must be within their thresholds
    MATCH_ANY = "match_any"    # Either pHash or dHash within threshold qualifies as candidate
    WEIGHTED = "weighted"      # Weighted composite similarity score threshold


class NearDuplicateConfig(BaseModel):
    """Configuration parameters for near-duplicate indexing and detection."""

    model_config = ConfigDict(frozen=True)

    phash_threshold: int = Field(
        default=10,
        ge=0,
        le=64,
        description="Maximum pHash Hamming distance to consider as candidate duplicate (0=exact)",
    )
    dhash_threshold: int = Field(
        default=10,
        ge=0,
        le=64,
        description="Maximum dHash Hamming distance to consider as candidate duplicate (0=exact)",
    )
    strategy: NearDuplicateStrategy = Field(
        default=NearDuplicateStrategy.MATCH_BOTH,
        description="Dual-hash matching policy",
    )
    weighted_min_similarity: float = Field(
        default=0.84,
        ge=0.0,
        le=1.0,
        description="Minimum similarity score threshold when strategy is WEIGHTED",
    )
    phash_weight: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Weight of pHash in composite similarity score",
    )
    dhash_weight: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Weight of dHash in composite similarity score",
    )


class PerceptualFingerprint(BaseModel):
    """Compact 64-bit perceptual fingerprint container for a sample."""

    model_config = ConfigDict(frozen=True)

    sample_id: str = Field(..., min_length=1)
    relative_path: str = Field(..., min_length=1)
    phash: str = Field(..., pattern=r"^[0-9a-f]{16}$", description="16-character lowercase hex pHash")
    dhash: str = Field(..., pattern=r"^[0-9a-f]{16}$", description="16-character lowercase hex dHash")
    contributors: Tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("contributors", mode="before")
    @classmethod
    def _coerce_contributors(cls, v: Any) -> Tuple[str, ...]:
        if isinstance(v, (list, tuple)):
            return tuple(str(x) for x in v)
        return v


class NearDuplicateRelationship(BaseModel):
    """Immutable undirected pairwise relationship between two near-duplicate samples."""

    model_config = ConfigDict(frozen=True)

    sample_a_id: str = Field(..., description="Canonical sample ID of first sample (lexicographically smaller)")
    sample_a_path: str = Field(..., description="Relative path of first sample")
    sample_b_id: str = Field(..., description="Canonical sample ID of second sample (lexicographically larger)")
    sample_b_path: str = Field(..., description="Relative path of second sample")
    phash_a: str = Field(..., pattern=r"^[0-9a-f]{16}$")
    phash_b: str = Field(..., pattern=r"^[0-9a-f]{16}$")
    phash_distance: int = Field(..., ge=0, le=64)
    dhash_a: str = Field(..., pattern=r"^[0-9a-f]{16}$")
    dhash_b: str = Field(..., pattern=r"^[0-9a-f]{16}$")
    dhash_distance: int = Field(..., ge=0, le=64)
    similarity_score: float = Field(..., ge=0.0, le=1.0, description="Normalized composite visual similarity [0.0, 1.0]")
    is_exact_perceptual_match: bool = Field(default=False, description="True if both pHash and dHash distances are 0")
    contributors_a: Tuple[str, ...] = Field(default_factory=tuple)
    contributors_b: Tuple[str, ...] = Field(default_factory=tuple)


class NearDuplicateCluster(BaseModel):
    """Connected component cluster representing a set of mutually linked near-duplicate samples."""

    model_config = ConfigDict(frozen=True)

    cluster_id: str = Field(..., min_length=1, description="Deterministic unique cluster identifier")
    sample_count: int = Field(..., ge=2, description="Total number of samples in the connected cluster")
    sample_ids: Tuple[str, ...] = Field(..., description="Sorted list of sample IDs in cluster")
    sample_paths: Tuple[str, ...] = Field(..., description="Sorted list of sample relative paths in cluster")
    relationships: Tuple[NearDuplicateRelationship, ...] = Field(
        default_factory=tuple, description="All pairwise relationships spanning this cluster"
    )
    contributors: Tuple[str, ...] = Field(
        default_factory=tuple, description="Deduplicated union of contributors associated with cluster samples"
    )


class NearDuplicateScanResult(BaseModel):
    """Structured result returned by the Near-Duplicate Detection Engine."""

    model_config = ConfigDict(frozen=True)

    total_samples: int = Field(..., ge=0)
    indexed_samples: int = Field(..., ge=0)
    candidate_pairs_evaluated: int = Field(..., ge=0)
    duplicate_relationships_count: int = Field(..., ge=0)
    cluster_count: int = Field(..., ge=0)
    relationships: Tuple[NearDuplicateRelationship, ...] = Field(default_factory=tuple)
    clusters: Tuple[NearDuplicateCluster, ...] = Field(default_factory=tuple)
    config: NearDuplicateConfig
    warnings: List[str] = Field(default_factory=list)
    capability_info: Dict[str, Any] = Field(default_factory=dict)
