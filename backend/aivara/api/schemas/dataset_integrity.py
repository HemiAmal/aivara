"""Dataset Integrity API request and response schemas (Phase 5.10)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# =====================================================================
# 1. Fingerprinting & Merkle Inclusion Proofs
# =====================================================================

class FingerprintScanRequest(BaseModel):
    """Request payload to compute multi-tier fingerprints and Merkle tree."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36)
    dataset_version_id: Optional[str] = Field(None, max_length=36)
    samples: Optional[List[Dict[str, Any]]] = Field(None, description="In-memory sample descriptors if not resolving from DB")
    include_pixel_hashes: bool = Field(True, description="Whether to compute decoded pixel SHA-256")


class FingerprintScanResponse(BaseModel):
    """Result of multi-tier dataset fingerprinting."""

    model_config = ConfigDict(extra="forbid")

    dataset_fingerprint: str
    merkle_root: str
    sample_count: int
    tree_depth: int
    leaf_hashes: List[str] = Field(default_factory=list)
    status: str = "COMPLETED"


class MerkleProofVerifyRequest(BaseModel):
    """Request to verify cryptographic Merkle inclusion proof."""

    model_config = ConfigDict(extra="ignore")

    sample_hash: Optional[str] = Field(None, min_length=64, max_length=64, description="64-hex SHA-256 sample hash")
    merkle_root: Optional[str] = Field(None, min_length=64, max_length=64, description="Expected 64-hex SHA-256 Merkle root")
    proof_hashes: Optional[List[str]] = Field(None, description="Audit path sibling hashes")
    proof_indices: Optional[List[int]] = Field(None, description="Audit path branch directions (0=left, 1=right)")
    proof_version: str = "1.0"
    dataset_merkle_root: Optional[str] = None
    leaf_index: int = 0
    total_leaves: int = 1
    sample_path: str = "sample.jpg"
    leaf_hash: Optional[str] = None
    audit_path: Optional[List[Dict[str, Any]]] = None


class MerkleProofVerifyResponse(BaseModel):
    """Verification result for a Merkle inclusion proof."""

    model_config = ConfigDict(extra="forbid")

    is_valid: bool
    computed_root: str
    expected_root: str
    message: str


# =====================================================================
# 2. Near-Duplicate Analysis
# =====================================================================

class NearDuplicateScanRequest(BaseModel):
    """Request to detect near-duplicate visual relationships."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36)
    dataset_version_id: Optional[str] = Field(None, max_length=36)
    strategy: str = Field("BK_TREE", description="Matching strategy (BK_TREE, MIH, EXHAUSTIVE)")
    algorithm: str = Field("PHASH_64", description="Hash algorithm (PHASH_64, DHASH_64)")
    threshold: int = Field(5, ge=0, le=64, description="Max Hamming distance threshold")
    samples: Optional[List[Dict[str, Any]]] = Field(None, description="Optional sample descriptors with perceptual hashes")


class NearDuplicateScanResponse(BaseModel):
    """Result of near-duplicate visual analysis."""

    model_config = ConfigDict(extra="forbid")

    total_samples_analyzed: int
    duplicate_pairs_count: int
    cluster_count: int
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    clusters: List[Dict[str, Any]] = Field(default_factory=list)
    config_hash: str
    status: str = "COMPLETED"


# =====================================================================
# 3. Label Anomaly Analysis
# =====================================================================

class LabelAnomalyScanRequest(BaseModel):
    """Request to detect label ambiguities and mislabel anomalies."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36)
    dataset_version_id: Optional[str] = Field(None, max_length=36)
    model_id: Optional[str] = Field(None, max_length=36)
    prune_method: str = Field("both", description="Cleanlab pruning mode (prune_by_noise_rate, prune_by_class, both)")
    confidence_threshold: float = Field(0.65, ge=0.0, le=1.0, description="Minimum prediction margin threshold")
    samples: Optional[List[Dict[str, Any]]] = Field(None)
    predictions: Optional[List[Dict[str, Any]]] = Field(None)


class LabelAnomalyScanResponse(BaseModel):
    """Result of label anomaly and confident learning analysis."""

    model_config = ConfigDict(extra="forbid")

    total_samples_analyzed: int
    anomaly_count: int
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    joint_distribution_summary: Dict[str, Any] = Field(default_factory=dict)
    config_hash: str
    status: str = "COMPLETED"


# =====================================================================
# 4. Label-Flipping Analysis
# =====================================================================

class LabelFlipScanRequest(BaseModel):
    """Request to detect targeted directional label-flipping transitions."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36)
    dataset_version_id: Optional[str] = Field(None, max_length=36)
    min_samples_per_pair: int = Field(5, ge=1, description="Minimum support per class transition pair")
    asymmetry_threshold: float = Field(0.3, ge=0.0, le=1.0)
    noise_concentration_threshold: float = Field(0.4, ge=0.0, le=1.0)
    targeted_flip_threshold: float = Field(0.5, ge=0.0, le=1.0)
    samples: Optional[List[Dict[str, Any]]] = Field(None)
    annotations: Optional[List[Dict[str, Any]]] = Field(None)


class LabelFlipScanResponse(BaseModel):
    """Result of targeted label-flipping detection."""

    model_config = ConfigDict(extra="forbid")

    total_annotations: int
    targeted_flips_detected: int
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    transition_matrix_summary: Dict[str, Any] = Field(default_factory=dict)
    config_hash: str
    status: str = "COMPLETED"


# =====================================================================
# 5. Out-of-Distribution & Image Quality Analysis
# =====================================================================

class OODQualityScanRequest(BaseModel):
    """Request to detect out-of-distribution samples and image quality degradation."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36)
    dataset_version_id: Optional[str] = Field(None, max_length=36)
    reference_mode: str = Field("BASELINE", description="Reference baseline mode (BASELINE, EMBEDDED, DATASET)")
    reference_distribution_id: Optional[str] = Field(None, max_length=36)
    knn_k: int = Field(5, ge=1, le=100)
    mad_threshold: float = Field(3.0, ge=0.1, le=20.0)
    samples: Optional[List[Dict[str, Any]]] = Field(None)


class OODQualityScanResponse(BaseModel):
    """Result of OOD and image quality detection."""

    model_config = ConfigDict(extra="forbid")

    total_samples_analyzed: int
    ood_count: int
    quality_anomaly_count: int
    drift_detected: bool = False
    energy_distance: Optional[float] = None
    mmd_score: Optional[float] = None
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    config_hash: str
    status: str = "COMPLETED"


# =====================================================================
# 6. Contributor Aggregation Analysis
# =====================================================================

class ContributorScanRequest(BaseModel):
    """Request to evaluate contributor statistical anomaly profiles."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(..., min_length=1, max_length=36)
    dataset_version_id: Optional[str] = Field(None, max_length=36)
    min_contributor_samples: int = Field(5, ge=1)
    wilson_confidence: float = Field(0.95, ge=0.50, le=0.999)
    hhi_threshold: float = Field(0.4, ge=0.0, le=1.0)
    anomaly_differential_threshold: float = Field(0.3, ge=0.0, le=1.0)
    samples: Optional[List[Dict[str, Any]]] = Field(None)
    evidence_items: Optional[List[Dict[str, Any]]] = Field(None)


class ContributorScanResponse(BaseModel):
    """Result of contributor aggregation analysis."""

    model_config = ConfigDict(extra="forbid")

    total_contributors: int
    attributed_samples: int
    unattributed_samples: int
    overall_hhi: float
    overall_gini: float
    profiles: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    config_hash: str
    status: str = "COMPLETED"
