"""Pydantic schemas and enums for Reference Model Comparison & Drift Attribution (Phase 7.5).

Defines deterministic data structures for multi-tier model comparisons, tensor-level
change attribution, structural differences, contract differences, and 8-state drift classifications.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.model_integrity.fingerprinting.schemas import MerkleInclusionProof


class ComparisonStatus(str, Enum):
    """Overall feasibility and validity status of model comparison."""

    COMPARABLE = "COMPARABLE"                            # Both models valid and fully comparable
    PARTIALLY_COMPARABLE = "PARTIALLY_COMPARABLE"        # Subset of dimensions comparable
    UNCOMPARABLE = "UNCOMPARABLE"                        # Incompatible or insufficient comparison data
    REFERENCE_UNVERIFIABLE = "REFERENCE_UNVERIFIABLE"    # Reference cannot be verified
    CANDIDATE_UNVERIFIABLE = "CANDIDATE_UNVERIFIABLE"    # Candidate cannot be verified
    INVALID_REFERENCE = "INVALID_REFERENCE"              # Reference model metadata is invalid/corrupt
    INVALID_CANDIDATE = "INVALID_CANDIDATE"              # Candidate model metadata is invalid/corrupt


class ArtifactComparisonStatus(str, Enum):
    """Outcome of raw byte-level artifact identity comparison."""

    ARTIFACT_MATCH = "ARTIFACT_MATCH"
    ARTIFACT_DIFFERENT = "ARTIFACT_DIFFERENT"
    ARTIFACT_UNAVAILABLE = "ARTIFACT_UNAVAILABLE"


class StructuralComparisonStatus(str, Enum):
    """Outcome of structural architecture and graph identity comparison."""

    STRUCTURE_MATCH = "STRUCTURE_MATCH"
    STRUCTURAL_DRIFT = "STRUCTURAL_DRIFT"
    STRUCTURE_UNAVAILABLE = "STRUCTURE_UNAVAILABLE"


class WeightComparisonStatus(str, Enum):
    """Outcome of weight Merkle root comparison."""

    WEIGHT_MERKLE_MATCH = "WEIGHT_MERKLE_MATCH"
    WEIGHT_DRIFT = "WEIGHT_DRIFT"
    WEIGHT_COMPARISON_UNAVAILABLE = "WEIGHT_COMPARISON_UNAVAILABLE"


class ContractComparisonStatus(str, Enum):
    """Outcome of operational I/O contract identity comparison."""

    CONTRACT_MATCH = "CONTRACT_MATCH"
    CONTRACT_DRIFT = "CONTRACT_DRIFT"
    CONTRACT_COMPARISON_UNAVAILABLE = "CONTRACT_COMPARISON_UNAVAILABLE"


class DriftClassification(str, Enum):
    """Deterministic eight-state multi-tier drift classification matrix."""

    EXACT_INTEGRITY_MATCH = "EXACT_INTEGRITY_MATCH"                      # S=0, W=0, C=0
    WEIGHT_ONLY_DRIFT = "WEIGHT_ONLY_DRIFT"                              # S=0, W=1, C=0
    STRUCTURAL_ONLY_DRIFT = "STRUCTURAL_ONLY_DRIFT"                      # S=1, W=0, C=0
    CONTRACT_ONLY_DRIFT = "CONTRACT_ONLY_DRIFT"                          # S=0, W=0, C=1
    STRUCTURAL_AND_WEIGHT_DRIFT = "STRUCTURAL_AND_WEIGHT_DRIFT"          # S=1, W=1, C=0
    STRUCTURAL_AND_CONTRACT_DRIFT = "STRUCTURAL_AND_CONTRACT_DRIFT"      # S=1, W=0, C=1
    WEIGHT_AND_CONTRACT_DRIFT = "WEIGHT_AND_CONTRACT_DRIFT"              # S=0, W=1, C=1
    STRUCTURAL_WEIGHT_CONTRACT_DRIFT = "STRUCTURAL_WEIGHT_CONTRACT_DRIFT" # S=1, W=1, C=1
    DRIFT_UNAVAILABLE = "DRIFT_UNAVAILABLE"                              # Comparison unavailable


class TensorChangeType(str, Enum):
    """Granular classification of tensor-level parameter changes."""

    UNCHANGED = "UNCHANGED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    CONTENT_CHANGED = "CONTENT_CHANGED"
    METADATA_CHANGED = "METADATA_CHANGED"
    CONTENT_AND_METADATA_CHANGED = "CONTENT_AND_METADATA_CHANGED"


class TensorChangeRecord(BaseModel):
    """Deterministic record of a single parameter tensor comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tensor_name: str = Field(..., description="Canonical parameter tensor name")
    change_type: TensorChangeType = Field(..., description="Granular change classification")
    reference_shape: Optional[List[int]] = Field(None, description="Reference tensor shape")
    candidate_shape: Optional[List[int]] = Field(None, description="Candidate tensor shape")
    reference_dtype: Optional[str] = Field(None, description="Reference tensor dtype")
    candidate_dtype: Optional[str] = Field(None, description="Candidate tensor dtype")
    reference_content_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Reference 64-char SHA-256 raw bytes digest",
    )
    candidate_content_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Candidate 64-char SHA-256 raw bytes digest",
    )
    reference_leaf_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Reference 64-char JCS leaf hash",
    )
    candidate_leaf_hash: Optional[str] = Field(
        None,
        pattern=r"^[0-9a-f]{64}$",
        description="Candidate 64-char JCS leaf hash",
    )
    inclusion_proof: Optional[MerkleInclusionProof] = Field(
        None,
        description="Optional cryptographic Merkle inclusion proof for verification",
    )


class StructuralDifferenceRecord(BaseModel):
    """Detailed record of a structural difference between reference and candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: str = Field(..., description="Structural category (format, operator, tensor_count, parameter_count, etc.)")
    path: str = Field(..., description="Location identifier or field name")
    reference_value: Any = Field(..., description="Reference value")
    candidate_value: Any = Field(..., description="Candidate value")
    severity: str = Field("HIGH", description="Severity classification (INFO, LOW, MEDIUM, HIGH)")
    reason_code: str = Field(..., description="Deterministic reason code")


class ContractDifferenceRecord(BaseModel):
    """Detailed record of an operational I/O contract difference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: str = Field(..., description="Contract category (input, output, shape, dtype, preprocessing, etc.)")
    path: str = Field(..., description="Interface name or property key")
    reference_value: Any = Field(..., description="Reference contract value")
    candidate_value: Any = Field(..., description="Candidate contract value")
    severity: str = Field("HIGH", description="Severity classification")
    reason_code: str = Field(..., description="Deterministic reason code")


class ModelComparisonResult(BaseModel):
    """Sealed deterministic result of reference vs candidate model comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Comparison schema version")
    comparison_status: ComparisonStatus = Field(..., description="Overall comparison status")
    reference_trust: str = Field("VERIFIED", description="Verification trust state of reference model")
    candidate_trust: str = Field("VERIFIED", description="Verification trust state of candidate model")
    drift_classification: DriftClassification = Field(..., description="Eight-state drift classification")
    is_exact_artifact_match: bool = Field(False, description="True if raw file artifact hashes match")
    is_exact_master_match: bool = Field(False, description="True if master model fingerprints match")
    artifact_status: ArtifactComparisonStatus = Field(..., description="Artifact hash comparison status")
    structural_status: StructuralComparisonStatus = Field(..., description="Structural hash comparison status")
    weight_status: WeightComparisonStatus = Field(..., description="Weight Merkle root comparison status")
    contract_status: ContractComparisonStatus = Field(..., description="Contract hash comparison status")
    reference_fingerprints: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="Reference model cryptographic identity digests",
    )
    candidate_fingerprints: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="Candidate model cryptographic identity digests",
    )
    structural_differences: List[StructuralDifferenceRecord] = Field(
        default_factory=list,
        description="Deterministically ordered structural differences",
    )
    contract_differences: List[ContractDifferenceRecord] = Field(
        default_factory=list,
        description="Deterministically ordered contract differences",
    )
    tensor_changes: List[TensorChangeRecord] = Field(
        default_factory=list,
        description="Deterministically ordered tensor change records (sorted by tensor name)",
    )
    tensor_summary: Dict[str, int] = Field(
        default_factory=dict,
        description="Counts of unchanged, added, removed, and modified tensors",
    )
    reason_codes: List[str] = Field(
        default_factory=list,
        description="Granular deterministic reason codes",
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Diagnostic non-fatal warnings",
    )
