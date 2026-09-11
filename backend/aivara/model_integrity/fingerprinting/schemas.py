"""Pydantic schemas and descriptors for Model Fingerprinting and Merkle Engine (Phase 7.3)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aivara.model_integrity.schemas import ModelFormat, ReasonCode


class ProofStepDirection(str, Enum):
    """Direction of sibling hash in Merkle audit path."""

    LEFT = "left"
    RIGHT = "right"


class MerkleProofStep(BaseModel):
    """Single step in a Merkle inclusion audit path."""

    model_config = ConfigDict(frozen=True)

    sibling_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hexadecimal sibling digest",
    )
    direction: ProofStepDirection = Field(
        ...,
        description="Relative direction of sibling (LEFT or RIGHT)",
    )


class MerkleInclusionProof(BaseModel):
    """Cryptographic Merkle inclusion proof for a single model parameter tensor."""

    model_config = ConfigDict(frozen=True)

    proof_version: str = Field("1.0", description="Schema version of proof")
    weight_merkle_root: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="Expected 64-character lowercase hex Merkle root",
    )
    leaf_index: int = Field(..., ge=0, description="0-based integer leaf index")
    total_leaves: int = Field(..., ge=1, description="Total number of tensor leaves")
    tensor_name: str = Field(..., min_length=1, description="Canonical name of target tensor")
    leaf_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex leaf digest",
    )
    audit_path: List[MerkleProofStep] = Field(
        default_factory=list,
        description="Ordered sequence of sibling steps from leaf to root",
    )


class TensorLeafDescriptor(BaseModel):
    """Cryptographic leaf representation of a parameter tensor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., description="Canonical tensor name")
    shape: List[int] = Field(..., description="Tensor dimensions")
    dtype: str = Field(..., description="Tensor data type")
    byte_length: int = Field(..., ge=0, description="Length of tensor in bytes")
    content_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-char lowercase SHA-256 digest of raw tensor bytes",
    )
    leaf_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-char lowercase SHA-256 digest of JCS canonicalized leaf payload",
    )


class WeightMerkleResult(BaseModel):
    """Result of Merkle tree computation over model weights."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Schema version")
    status: str = Field("verified", description="verified, empty, or unavailable")
    tensor_count: int = Field(0, ge=0, description="Total tensor leaf count")
    total_parameter_count: int = Field(0, ge=0, description="Total elements across all tensors")
    total_tensor_bytes: int = Field(0, ge=0, description="Total bytes across all tensors")
    merkle_root: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-character lowercase hex Merkle root",
    )
    leaves: List[TensorLeafDescriptor] = Field(
        default_factory=list,
        description="Deterministically ordered tensor leaf descriptors",
    )
    reason_codes: List[ReasonCode] = Field(default_factory=list)


class StructuralRepresentation(BaseModel):
    """Format-agnostic canonical structural representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Structural schema version")
    format: str = Field(..., description="Model format identifier")
    architecture: str = Field("", description="Detected or declared architecture family")
    tensor_count: int = Field(..., ge=0, description="Total number of tensors")
    parameter_count: int = Field(..., ge=0, description="Total parameter element count")
    tensors: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Sorted list of tensor metadata (name, shape, dtype, element_count, byte_size)",
    )
    operators: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Sorted list of graph operators (op_type, count, domain)",
    )
    metadata_props: Dict[str, str] = Field(
        default_factory=dict,
        description="Sorted key-value metadata properties",
    )


class ContractRepresentation(BaseModel):
    """Format-agnostic canonical contract representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Contract schema version")
    inputs: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Sorted input contract specifications",
    )
    outputs: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Sorted output contract specifications",
    )


class MasterFingerprintBinding(BaseModel):
    """Explicit canonical JCS payload for Master Model Fingerprint (ADR-040)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Master binding schema version")
    artifact_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-char lowercase hex SHA-256 of raw artifact bytes",
    )
    structural_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-char lowercase hex SHA-256 of canonical structural representation",
    )
    contract_hash: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description="64-char lowercase hex SHA-256 of canonical contract representation",
    )


class HierarchicalFingerprintResult(BaseModel):
    """Complete multi-tier cryptographic identity result for a model artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field("1.0", description="Schema version")
    status: str = Field("verified", description="verified, partial, or unavailable")
    artifact_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    structural_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    contract_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    weight_merkle_root: Optional[str] = Field(None, pattern=r"^[0-9a-f]{64}$")
    master_fingerprint: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    weight_status: str = Field("verified", description="verified, empty, or unavailable")
    tensor_count: int = Field(0, ge=0)
    parameter_count: int = Field(0, ge=0)
    reason_codes: List[ReasonCode] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
