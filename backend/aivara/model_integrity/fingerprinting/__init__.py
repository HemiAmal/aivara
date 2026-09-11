"""Model Fingerprinting and Weight Merkle Engine (Phase 7.3)."""

from aivara.model_integrity.fingerprinting.artifact import compute_artifact_hash
from aivara.model_integrity.fingerprinting.contract import (
    build_contract_representation,
    compute_contract_hash,
)
from aivara.model_integrity.fingerprinting.exceptions import (
    DuplicateTensorLeafError,
    FingerprintingError,
    InvalidMerkleProofError,
    WeightContentUnavailableError,
)
from aivara.model_integrity.fingerprinting.master import compute_master_fingerprint
from aivara.model_integrity.fingerprinting.merkle import (
    EMPTY_WEIGHT_ROOT_HEX,
    WeightMerkleTree,
    compute_internal_node_hash,
    compute_weight_merkle_root,
)
from aivara.model_integrity.fingerprinting.proofs import (
    generate_weight_inclusion_proof,
    verify_weight_inclusion_proof,
)
from aivara.model_integrity.fingerprinting.schemas import (
    ContractRepresentation,
    HierarchicalFingerprintResult,
    MasterFingerprintBinding,
    MerkleInclusionProof,
    MerkleProofStep,
    ProofStepDirection,
    StructuralRepresentation,
    TensorLeafDescriptor,
    WeightMerkleResult,
)
from aivara.model_integrity.fingerprinting.service import ModelFingerprintingService
from aivara.model_integrity.fingerprinting.structural import (
    build_structural_representation,
    compute_structural_hash,
)
from aivara.model_integrity.fingerprinting.tensors import (
    compute_tensor_leaf_hash,
    extract_tensor_leaves,
)

__all__ = [
    # Core Service
    "ModelFingerprintingService",
    # Functions
    "compute_artifact_hash",
    "build_structural_representation",
    "compute_structural_hash",
    "build_contract_representation",
    "compute_contract_hash",
    "extract_tensor_leaves",
    "compute_tensor_leaf_hash",
    "compute_weight_merkle_root",
    "compute_internal_node_hash",
    "generate_weight_inclusion_proof",
    "verify_weight_inclusion_proof",
    "compute_master_fingerprint",
    # Classes & Constants
    "WeightMerkleTree",
    "EMPTY_WEIGHT_ROOT_HEX",
    # Schemas
    "ProofStepDirection",
    "MerkleProofStep",
    "MerkleInclusionProof",
    "TensorLeafDescriptor",
    "WeightMerkleResult",
    "StructuralRepresentation",
    "ContractRepresentation",
    "MasterFingerprintBinding",
    "HierarchicalFingerprintResult",
    # Exceptions
    "FingerprintingError",
    "WeightContentUnavailableError",
    "InvalidMerkleProofError",
    "DuplicateTensorLeafError",
]
