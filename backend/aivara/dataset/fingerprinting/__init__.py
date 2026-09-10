"""AIVARA Dataset Multi-Tier Fingerprinting & Merkle Tree Engine (Phase 5.3)."""

from aivara.dataset.fingerprinting.annotations import (
    ANNOTATION_DOMAIN_PREFIX,
    ANNOTSET_DOMAIN_PREFIX,
    EMPTY_ANNOTSET_DIGEST,
    compute_annotation_set_hash,
    compute_single_annotation_digest,
)
from aivara.dataset.fingerprinting.dataset import (
    DATASET_DOMAIN_PREFIX,
    DATASET_FINGERPRINT_VERSION,
    compute_dataset_hash,
)
from aivara.dataset.fingerprinting.engine import (
    DatasetFingerprintEngine,
    FingerprintedDatasetResult,
    FingerprintedSample,
    fingerprint_dataset,
)
from aivara.dataset.fingerprinting.exceptions import (
    DuplicateSampleIdError,
    DuplicateSamplePathError,
    FingerprintError,
    FingerprintVersionMismatchError,
    InvalidCanonicalInputError,
    InvalidHashFormatError,
    InvalidImageDecodingError,
    InvalidInclusionProofError,
    MalformedAnnotationFingerprintError,
    MalformedMerkleTreeError,
    MissingFileError,
    UnreadableFileError,
    UnsupportedImageEncodingError,
)
from aivara.dataset.fingerprinting.merkle import (
    EMPTY_MERKLE_ROOT_BYTES,
    EMPTY_MERKLE_ROOT_HEX,
    INTERNAL_PREFIX,
    LEAF_PREFIX,
    MerkleLeaf,
    MerkleTree,
    collate_and_build_merkle_tree,
    compute_internal_hash,
    compute_leaf_hash,
    compute_rfc6962_merkle_root,
)
from aivara.dataset.fingerprinting.pixels import (
    PIXEL_DOMAIN_PREFIX,
    compute_decoded_rgb_sha256,
)
from aivara.dataset.fingerprinting.proofs import (
    MerkleInclusionProof,
    MerkleProofStep,
    ProofStepDirection,
    generate_inclusion_proof,
    verify_inclusion_proof,
)
from aivara.dataset.fingerprinting.sample import (
    SAMPLE_DOMAIN_PREFIX,
    SAMPLE_FINGERPRINT_VERSION,
    compute_sample_fingerprint,
)
from aivara.dataset.fingerprinting.raw import (
    RAW_CHUNK_SIZE,
    compute_raw_image_sha256,
)

__all__ = [
    # Level 0
    "RAW_CHUNK_SIZE",
    "compute_raw_image_sha256",
    # Level 1
    "PIXEL_DOMAIN_PREFIX",
    "compute_decoded_rgb_sha256",
    # Level 2
    "ANNOTATION_DOMAIN_PREFIX",
    "ANNOTSET_DOMAIN_PREFIX",
    "EMPTY_ANNOTSET_DIGEST",
    "compute_single_annotation_digest",
    "compute_annotation_set_hash",
    # Level 3 & Engine
    "SAMPLE_DOMAIN_PREFIX",
    "SAMPLE_FINGERPRINT_VERSION",
    "compute_sample_fingerprint",
    "FingerprintedSample",
    "FingerprintedDatasetResult",
    "DatasetFingerprintEngine",
    "fingerprint_dataset",
    # Level 4 & Merkle
    "LEAF_PREFIX",
    "INTERNAL_PREFIX",
    "EMPTY_MERKLE_ROOT_HEX",
    "EMPTY_MERKLE_ROOT_BYTES",
    "MerkleLeaf",
    "MerkleTree",
    "compute_leaf_hash",
    "compute_internal_hash",
    "compute_rfc6962_merkle_root",
    "collate_and_build_merkle_tree",
    # Dataset Manifest Digest
    "DATASET_DOMAIN_PREFIX",
    "DATASET_FINGERPRINT_VERSION",
    "compute_dataset_hash",
    # Inclusion Proofs
    "ProofStepDirection",
    "MerkleProofStep",
    "MerkleInclusionProof",
    "generate_inclusion_proof",
    "verify_inclusion_proof",
    # Exceptions
    "FingerprintError",
    "MissingFileError",
    "UnreadableFileError",
    "InvalidImageDecodingError",
    "UnsupportedImageEncodingError",
    "MalformedAnnotationFingerprintError",
    "InvalidCanonicalInputError",
    "DuplicateSamplePathError",
    "DuplicateSampleIdError",
    "InvalidHashFormatError",
    "MalformedMerkleTreeError",
    "InvalidInclusionProofError",
    "FingerprintVersionMismatchError",
]
