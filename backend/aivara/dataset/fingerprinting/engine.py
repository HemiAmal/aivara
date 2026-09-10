"""Dataset Fingerprinting Orchestration Engine (Phase 5.3).

Coordinates multi-tier cryptographic fingerprinting across raw image files, decoded
pixels, annotations, canonical samples, and RFC 6962 binary Merkle trees.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field

from aivara.dataset.fingerprinting.annotations import compute_annotation_set_hash
from aivara.dataset.fingerprinting.dataset import compute_dataset_hash
from aivara.dataset.fingerprinting.merkle import (
    MerkleTree,
    collate_and_build_merkle_tree,
)
from aivara.dataset.fingerprinting.pixels import compute_decoded_rgb_sha256
from aivara.dataset.fingerprinting.raw import compute_raw_image_sha256
from aivara.dataset.fingerprinting.sample import compute_sample_fingerprint
from aivara.dataset.path_security import resolve_safe_path
from aivara.dataset.schemas import (
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetIngestionResult,
)


class FingerprintedSample(BaseModel):
    """Cryptographic multi-tier fingerprint container for a CanonicalSample."""

    model_config = ConfigDict(frozen=True)

    sample: CanonicalSample
    raw_image_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    decoded_rgb_sha256: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    annotation_set_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    sample_fingerprint: str = Field(..., pattern=r"^[0-9a-f]{64}$")


class FingerprintedDatasetResult(BaseModel):
    """Immutable composite result containing the full cryptographic identity of a dataset."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    manifest: CanonicalDatasetManifest
    dataset_root: str
    fingerprinted_samples: Tuple[FingerprintedSample, ...]
    dataset_merkle_root: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    dataset_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    sample_count: int = Field(..., ge=0)
    annotation_count: int = Field(..., ge=0)
    fingerprint_version: str = "1.0"
    tree: Optional[MerkleTree] = None


class DatasetFingerprintEngine:
    """Orchestrator for multi-tier dataset fingerprinting and Merkle root calculation."""

    def __init__(self, fingerprint_version: str = "1.0") -> None:
        self.fingerprint_version = fingerprint_version

    def fingerprint_sample(
        self,
        sample: CanonicalSample,
        dataset_root: Union[str, Path],
    ) -> FingerprintedSample:
        """Compute all cryptographic fingerprint tiers for an individual sample.

        Args:
            sample: CanonicalSample domain object.
            dataset_root: Base dataset directory.

        Returns:
            Immutable FingerprintedSample.
        """
        full_image_path = resolve_safe_path(dataset_root, sample.relative_path)

        # Level 0: Raw file digest
        raw_hash = compute_raw_image_sha256(full_image_path)

        # Level 1: Decoded pixel buffer digest
        pixel_hash = compute_decoded_rgb_sha256(full_image_path)

        # Level 2: Annotation set digest
        annot_hash = compute_annotation_set_hash(sample.annotations)

        # Level 3: Canonical sample fingerprint
        sample_fp = compute_sample_fingerprint(
            sample=sample,
            raw_image_sha256=raw_hash,
            decoded_rgb_sha256=pixel_hash,
            annotation_set_hash=annot_hash,
            version=self.fingerprint_version,
        )

        return FingerprintedSample(
            sample=sample,
            raw_image_sha256=raw_hash,
            decoded_rgb_sha256=pixel_hash,
            annotation_set_hash=annot_hash,
            sample_fingerprint=sample_fp,
        )

    def fingerprint_dataset(
        self,
        target: Union[DatasetIngestionResult, CanonicalDatasetManifest],
        dataset_root: Union[str, Path],
    ) -> FingerprintedDatasetResult:
        """Execute full multi-tier fingerprinting pipeline on a canonical dataset.

        Args:
            target: DatasetIngestionResult or CanonicalDatasetManifest instance.
            dataset_root: Base filesystem directory of the dataset.

        Returns:
            FingerprintedDatasetResult with sample fingerprints, Merkle root, and dataset_hash.
        """
        manifest = target.manifest if isinstance(target, DatasetIngestionResult) else target

        fingerprinted_samples: List[FingerprintedSample] = []
        sample_pairs: List[Tuple[CanonicalSample, str]] = []

        for sample in manifest.samples:
            fp_sample = self.fingerprint_sample(sample, dataset_root)
            fingerprinted_samples.append(fp_sample)
            sample_pairs.append((sample, fp_sample.sample_fingerprint))

        # Level 4: Build RFC 6962 binary Merkle tree
        tree = collate_and_build_merkle_tree(sample_pairs)
        dataset_merkle_root = tree.root_hex

        # Manifest Digest: Compute dataset_hash
        dataset_hash = compute_dataset_hash(
            manifest=manifest,
            dataset_merkle_root=dataset_merkle_root,
            fingerprint_version=self.fingerprint_version,
        )

        return FingerprintedDatasetResult(
            manifest=manifest,
            dataset_root=str(dataset_root),
            fingerprinted_samples=tuple(fingerprinted_samples),
            dataset_merkle_root=dataset_merkle_root,
            dataset_hash=dataset_hash,
            sample_count=manifest.sample_count,
            annotation_count=manifest.annotation_count,
            fingerprint_version=self.fingerprint_version,
            tree=tree,
        )


def fingerprint_dataset(
    target: Union[DatasetIngestionResult, CanonicalDatasetManifest],
    dataset_root: Union[str, Path],
    fingerprint_version: str = "1.0",
) -> FingerprintedDatasetResult:
    """Convenience function to fingerprint a dataset."""
    engine = DatasetFingerprintEngine(fingerprint_version=fingerprint_version)
    return engine.fingerprint_dataset(target, dataset_root)
