"""Comprehensive test suite for Phase 5.3: Multi-Tier Fingerprinting & Merkle Tree Engine.

Covers all 18 mandated testing categories:
  A. Raw image file hash integrity (Level 0)
  B. Decoded sRGB 8-bit pixel buffer hash (Level 1)
  C. Annotation & annotation-set hash integrity (Level 2)
  D. Canonical sample fingerprint integrity (Level 3)
  E. Domain separation & prefix validation
  F. Merkle leaf collation & UTF-8 path ordering
  G. RFC 6962 balanced power-of-2 Merkle tree construction
  H. Empty dataset Merkle tree semantics (N=0)
  I. Odd leaf count Merkle trees (N=1, 3, 5, 7, 9)
  J. Merkle inclusion proof generation & verification
  K. Inclusion proof tampering & adversarial rejections
  L. Dataset manifest hash separation (dataset_hash vs dataset_merkle_root)
  M. Versioning & schema mismatch handling
  N. Duplicate path & duplicate ID rejection
  O. Unicode path collation & normalization
  P. Cross-platform path handling
  Q. End-to-End integration across COCO, YOLO, ImageFolder
  R. 100% offline air-gapped guarantee
"""

import hashlib
import io
import os
import struct
import tempfile
from pathlib import Path
from typing import List, Tuple

import pytest
from PIL import Image

from aivara.crypto.hashing import sha256_bytes, sha256_text
from aivara.dataset.exceptions import DatasetIngestionError
from aivara.dataset.fingerprinting import (
    ANNOTATION_DOMAIN_PREFIX,
    ANNOTSET_DOMAIN_PREFIX,
    DATASET_DOMAIN_PREFIX,
    DATASET_FINGERPRINT_VERSION,
    EMPTY_ANNOTSET_DIGEST,
    EMPTY_MERKLE_ROOT_BYTES,
    EMPTY_MERKLE_ROOT_HEX,
    INTERNAL_PREFIX,
    LEAF_PREFIX,
    PIXEL_DOMAIN_PREFIX,
    DatasetFingerprintEngine,
    DuplicateSampleIdError,
    DuplicateSamplePathError,
    FingerprintedDatasetResult,
    FingerprintedSample,
    FingerprintVersionMismatchError,
    InvalidCanonicalInputError,
    InvalidHashFormatError,
    InvalidImageDecodingError,
    InvalidInclusionProofError,
    MalformedAnnotationFingerprintError,
    MerkleInclusionProof,
    MerkleLeaf,
    MerkleProofStep,
    MerkleTree,
    MissingFileError,
    ProofStepDirection,
    UnreadableFileError,
    collate_and_build_merkle_tree,
    compute_annotation_set_hash,
    compute_dataset_hash,
    compute_decoded_rgb_sha256,
    compute_internal_hash,
    compute_leaf_hash,
    compute_raw_image_sha256,
    compute_rfc6962_merkle_root,
    compute_sample_fingerprint,
    compute_single_annotation_digest,
    fingerprint_dataset,
    generate_inclusion_proof,
    verify_inclusion_proof,
)
from aivara.dataset.ingester import ingest_dataset
from aivara.dataset.schemas import (
    CanonicalAnnotation,
    CanonicalBBox,
    CanonicalCategory,
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetFormat,
)


# =====================================================================
# Fixtures & Helpers
# =====================================================================


def _create_synthetic_png(width: int = 10, height: int = 10, color: Tuple[int, int, int] = (255, 0, 0)) -> bytes:
    """Create raw bytes of a valid PNG image."""
    buf = io.BytesIO()
    img = Image.new("RGB", (width, height), color)
    img.save(buf, format="PNG")
    return buf.getvalue()


def _create_synthetic_bmp(width: int = 10, height: int = 10, color: Tuple[int, int, int] = (255, 0, 0)) -> bytes:
    """Create raw bytes of a valid BMP image with identical pixels."""
    buf = io.BytesIO()
    img = Image.new("RGB", (width, height), color)
    img.save(buf, format="BMP")
    return buf.getvalue()


# =====================================================================
# Level 0: Raw File Hash Tests
# =====================================================================


class TestLevel0RawFileHash:
    """Tests for raw image file SHA-256 streaming hashing."""

    def test_raw_hash_happy_path(self, tmp_path: Path):
        img_bytes = _create_synthetic_png(20, 20, (10, 20, 30))
        img_file = tmp_path / "sample.png"
        img_file.write_bytes(img_bytes)

        digest = compute_raw_image_sha256(img_file)
        assert len(digest) == 64
        assert digest == hashlib.sha256(img_bytes).hexdigest().lower()

    def test_raw_hash_empty_file(self, tmp_path: Path):
        empty_file = tmp_path / "empty.png"
        empty_file.write_bytes(b"")

        digest = compute_raw_image_sha256(empty_file)
        assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_raw_hash_missing_file(self, tmp_path: Path):
        missing_file = tmp_path / "non_existent.png"
        with pytest.raises(MissingFileError) as exc_info:
            compute_raw_image_sha256(missing_file)
        assert exc_info.value.code == "MISSING_IMAGE_FILE"

    def test_raw_hash_single_byte_mutation(self, tmp_path: Path):
        img_bytes = _create_synthetic_png(10, 10, (100, 100, 100))
        file_a = tmp_path / "a.png"
        file_a.write_bytes(img_bytes)

        mutated_bytes = bytearray(img_bytes)
        mutated_bytes[10] = (mutated_bytes[10] + 1) % 256
        file_b = tmp_path / "b.png"
        file_b.write_bytes(bytes(mutated_bytes))

        hash_a = compute_raw_image_sha256(file_a)
        hash_b = compute_raw_image_sha256(file_b)
        assert hash_a != hash_b

    def test_raw_hash_streaming_large_file(self, tmp_path: Path):
        # 200 KiB file to exercise multiple 64 KiB chunks
        large_bytes = b"A" * (200 * 1024)
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(large_bytes)

        digest = compute_raw_image_sha256(large_file)
        assert digest == hashlib.sha256(large_bytes).hexdigest().lower()


# =====================================================================
# Level 1: Decoded RGB Pixel Hash Tests
# =====================================================================


class TestLevel1DecodedPixelHash:
    """Tests for decoded uncompressed sRGB 8-bit pixel buffer hashing."""

    def test_pixel_hash_format_invariance(self, tmp_path: Path):
        """PNG and BMP with identical 10x10 RGB pixels must produce the exact same pixel hash."""
        color = (45, 90, 180)
        png_bytes = _create_synthetic_png(10, 10, color)
        bmp_bytes = _create_synthetic_bmp(10, 10, color)

        png_file = tmp_path / "test.png"
        bmp_file = tmp_path / "test.bmp"
        png_file.write_bytes(png_bytes)
        bmp_file.write_bytes(bmp_bytes)

        # Raw file hashes must differ (different container encodings)
        raw_png = compute_raw_image_sha256(png_file)
        raw_bmp = compute_raw_image_sha256(bmp_file)
        assert raw_png != raw_bmp

        # Decoded pixel hashes must be identical
        pixel_png = compute_decoded_rgb_sha256(png_file)
        pixel_bmp = compute_decoded_rgb_sha256(bmp_file)
        assert pixel_png == pixel_bmp

    def test_pixel_hash_grayscale_conversion(self, tmp_path: Path):
        """1-channel grayscale image must convert to RGB (L, L, L) identically to explicit RGB."""
        # Create Grayscale 10x10 with value 128
        gray_img = Image.new("L", (10, 10), 128)
        gray_file = tmp_path / "gray.png"
        gray_img.save(gray_file)

        # Create RGB 10x10 with value (128, 128, 128)
        rgb_img = Image.new("RGB", (10, 10), (128, 128, 128))
        rgb_file = tmp_path / "rgb.png"
        rgb_img.save(rgb_file)

        gray_hash = compute_decoded_rgb_sha256(gray_file)
        rgb_hash = compute_decoded_rgb_sha256(rgb_file)
        assert gray_hash == rgb_hash

    def test_pixel_hash_rgba_alpha_flattening(self, tmp_path: Path):
        """Opaque RGBA image must produce the exact same pixel hash as equivalent RGB."""
        # Opaque RGBA (50, 100, 150, 255)
        rgba_img = Image.new("RGBA", (8, 8), (50, 100, 150, 255))
        rgba_file = tmp_path / "rgba.png"
        rgba_img.save(rgba_file)

        # Pure RGB (50, 100, 150)
        rgb_img = Image.new("RGB", (8, 8), (50, 100, 150))
        rgb_file = tmp_path / "pure_rgb.png"
        rgb_img.save(rgb_file)

        rgba_hash = compute_decoded_rgb_sha256(rgba_file)
        rgb_hash = compute_decoded_rgb_sha256(rgb_file)
        assert rgba_hash == rgb_hash

    def test_pixel_hash_corrupted_file(self, tmp_path: Path):
        corrupt_file = tmp_path / "corrupt.png"
        corrupt_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)

        with pytest.raises(InvalidImageDecodingError):
            compute_decoded_rgb_sha256(corrupt_file)

    def test_pixel_hash_dimension_sensitivity(self, tmp_path: Path):
        """2x3 image and 3x2 image with identical total bytes must have different pixel hashes."""
        img_2x3 = Image.new("RGB", (2, 3), (255, 255, 255))
        img_3x2 = Image.new("RGB", (3, 2), (255, 255, 255))

        f_2x3 = tmp_path / "2x3.png"
        f_3x2 = tmp_path / "3x2.png"
        img_2x3.save(f_2x3)
        img_3x2.save(f_3x2)

        hash_2x3 = compute_decoded_rgb_sha256(f_2x3)
        hash_3x2 = compute_decoded_rgb_sha256(f_3x2)
        assert hash_2x3 != hash_3x2


# =====================================================================
# Level 2: Annotation Digest Tests
# =====================================================================


class TestLevel2AnnotationHash:
    """Tests for deterministic annotation and annotation-set hashing."""

    def test_single_annotation_digest_reproducibility(self):
        ann = CanonicalAnnotation(
            annotation_id="ann-01",
            category_id=1,
            category_name="dog",
            bbox=CanonicalBBox(x_min=10.123456, y_min=20.654321, width=100.0, height=200.0),
            area=20000.0,
        )
        digest1 = compute_single_annotation_digest(ann)
        digest2 = compute_single_annotation_digest(ann)
        assert digest1 == digest2
        assert len(digest1) == 64

    def test_coordinate_quantization_to_4_decimals(self):
        """Coordinates differing only beyond 4 decimal places must yield identical hashes."""
        ann1 = CanonicalAnnotation(
            annotation_id="ann-01",
            category_id=1,
            category_name="car",
            bbox=CanonicalBBox(x_min=10.12341, y_min=20.0, width=50.0, height=50.0),
        )
        ann2 = CanonicalAnnotation(
            annotation_id="ann-01",
            category_id=1,
            category_name="car",
            bbox=CanonicalBBox(x_min=10.12344, y_min=20.0, width=50.0, height=50.0),
        )
        assert compute_single_annotation_digest(ann1) == compute_single_annotation_digest(ann2)

    def test_coordinate_change_within_4_decimals_mutates_hash(self):
        ann1 = CanonicalAnnotation(
            annotation_id="ann-01",
            category_id=1,
            category_name="car",
            bbox=CanonicalBBox(x_min=10.1234, y_min=20.0, width=50.0, height=50.0),
        )
        ann2 = CanonicalAnnotation(
            annotation_id="ann-01",
            category_id=1,
            category_name="car",
            bbox=CanonicalBBox(x_min=10.1235, y_min=20.0, width=50.0, height=50.0),
        )
        assert compute_single_annotation_digest(ann1) != compute_single_annotation_digest(ann2)

    def test_annotation_set_order_invariance(self):
        """Shuffled list of annotations must produce the exact same composite annotation set hash."""
        ann1 = CanonicalAnnotation(
            annotation_id="ann-01",
            category_id=1,
            category_name="cat",
            bbox=CanonicalBBox(x_min=10.0, y_min=10.0, width=30.0, height=30.0),
        )
        ann2 = CanonicalAnnotation(
            annotation_id="ann-02",
            category_id=2,
            category_name="dog",
            bbox=CanonicalBBox(x_min=50.0, y_min=50.0, width=40.0, height=40.0),
        )
        ann3 = CanonicalAnnotation(
            annotation_id="ann-03",
            category_id=1,
            category_name="cat",
            bbox=CanonicalBBox(x_min=100.0, y_min=100.0, width=20.0, height=20.0),
        )

        hash_forward = compute_annotation_set_hash([ann1, ann2, ann3])
        hash_reversed = compute_annotation_set_hash([ann3, ann1, ann2])
        assert hash_forward == hash_reversed

    def test_empty_annotation_set_deterministic_constant(self):
        digest = compute_annotation_set_hash([])
        assert digest == EMPTY_ANNOTSET_DIGEST
        assert digest == sha256_text("aivara-annotset-v1:empty")


# =====================================================================
# Level 3: Canonical Sample Fingerprint Tests
# =====================================================================


class TestLevel3SampleFingerprint:
    """Tests for composite CanonicalSample fingerprinting."""

    def test_sample_fingerprint_happy_path(self):
        sample = CanonicalSample(
            sample_id="sample-001",
            relative_path="images/001.jpg",
            file_size_bytes=1024,
            width=640,
            height=480,
            channels=3,
            color_space="RGB",
            contributors=("user-b", "user-a"),
        )
        raw_hash = "a" * 64
        pixel_hash = "b" * 64
        annot_hash = "c" * 64

        fp1 = compute_sample_fingerprint(sample, raw_hash, pixel_hash, annot_hash)
        fp2 = compute_sample_fingerprint(sample, raw_hash, pixel_hash, annot_hash)
        assert fp1 == fp2
        assert len(fp1) == 64

    def test_sample_fingerprint_field_sensitivity(self):
        sample_base = CanonicalSample(
            sample_id="sample-001",
            relative_path="images/001.jpg",
            file_size_bytes=1024,
            width=640,
            height=480,
        )
        raw_hash = "a" * 64
        pixel_hash = "b" * 64
        annot_hash = "c" * 64

        fp_base = compute_sample_fingerprint(sample_base, raw_hash, pixel_hash, annot_hash)

        # Mutate width
        sample_mut = CanonicalSample(
            sample_id="sample-001",
            relative_path="images/001.jpg",
            file_size_bytes=1024,
            width=641,
            height=480,
        )
        fp_mut = compute_sample_fingerprint(sample_mut, raw_hash, pixel_hash, annot_hash)
        assert fp_base != fp_mut

        # Mutate raw hash
        fp_mut_raw = compute_sample_fingerprint(sample_base, "d" * 64, pixel_hash, annot_hash)
        assert fp_base != fp_mut_raw

    def test_sample_fingerprint_invalid_hash_format(self):
        sample = CanonicalSample(
            sample_id="sample-001",
            relative_path="images/001.jpg",
            file_size_bytes=1024,
            width=640,
            height=480,
        )
        with pytest.raises(InvalidHashFormatError):
            compute_sample_fingerprint(sample, "short-hash", "b" * 64, "c" * 64)

    def test_sample_fingerprint_version_mismatch(self):
        sample = CanonicalSample(
            sample_id="sample-001",
            relative_path="images/001.jpg",
            file_size_bytes=1024,
            width=640,
            height=480,
        )
        with pytest.raises(FingerprintVersionMismatchError):
            compute_sample_fingerprint(sample, "a" * 64, "b" * 64, "c" * 64, version="2.0")


# =====================================================================
# Level 4: Binary Merkle Tree & Inclusion Proof Tests
# =====================================================================


class TestLevel4MerkleTree:
    """Tests for RFC 6962 binary Merkle tree construction, leaf collation, and proofs."""

    def test_empty_merkle_tree(self):
        root = compute_rfc6962_merkle_root([])
        assert root.hex().lower() == EMPTY_MERKLE_ROOT_HEX
        assert root == EMPTY_MERKLE_ROOT_BYTES

    def test_single_leaf_merkle_tree(self):
        fp = "1" * 64
        leaf_hash = compute_leaf_hash(fp)
        root = compute_rfc6962_merkle_root([leaf_hash])
        assert root == leaf_hash

    def test_two_leaves_merkle_tree(self):
        leaf0 = compute_leaf_hash("a" * 64)
        leaf1 = compute_leaf_hash("b" * 64)
        root = compute_rfc6962_merkle_root([leaf0, leaf1])
        expected = compute_internal_hash(leaf0, leaf1)
        assert root == expected

    def test_odd_leaves_merkle_tree_balanced_split(self):
        """For N=3: k=2. Root = H(H(L0, L1), L2). Balanced split, zero node duplication."""
        l0 = compute_leaf_hash("0" * 64)
        l1 = compute_leaf_hash("1" * 64)
        l2 = compute_leaf_hash("2" * 64)

        root = compute_rfc6962_merkle_root([l0, l1, l2])
        left_sub = compute_internal_hash(l0, l1)
        expected = compute_internal_hash(left_sub, l2)
        assert root == expected

    def test_merkle_leaf_ordering_by_utf8_path(self):
        """Samples must be sorted strictly by relative_path UTF-8 binary collation."""
        s1 = CanonicalSample(sample_id="s1", relative_path="b/image.jpg", file_size_bytes=10, width=10, height=10)
        s2 = CanonicalSample(sample_id="s2", relative_path="a/image.jpg", file_size_bytes=10, width=10, height=10)
        s3 = CanonicalSample(sample_id="s3", relative_path="c/image.jpg", file_size_bytes=10, width=10, height=10)

        pairs = [(s1, "1" * 64), (s2, "2" * 64), (s3, "3" * 64)]
        tree = collate_and_build_merkle_tree(pairs)

        assert [l.relative_path for l in tree.leaves] == ["a/image.jpg", "b/image.jpg", "c/image.jpg"]

    def test_duplicate_sample_path_rejected(self):
        s1 = CanonicalSample(sample_id="s1", relative_path="same/path.jpg", file_size_bytes=10, width=10, height=10)
        s2 = CanonicalSample(sample_id="s2", relative_path="same/path.jpg", file_size_bytes=10, width=10, height=10)

        with pytest.raises(DuplicateSamplePathError):
            collate_and_build_merkle_tree([(s1, "1" * 64), (s2, "2" * 64)])

    def test_duplicate_sample_id_rejected(self):
        s1 = CanonicalSample(sample_id="same-id", relative_path="path/1.jpg", file_size_bytes=10, width=10, height=10)
        s2 = CanonicalSample(sample_id="same-id", relative_path="path/2.jpg", file_size_bytes=10, width=10, height=10)

        with pytest.raises(DuplicateSampleIdError):
            collate_and_build_merkle_tree([(s1, "1" * 64), (s2, "2" * 64)])

    @pytest.mark.parametrize("leaf_count", [1, 2, 3, 4, 5, 7, 8, 9, 16, 25, 64, 100])
    def test_inclusion_proof_generation_and_verification_all_leaves(self, leaf_count: int):
        pairs: List[Tuple[CanonicalSample, str]] = []
        for i in range(leaf_count):
            s = CanonicalSample(
                sample_id=f"sample-{i:04d}",
                relative_path=f"images/{i:04d}.jpg",
                file_size_bytes=100,
                width=100,
                height=100,
            )
            fp = hashlib.sha256(f"fp-{i}".encode("utf-8")).hexdigest().lower()
            pairs.append((s, fp))

        tree = collate_and_build_merkle_tree(pairs)
        assert tree.total_leaves == leaf_count

        # Generate and verify inclusion proof for every single leaf
        for idx in range(leaf_count):
            proof = generate_inclusion_proof(tree, idx)
            assert proof.leaf_index == idx
            assert proof.total_leaves == leaf_count
            assert proof.dataset_merkle_root == tree.root_hex
            assert verify_inclusion_proof(proof) is True

    def test_inclusion_proof_tampering_rejections(self):
        pairs = [
            (CanonicalSample(sample_id=f"s{i}", relative_path=f"img/{i}.jpg", file_size_bytes=10, width=10, height=10), "a" * 63 + str(i))
            for i in range(5)
        ]
        tree = collate_and_build_merkle_tree(pairs)
        proof = generate_inclusion_proof(tree, 2)
        assert verify_inclusion_proof(proof) is True

        # 1. Tamper with leaf hash
        tampered_leaf = proof.model_copy(update={"leaf_hash": "f" * 64})
        assert verify_inclusion_proof(tampered_leaf) is False

        # 2. Tamper with dataset root
        tampered_root = proof.model_copy(update={"dataset_merkle_root": "0" * 64})
        assert verify_inclusion_proof(tampered_root) is False

        # 3. Tamper with audit path sibling
        mutated_path = [
            MerkleProofStep(sibling_hash="9" * 64, direction=step.direction)
            if idx == 0 else step
            for idx, step in enumerate(proof.audit_path)
        ]
        tampered_sibling = proof.model_copy(update={"audit_path": mutated_path})
        assert verify_inclusion_proof(tampered_sibling) is False

        # 4. Tamper with sibling direction
        mutated_dir = [
            MerkleProofStep(
                sibling_hash=step.sibling_hash,
                direction=ProofStepDirection.RIGHT if step.direction == ProofStepDirection.LEFT else ProofStepDirection.LEFT,
            )
            if idx == 0 else step
            for idx, step in enumerate(proof.audit_path)
        ]
        tampered_direction = proof.model_copy(update={"audit_path": mutated_dir})
        assert verify_inclusion_proof(tampered_direction) is False


# =====================================================================
# Dataset Manifest Digest Tests
# =====================================================================


class TestDatasetManifestDigest:
    """Tests for dataset_hash computation."""

    def test_dataset_hash_distinct_from_merkle_root(self):
        cat = CanonicalCategory(category_id=1, category_name="car")
        manifest = CanonicalDatasetManifest(
            format=DatasetFormat.COCO,
            dataset_name="cars-dataset",
            sample_count=10,
            annotation_count=20,
            categories=(cat,),
        )
        merkle_root = "e" * 64
        dataset_h = compute_dataset_hash(manifest, merkle_root)

        assert dataset_h != merkle_root
        assert len(dataset_h) == 64

    def test_dataset_hash_metadata_sensitivity(self):
        cat = CanonicalCategory(category_id=1, category_name="car")
        manifest1 = CanonicalDatasetManifest(
            format=DatasetFormat.COCO,
            dataset_name="cars-v1",
            sample_count=10,
            annotation_count=20,
            categories=(cat,),
        )
        manifest2 = CanonicalDatasetManifest(
            format=DatasetFormat.COCO,
            dataset_name="cars-v2",  # Renamed dataset
            sample_count=10,
            annotation_count=20,
            categories=(cat,),
        )
        merkle_root = "e" * 64
        h1 = compute_dataset_hash(manifest1, merkle_root)
        h2 = compute_dataset_hash(manifest2, merkle_root)
        assert h1 != h2


# =====================================================================
# End-to-End Orchestrator & Integration Tests
# =====================================================================


class TestEndToEndFingerprintingEngine:
    """End-to-End tests fingerprinting full ingested datasets across COCO, YOLO, and ImageFolder."""

    def test_e2e_imagefolder_fingerprinting(self, tmp_path: Path):
        """Build a synthetic ImageFolder dataset, ingest it, and fingerprint it."""
        dataset_dir = tmp_path / "animal_dataset"
        cat_dir = dataset_dir / "cat"
        dog_dir = dataset_dir / "dog"
        cat_dir.mkdir(parents=True)
        dog_dir.mkdir(parents=True)

        (cat_dir / "cat1.png").write_bytes(_create_synthetic_png(16, 16, (200, 100, 50)))
        (cat_dir / "cat2.png").write_bytes(_create_synthetic_png(16, 16, (210, 110, 60)))
        (dog_dir / "dog1.png").write_bytes(_create_synthetic_png(16, 16, (50, 100, 200)))

        # 1. Ingest via Phase 5.2 engine
        ingestion_result = ingest_dataset(dataset_dir)
        assert ingestion_result.total_samples == 3

        # 2. Fingerprint via Phase 5.3 engine
        fp_result = fingerprint_dataset(ingestion_result, dataset_dir)

        assert isinstance(fp_result, FingerprintedDatasetResult)
        assert fp_result.sample_count == 3
        assert len(fp_result.fingerprinted_samples) == 3
        assert len(fp_result.dataset_merkle_root) == 64
        assert len(fp_result.dataset_hash) == 64

        # Verify inclusion proof for each sample
        for idx in range(3):
            proof = generate_inclusion_proof(fp_result.tree, idx)
            assert verify_inclusion_proof(proof) is True

    def test_e2e_fingerprint_reproducibility(self, tmp_path: Path):
        """Repeated fingerprinting of the same dataset must yield identical Merkle roots and dataset hashes."""
        dataset_dir = tmp_path / "dataset"
        cls_dir = dataset_dir / "vehicle"
        cls_dir.mkdir(parents=True)
        (cls_dir / "car.png").write_bytes(_create_synthetic_png(16, 16, (255, 0, 0)))
        (cls_dir / "van.png").write_bytes(_create_synthetic_png(16, 16, (0, 255, 0)))

        ingest1 = ingest_dataset(dataset_dir)
        res1 = fingerprint_dataset(ingest1, dataset_dir)

        ingest2 = ingest_dataset(dataset_dir)
        res2 = fingerprint_dataset(ingest2, dataset_dir)

        assert res1.dataset_merkle_root == res2.dataset_merkle_root
        assert res1.dataset_hash == res2.dataset_hash
        assert [s.sample_fingerprint for s in res1.fingerprinted_samples] == [
            s.sample_fingerprint for s in res2.fingerprinted_samples
        ]
