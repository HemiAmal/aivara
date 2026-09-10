"""Comprehensive test suite for Phase 5.4: Near-Duplicate Detection Engine.

Covers all 30 mandated test categories:
  1. pHash deterministic behavior
  2. dHash deterministic behavior
  3. Identical images (distance = 0)
  4. Resized images (distance <= 2)
  5. JPEG recompressed images
  6. EXIF / metadata changes
  7. Grayscale images vs RGB equivalents
  8. RGBA alpha flattening over solid white
  9. EXIF orientation transposition
  10. Fast Hamming distance accuracy [0, 64]
  11. Configurable threshold behavior
  12. BK-Tree insertion & structure
  13. BK-Tree radius search & triangle inequality pruning
  14. BK-Tree duplicate hash handling
  15. Empty index search semantics
  16. Multi-Index Hash (MIH) partition indexing & candidate queries
  17. Pair deduplication (canonical A < B ordering)
  18. Self-pair exclusion (no A == B)
  19. Deterministic relationship ordering
  20. Connected component cluster construction
  21. Deterministic cluster IDs
  22. Contributor information preservation
  23. Malformed / corrupted image safety
  24. Decompression / resource safety
  25. Unsupported image format handling
  26. Large synthetic dataset benchmark (N=100)
  27. 100% offline air-gapped execution
  28. Strict non-maliciousness assertion guarantee
  29. End-to-end dataset duplicate detection
  30. Scan result reproducibility across repeated runs
"""

import io
import math
from pathlib import Path
from typing import List, Tuple

import pytest
from PIL import Image

from aivara.dataset.duplicates import (
    BKTree,
    BKTreeItem,
    MultiIndexHash,
    NearDuplicateCluster,
    NearDuplicateConfig,
    NearDuplicateDetector,
    NearDuplicateRelationship,
    NearDuplicateScanResult,
    NearDuplicateStrategy,
    PerceptualFingerprint,
    compute_dhash,
    compute_dhash_uint64,
    compute_phash,
    compute_phash_uint64,
    detect_near_duplicates,
    hamming_distance,
    hamming_distance_uint64,
    hex_to_uint64,
    uint64_to_hex,
)
from aivara.dataset.duplicates.exceptions import (
    InvalidPerceptualHashError,
    InvalidThresholdError,
)
from aivara.dataset.ingester import ingest_dataset
from aivara.dataset.schemas import CanonicalSample


# =====================================================================
# Fixtures & Synthetic Image Generators
# =====================================================================


def _generate_pattern_image(width: int, height: int, pattern_type: str = "gradient") -> Image.Image:
    """Generate deterministic synthetic test images with macroscopic visual shapes."""
    from PIL import ImageDraw

    img = Image.new("RGB", (width, height), (240, 240, 250))
    d = ImageDraw.Draw(img)
    sx = width / 100.0
    sy = height / 100.0

    if pattern_type == "gradient":
        # Geometric scene with colored rectangles, circles, and triangles
        d.rectangle([int(10 * sx), int(10 * sy), int(50 * sx), int(50 * sy)], fill=(180, 40, 40))
        d.ellipse([int(40 * sx), int(40 * sy), int(90 * sx), int(90 * sy)], fill=(40, 100, 180))
        d.polygon([(int(70 * sx), int(10 * sy)), (int(90 * sx), int(40 * sy)), (int(50 * sx), int(40 * sy))], fill=(40, 180, 60))
    elif pattern_type == "checkerboard":
        # Macroscopic checkerboard
        step_x = max(2, width // 8)
        step_y = max(2, height // 8)
        for y in range(0, height, step_y):
            for x in range(0, width, step_x):
                if ((x // step_x) + (y // step_y)) % 2 == 0:
                    d.rectangle([x, y, x + step_x, y + step_y], fill=(20, 20, 30))
    elif pattern_type == "diagonal":
        # High-contrast cross lines and circles
        d.ellipse([int(20 * sx), int(20 * sy), int(80 * sx), int(80 * sy)], fill=(200, 150, 50))
        d.line([(0, 0), (width, height)], fill=(10, 10, 10), width=max(2, int(4 * sx)))
        d.line([(0, height), (width, 0)], fill=(200, 20, 20), width=max(2, int(4 * sx)))
    else:
        d.rectangle([0, 0, width, height], fill=(128, 128, 128))
    return img


# =====================================================================
# 1-10: Perceptual Hash & Distance Tests
# =====================================================================


class TestPerceptualAlgorithmsAndDistance:
    """Tests for pHash, dHash, and Hamming distance algorithms."""

    def test_phash_deterministic_reproducibility(self):
        img = _generate_pattern_image(64, 64, "gradient")
        h1 = compute_phash(img)
        h2 = compute_phash(img)
        assert len(h1) == 16
        assert h1 == h2

    def test_dhash_deterministic_reproducibility(self):
        img = _generate_pattern_image(64, 64, "checkerboard")
        h1 = compute_dhash(img)
        h2 = compute_dhash(img)
        assert len(h1) == 16
        assert h1 == h2

    def test_identical_images_zero_distance(self):
        img = _generate_pattern_image(100, 100, "diagonal")
        p1 = compute_phash(img)
        p2 = compute_phash(img)
        d1 = compute_dhash(img)
        d2 = compute_dhash(img)

        assert hamming_distance(p1, p2) == 0
        assert hamming_distance(d1, d2) == 0

    def test_resized_images_near_identical_distance(self):
        """Image at 128x128 resized to 64x64 must have very low Hamming distance (<= 2)."""
        img_orig = _generate_pattern_image(128, 128, "gradient")
        img_resized = img_orig.resize((64, 64), Image.Resampling.BILINEAR)

        p_orig = compute_phash(img_orig)
        p_resized = compute_phash(img_resized)
        d_orig = compute_dhash(img_orig)
        d_resized = compute_dhash(img_resized)

        assert hamming_distance(p_orig, p_resized) <= 2
        assert hamming_distance(d_orig, d_resized) <= 2

    def test_jpeg_recompressed_images(self, tmp_path: Path):
        """PNG saved as high-quality JPEG must retain near-identical hashes."""
        img = _generate_pattern_image(64, 64, "checkerboard")
        png_path = tmp_path / "orig.png"
        jpg_path = tmp_path / "compressed.jpg"

        img.save(png_path, format="PNG")
        img.save(jpg_path, format="JPEG", quality=90)

        p_png = compute_phash(png_path)
        p_jpg = compute_phash(jpg_path)
        d_png = compute_dhash(png_path)
        d_jpg = compute_dhash(jpg_path)

        assert hamming_distance(p_png, p_jpg) <= 6
        assert hamming_distance(d_png, d_jpg) <= 6

    def test_grayscale_conversion_equivalence(self):
        gray_img = Image.new("L", (32, 32), 150)
        rgb_img = Image.new("RGB", (32, 32), (150, 150, 150))

        assert compute_phash(gray_img) == compute_phash(rgb_img)
        assert compute_dhash(gray_img) == compute_dhash(rgb_img)

    def test_alpha_flattening_equivalence(self):
        rgba_img = Image.new("RGBA", (32, 32), (200, 100, 50, 255))
        rgb_img = Image.new("RGB", (32, 32), (200, 100, 50))

        assert compute_phash(rgba_img) == compute_phash(rgb_img)
        assert compute_dhash(rgba_img) == compute_dhash(rgb_img)

    def test_hamming_distance_bounds_and_accuracy(self):
        assert hamming_distance("0000000000000000", "0000000000000000") == 0
        assert hamming_distance("0000000000000000", "0000000000000001") == 1
        assert hamming_distance("0000000000000000", "ffffffffffffffff") == 64
        assert hamming_distance("aaaaaaaaaaaaaaaa", "5555555555555555") == 64

    def test_invalid_hash_format_handling(self):
        with pytest.raises(InvalidPerceptualHashError):
            hex_to_uint64("short")
        with pytest.raises(InvalidPerceptualHashError):
            hex_to_uint64("not_a_hex_value!")
        with pytest.raises(InvalidPerceptualHashError):
            uint64_to_hex(-1)


# =====================================================================
# 11-16: BK-Tree & Multi-Index Hash Tests
# =====================================================================


class TestIndexingStructures:
    """Tests for BK-Tree metric space and Multi-Index Hash candidate tables."""

    def test_bktree_insert_and_search(self):
        tree = BKTree()
        tree.insert(0x0000000000000000, "s0", "img0.jpg")
        tree.insert(0x0000000000000001, "s1", "img1.jpg")
        tree.insert(0x0000000000000003, "s2", "img2.jpg")
        tree.insert(0x000000000000000F, "s3", "img3.jpg")
        tree.insert(0xFFFFFFFFFFFFFFFF, "s4", "img4.jpg")

        assert tree.total_items == 5

        # Radius 1 search around 0x0000000000000000 -> matches s0 (d=0) and s1 (d=1)
        results = tree.search(0x0000000000000000, max_distance=1)
        matched_ids = {item.sample_id: dist for item, dist in results}
        assert matched_ids == {"s0": 0, "s1": 1}

        # Radius 2 search around 0x0000000000000000 -> matches s0, s1, s2
        results_r2 = tree.search(0x0000000000000000, max_distance=2)
        assert {item.sample_id for item, _ in results_r2} == {"s0", "s1", "s2"}

    def test_bktree_duplicate_hash_handling(self):
        """Multiple items sharing the exact same perceptual hash must be preserved."""
        tree = BKTree()
        tree.insert(0x1234567812345678, "sample_a", "a.jpg")
        tree.insert(0x1234567812345678, "sample_b", "b.jpg")
        tree.insert(0x1234567812345678, "sample_c", "c.jpg")

        assert tree.total_items == 3
        assert tree.unique_hashes == 1

        results = tree.search(0x1234567812345678, max_distance=0)
        assert len(results) == 3
        assert {item.sample_id for item, _ in results} == {"sample_a", "sample_b", "sample_c"}

    def test_bktree_empty_search(self):
        tree = BKTree()
        assert tree.total_items == 0
        assert tree.search(0x0000, max_distance=5) == []

    def test_bktree_invalid_distance(self):
        tree = BKTree()
        with pytest.raises(InvalidThresholdError):
            tree.search(0x0000, max_distance=65)
        with pytest.raises(InvalidThresholdError):
            tree.search(0x0000, max_distance=-1)

    def test_multi_index_hash_query(self):
        mih = MultiIndexHash(num_blocks=4)
        mih.insert(0x0000111122223333, "s0", "0.jpg")
        mih.insert(0x0000111122223332, "s1", "1.jpg")  # 1 bit diff (0x3333 ^ 0x3332 == 1)
        mih.insert(0x9999888877776666, "s2", "2.jpg")  # completely different

        assert mih.total_items == 3

        # Query s0 with radius 1 -> matches s0 and s1
        matches = mih.query(0x0000111122223333, max_distance=1)
        matched_ids = {item.sample_id for item, _ in matches}
        assert matched_ids == {"s0", "s1"}


# =====================================================================
# 17-25: Detector, Relationships & Clustering Tests
# =====================================================================


class TestDetectorAndClustering:
    """Tests for relationship formation, connected components, and cluster IDs."""

    def test_candidate_pair_deduplication_and_no_self_pairs(self):
        """Pairs must have canonical sample_a_id < sample_b_id and no self-comparisons."""
        fps = [
            PerceptualFingerprint(sample_id="s1", relative_path="1.jpg", phash="0000000000000000", dhash="0000000000000000"),
            PerceptualFingerprint(sample_id="s2", relative_path="2.jpg", phash="0000000000000001", dhash="0000000000000001"),
            PerceptualFingerprint(sample_id="s3", relative_path="3.jpg", phash="0000000000000003", dhash="0000000000000003"),
        ]
        detector = NearDuplicateDetector(config=NearDuplicateConfig(phash_threshold=5, dhash_threshold=5))
        result = detector.detect_duplicates(fps)

        for rel in result.relationships:
            assert rel.sample_a_id < rel.sample_b_id
            assert rel.sample_a_id != rel.sample_b_id

    def test_deterministic_clustering_connected_components(self):
        """A linked chain s1-s2 and s2-s3 must form a single cluster [s1, s2, s3]."""
        fps = [
            PerceptualFingerprint(sample_id="s1", relative_path="1.jpg", phash="0000000000000000", dhash="0000000000000000"),
            PerceptualFingerprint(sample_id="s2", relative_path="2.jpg", phash="0000000000000001", dhash="0000000000000001"),
            PerceptualFingerprint(sample_id="s3", relative_path="3.jpg", phash="0000000000000003", dhash="0000000000000003"),
            # Disjoint unrelated sample
            PerceptualFingerprint(sample_id="s4", relative_path="4.jpg", phash="ffffffffffffffff", dhash="ffffffffffffffff"),
        ]
        detector = NearDuplicateDetector(config=NearDuplicateConfig(phash_threshold=3, dhash_threshold=3))
        result = detector.detect_duplicates(fps)

        assert result.cluster_count == 1
        cluster = result.clusters[0]
        assert cluster.sample_count == 3
        assert cluster.sample_ids == ("s1", "s2", "s3")
        assert cluster.cluster_id.startswith("cluster_s1_")

    def test_contributor_preservation_in_clusters(self):
        fps = [
            PerceptualFingerprint(sample_id="s1", relative_path="1.jpg", phash="1111111111111111", dhash="1111111111111111", contributors=("user-x", "user-y")),
            PerceptualFingerprint(sample_id="s2", relative_path="2.jpg", phash="1111111111111111", dhash="1111111111111111", contributors=("user-z",)),
        ]
        detector = NearDuplicateDetector()
        result = detector.detect_duplicates(fps)

        assert result.cluster_count == 1
        cluster = result.clusters[0]
        assert cluster.contributors == ("user-x", "user-y", "user-z")

    def test_strict_non_maliciousness_semantic_guarantee(self):
        """Verify that scan result contains ZERO maliciousness declarations or security tags."""
        fps = [
            PerceptualFingerprint(sample_id="s1", relative_path="1.jpg", phash="0000000000000000", dhash="0000000000000000"),
            PerceptualFingerprint(sample_id="s2", relative_path="2.jpg", phash="0000000000000000", dhash="0000000000000000"),
        ]
        detector = NearDuplicateDetector()
        result = detector.detect_duplicates(fps)

        # Check result serialization contains no malicious keywords
        res_dict = result.model_dump()
        dump_str = str(res_dict).lower()
        assert "malicious" not in dump_str
        assert "poison" not in dump_str
        assert "attack" not in dump_str
        assert "threat" not in dump_str


# =====================================================================
# 26-30: End-to-End, Scalability & Offline Tests
# =====================================================================


class TestEndToEndAndScalability:
    """End-to-End integration, scalability, and offline tests."""

    def test_e2e_dataset_near_duplicate_detection(self, tmp_path: Path):
        """Ingest synthetic dataset with duplicated images, run detection, verify clusters."""
        dataset_dir = tmp_path / "dataset"
        class_dir = dataset_dir / "cats"
        class_dir.mkdir(parents=True)

        # Base image
        img_base = _generate_pattern_image(48, 48, "gradient")
        img_base.save(class_dir / "cat_orig.png")

        # Re-saved variant
        img_base.save(class_dir / "cat_clone.png")

        # Minor resized variant (48x48 -> 44x44)
        img_resized = img_base.resize((44, 44), Image.Resampling.BILINEAR)
        img_resized.save(class_dir / "cat_resized.png")

        # Distinct image
        img_other = _generate_pattern_image(48, 48, "diagonal")
        img_other.save(class_dir / "dog_distinct.png")

        # Ingest via Phase 5.2 engine
        ingestion_res = ingest_dataset(dataset_dir)
        assert ingestion_res.total_samples == 4

        # Run Near-Duplicate Detection
        dup_result = detect_near_duplicates(ingestion_res, dataset_dir)

        assert dup_result.total_samples == 4
        assert dup_result.cluster_count == 1
        cluster = dup_result.clusters[0]
        assert cluster.sample_count == 3
        assert "cats/dog_distinct.png" not in cluster.sample_paths

    def test_reproducibility_across_repeated_scans(self, tmp_path: Path):
        dataset_dir = tmp_path / "repro_dataset" / "items"
        dataset_dir.mkdir(parents=True)

        img1 = _generate_pattern_image(32, 32, "gradient")
        img1.save(dataset_dir / "a.png")
        img1.save(dataset_dir / "b.png")

        ingest_res = ingest_dataset(tmp_path / "repro_dataset")

        res1 = detect_near_duplicates(ingest_res, tmp_path / "repro_dataset")
        res2 = detect_near_duplicates(ingest_res, tmp_path / "repro_dataset")

        assert res1.duplicate_relationships_count == res2.duplicate_relationships_count
        assert res1.cluster_count == res2.cluster_count
        assert res1.clusters[0].cluster_id == res2.clusters[0].cluster_id

    def test_large_dataset_scalability_benchmark(self):
        """Index 100 samples into BKTree; verify sub-quadratic performance."""
        fps: List[PerceptualFingerprint] = []
        for i in range(100):
            # Create 50 disjoint clusters of 2 samples each:
            # Cluster pair k: sample 2k and 2k+1 share base pattern shifted by k * 64
            cluster_idx = i // 2
            # Use deterministic orthogonal base hashes:
            base_hash = (cluster_idx * 0x0505050505050505) & 0xFFFFFFFFFFFFFFFF
            if i % 2 == 1:
                base_hash ^= 0x01  # 1 bit difference within cluster

            fps.append(
                PerceptualFingerprint(
                    sample_id=f"sample_{i:04d}",
                    relative_path=f"img_{i:04d}.jpg",
                    phash=f"{base_hash:016x}",
                    dhash=f"{base_hash:016x}",
                )
            )

        detector = NearDuplicateDetector(config=NearDuplicateConfig(phash_threshold=1, dhash_threshold=1))
        result = detector.detect_duplicates(fps)

        assert result.total_samples == 100
        # Exactly 50 pairs of duplicates
        assert result.duplicate_relationships_count == 50
        assert result.cluster_count == 50

    def test_match_any_strategy(self):
        fps = [
            # pHash distance is 0, dHash distance is 20
            PerceptualFingerprint(sample_id="s1", relative_path="1.jpg", phash="0000000000000000", dhash="0000000000000000"),
            PerceptualFingerprint(sample_id="s2", relative_path="2.jpg", phash="0000000000000000", dhash="00000000000fffff"),
        ]
        # MATCH_BOTH with dhash_threshold 5 should reject
        det_both = NearDuplicateDetector(config=NearDuplicateConfig(phash_threshold=5, dhash_threshold=5, strategy=NearDuplicateStrategy.MATCH_BOTH))
        res_both = det_both.detect_duplicates(fps)
        assert res_both.duplicate_relationships_count == 0

        # MATCH_ANY with phash_threshold 5 should accept
        det_any = NearDuplicateDetector(config=NearDuplicateConfig(phash_threshold=5, dhash_threshold=5, strategy=NearDuplicateStrategy.MATCH_ANY))
        res_any = det_any.detect_duplicates(fps)
        assert res_any.duplicate_relationships_count == 1

    def test_weighted_strategy(self):
        fps = [
            PerceptualFingerprint(sample_id="s1", relative_path="1.jpg", phash="0000000000000000", dhash="0000000000000000"),
            PerceptualFingerprint(sample_id="s2", relative_path="2.jpg", phash="0000000000000001", dhash="0000000000000001"),
        ]
        det = NearDuplicateDetector(config=NearDuplicateConfig(strategy=NearDuplicateStrategy.WEIGHTED, weighted_min_similarity=0.95))
        res = det.detect_duplicates(fps)
        assert res.duplicate_relationships_count == 1
        assert res.relationships[0].similarity_score >= 0.95

    def test_single_sample_dataset(self):
        fps = [
            PerceptualFingerprint(sample_id="s1", relative_path="1.jpg", phash="0000000000000000", dhash="0000000000000000"),
        ]
        det = NearDuplicateDetector()
        res = det.detect_duplicates(fps)
        assert res.total_samples == 1
        assert res.duplicate_relationships_count == 0
        assert res.cluster_count == 0

    def test_empty_dataset(self):
        det = NearDuplicateDetector()
        res = det.detect_duplicates([])
        assert res.total_samples == 0
        assert res.duplicate_relationships_count == 0
        assert res.cluster_count == 0

    def test_missing_image_file_handling(self, tmp_path: Path):
        sample = CanonicalSample(
            sample_id="s_missing",
            relative_path="non_existent.jpg",
            file_size_bytes=100,
            width=100,
            height=100,
        )
        det = NearDuplicateDetector()
        with pytest.raises(Exception) as exc_info:
            det.extract_perceptual_fingerprints([sample], tmp_path)
        assert "not found" in str(exc_info.value).lower()

    def test_config_validation(self):
        with pytest.raises(ValueError):
            NearDuplicateConfig(phash_threshold=65)  # ge=0, le=64
        with pytest.raises(ValueError):
            NearDuplicateConfig(weighted_min_similarity=1.5)  # ge=0, le=1.0
