"""Near-Duplicate Detection Engine and Clustering Orchestrator (Phase 5.4).

Identifies visually and structurally similar samples within datasets without asserting
maliciousness or subjective culpability. Produces structured, deterministic similarity
evidence and connected-component clusters.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from aivara.dataset.duplicates.bktree import BKTree
from aivara.dataset.duplicates.distance import (
    hamming_distance_uint64,
    hex_to_uint64,
    uint64_to_hex,
)
from aivara.dataset.duplicates.exceptions import DuplicateDetectionError
from aivara.dataset.duplicates.perceptual import (
    compute_dhash_uint64,
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
from aivara.dataset.path_security import resolve_safe_path
from aivara.dataset.schemas import CanonicalDatasetManifest, CanonicalSample, DatasetIngestionResult


class NearDuplicateDetector:
    """Detects near-duplicate image samples and constructs deterministic similarity clusters."""

    def __init__(self, config: Optional[NearDuplicateConfig] = None) -> None:
        self.config: NearDuplicateConfig = config or NearDuplicateConfig()

    def extract_perceptual_fingerprints(
        self,
        samples: Sequence[CanonicalSample],
        dataset_root: Union[str, Path],
    ) -> List[PerceptualFingerprint]:
        """Extract 64-bit pHash and dHash fingerprints for all samples in a dataset.

        Args:
            samples: Sequence of CanonicalSample objects.
            dataset_root: Dataset base directory on disk.

        Returns:
            List of PerceptualFingerprint domain objects.
        """
        fingerprints: List[PerceptualFingerprint] = []
        for sample in samples:
            full_path = resolve_safe_path(dataset_root, sample.relative_path)
            phash_uint = compute_phash_uint64(full_path)
            dhash_uint = compute_dhash_uint64(full_path)

            fingerprints.append(
                PerceptualFingerprint(
                    sample_id=sample.sample_id,
                    relative_path=sample.relative_path,
                    phash=uint64_to_hex(phash_uint),
                    dhash=uint64_to_hex(dhash_uint),
                    contributors=tuple(sorted(str(c) for c in (sample.contributors or ()))),
                )
            )
        return fingerprints

    def detect_duplicates(
        self,
        fingerprints: Sequence[PerceptualFingerprint],
    ) -> NearDuplicateScanResult:
        """Run candidate indexing, dual-hash verification, and clustering over fingerprints.

        Args:
            fingerprints: Precomputed perceptual fingerprints.

        Returns:
            Structured NearDuplicateScanResult.
        """
        total_samples = len(fingerprints)
        if total_samples <= 1:
            return NearDuplicateScanResult(
                total_samples=total_samples,
                indexed_samples=total_samples,
                candidate_pairs_evaluated=0,
                duplicate_relationships_count=0,
                cluster_count=0,
                relationships=(),
                clusters=(),
                config=self.config,
                capability_info={"engine": "NearDuplicateDetector", "version": "1.0"},
            )

        # 1. Build BK-Tree on pHash metric space
        tree = BKTree()
        fp_by_id: Dict[str, PerceptualFingerprint] = {}

        for fp in fingerprints:
            fp_by_id[fp.sample_id] = fp
            phash_val = hex_to_uint64(fp.phash)
            tree.insert(
                hash_val=phash_val,
                sample_id=fp.sample_id,
                relative_path=fp.relative_path,
                data=fp,
            )

        # 2. Candidate generation & dual-hash verification
        # Maximum radius to search in BK-tree
        search_radius = (
            max(self.config.phash_threshold, self.config.dhash_threshold)
            if self.config.strategy == NearDuplicateStrategy.MATCH_ANY
            else self.config.phash_threshold
        )

        evaluated_pairs: Set[Tuple[str, str]] = set()
        relationships: List[NearDuplicateRelationship] = []

        # Sort fingerprints by sample_id for deterministic iteration
        sorted_fps = sorted(fingerprints, key=lambda f: f.sample_id)

        for fp_a in sorted_fps:
            phash_a_uint = hex_to_uint64(fp_a.phash)
            candidates = tree.search(phash_a_uint, max_distance=search_radius)

            for item_b, p_dist in candidates:
                fp_b: PerceptualFingerprint = item_b.data
                if fp_a.sample_id == fp_b.sample_id:
                    continue  # Skip self-pair

                # Canonical pair ordering (lexicographical smaller first)
                if fp_a.sample_id < fp_b.sample_id:
                    pair_key = (fp_a.sample_id, fp_b.sample_id)
                    first_fp, second_fp = fp_a, fp_b
                else:
                    pair_key = (fp_b.sample_id, fp_a.sample_id)
                    first_fp, second_fp = fp_b, fp_a

                if pair_key in evaluated_pairs:
                    continue
                evaluated_pairs.add(pair_key)

                # Compute exact distances
                dist_p = hamming_distance_uint64(
                    hex_to_uint64(first_fp.phash), hex_to_uint64(second_fp.phash)
                )
                dist_d = hamming_distance_uint64(
                    hex_to_uint64(first_fp.dhash), hex_to_uint64(second_fp.dhash)
                )

                # Composite normalized similarity score in [0.0, 1.0]
                norm_p = 1.0 - (dist_p / 64.0)
                norm_d = 1.0 - (dist_d / 64.0)
                similarity_score = round(
                    self.config.phash_weight * norm_p + self.config.dhash_weight * norm_d, 4
                )

                # Evaluate match strategy
                qualifies = False
                if self.config.strategy == NearDuplicateStrategy.MATCH_BOTH:
                    qualifies = (
                        dist_p <= self.config.phash_threshold
                        and dist_d <= self.config.dhash_threshold
                    )
                elif self.config.strategy == NearDuplicateStrategy.MATCH_ANY:
                    qualifies = (
                        dist_p <= self.config.phash_threshold
                        or dist_d <= self.config.dhash_threshold
                    )
                elif self.config.strategy == NearDuplicateStrategy.WEIGHTED:
                    qualifies = similarity_score >= self.config.weighted_min_similarity

                if qualifies:
                    is_exact = dist_p == 0 and dist_d == 0
                    rel = NearDuplicateRelationship(
                        sample_a_id=first_fp.sample_id,
                        sample_a_path=first_fp.relative_path,
                        sample_b_id=second_fp.sample_id,
                        sample_b_path=second_fp.relative_path,
                        phash_a=first_fp.phash,
                        phash_b=second_fp.phash,
                        phash_distance=dist_p,
                        dhash_a=first_fp.dhash,
                        dhash_b=second_fp.dhash,
                        dhash_distance=dist_d,
                        similarity_score=similarity_score,
                        is_exact_perceptual_match=is_exact,
                        contributors_a=first_fp.contributors,
                        contributors_b=second_fp.contributors,
                    )
                    relationships.append(rel)

        # Sort relationships deterministically by (sample_a_id, sample_b_id)
        relationships.sort(key=lambda r: (r.sample_a_id, r.sample_b_id))

        # 3. Construct Connected-Component Clusters
        clusters = self._build_clusters(relationships, fp_by_id)

        return NearDuplicateScanResult(
            total_samples=total_samples,
            indexed_samples=total_samples,
            candidate_pairs_evaluated=len(evaluated_pairs),
            duplicate_relationships_count=len(relationships),
            cluster_count=len(clusters),
            relationships=tuple(relationships),
            clusters=tuple(clusters),
            config=self.config,
            capability_info={
                "engine": "NearDuplicateDetector",
                "version": "1.0",
                "index_type": "BKTree",
            },
        )

    def _build_clusters(
        self,
        relationships: List[NearDuplicateRelationship],
        fp_by_id: Dict[str, PerceptualFingerprint],
    ) -> List[NearDuplicateCluster]:
        """Build deterministic connected components from pairwise near-duplicate relationships."""
        if not relationships:
            return []

        adj: Dict[str, Set[str]] = defaultdict(set)
        rel_by_pair: Dict[Tuple[str, str], NearDuplicateRelationship] = {}

        for rel in relationships:
            adj[rel.sample_a_id].add(rel.sample_b_id)
            adj[rel.sample_b_id].add(rel.sample_a_id)
            rel_by_pair[(rel.sample_a_id, rel.sample_b_id)] = rel

        visited: Set[str] = set()
        clusters: List[NearDuplicateCluster] = []

        # Deterministic component discovery by sorting nodes
        all_nodes = sorted(adj.keys())

        for start_node in all_nodes:
            if start_node in visited:
                continue

            # BFS traversal
            component_nodes: List[str] = []
            queue = deque([start_node])
            visited.add(start_node)

            while queue:
                curr = queue.popleft()
                component_nodes.append(curr)
                for neighbor in sorted(adj[curr]):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            # Sort component nodes
            component_nodes.sort()
            if len(component_nodes) < 2:
                continue

            # Deterministic cluster ID: cluster_{min_sample_id}_{sha256(members)[:12]}
            member_digest = hashlib.sha256(
                ",".join(component_nodes).encode("utf-8")
            ).hexdigest()[:12]
            cluster_id = f"cluster_{component_nodes[0]}_{member_digest}"

            # Collect paths and contributors
            sample_paths: List[str] = []
            contributor_set: Set[str] = set()
            for s_id in component_nodes:
                fp = fp_by_id[s_id]
                sample_paths.append(fp.relative_path)
                for c in fp.contributors:
                    contributor_set.add(c)

            # Collect all relationships belonging to this cluster
            cluster_rels: List[NearDuplicateRelationship] = []
            for i in range(len(component_nodes)):
                for j in range(i + 1, len(component_nodes)):
                    pair = (component_nodes[i], component_nodes[j])
                    if pair in rel_by_pair:
                        cluster_rels.append(rel_by_pair[pair])

            clusters.append(
                NearDuplicateCluster(
                    cluster_id=cluster_id,
                    sample_count=len(component_nodes),
                    sample_ids=tuple(component_nodes),
                    sample_paths=tuple(sample_paths),
                    relationships=tuple(cluster_rels),
                    contributors=tuple(sorted(contributor_set)),
                )
            )

        # Sort clusters deterministically by cluster_id
        clusters.sort(key=lambda c: c.cluster_id)
        return clusters


def detect_near_duplicates(
    target: Union[DatasetIngestionResult, CanonicalDatasetManifest, Sequence[CanonicalSample]],
    dataset_root: Union[str, Path],
    config: Optional[NearDuplicateConfig] = None,
) -> NearDuplicateScanResult:
    """High-level functional API for scanning a dataset for near-duplicate samples.

    Args:
        target: DatasetIngestionResult, CanonicalDatasetManifest, or sequence of CanonicalSample.
        dataset_root: Filesystem dataset root path.
        config: Optional NearDuplicateConfig settings.

    Returns:
        NearDuplicateScanResult containing similarity relationships and clusters.
    """
    if isinstance(target, DatasetIngestionResult):
        samples = target.manifest.samples
    elif isinstance(target, CanonicalDatasetManifest):
        samples = target.samples
    elif isinstance(target, (list, tuple)):
        samples = target
    else:
        raise DuplicateDetectionError(f"Unsupported target type: '{type(target).__name__}'.")

    detector = NearDuplicateDetector(config=config)
    fingerprints = detector.extract_perceptual_fingerprints(samples, dataset_root)
    return detector.detect_duplicates(fingerprints)
