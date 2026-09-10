"""High-level orchestration and detection engine for OOD & Image Quality (Phase 5.7).

Coordinates:
  1. Header validation & anti-DoS safeguards (Phase 5.2).
  2. Deterministic Image Quality Analysis (IQA).
  3. Dual-Tier feature extraction (Tier 1 statistical descriptor / Tier 2 deep embedding).
  4. Robust non-parametric Median + MAD threshold calibration.
  5. Global, local, and class-conditional OOD distance scoring.
  6. Dataset-level operational distribution shift evaluation (MMD / Energy Distance).
  7. Multi-signal structured immutable findings output.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
from PIL import Image

from aivara.dataset.ood.drift import evaluate_distribution_shift
from aivara.dataset.ood.exceptions import (
    FeatureExtractionError,
    ImageQualityError,
    InsufficientReferenceSupportError,
    OODQualityError,
)
from aivara.dataset.ood.features import VisualFeatureExtractor
from aivara.dataset.ood.quality import extract_image_quality_metrics
from aivara.dataset.ood.schemas import (
    DistributionShiftEvidence,
    FeatureExtractionStatus,
    ImageQualityConfig,
    ImageQualityMetrics,
    OODCategory,
    OODConfig,
    OODScanFinding,
    OODScanResult,
    OODScore,
    ReferenceDistribution,
    ReferenceMode,
)
from aivara.dataset.schemas import CanonicalDatasetManifest, CanonicalSample


def compute_mad_threshold(distances: np.ndarray, beta: float = 3.5) -> Tuple[float, float, float]:
    """Compute robust non-parametric Median + MAD decision threshold.
    
    Formula:
      tau = Median + beta * (1.4826 * MAD)
      
    Returns:
      Tuple of (median_distance, mad_distance, calibrated_threshold)
    """
    if len(distances) == 0:
        return 0.0, 0.0, 0.0

    valid_dists = distances[np.isfinite(distances)]
    if len(valid_dists) == 0:
        return 0.0, 0.0, 0.0

    med = float(np.median(valid_dists))
    abs_dev = np.abs(valid_dists - med)
    mad = float(np.median(abs_dev))

    # Standard normal consistency scale factor: 1.4826
    normal_scale_mad = 1.4826 * mad
    tau = float(med + beta * max(1e-4, normal_scale_mad))

    return med, mad, tau


def compute_knn_distance(
    query_vec: np.ndarray,
    reference_mat: np.ndarray,
    k: int = 10,
) -> Tuple[float, Tuple[int, ...]]:
    """Compute average cosine distance to k nearest reference neighbors.
    
    Returns:
      Tuple of (average_knn_distance, nearest_indices)
    """
    if len(reference_mat) == 0:
        return 0.0, ()

    # Cosine distance for L2-normalized vectors: d = 1 - dot(q, r)
    dots = np.dot(reference_mat, query_vec)
    dists = np.maximum(0.0, 1.0 - dots)

    k_actual = min(k, len(reference_mat))
    if k_actual == 0:
        return 0.0, ()

    # Top k smallest distances
    partition_idx = np.argpartition(dists, k_actual - 1)[:k_actual]
    sorted_top_k = partition_idx[np.argsort(dists[partition_idx])]

    avg_dist = float(np.mean(dists[sorted_top_k]))
    return max(0.0, avg_dist), tuple(int(idx) for idx in sorted_top_k)


class OODQualityDetector:
    """Offline, deterministic OOD and Image Quality Analysis Engine."""

    def __init__(
        self,
        config: Optional[OODConfig] = None,
        tier2_model: Optional[Callable[[Image.Image], np.ndarray]] = None,
        force_tier1: bool = False,
    ) -> None:
        self.config = config or OODConfig()
        self.feature_extractor = VisualFeatureExtractor(
            tier2_model=tier2_model,
            force_tier1=force_tier1,
        )

    def scan_manifest(
        self,
        manifest: CanonicalDatasetManifest,
        dataset_root: Union[str, Path],
        reference_manifest: Optional[CanonicalDatasetManifest] = None,
        reference_root: Optional[Union[str, Path]] = None,
        reference_features: Optional[np.ndarray] = None,
        reference_labels: Optional[Sequence[str]] = None,
    ) -> OODScanResult:
        """Execute complete OOD & Image Quality scan over a canonical dataset manifest.
        
        Args:
            manifest: Canonical dataset manifest to audit.
            dataset_root: Local root directory on disk.
            reference_manifest: Optional explicit external reference manifest.
            reference_root: Local root directory for reference manifest if provided.
            reference_features: Optional pre-extracted reference feature matrix.
            reference_labels: Optional labels for pre-extracted reference features.
            
        Returns:
            OODScanResult immutable summary.
        """
        root_path = Path(dataset_root)
        total_samples = len(manifest.samples)

        # Deterministic scan identifier
        scan_hasher = hashlib.sha256()
        scan_hasher.update(manifest.dataset_name.encode("utf-8"))
        scan_hasher.update(str(total_samples).encode("utf-8"))
        scan_hasher.update(str(self.config.deterministic_seed).encode("utf-8"))
        scan_id = f"oqae_scan_{scan_hasher.hexdigest()[:16]}"

        dataset_fp = manifest.metadata.get("dataset_merkle_root") or manifest.metadata.get("dataset_hash") or ("0" * 64)

        findings: List[OODScanFinding] = []
        diagnostics: Dict[str, Any] = {
            "guardrail_triggered": False,
            "tier1_fallback": False,
        }

        # Check micro-dataset guardrail
        if total_samples < self.config.min_dataset_size_guardrail and reference_manifest is None and reference_features is None:
            diagnostics["guardrail_triggered"] = True
            diagnostics["reason"] = f"Dataset size N={total_samples} below minimum guardrail N={self.config.min_dataset_size_guardrail}"
            
            # Extract basic IQA only, skip OOD distribution estimation
            scanned_count = 0
            quality_anomalies = 0
            for s in manifest.samples:
                sample_file = root_path / s.relative_path
                try:
                    iqa = extract_image_quality_metrics(sample_file)
                    scanned_count += 1
                    sample_findings = self._audit_image_quality(s.sample_id, iqa, s.contributors)
                    if sample_findings:
                        quality_anomalies += 1
                        findings.extend(sample_findings)
                except Exception:
                    pass

            finding_small = OODScanFinding(
                finding_id=f"{scan_id}_guardrail_small_dataset",
                sample_id=manifest.samples[0].sample_id if manifest.samples else "dataset",
                category=OODCategory.INSUFFICIENT_EVIDENCE,
                severity="LOW",
                confidence=0.0,
                explanation="Dataset sample count is below the minimum statistical guardrail of 25 samples. Complex distribution shift and OOD novelty estimation were bypassed to prevent uncalibrated findings.",
                limitations=("Micro-dataset guardrail active (N < 25).",),
            )
            findings.append(finding_small)

            return OODScanResult(
                scan_id=scan_id,
                dataset_name=manifest.dataset_name,
                dataset_fingerprint=dataset_fp if len(dataset_fp) == 64 else ("0" * 64),
                total_samples=total_samples,
                scanned_samples=scanned_count,
                feature_extraction_status=FeatureExtractionStatus.TIER1_STATISTICAL_ONLY,
                quality_anomaly_count=quality_anomalies,
                ood_sample_count=0,
                findings=tuple(findings),
                diagnostics=diagnostics,
            )

        # 1. Image Quality & Feature Extraction Pipeline
        sample_features: List[np.ndarray] = []
        valid_sample_ids: List[str] = []
        valid_sample_labels: List[str] = []
        sample_iqa_map: Dict[str, ImageQualityMetrics] = {}
        sample_contributors_map: Dict[str, Tuple[str, ...]] = {}
        scanned_count = 0
        quality_anomaly_count = 0
        overall_feat_status = FeatureExtractionStatus.TIER1_STATISTICAL_ONLY
        feat_method_name = "tier1_spatial_histogram"

        for s in manifest.samples:
            sample_file = root_path / s.relative_path

            # Decompression bomb and security checks
            if s.width * s.height > 100_000_000 or (s.width / max(1, s.height)) > 100.0 or (s.height / max(1, s.width)) > 100.0:
                findings.append(
                    OODScanFinding(
                        finding_id=f"{scan_id}_{s.sample_id}_security_violation",
                        sample_id=s.sample_id,
                        category=OODCategory.SECURITY_VALIDATION_FAILED,
                        severity="HIGH",
                        confidence=1.0,
                        contributors=s.contributors,
                        explanation=f"Image {s.relative_path} exceeded maximum safe dimension or aspect ratio bounds ({s.width}x{s.height}).",
                        limitations=("Defensive anti-decompression bomb filter triggered.",),
                    )
                )
                continue

            # IQA extraction
            try:
                iqa = extract_image_quality_metrics(sample_file)
                sample_iqa_map[s.sample_id] = iqa
                scanned_count += 1
                sample_q_findings = self._audit_image_quality(s.sample_id, iqa, s.contributors)
                if sample_q_findings:
                    quality_anomaly_count += 1
                    findings.extend(sample_q_findings)
            except Exception as exc:
                findings.append(
                    OODScanFinding(
                        finding_id=f"{scan_id}_{s.sample_id}_corruption",
                        sample_id=s.sample_id,
                        category=OODCategory.IMAGE_CORRUPTION,
                        severity="HIGH",
                        confidence=1.0,
                        contributors=s.contributors,
                        explanation=f"Image file {s.relative_path} could not be parsed or decoded: {str(exc)}.",
                        limitations=("Payload damaged or corrupted.",),
                    )
                )
                continue

            # Feature extraction
            try:
                feat, status, m_name = self.feature_extractor.extract(sample_file)
                sample_features.append(feat)
                valid_sample_ids.append(s.sample_id)
                primary_label = s.annotations[0].category_name if s.annotations else "unlabeled"
                valid_sample_labels.append(primary_label)
                sample_contributors_map[s.sample_id] = s.contributors
                overall_feat_status = status
                feat_method_name = m_name
            except Exception as exc:
                findings.append(
                    OODScanFinding(
                        finding_id=f"{scan_id}_{s.sample_id}_feat_err",
                        sample_id=s.sample_id,
                        category=OODCategory.FEATURE_EXTRACTOR_UNAVAILABLE,
                        severity="MEDIUM",
                        confidence=0.5,
                        contributors=s.contributors,
                        explanation=f"Feature extraction failed for sample {s.relative_path}: {str(exc)}.",
                        limitations=("Feature extraction exception.",),
                    )
                )

        if len(sample_features) == 0:
            return OODScanResult(
                scan_id=scan_id,
                dataset_name=manifest.dataset_name,
                dataset_fingerprint=dataset_fp if len(dataset_fp) == 64 else ("0" * 64),
                total_samples=total_samples,
                scanned_samples=scanned_count,
                feature_extraction_status=overall_feat_status,
                quality_anomaly_count=quality_anomaly_count,
                ood_sample_count=0,
                findings=tuple(findings),
                diagnostics={"error": "Zero valid visual features extracted."},
            )

        query_feat_mat = np.array(sample_features, dtype=np.float64)

        # 2. Reference Distribution Setup
        ref_feat_mat: np.ndarray
        ref_labels: List[str]
        ref_mode: ReferenceMode
        ref_id: str

        if reference_features is not None:
            ref_feat_mat = reference_features
            ref_labels = list(reference_labels or ["unlabeled"] * len(reference_features))
            ref_mode = ReferenceMode.FROZEN_DOMAIN_REFERENCE
            ref_id = "frozen_domain_ref"
        elif reference_manifest is not None and reference_root is not None:
            # Extract reference features from reference manifest
            ref_root = Path(reference_root)
            extracted_ref_feats = []
            extracted_ref_lbls = []
            for rs in reference_manifest.samples:
                rf_path = ref_root / rs.relative_path
                try:
                    r_feat, _, _ = self.feature_extractor.extract(rf_path)
                    extracted_ref_feats.append(r_feat)
                    r_lbl = rs.annotations[0].category_name if rs.annotations else "unlabeled"
                    extracted_ref_lbls.append(r_lbl)
                except Exception:
                    continue
            ref_feat_mat = np.array(extracted_ref_feats, dtype=np.float64) if extracted_ref_feats else np.empty((0, 128))
            ref_labels = extracted_ref_lbls
            ref_mode = ReferenceMode.EXPLICIT_REFERENCE_DATASET
            ref_id = reference_manifest.dataset_name
        else:
            # INTERNAL_DATASET_BASELINE mode
            ref_feat_mat = query_feat_mat
            ref_labels = valid_sample_labels
            ref_mode = ReferenceMode.INTERNAL_DATASET_BASELINE
            ref_id = manifest.dataset_name

        m_ref = len(ref_feat_mat)
        if m_ref < self.config.min_reference_size_guardrail:
            # Insufficient reference support
            findings.append(
                OODScanFinding(
                    finding_id=f"{scan_id}_insufficient_reference",
                    sample_id="reference",
                    category=OODCategory.INSUFFICIENT_REFERENCE_SUPPORT,
                    severity="LOW",
                    confidence=0.0,
                    explanation=f"Reference distribution size M={m_ref} is below the required support threshold of {self.config.min_reference_size_guardrail}. OOD novelty calibration skipped.",
                    limitations=("Insufficient reference samples for reliable non-parametric calibration.",),
                )
            )
            return OODScanResult(
                scan_id=scan_id,
                dataset_name=manifest.dataset_name,
                dataset_fingerprint=dataset_fp if len(dataset_fp) == 64 else ("0" * 64),
                total_samples=total_samples,
                scanned_samples=scanned_count,
                feature_extraction_status=overall_feat_status,
                quality_anomaly_count=quality_anomaly_count,
                ood_sample_count=0,
                findings=tuple(findings),
                diagnostics={"insufficient_reference": True, "reference_count": m_ref},
            )

        # 3. Non-Parametric Threshold Calibration (Median + MAD)
        ref_dists = []
        for i in range(m_ref):
            r_vec = ref_feat_mat[i]
            # Leave-one-out if evaluating on internal baseline
            if ref_mode == ReferenceMode.INTERNAL_DATASET_BASELINE:
                mask = np.ones(m_ref, dtype=bool)
                mask[i] = False
                sub_ref = ref_feat_mat[mask]
            else:
                sub_ref = ref_feat_mat
            d, _ = compute_knn_distance(r_vec, sub_ref, k=self.config.k_neighbors)
            ref_dists.append(d)

        ref_dists_arr = np.array(ref_dists)
        med_dist, mad_dist, tau_ood = compute_mad_threshold(ref_dists_arr, beta=self.config.mad_beta)

        # Class reference counts
        unique_classes, counts = np.unique(ref_labels, return_counts=True)
        class_ref_counts = {str(c): int(cnt) for c, cnt in zip(unique_classes, counts)}

        ref_dist_model = ReferenceDistribution(
            reference_mode=ref_mode,
            reference_identity=ref_id,
            reference_sample_count=m_ref,
            feature_method=feat_method_name,
            feature_dimension=ref_feat_mat.shape[1],
            median_distance=med_dist,
            mad_distance=mad_dist,
            calibrated_threshold=tau_ood,
            class_reference_counts=class_ref_counts,
        )

        # 4. Global & Local/Class-Conditional OOD Scoring
        ood_sample_count = 0

        for i, s_id in enumerate(valid_sample_ids):
            q_vec = query_feat_mat[i]
            s_label = valid_sample_labels[i]

            # Global kNN
            if ref_mode == ReferenceMode.INTERNAL_DATASET_BASELINE:
                mask = np.ones(m_ref, dtype=bool)
                mask[i] = False
                target_ref = ref_feat_mat[mask]
            else:
                target_ref = ref_feat_mat

            glob_dist, nearest_idx = compute_knn_distance(q_vec, target_ref, k=self.config.k_neighbors)
            is_glob_ood = bool(glob_dist > tau_ood)

            # Local / Class-conditional kNN
            local_dist: Optional[float] = None
            is_loc_ood: Optional[bool] = None
            subgroup_status: Optional[str] = None

            c_count = class_ref_counts.get(s_label, 0)
            if c_count >= self.config.min_class_support_guardrail:
                c_indices = [idx for idx, lbl in enumerate(ref_labels) if lbl == s_label]
                if ref_mode == ReferenceMode.INTERNAL_DATASET_BASELINE and i in c_indices:
                    c_indices.remove(i)
                if len(c_indices) >= self.config.min_class_support_guardrail:
                    c_ref_mat = ref_feat_mat[c_indices]
                    local_dist, _ = compute_knn_distance(q_vec, c_ref_mat, k=min(self.config.k_neighbors, len(c_indices)))
                    # Class threshold approximation
                    is_loc_ood = bool(local_dist > (tau_ood * 1.1))
                else:
                    subgroup_status = OODCategory.FALLBACK_GLOBAL_OOD.value
            else:
                subgroup_status = OODCategory.FALLBACK_GLOBAL_OOD.value

            # Normalized novelty index [0.0, 1.0]
            if tau_ood > 1e-4:
                diff = glob_dist - tau_ood
                scale = max(1e-4, 1.4826 * mad_dist)
                novelty_score = float(1.0 / (1.0 + math.exp(-2.0 * (diff / scale))))
            else:
                novelty_score = 0.0

            novelty_score = min(1.0, max(0.0, novelty_score))

            nearest_sample_ids = tuple(valid_sample_ids[idx] for idx in nearest_idx if idx < len(valid_sample_ids))

            ood_score_obj = OODScore(
                global_knn_distance=glob_dist,
                local_class_knn_distance=local_dist,
                is_global_ood=is_glob_ood,
                is_local_ood=is_loc_ood,
                calibrated_threshold=tau_ood,
                normalized_novelty_score=novelty_score,
                subgroup_status=subgroup_status,
                nearest_reference_sample_ids=nearest_sample_ids,
            )

            # Generate OOD finding if anomalous
            if is_glob_ood or is_loc_ood:
                ood_sample_count += 1
                cat = OODCategory.LOCAL_SUBGROUP_OOD if (is_loc_ood and not is_glob_ood) else OODCategory.GLOBAL_OOD
                conf = min(1.0, max(0.5, novelty_score))
                findings.append(
                    OODScanFinding(
                        finding_id=f"{scan_id}_{s_id}_{cat.value.lower()}",
                        sample_id=s_id,
                        category=cat,
                        severity="MEDIUM" if glob_dist < (tau_ood * 1.3) else "HIGH",
                        confidence=conf,
                        contributors=sample_contributors_map.get(s_id, ()),
                        quality_metrics=sample_iqa_map.get(s_id),
                        ood_score=ood_score_obj,
                        explanation=(
                            f"Sample {s_id} exhibits a visual feature distance of {glob_dist:.4f}, "
                            f"exceeding the robust reference threshold ({tau_ood:.4f})."
                        ),
                        limitations=(
                            "Measured in feature space relative to reference baseline.",
                            "Does not evaluate semantics or intent.",
                        ),
                    )
                )

        # 5. Dataset-Level Operational Distribution Shift (MMD / Energy)
        shift_evidence: Optional[DistributionShiftEvidence] = None
        if ref_mode != ReferenceMode.INTERNAL_DATASET_BASELINE:
            query_contributors = tuple(manifest.samples[0].contributors if manifest.samples else ())
            shift_evidence = evaluate_distribution_shift(
                query_features=query_feat_mat,
                ref_features=ref_feat_mat,
                seed=self.config.deterministic_seed,
                max_subsample=self.config.max_subsample_shift,
                n_permutations=50,
            )

            if shift_evidence.is_shift_detected:
                findings.append(
                    OODScanFinding(
                        finding_id=f"{scan_id}_dataset_distribution_shift",
                        sample_id="dataset_batch",
                        category=OODCategory.OPERATIONAL_DISTRIBUTION_SHIFT,
                        severity="MEDIUM",
                        confidence=min(1.0, max(0.6, 1.0 - (shift_evidence.p_value_estimate or 0.0))),
                        explanation=(
                            f"Statistical distribution shift detected across dataset batch (MMD={shift_evidence.mmd_statistic:.4f}, "
                            f"Energy={shift_evidence.energy_distance:.4f}, p={shift_evidence.p_value_estimate:.4f}). "
                            f"Primary variation axes: {', '.join(shift_evidence.primary_shift_factors) if shift_evidence.primary_shift_factors else 'feature distribution'}."
                        ),
                        limitations=(
                            "Indicates overall acquisition/environmental divergence.",
                            "Represents non-adversarial operational shift.",
                        ),
                    )
                )

        # Sort findings deterministically by sample_id, finding_id
        findings.sort(key=lambda f: (f.sample_id, f.finding_id))

        return OODScanResult(
            scan_id=scan_id,
            dataset_name=manifest.dataset_name,
            dataset_fingerprint=dataset_fp if len(dataset_fp) == 64 else ("0" * 64),
            total_samples=total_samples,
            scanned_samples=scanned_count,
            feature_extraction_status=overall_feat_status,
            quality_anomaly_count=quality_anomaly_count,
            ood_sample_count=ood_sample_count,
            reference_distribution=ref_dist_model,
            distribution_shift=shift_evidence,
            findings=tuple(findings),
            diagnostics=diagnostics,
        )

    def _audit_image_quality(
        self,
        sample_id: str,
        iqa: ImageQualityMetrics,
        contributors: Tuple[str, ...],
    ) -> List[OODScanFinding]:
        """Generate objective, strongly-typed physical quality anomaly findings."""
        q_findings: List[OODScanFinding] = []
        cfg = self.config.iqa_config

        # 1. Blur
        if iqa.blur_laplacian_var < cfg.min_blur_laplacian_var:
            q_findings.append(
                OODScanFinding(
                    finding_id=f"iqa_{sample_id}_blur",
                    sample_id=sample_id,
                    category=OODCategory.BLUR_ANOMALY,
                    severity="MEDIUM",
                    confidence=min(1.0, max(0.5, 1.0 - (iqa.blur_laplacian_var / max(1.0, cfg.min_blur_laplacian_var)))),
                    contributors=contributors,
                    quality_metrics=iqa,
                    explanation=f"Sample displays optical or motion blur with low Laplacian focus variance ({iqa.blur_laplacian_var:.2f} < {cfg.min_blur_laplacian_var:.2f}).",
                    limitations=("Physical edge-frequency measurement.",),
                )
            )

        # 2. Underexposure
        if iqa.underexposure_ratio > cfg.max_underexposure_ratio:
            q_findings.append(
                OODScanFinding(
                    finding_id=f"iqa_{sample_id}_underexposed",
                    sample_id=sample_id,
                    category=OODCategory.EXPOSURE_UNDEREXPOSED,
                    severity="MEDIUM",
                    confidence=min(1.0, max(0.5, iqa.underexposure_ratio)),
                    contributors=contributors,
                    quality_metrics=iqa,
                    explanation=f"Sample exhibits severe shadow clipping ({iqa.underexposure_ratio * 100:.1f}% pixels with Y < 15).",
                    limitations=("Evaluates luminance distribution only.",),
                )
            )

        # 3. Overexposure
        if iqa.overexposure_ratio > cfg.max_overexposure_ratio:
            q_findings.append(
                OODScanFinding(
                    finding_id=f"iqa_{sample_id}_overexposed",
                    sample_id=sample_id,
                    category=OODCategory.EXPOSURE_OVEREXPOSED,
                    severity="MEDIUM",
                    confidence=min(1.0, max(0.5, iqa.overexposure_ratio)),
                    contributors=contributors,
                    quality_metrics=iqa,
                    explanation=f"Sample exhibits severe highlight saturation ({iqa.overexposure_ratio * 100:.1f}% pixels with Y > 240).",
                    limitations=("Evaluates luminance clipping only.",),
                )
            )

        # 4. Noise
        if iqa.noise_variance > cfg.max_noise_variance:
            q_findings.append(
                OODScanFinding(
                    finding_id=f"iqa_{sample_id}_noise",
                    sample_id=sample_id,
                    category=OODCategory.NOISE_ANOMALY,
                    severity="MEDIUM",
                    confidence=min(1.0, max(0.5, iqa.noise_variance / (cfg.max_noise_variance * 2.0))),
                    contributors=contributors,
                    quality_metrics=iqa,
                    explanation=f"High spatial noise variance detected ({iqa.noise_variance:.2f} > {cfg.max_noise_variance:.2f}, SNR={iqa.snr_db:.1f}dB).",
                    limitations=("Immerkaer high-frequency spatial estimation.",),
                )
            )

        # 5. JPEG Blockiness
        if iqa.jpeg_blockiness > cfg.max_jpeg_blockiness:
            q_findings.append(
                OODScanFinding(
                    finding_id=f"iqa_{sample_id}_blockiness",
                    sample_id=sample_id,
                    category=OODCategory.COMPRESSION_BLOCKINESS,
                    severity="LOW",
                    confidence=min(1.0, max(0.4, (iqa.jpeg_blockiness - 1.0) / 3.0)),
                    contributors=contributors,
                    quality_metrics=iqa,
                    explanation=f"Visible 8x8 DCT compression grid blocking detected (blockiness ratio {iqa.jpeg_blockiness:.2f} > {cfg.max_jpeg_blockiness:.2f}).",
                    limitations=("Lossy compression artifact estimation.",),
                )
            )

        # 6. Aspect Ratio / Resolution
        if iqa.width < cfg.min_dimension or iqa.height < cfg.min_dimension:
            q_findings.append(
                OODScanFinding(
                    finding_id=f"iqa_{sample_id}_low_resolution",
                    sample_id=sample_id,
                    category=OODCategory.RESOLUTION_ANOMALY,
                    severity="LOW",
                    confidence=1.0,
                    contributors=contributors,
                    quality_metrics=iqa,
                    explanation=f"Sample resolution ({iqa.width}x{iqa.height}) is below minimum acceptable threshold ({cfg.min_dimension}px).",
                    limitations=("Geometric dimension threshold.",),
                )
            )
        elif iqa.aspect_ratio < cfg.min_aspect_ratio or iqa.aspect_ratio > cfg.max_aspect_ratio:
            q_findings.append(
                OODScanFinding(
                    finding_id=f"iqa_{sample_id}_aspect_ratio",
                    sample_id=sample_id,
                    category=OODCategory.ASPECT_RATIO_ANOMALY,
                    severity="LOW",
                    confidence=0.8,
                    contributors=contributors,
                    quality_metrics=iqa,
                    explanation=f"Extreme aspect ratio ({iqa.aspect_ratio:.2f}) outside nominal range [{cfg.min_aspect_ratio}, {cfg.max_aspect_ratio}].",
                    limitations=("Geometric aspect ratio threshold.",),
                )
            )

        # 7. Color Cast
        if iqa.color_cast_delta > cfg.max_color_cast_delta:
            q_findings.append(
                OODScanFinding(
                    finding_id=f"iqa_{sample_id}_color_cast",
                    sample_id=sample_id,
                    category=OODCategory.COLOR_CAST_ANOMALY,
                    severity="LOW",
                    confidence=min(1.0, max(0.5, iqa.color_cast_delta / (cfg.max_color_cast_delta * 1.5))),
                    contributors=contributors,
                    quality_metrics=iqa,
                    explanation=f"Strong chromaticity divergence delta ({iqa.color_cast_delta:.2f} > {cfg.max_color_cast_delta:.2f}) indicates monochromatic or skewed color tint.",
                    limitations=("CIELAB chromaticity divergence.",),
                )
            )

        return q_findings


def detect_ood_and_quality(
    manifest: CanonicalDatasetManifest,
    dataset_root: Union[str, Path],
    config: Optional[OODConfig] = None,
    reference_manifest: Optional[CanonicalDatasetManifest] = None,
    reference_root: Optional[Union[str, Path]] = None,
    reference_features: Optional[np.ndarray] = None,
    reference_labels: Optional[Sequence[str]] = None,
    tier2_model: Optional[Callable[[Image.Image], np.ndarray]] = None,
    force_tier1: bool = False,
) -> OODScanResult:
    """Convenience entrypoint for executing Phase 5.7 OOD & Image Quality scan."""
    detector = OODQualityDetector(
        config=config,
        tier2_model=tier2_model,
        force_tier1=force_tier1,
    )
    return detector.scan_manifest(
        manifest=manifest,
        dataset_root=dataset_root,
        reference_manifest=reference_manifest,
        reference_root=reference_root,
        reference_features=reference_features,
        reference_labels=reference_labels,
    )
