"""High-level orchestration and finding synthesis for Contributor Aggregation Engine (Phase 5.8)."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from aivara.dataset.contributors.aggregation import build_contributor_profiles
from aivara.dataset.contributors.attribution import UNATTRIBUTED_KEY
from aivara.dataset.contributors.schemas import (
    ContributorAggregationConfig,
    ContributorAggregationResult,
    ContributorCategory,
    ContributorEvidenceProfile,
    ContributorScanFinding,
)
from aivara.dataset.schemas import CanonicalDatasetManifest, CanonicalSample


class ContributorAggregationEngine:
    """Offline Contributor Evidence Aggregation & Profiling Engine."""

    def __init__(self, config: Optional[ContributorAggregationConfig] = None) -> None:
        self.config = config or ContributorAggregationConfig()

    def aggregate_manifest(
        self,
        manifest: CanonicalDatasetManifest,
        evidence_by_sample: Optional[Dict[str, Set[str]]] = None,
        subgroup_extractor: Optional[callable] = None,
    ) -> ContributorAggregationResult:
        """Aggregate dataset evidence across all contributors.
        
        Args:
            manifest: Canonical dataset manifest to audit.
            evidence_by_sample: Mapping of sample_id to set of triggered anomaly metric keys.
            subgroup_extractor: Optional callable extracting subgroup string from sample.
            
        Returns:
            ContributorAggregationResult immutable summary.
        """
        cfg = self.config
        samples = manifest.samples
        total_samples = len(samples)

        # Deterministic scan identifier
        scan_hasher = hashlib.sha256()
        scan_hasher.update(manifest.dataset_name.encode("utf-8"))
        scan_hasher.update(str(total_samples).encode("utf-8"))
        scan_hasher.update(str(cfg.deterministic_seed).encode("utf-8"))
        scan_id = f"cae_scan_{scan_hasher.hexdigest()[:16]}"

        dataset_fp = (
            manifest.metadata.get("dataset_merkle_root")
            or manifest.metadata.get("dataset_hash")
            or ("0" * 64)
        )
        if len(dataset_fp) != 64:
            dataset_fp = "0" * 64

        evidence_map = evidence_by_sample or {}

        # Build contributor profiles
        profiles, anomaly_hhi = build_contributor_profiles(
            samples=samples,
            evidence_by_sample=evidence_map,
            config=cfg,
            subgroup_extractor=subgroup_extractor,
        )

        findings: List[ContributorScanFinding] = []
        profiled_count = 0
        unattributed_count = 0

        # Small dataset warning
        if total_samples < cfg.min_dataset_support:
            findings.append(
                ContributorScanFinding(
                    finding_id=f"{scan_id}_small_dataset_support",
                    contributor_id="dataset",
                    category=ContributorCategory.INSUFFICIENT_CONTRIBUTOR_SUPPORT,
                    severity="LOW",
                    confidence=0.0,
                    explanation=(
                        f"Dataset sample count N={total_samples} is below minimum statistical support "
                        f"threshold of {cfg.min_dataset_support}. Comparative differentials may have wide uncertainty bounds."
                    ),
                    limitations=("Small total dataset size.",),
                )
            )

        for c_id in sorted(profiles.keys()):
            prof = profiles[c_id]
            if prof.is_sufficient_support and c_id != UNATTRIBUTED_KEY:
                profiled_count += 1
            if c_id == UNATTRIBUTED_KEY:
                unattributed_count = int(prof.total_samples_contributed)

            # 1. Unattributed Container finding
            if c_id == UNATTRIBUTED_KEY and prof.total_samples_contributed > 0:
                tot_anom = sum(m.contributor_count for m in prof.metrics.values())
                if tot_anom > 0:
                    findings.append(
                        ContributorScanFinding(
                            finding_id=f"{scan_id}_unattributed_evidence",
                            contributor_id=UNATTRIBUTED_KEY,
                            category=ContributorCategory.UNATTRIBUTED_EVIDENCE,
                            severity="LOW",
                            confidence=1.0,
                            profile=prof,
                            explanation=(
                                f"Preserved {tot_anom:.1f} weighted anomaly evidence items across "
                                f"{prof.total_samples_contributed} samples lacking contributor metadata."
                            ),
                            limitations=("Missing contributor identifiers in source dataset.",),
                        )
                    )
                continue

            # 2. Insufficient Contributor Support
            if not prof.is_sufficient_support:
                findings.append(
                    ContributorScanFinding(
                        finding_id=f"{scan_id}_{c_id}_insufficient_support",
                        contributor_id=c_id,
                        category=ContributorCategory.INSUFFICIENT_CONTRIBUTOR_SUPPORT,
                        severity="LOW",
                        confidence=0.0,
                        profile=prof,
                        explanation=(
                            f"Contributor {c_id} has exposure n={prof.weighted_sample_exposure:.1f}, "
                            f"which is below the minimum support threshold of {cfg.min_contributor_support} samples. "
                            f"Statistical differentials and confidence bounds were discounted."
                        ),
                        limitations=("Micro-contributor sample size (n < 5).",),
                    )
                )
                continue

            # 3. Class Specialization (Descriptive Policy Threshold)
            # AIVARA v1 Policy Thresholds: H(c) < 0.5 bits and dominant class proportion >= 85%.
            # These are policy cutoffs for highlighting domain specialization, not universal scientific constants.
            if len(prof.class_distribution) >= 1 and prof.class_entropy < 0.5:
                dominant_class = max(prof.class_distribution.items(), key=lambda x: x[1])[0]
                dom_prop = prof.class_distribution[dominant_class]
                if dom_prop >= 0.85:
                    findings.append(
                        ContributorScanFinding(
                            finding_id=f"{scan_id}_{c_id}_class_distribution",
                            contributor_id=c_id,
                            category=ContributorCategory.CONTRIBUTOR_CLASS_DISTRIBUTION,
                            severity="LOW",
                            confidence=dom_prop,
                            profile=prof,
                            explanation=(
                                f"Contributor {c_id} displays focused class specialization ({dom_prop * 100:.1f}% "
                                f"in class '{dominant_class}', class entropy {prof.class_entropy:.2f} bits under AIVARA v1 policy thresholds)."
                            ),
                            limitations=(
                                "Reflects sampling or domain specialization.",
                                "Controls for observed class composition.",
                                "Entropy depends on dataset class count and distribution.",
                            ),
                        )
                    )

            # 4. Multi-Signal Evidence Concurrence
            # Note: Evidence categories (e.g. OOD, quality, label anomalies) may be correlated.
            # Diversity count tracks presence of distinct signal categories without assuming statistical independence or adding scores.
            if prof.evidence_diversity_count >= 3:
                findings.append(
                    ContributorScanFinding(
                        finding_id=f"{scan_id}_{c_id}_multi_signal",
                        contributor_id=c_id,
                        category=ContributorCategory.CONTRIBUTOR_MULTI_SIGNAL_EVIDENCE,
                        severity="HIGH",
                        confidence=min(1.0, 0.5 + 0.15 * prof.evidence_diversity_count),
                        profile=prof,
                        explanation=(
                            f"Contributor {c_id} displays elevated evidence across {prof.evidence_diversity_count} "
                            f"distinct observational evidence categories without score summation."
                        ),
                        limitations=(
                            "Signals are evaluated in parallel as separate observations.",
                            "No assumption of statistical independence among evidence types.",
                            "Observational evidence layer.",
                        ),
                    )
                )

            # 5. Per-metric anomaly concentration and differentials
            for m_name, m_val in prof.metrics.items():
                if m_val.contributor_count <= 0.0:
                    continue

                # Concentration share
                if m_val.anomaly_share >= cfg.anomaly_share_threshold and anomaly_hhi.get(m_name, 0.0) >= cfg.concentration_hhi_threshold:
                    findings.append(
                        ContributorScanFinding(
                            finding_id=f"{scan_id}_{c_id}_concentration_{m_name}",
                            contributor_id=c_id,
                            category=ContributorCategory.CONTRIBUTOR_ANOMALY_CONCENTRATION,
                            severity="MEDIUM",
                            confidence=min(1.0, m_val.anomaly_share),
                            profile=prof,
                            explanation=(
                                f"Contributor {c_id} accounts for {m_val.anomaly_share * 100:.1f}% of all "
                                f"'{m_name}' dataset anomalies (HHI={anomaly_hhi.get(m_name, 0.0):.2f})."
                            ),
                            limitations=("Statistical concentration metric.",),
                        )
                    )

                # Skip comparative differential findings if background is insufficient
                if m_val.rate_differential is None or m_val.background_rate is None:
                    continue

                # Label transition differential
                if m_name == "label_flip" and m_val.rate_differential >= cfg.transition_differential_threshold:
                    se_str = f"{m_val.standard_error:.3f}" if m_val.standard_error is not None else "N/A"
                    findings.append(
                        ContributorScanFinding(
                            finding_id=f"{scan_id}_{c_id}_transition_differential",
                            contributor_id=c_id,
                            category=ContributorCategory.CONTRIBUTOR_LABEL_TRANSITION,
                            severity="MEDIUM",
                            confidence=min(1.0, max(0.5, m_val.wilson_lower_bound)),
                            profile=prof,
                            explanation=(
                                f"Elevated directional transition rate observed for contributor {c_id} "
                                f"(rate {m_val.contributor_rate * 100:.1f}% vs background {m_val.background_rate * 100:.1f}%, "
                                f"Delta={m_val.rate_differential * 100:.1f}%, SE={se_str})."
                            ),
                            limitations=("Leave-one-out background comparison.",),
                        )
                    )

                # OOD concentration differential
                if m_name == "ood" and m_val.rate_differential >= 0.25 and m_val.wilson_lower_bound >= 0.15:
                    findings.append(
                        ContributorScanFinding(
                            finding_id=f"{scan_id}_{c_id}_ood_concentration",
                            contributor_id=c_id,
                            category=ContributorCategory.CONTRIBUTOR_OOD_CONCENTRATION,
                            severity="MEDIUM",
                            confidence=min(1.0, m_val.wilson_lower_bound * 1.5),
                            profile=prof,
                            explanation=(
                                f"Elevated out-of-distribution sample rate for contributor {c_id} "
                                f"(rate {m_val.contributor_rate * 100:.1f}% vs background {m_val.background_rate * 100:.1f}%, "
                                f"Delta={m_val.rate_differential * 100:.1f}%)."
                            ),
                            limitations=("Feature-space distance evaluation.",),
                        )
                    )

                # Quality concentration differential
                if m_name == "quality" and m_val.rate_differential >= 0.30 and m_val.wilson_lower_bound >= 0.20:
                    findings.append(
                        ContributorScanFinding(
                            finding_id=f"{scan_id}_{c_id}_quality_concentration",
                            contributor_id=c_id,
                            category=ContributorCategory.CONTRIBUTOR_QUALITY_CONCENTRATION,
                            severity="MEDIUM",
                            confidence=min(1.0, m_val.wilson_lower_bound * 1.5),
                            profile=prof,
                            explanation=(
                                f"Elevated physical quality degradation rate for contributor {c_id} "
                                f"(rate {m_val.contributor_rate * 100:.1f}% vs background {m_val.background_rate * 100:.1f}%, "
                                f"Delta={m_val.rate_differential * 100:.1f}%)."
                            ),
                            limitations=("Physical image quality measurements.",),
                        )
                    )

                # Duplicate concentration differential
                if m_name == "duplicate" and m_val.rate_differential >= 0.25 and m_val.wilson_lower_bound >= 0.15:
                    findings.append(
                        ContributorScanFinding(
                            finding_id=f"{scan_id}_{c_id}_duplicate_concentration",
                            contributor_id=c_id,
                            category=ContributorCategory.CONTRIBUTOR_DUPLICATE_CONCENTRATION,
                            severity="MEDIUM",
                            confidence=min(1.0, m_val.wilson_lower_bound * 1.5),
                            profile=prof,
                            explanation=(
                                f"Elevated near-duplicate submission rate for contributor {c_id} "
                                f"(rate {m_val.contributor_rate * 100:.1f}% vs background {m_val.background_rate * 100:.1f}%, "
                                f"Delta={m_val.rate_differential * 100:.1f}%)."
                            ),
                            limitations=("Perceptual hashing near-duplicate graph.",),
                        )
                    )

        # Sort findings deterministically
        findings.sort(key=lambda f: (f.contributor_id, f.finding_id))

        return ContributorAggregationResult(
            scan_id=scan_id,
            dataset_name=manifest.dataset_name,
            dataset_fingerprint=dataset_fp,
            total_contributors=len(profiles),
            profiled_contributors=profiled_count,
            unattributed_sample_count=unattributed_count,
            anomaly_hhi=anomaly_hhi,
            profiles=profiles,
            findings=tuple(findings),
            diagnostics={
                "min_contributor_support": cfg.min_contributor_support,
                "wilson_confidence": cfg.wilson_confidence,
            },
        )


def aggregate_contributor_evidence(
    manifest: CanonicalDatasetManifest,
    evidence_by_sample: Optional[Dict[str, Set[str]]] = None,
    config: Optional[ContributorAggregationConfig] = None,
    subgroup_extractor: Optional[callable] = None,
) -> ContributorAggregationResult:
    """Convenience functional entrypoint for executing Phase 5.8 contributor aggregation."""
    engine = ContributorAggregationEngine(config=config)
    return engine.aggregate_manifest(
        manifest=manifest,
        evidence_by_sample=evidence_by_sample,
        subgroup_extractor=subgroup_extractor,
    )
