"""Label-Flipping Detection Engine (Phase 5.6).

Identifies directional, asymmetric, and targeted label transition patterns across
contributed computer vision datasets and contributor subsets.

MANDATORY INVARIANTS:
1. LABEL-FLIPPING EVIDENCE != MALICIOUSNESS (evidence_layer="detection").
2. NO BASELINE RETRAINING (evaluates frozen feature outputs / out-of-fold estimates).
3. NEVER CALL y* GROUND TRUTH (observed label y_tilde vs estimated latent label y_star_hat).
4. STRICT MODEL-BIAS & RECIPROCAL CONTROLS (filters ordinary symmetric visual confusion).
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import numpy as np

from aivara.dataset.anomalies.detector import LabelAnomalyDetector
from aivara.dataset.anomalies.schemas import (
    LabelAnomalyFinding,
    LabelAnomalyScanResult,
    LabelPrediction,
    ModelState,
)
from aivara.dataset.flipping.exceptions import (
    InvalidTransitionMatrixError,
    LabelFlippingError,
)
from aivara.dataset.flipping.metrics import (
    compute_directional_asymmetry,
    compute_noise_concentration_index,
    compute_row_normalized_transition_rates,
    compute_support_discount,
    compute_targeted_flip_score,
    compute_transition_count_matrix,
    compute_wilson_lower_bound,
)
from aivara.dataset.flipping.schemas import (
    ContributorTransitionSummary,
    LabelFlipCategory,
    LabelFlipConfig,
    LabelFlipFinding,
    LabelFlipScanResult,
    LabelTransitionPair,
)
from aivara.dataset.schemas import (
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetIngestionResult,
)


class _AnalyticalTransitionUnit:
    """Internal atomic unit of label evaluation for transition analysis."""

    def __init__(
        self,
        sample_id: str,
        relative_path: str,
        annotation_id: Optional[str],
        observed_category_id: int,
        observed_category_name: str,
        estimated_latent_category_id: int,
        estimated_latent_category_name: str,
        margin: float,
        contributors: Tuple[str, ...],
        is_unsupported_modality: bool = False,
        modality_reason: Optional[str] = None,
    ) -> None:
        self.sample_id = sample_id
        self.relative_path = relative_path
        self.annotation_id = annotation_id
        self.observed_category_id = observed_category_id
        self.observed_category_name = observed_category_name
        self.estimated_latent_category_id = estimated_latent_category_id
        self.estimated_latent_category_name = estimated_latent_category_name
        self.margin = margin
        self.contributors = contributors
        self.is_unsupported_modality = is_unsupported_modality
        self.modality_reason = modality_reason


class LabelFlipDetector:
    """Deterministic, offline detector for directional and targeted label-flipping patterns."""

    def __init__(self, config: Optional[LabelFlipConfig] = None) -> None:
        self.config: LabelFlipConfig = config or LabelFlipConfig()

    def detect_flipping_from_predictions(
        self,
        predictions: Sequence[LabelPrediction],
        num_classes: Optional[int] = None,
        category_names: Optional[Dict[int, str]] = None,
        contributors_by_unit: Optional[Dict[str, Tuple[str, ...]]] = None,
        model_id: Optional[str] = "reference_model",
        model_hash: Optional[str] = None,
    ) -> LabelFlipScanResult:
        """Run Label-Flipping detection over Phase 5.5 out-of-fold probability predictions.

        Args:
            predictions: Sequence of LabelPrediction objects.
            num_classes: Optional total number of classes.
            category_names: Optional map of category ID to class label name.
            contributors_by_unit: Optional map of (sample_id or sample_id_ann_id) to contributor IDs.
            model_id: Model identifier.
            model_hash: Optional SHA-256 hash of model weights.

        Returns:
            Structured LabelFlipScanResult.
        """
        total_samples = len(predictions)
        if total_samples == 0:
            return LabelFlipScanResult(
                total_samples=0,
                evaluated_samples=0,
                transition_matrix=[],
                raw_count_matrix=[],
                findings=(),
                model_state=ModelState.MODEL_AVAILABLE,
                warnings=["No predictions supplied for label-flipping analysis."],
                capability_info={"engine": "LabelFlipDetector", "version": "1.0"},
            )

        # 1. Infer category mapping and total classes
        cat_map: Dict[int, str] = dict(category_names or {})
        for p in predictions:
            cat_map[p.observed_category_id] = p.observed_category_name
            cat_map[p.predicted_category_id] = p.predicted_category_name
            for k in p.probabilities.keys():
                if k not in cat_map:
                    cat_map[k] = f"class_{k}"

        k_classes = num_classes if num_classes is not None else (max(cat_map.keys()) + 1 if cat_map else 1)
        contrib_map = contributors_by_unit or {}

        # 2. Extract analytical transition units
        units: List[_AnalyticalTransitionUnit] = []
        observed_labels: List[int] = []
        latent_labels: List[int] = []

        for p in predictions:
            # Latent candidate is class maximizing threshold-adjusted probability
            # If highest alternative exceeds observed label, it's latent estimate, otherwise observed
            obs_id = p.observed_category_id
            probs = p.probabilities
            
            # Find best candidate
            best_cat = max(probs.items(), key=lambda kv: kv[1])[0] if probs else obs_id
            obs_prob = probs.get(obs_id, 0.0)
            best_prob = probs.get(best_cat, 0.0)
            margin = float(best_prob - obs_prob)

            unit_key = f"{p.sample_id}_{p.annotation_id or 'none'}"
            unit_contributors = contrib_map.get(unit_key, contrib_map.get(p.sample_id, ()))

            unit = _AnalyticalTransitionUnit(
                sample_id=p.sample_id,
                relative_path=p.relative_path,
                annotation_id=p.annotation_id,
                observed_category_id=obs_id,
                observed_category_name=cat_map.get(obs_id, f"class_{obs_id}"),
                estimated_latent_category_id=best_cat,
                estimated_latent_category_name=cat_map.get(best_cat, f"class_{best_cat}"),
                margin=margin,
                contributors=unit_contributors,
            )
            units.append(unit)
            observed_labels.append(obs_id)
            latent_labels.append(best_cat)

        # 3. Small Dataset Guardrail: N < min_total_samples (default 25)
        if total_samples < self.config.min_total_samples:
            insufficient_finding_id = hashlib.sha256(
                f"small_dataset:{total_samples}:{self.config.min_total_samples}".encode("utf-8")
            ).hexdigest()[:16]

            insufficient_finding = LabelFlipFinding(
                finding_id=f"lff_{insufficient_finding_id}",
                source_category_id=0,
                source_category_name=cat_map.get(0, "class_0"),
                target_category_id=None,
                target_category_name=None,
                category=LabelFlipCategory.INSUFFICIENT_SUPPORT,
                targeted_flip_score=0.0,
                confidence=0.0,
                evidence_layer="detection",
                limitations=[
                    f"Small dataset guardrail applied: sample count ({total_samples}) is below statistical minimum ({self.config.min_total_samples})."
                ],
            )

            return LabelFlipScanResult(
                total_samples=total_samples,
                evaluated_samples=total_samples,
                transition_matrix=[[0.0] * k_classes for _ in range(k_classes)],
                raw_count_matrix=[[0] * k_classes for _ in range(k_classes)],
                findings=(insufficient_finding,),
                model_state=ModelState.MODEL_AVAILABLE,
                warnings=[f"Statistical sample count {total_samples} < {self.config.min_total_samples}; label-flipping analysis skipped."],
                capability_info={"engine": "LabelFlipDetector", "version": "1.0"},
            )

        # 4. Compute Transition Count Matrix & Row-Normalized Rates
        count_matrix = compute_transition_count_matrix(
            observed_labels=observed_labels,
            latent_labels=latent_labels,
            num_classes=k_classes,
        )
        rate_matrix = compute_row_normalized_transition_rates(count_matrix)

        # Calculate sample support per observed class
        class_support: Dict[int, int] = {
            i: int(np.sum(count_matrix[i, :])) for i in range(k_classes)
        }

        # Index units by transition pair (i, j)
        units_by_pair: Dict[Tuple[int, int], List[_AnalyticalTransitionUnit]] = defaultdict(list)
        for u in units:
            units_by_pair[(u.observed_category_id, u.estimated_latent_category_id)].append(u)

        findings: List[LabelFlipFinding] = []
        sink_target_counts: Dict[int, Set[int]] = defaultdict(set)

        # 5. Evaluate Pairwise Transitions (i -> j for i != j)
        for i in range(k_classes):
            source_count = class_support.get(i, 0)
            source_name = cat_map.get(i, f"class_{i}")

            # Check if source class is singleton or rare
            if source_count < self.config.min_class_samples:
                # Class count < 5: cannot reliably serve as source of flipping analysis
                for j in range(k_classes):
                    if i != j and count_matrix[i, j] > 0:
                        target_name = cat_map.get(j, f"class_{j}")
                        pair_units = units_by_pair.get((i, j), [])
                        finding_id = hashlib.sha256(
                            f"rare_src:{i}:{j}:{source_count}".encode("utf-8")
                        ).hexdigest()[:16]

                        findings.append(
                            LabelFlipFinding(
                                finding_id=f"lff_{finding_id}",
                                source_category_id=i,
                                source_category_name=source_name,
                                target_category_id=j,
                                target_category_name=target_name,
                                category=LabelFlipCategory.INSUFFICIENT_SUPPORT,
                                targeted_flip_score=0.0,
                                confidence=0.0,
                                evidence_layer="detection",
                                affected_sample_ids=tuple(u.sample_id for u in pair_units),
                                affected_annotation_ids=tuple(u.annotation_id for u in pair_units if u.annotation_id),
                                limitations=[
                                    f"Source class '{source_name}' has only {source_count} samples (< {self.config.min_class_samples}); directional transition is statistically unverifiable."
                                ],
                            )
                        )
                continue

            for j in range(k_classes):
                if i == j:
                    continue

                n_ij = int(count_matrix[i, j])
                n_ji = int(count_matrix[j, i])
                target_count = class_support.get(j, 0)
                target_name = cat_map.get(j, f"class_{j}")
                pair_units = units_by_pair.get((i, j), [])

                if n_ij == 0:
                    continue

                # Transition metrics
                t_ij = float(rate_matrix[i][j])
                t_ji = float(rate_matrix[j][i])
                asym = compute_directional_asymmetry(n_ij, n_ji)
                nci = compute_noise_concentration_index(count_matrix, i, j)
                tfs, support_disc = compute_targeted_flip_score(
                    transition_rate=t_ij,
                    asymmetry=asym,
                    noise_concentration=nci,
                    transition_count=n_ij,
                    target_n=self.config.support_target_n,
                )
                w_lower = compute_wilson_lower_bound(t_ij, source_count)

                # Mean margin across samples in this transition
                avg_margin = float(np.mean([u.margin for u in pair_units])) if pair_units else 0.0

                # Check Insufficient Transition Support (N_{i, j} < 3)
                if n_ij < self.config.min_transition_count:
                    finding_id = hashlib.sha256(
                        f"sparse_trans:{i}:{j}:{n_ij}".encode("utf-8")
                    ).hexdigest()[:16]

                    transition_pair = LabelTransitionPair(
                        source_category_id=i,
                        source_category_name=source_name,
                        target_category_id=j,
                        target_category_name=target_name,
                        transition_count=n_ij,
                        reverse_transition_count=n_ji,
                        source_total_samples=source_count,
                        transition_rate=t_ij,
                        reverse_transition_rate=t_ji,
                        asymmetry_index=asym,
                        noise_concentration_index=nci,
                        targeted_flip_score=tfs,
                        average_margin=avg_margin,
                        wilson_lower_bound=w_lower,
                        support_discount=support_disc,
                        is_targeted=False,
                        is_reciprocal=False,
                    )

                    findings.append(
                        LabelFlipFinding(
                            finding_id=f"lff_{finding_id}",
                            source_category_id=i,
                            source_category_name=source_name,
                            target_category_id=j,
                            target_category_name=target_name,
                            category=LabelFlipCategory.INSUFFICIENT_SUPPORT,
                            targeted_flip_score=tfs,
                            confidence=0.0,
                            evidence_layer="detection",
                            affected_sample_ids=tuple(u.sample_id for u in pair_units),
                            affected_annotation_ids=tuple(u.annotation_id for u in pair_units if u.annotation_id),
                            transition_metrics=transition_pair,
                            limitations=[
                                f"Transition count ({n_ij}) is below minimum statistical support ({self.config.min_transition_count})."
                            ],
                        )
                    )
                    continue

                # Model-Bias Control Triad & Categorization
                limitations: List[str] = []
                is_reciprocal = False
                is_targeted = False
                final_confidence = w_lower

                # 1. Reciprocal Filter: |Asym| <= reciprocal_asym_threshold (0.35)
                if abs(asym) <= self.config.reciprocal_asym_threshold and n_ji >= self.config.min_transition_count:
                    category = LabelFlipCategory.RECIPROCAL_CLASS_CONFUSION
                    is_reciprocal = True
                    final_confidence = w_lower * 0.5
                    limitations.append(
                        f"Symmetric confusion detected between '{source_name}' and '{target_name}' (|Asym|={asym:.2f} <= {self.config.reciprocal_asym_threshold}); consistent with visual similarity or shared ontology."
                    )
                # 2. Targeted Label Flip Criteria:
                elif (
                    tfs >= self.config.targeted_tfs_threshold
                    and asym >= self.config.targeted_asym_threshold
                    and nci >= self.config.targeted_nci_threshold
                ):
                    category = LabelFlipCategory.POSSIBLE_LABEL_FLIP
                    is_targeted = True
                    sink_target_counts[j].add(i)

                    # Average Latent Margin Constraint
                    if avg_margin < self.config.min_latent_margin_threshold:
                        final_confidence = w_lower * 0.5
                        limitations.append(
                            f"Average prediction margin ({avg_margin:.3f}) is below threshold ({self.config.min_latent_margin_threshold}); confidence discounted by 50%."
                        )
                # 3. Directional Label Transition Criteria:
                elif asym >= self.config.directional_asym_threshold:
                    category = LabelFlipCategory.DIRECTIONAL_LABEL_TRANSITION
                    final_confidence = w_lower * support_disc
                # 4. Systematic Class Transition:
                elif t_ij >= self.config.systematic_rate_threshold:
                    category = LabelFlipCategory.SYSTEMATIC_CLASS_TRANSITION
                    final_confidence = w_lower * support_disc
                else:
                    category = LabelFlipCategory.DIRECTIONAL_LABEL_TRANSITION
                    final_confidence = w_lower * support_disc

                # Contributor Differential Analysis for Pair (i, j)
                contributor_summaries: List[ContributorTransitionSummary] = []
                contrib_source_counts: Dict[str, int] = defaultdict(int)
                contrib_trans_counts: Dict[str, int] = defaultdict(int)

                for u in units:
                    if u.observed_category_id == i:
                        for c in u.contributors:
                            contrib_source_counts[c] += 1
                            if u.estimated_latent_category_id == j:
                                contrib_trans_counts[c] += 1

                for c, c_source_total in contrib_source_counts.items():
                    c_trans_count = contrib_trans_counts[c]
                    if (
                        c_source_total >= self.config.min_contributor_samples
                        and c_trans_count >= self.config.min_contributor_transition_count
                    ):
                        c_rate = float(c_trans_count) / float(c_source_total)
                        bg_source = max(1, source_count - c_source_total)
                        bg_trans = max(0, n_ij - c_trans_count)
                        bg_rate = float(bg_trans) / float(bg_source)
                        delta_rate = c_rate - bg_rate

                        if delta_rate >= self.config.contributor_diff_threshold:
                            summary = ContributorTransitionSummary(
                                contributor_id=c,
                                source_category_id=i,
                                source_category_name=source_name,
                                target_category_id=j,
                                target_category_name=target_name,
                                contributor_transition_count=c_trans_count,
                                contributor_source_total=c_source_total,
                                contributor_transition_rate=c_rate,
                                dataset_baseline_rate=bg_rate,
                                rate_differential=delta_rate,
                                support_adequate=True,
                            )
                            contributor_summaries.append(summary)

                transition_pair = LabelTransitionPair(
                    source_category_id=i,
                    source_category_name=source_name,
                    target_category_id=j,
                    target_category_name=target_name,
                    transition_count=n_ij,
                    reverse_transition_count=n_ji,
                    source_total_samples=source_count,
                    transition_rate=t_ij,
                    reverse_transition_rate=t_ji,
                    asymmetry_index=asym,
                    noise_concentration_index=nci,
                    targeted_flip_score=tfs,
                    average_margin=avg_margin,
                    wilson_lower_bound=w_lower,
                    support_discount=support_disc,
                    is_targeted=is_targeted,
                    is_reciprocal=is_reciprocal,
                )

                finding_id_raw = f"{i}:{j}:{category.value}:{n_ij}:{asym:.3f}"
                finding_id = hashlib.sha256(finding_id_raw.encode("utf-8")).hexdigest()[:16]

                findings.append(
                    LabelFlipFinding(
                        finding_id=f"lff_{finding_id}",
                        source_category_id=i,
                        source_category_name=source_name,
                        target_category_id=j,
                        target_category_name=target_name,
                        category=category,
                        targeted_flip_score=tfs,
                        confidence=final_confidence,
                        evidence_layer="detection",
                        affected_sample_ids=tuple(u.sample_id for u in pair_units),
                        affected_annotation_ids=tuple(u.annotation_id for u in pair_units if u.annotation_id),
                        contributor_summaries=tuple(contributor_summaries),
                        transition_metrics=transition_pair,
                        limitations=limitations,
                    )
                )

                # Emit standalone contributor findings if significant differential present
                for c_sum in contributor_summaries:
                    c_finding_id = hashlib.sha256(
                        f"contrib:{c_sum.contributor_id}:{i}:{j}:{c_sum.rate_differential:.3f}".encode("utf-8")
                    ).hexdigest()[:16]

                    c_units = [
                        u for u in pair_units if c_sum.contributor_id in u.contributors
                    ]

                    findings.append(
                        LabelFlipFinding(
                            finding_id=f"lff_{c_finding_id}",
                            source_category_id=i,
                            source_category_name=source_name,
                            target_category_id=j,
                            target_category_name=target_name,
                            category=LabelFlipCategory.CONTRIBUTOR_ASSOCIATED_LABEL_TRANSITION,
                            targeted_flip_score=tfs,
                            confidence=min(1.0, c_sum.rate_differential),
                            evidence_layer="detection",
                            affected_sample_ids=tuple(u.sample_id for u in c_units),
                            affected_annotation_ids=tuple(u.annotation_id for u in c_units if u.annotation_id),
                            contributor_summaries=(c_sum,),
                            transition_metrics=transition_pair,
                            limitations=[
                                f"Contributor '{c_sum.contributor_id}' exhibits a {c_sum.rate_differential*100:.1f}% higher transition rate from '{source_name}' to '{target_name}' compared to dataset baseline."
                            ],
                        )
                    )

        # 6. Many-to-One Class Collapse Detection
        for sink_cls, source_classes in sink_target_counts.items():
            if len(source_classes) >= 3:
                sink_name = cat_map.get(sink_cls, f"class_{sink_cls}")
                collapse_finding_id = hashlib.sha256(
                    f"collapse:{sink_cls}:{','.join(str(s) for s in sorted(source_classes))}".encode("utf-8")
                ).hexdigest()[:16]

                collapse_units: List[_AnalyticalTransitionUnit] = []
                for s in source_classes:
                    collapse_units.extend(units_by_pair.get((s, sink_cls), []))

                findings.append(
                    LabelFlipFinding(
                        finding_id=f"lff_{collapse_finding_id}",
                        source_category_id=sink_cls,
                        source_category_name=sink_name,
                        target_category_id=sink_cls,
                        target_category_name=sink_name,
                        category=LabelFlipCategory.MANY_TO_ONE_COLLAPSE,
                        targeted_flip_score=0.8,
                        confidence=0.85,
                        evidence_layer="detection",
                        affected_sample_ids=tuple(u.sample_id for u in collapse_units),
                        affected_annotation_ids=tuple(u.annotation_id for u in collapse_units if u.annotation_id),
                        limitations=[
                            f"Multiple distinct classes ({len(source_classes)} classes: {', '.join(cat_map.get(s, str(s)) for s in sorted(source_classes))}) systematically transition into sink class '{sink_name}'."
                        ],
                    )
                )

        return LabelFlipScanResult(
            total_samples=total_samples,
            evaluated_samples=total_samples,
            transition_matrix=rate_matrix,
            raw_count_matrix=[[int(v) for v in row] for row in count_matrix],
            findings=tuple(findings),
            model_state=ModelState.MODEL_AVAILABLE,
            warnings=[],
            capability_info={
                "engine": "LabelFlipDetector",
                "version": "1.0",
                "evidence_layer": "detection",
            },
        )

    def detect_flipping(
        self,
        target: Union[
            DatasetIngestionResult,
            CanonicalDatasetManifest,
            Sequence[CanonicalSample],
            Sequence[LabelPrediction],
            LabelAnomalyScanResult,
        ],
        features: Optional[np.ndarray] = None,
        model_state: ModelState = ModelState.MODEL_AVAILABLE,
        model_id: Optional[str] = "detector_side_centroid_estimator",
        model_hash: Optional[str] = None,
        dataset_fingerprint: Optional[str] = None,
    ) -> LabelFlipScanResult:
        """High-level orchestration detecting label-flipping patterns across samples or manifests."""
        # 1. Handle Upstream Model State Failures
        if model_state != ModelState.MODEL_AVAILABLE:
            reason_map = {
                ModelState.MODEL_UNAVAILABLE: "Offline inference model is unavailable; zero synthetic predictions generated.",
                ModelState.MODEL_INCOMPATIBLE: "Model architecture or input shape is incompatible with dataset ontology.",
                ModelState.MODEL_LOAD_FAILED: "Offline model deserialization or weight loading failed.",
            }
            warning_msg = reason_map.get(model_state, "Model unavailable in offline environment.")

            finding_id = hashlib.sha256(
                f"model_state_fail:{model_state.value}".encode("utf-8")
            ).hexdigest()[:16]

            finding = LabelFlipFinding(
                finding_id=f"lff_{finding_id}",
                source_category_id=0,
                source_category_name="unknown",
                target_category_id=None,
                target_category_name=None,
                category=LabelFlipCategory.MODEL_UNAVAILABLE,
                targeted_flip_score=0.0,
                confidence=0.0,
                evidence_layer="detection",
                limitations=[warning_msg],
            )

            return LabelFlipScanResult(
                total_samples=0,
                evaluated_samples=0,
                transition_matrix=[],
                raw_count_matrix=[],
                findings=(finding,),
                model_state=model_state,
                warnings=[warning_msg],
                capability_info={
                    "engine": "LabelFlipDetector",
                    "version": "1.0",
                    "model_state": model_state.value,
                },
            )

        # 2. If target is already a sequence of LabelPrediction
        if isinstance(target, (list, tuple)) and target and isinstance(target[0], LabelPrediction):
            return self.detect_flipping_from_predictions(
                predictions=target,  # type: ignore
                model_id=model_id,
                model_hash=model_hash,
            )

        # 3. If target is already a LabelAnomalyScanResult from Phase 5.5
        if isinstance(target, LabelAnomalyScanResult):
            # Extract predictions from Phase 5.5 findings/evidence
            predictions: List[LabelPrediction] = []
            contrib_map: Dict[str, Tuple[str, ...]] = {}

            for f in target.findings:
                if f.evidence_data is not None:
                    # Construct pseudo-prediction from evidence data
                    latent_id = f.suggested_category_id if f.suggested_category_id is not None else f.observed_category_id
                    probs = {
                        f.observed_category_id: f.evidence_data.observed_prob,
                        latent_id: f.evidence_data.latent_prob,
                    }
                    pred = LabelPrediction(
                        sample_id=f.sample_id,
                        relative_path=f.relative_path,
                        annotation_id=f.annotation_id,
                        observed_category_id=f.observed_category_id,
                        observed_category_name=f.observed_category_name,
                        predicted_category_id=latent_id,
                        predicted_category_name=f.suggested_category_name or f.observed_category_name,
                        probabilities=probs,
                        is_out_of_fold=True,
                    )
                    predictions.append(pred)
                    unit_key = f"{f.sample_id}_{f.annotation_id or 'none'}"
                    contrib_map[unit_key] = f.contributors

            return self.detect_flipping_from_predictions(
                predictions=predictions,
                contributors_by_unit=contrib_map,
                model_id=model_id,
                model_hash=model_hash,
            )

        # 4. Otherwise, run Phase 5.5 detector to obtain predictions
        lade = LabelAnomalyDetector()
        anomaly_res = lade.detect_anomalies(
            target=target,  # type: ignore
            features=features,
            model_state=model_state,
            model_id=model_id,
            model_hash=model_hash,
            dataset_fingerprint=dataset_fingerprint,
        )

        return self.detect_flipping(
            target=anomaly_res,
            model_state=model_state,
            model_id=model_id,
            model_hash=model_hash,
            dataset_fingerprint=dataset_fingerprint,
        )


def detect_label_flipping(
    target: Union[
        DatasetIngestionResult,
        CanonicalDatasetManifest,
        Sequence[CanonicalSample],
        Sequence[LabelPrediction],
        LabelAnomalyScanResult,
    ],
    features: Optional[np.ndarray] = None,
    config: Optional[LabelFlipConfig] = None,
    model_state: ModelState = ModelState.MODEL_AVAILABLE,
    model_id: Optional[str] = "detector_side_centroid_estimator",
    model_hash: Optional[str] = None,
    dataset_fingerprint: Optional[str] = None,
) -> LabelFlipScanResult:
    """High-level functional entrypoint for label-flipping detection."""
    detector = LabelFlipDetector(config=config)
    return detector.detect_flipping(
        target=target,
        features=features,
        model_state=model_state,
        model_id=model_id,
        model_hash=model_hash,
        dataset_fingerprint=dataset_fingerprint,
    )
