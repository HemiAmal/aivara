"""Label Anomaly & Confident Learning Detection Engine (Phase 5.5).

Identifies statistical inconsistencies and predictive disagreement between observed
dataset annotations and visual feature representations.

MANDATORY INVARIANTS:
1. LABEL ANOMALY != MALICIOUSNESS (evidence_layer="detection").
2. NO BASELINE RETRAINING (only frozen feature extraction and detector-side temporary estimators).
3. NO DATA LEAKAGE (strictly out-of-fold probability estimation).
4. NEVER FABRICATE PREDICTIONS (structured insufficient evidence on missing/failed models).
5. NEVER CALL y* GROUND TRUTH (observed label y_tilde vs estimated latent label y_star_hat).
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import numpy as np

from aivara.dataset.anomalies.confident_learning import (
    compute_class_thresholds,
    compute_confident_count_matrix,
    compute_joint_distribution_matrix,
    compute_sample_anomaly_metrics,
    identify_systematic_anomalies,
)
from aivara.dataset.anomalies.estimator import (
    compute_out_of_fold_probabilities,
)
from aivara.dataset.anomalies.exceptions import (
    LabelAnomalyError,
    ModelIncompatibleError,
    ModelLoadFailedError,
    ModelUnavailableError,
    UnsupportedModalityError,
)
from aivara.dataset.anomalies.schemas import (
    LabelAnomalyCategory,
    LabelAnomalyConfig,
    LabelAnomalyEvidence,
    LabelAnomalyFinding,
    LabelAnomalyScanResult,
    LabelPrediction,
    ModelState,
)
from aivara.dataset.schemas import (
    CanonicalAnnotation,
    CanonicalDatasetManifest,
    CanonicalSample,
    DatasetIngestionResult,
)


class _AnalyticalUnit:
    """Internal representation of an atomic unit of label evaluation (image or bounding-box RoI)."""

    def __init__(
        self,
        sample_id: str,
        relative_path: str,
        category_id: int,
        category_name: str,
        annotation_id: Optional[str] = None,
        contributors: Tuple[str, ...] = (),
        is_unsupported_modality: bool = False,
        modality_reason: Optional[str] = None,
    ) -> None:
        self.sample_id = sample_id
        self.relative_path = relative_path
        self.category_id = category_id
        self.category_name = category_name
        self.annotation_id = annotation_id
        self.contributors = contributors
        self.is_unsupported_modality = is_unsupported_modality
        self.modality_reason = modality_reason


class LabelAnomalyDetector:
    """Deterministic, offline detector for statistical label anomalies and confident learning."""

    def __init__(self, config: Optional[LabelAnomalyConfig] = None) -> None:
        self.config: LabelAnomalyConfig = config or LabelAnomalyConfig()

    def extract_analytical_units(
        self,
        samples: Sequence[CanonicalSample],
    ) -> List[_AnalyticalUnit]:
        """Extract evaluation units from canonical samples for classification and object detection.

        - For ImageFolder/Classification: 1 unit per sample.
        - For Object Detection: 1 unit per bounding-box annotation, preserving annotation_id.
        - Dense segmentations or regression targets without valid bboxes are marked as unsupported modalities.
        """
        units: List[_AnalyticalUnit] = []

        for sample in samples:
            sample_contributors = tuple(sorted(str(c) for c in (sample.contributors or ())))

            if not sample.annotations:
                # Sample without annotations (e.g. unannotated or implicit folder class if metadata has class)
                cat_id = sample.metadata.get("category_id", 0)
                cat_name = sample.metadata.get("category_name", "unknown")
                units.append(
                    _AnalyticalUnit(
                        sample_id=sample.sample_id,
                        relative_path=sample.relative_path,
                        category_id=int(cat_id),
                        category_name=str(cat_name),
                        annotation_id=None,
                        contributors=sample_contributors,
                    )
                )
                continue

            # Process annotations
            for ann in sample.annotations:
                # Check for unsupported dense segmentation masks without bbox
                if ann.segmentation is not None and ann.bbox is None:
                    units.append(
                        _AnalyticalUnit(
                            sample_id=sample.sample_id,
                            relative_path=sample.relative_path,
                            category_id=ann.category_id,
                            category_name=ann.category_name,
                            annotation_id=ann.annotation_id,
                            contributors=sample_contributors,
                            is_unsupported_modality=True,
                            modality_reason="Dense segmentation masks without bounding-box RoI are unsupported in Phase 5.5",
                        )
                    )
                    continue

                # Supported classification or bounding-box RoI
                units.append(
                    _AnalyticalUnit(
                        sample_id=sample.sample_id,
                        relative_path=sample.relative_path,
                        category_id=ann.category_id,
                        category_name=ann.category_name,
                        annotation_id=ann.annotation_id if ann.bbox is not None else None,
                        contributors=sample_contributors,
                    )
                )

        return units

    def detect_anomalies_from_predictions(
        self,
        predictions: Sequence[LabelPrediction],
        num_classes: Optional[int] = None,
        category_names: Optional[Dict[int, str]] = None,
        model_id: Optional[str] = "reference_model",
        model_hash: Optional[str] = None,
        dataset_fingerprint: Optional[str] = None,
    ) -> LabelAnomalyScanResult:
        """Run Confident Learning anomaly detection over precomputed out-of-fold probability predictions.

        Args:
            predictions: Sequence of LabelPrediction objects with out-of-fold probabilities.
            num_classes: Optional total number of classes. Inferred if not provided.
            category_names: Optional map of category ID to category name.
            model_id: Model identifier string.
            model_hash: Optional SHA-256 digest of model weights.
            dataset_fingerprint: Optional cryptographic dataset hash.

        Returns:
            Structured LabelAnomalyScanResult.
        """
        total_samples = len(predictions)
        if total_samples == 0:
            return LabelAnomalyScanResult(
                total_samples=0,
                evaluated_samples=0,
                anomalous_samples_count=0,
                model_state=ModelState.MODEL_AVAILABLE,
                warnings=["No predictions supplied for evaluation."],
                capability_info={"engine": "LabelAnomalyDetector", "version": "1.0"},
            )

        # Infer category mapping and total classes
        cat_map: Dict[int, str] = dict(category_names or {})
        for p in predictions:
            cat_map[p.observed_category_id] = p.observed_category_name
            cat_map[p.predicted_category_id] = p.predicted_category_name
            for k in p.probabilities.keys():
                if k not in cat_map:
                    cat_map[k] = f"class_{k}"

        k_classes = num_classes if num_classes is not None else (max(cat_map.keys()) + 1 if cat_map else 1)

        # Build arrays
        observed_labels = [p.observed_category_id for p in predictions]
        probs_matrix = np.zeros((total_samples, k_classes), dtype=np.float64)
        for idx, p in enumerate(predictions):
            for cat_id, prob_val in p.probabilities.items():
                if 0 <= cat_id < k_classes:
                    probs_matrix[idx, cat_id] = float(prob_val)
            # Normalize row to ensure sum to 1.0
            row_sum = np.sum(probs_matrix[idx])
            if row_sum > 0:
                probs_matrix[idx] /= row_sum

        # Calculate class counts
        class_counts: Dict[int, int] = {}
        for y_i in observed_labels:
            class_counts[y_i] = class_counts.get(y_i, 0) + 1

        # Small dataset guardrail: N < min_total_samples (default 25)
        if total_samples < self.config.min_total_samples:
            insufficient_findings: List[LabelAnomalyFinding] = []
            for p in predictions:
                finding_id = hashlib.sha256(
                    f"{p.sample_id}:{p.annotation_id or 'none'}:{p.observed_category_id}:insufficient".encode("utf-8")
                ).hexdigest()[:16]

                finding = LabelAnomalyFinding(
                    finding_id=f"laf_{finding_id}",
                    sample_id=p.sample_id,
                    relative_path=p.relative_path,
                    annotation_id=p.annotation_id,
                    observed_category_id=p.observed_category_id,
                    observed_category_name=p.observed_category_name,
                    suggested_category_id=None,
                    suggested_category_name=None,
                    anomaly_score=0.5,
                    confidence=0.0,
                    category=LabelAnomalyCategory.INSUFFICIENT_EVIDENCE,
                    margin=0.0,
                    evidence_layer="detection",
                    model_id=model_id,
                    model_hash=model_hash,
                    limitations=[
                        f"Small dataset guardrail applied: sample count ({total_samples}) is below statistical minimum ({self.config.min_total_samples})."
                    ],
                )
                insufficient_findings.append(finding)

            return LabelAnomalyScanResult(
                total_samples=total_samples,
                evaluated_samples=total_samples,
                anomalous_samples_count=0,
                joint_distribution_matrix=[[0.0] * k_classes for _ in range(k_classes)],
                class_thresholds={c: 1.0 / k_classes for c in range(k_classes)},
                findings=tuple(insufficient_findings),
                model_state=ModelState.MODEL_AVAILABLE,
                warnings=[f"Statistical sample count {total_samples} < {self.config.min_total_samples}; confident learning skipped."],
                capability_info={"engine": "LabelAnomalyDetector", "version": "1.0"},
            )

        # 1. Compute empirical class thresholds t_j
        thresholds = compute_class_thresholds(
            observed_labels=observed_labels,
            predicted_probs=probs_matrix,
            num_classes=k_classes,
        )

        # 2. Compute Confident Count Matrix C_{i, j}
        count_matrix = compute_confident_count_matrix(
            observed_labels=observed_labels,
            predicted_probs=probs_matrix,
            thresholds=thresholds,
            num_classes=k_classes,
        )

        # 3. Compute Normalized Joint Distribution Matrix Q_{i, j}
        joint_matrix = compute_joint_distribution_matrix(
            confident_counts=count_matrix,
            observed_labels=observed_labels,
            num_classes=k_classes,
        )

        # 4. Compute metrics per sample
        margins: List[float] = []
        top_alts: List[int] = []
        sample_metrics: List[Tuple[int, float, float, float, float, float]] = []

        for idx, p in enumerate(predictions):
            metrics = compute_sample_anomaly_metrics(
                observed_label=p.observed_category_id,
                probabilities=probs_matrix[idx],
                thresholds=thresholds,
                class_counts=class_counts,
                num_classes=k_classes,
            )
            sample_metrics.append(metrics)
            top_alts.append(metrics[0])
            margins.append(metrics[3])

        # 5. Identify systematic class confusion pairs
        systematic_pairs = identify_systematic_anomalies(
            observed_labels=observed_labels,
            predicted_top_alts=top_alts,
            margins=margins,
            class_counts=class_counts,
            systematic_ratio_threshold=self.config.systematic_anomaly_ratio_threshold,
        )

        # 6. Construct structured findings
        findings: List[LabelAnomalyFinding] = []
        anomalous_count = 0

        for idx, p in enumerate(predictions):
            j_star, obs_prob, latent_prob, margin, score, raw_conf = sample_metrics[idx]
            obs_id = p.observed_category_id
            obs_name = cat_map.get(obs_id, f"class_{obs_id}")
            latent_name = cat_map.get(j_star, f"class_{j_star}")
            obs_class_size = class_counts.get(obs_id, 0)

            guardrails_applied: List[str] = []
            final_conf = raw_conf
            limitations: List[str] = []

            # Check singleton class
            if obs_class_size <= 1:
                category = LabelAnomalyCategory.INSUFFICIENT_EVIDENCE
                final_conf = 0.0
                limitations.append("Singleton class (N=1): statistically unverifiable across cross-validation folds.")
                guardrails_applied.append("singleton_class_guardrail")
            elif margin > 0.0:
                # Anomaly detected!
                anomalous_count += 1
                
                # Check rare-class discount (< 5 samples)
                if obs_class_size < self.config.min_class_samples:
                    category = LabelAnomalyCategory.RARE_CLASS_ANOMALY
                    final_conf = raw_conf * self.config.rare_class_confidence_discount
                    guardrails_applied.append(f"rare_class_discount_{int(self.config.rare_class_confidence_discount*100)}pct")
                    limitations.append(
                        f"Rare class ({obs_class_size} samples < {self.config.min_class_samples}): confidence discounted by {int((1-self.config.rare_class_confidence_discount)*100)}%."
                    )
                # Check high confidence alternative class
                elif (
                    latent_prob >= self.config.high_confidence_prob_threshold
                    and obs_prob <= self.config.observed_prob_upper_threshold
                ):
                    category = LabelAnomalyCategory.HIGH_CONFIDENCE_ALTERNATIVE_CLASS
                # Check systematic class anomaly
                elif (obs_id, j_star) in systematic_pairs:
                    category = LabelAnomalyCategory.CLASS_SYSTEMATIC_ANOMALY
                    limitations.append(
                        f"Systematic confusion detected between class '{obs_name}' and '{latent_name}'."
                    )
                else:
                    category = LabelAnomalyCategory.POSSIBLE_LABEL_MISMATCH
            else:
                # Margin <= 0
                if latent_prob > obs_prob:
                    category = LabelAnomalyCategory.MODEL_DISAGREEMENT
                else:
                    # Normal consistency (not an anomaly finding, or marginal)
                    category = LabelAnomalyCategory.MODEL_DISAGREEMENT
                    final_conf = 0.0

            evidence_data = LabelAnomalyEvidence(
                observed_category_id=obs_id,
                observed_category_name=obs_name,
                estimated_latent_category_id=j_star,
                estimated_latent_category_name=latent_name,
                observed_prob=obs_prob,
                latent_prob=latent_prob,
                class_threshold=thresholds.get(j_star, 0.0),
                margin=margin,
                anomaly_score=score,
                raw_confidence=raw_conf,
                guardrails_applied=guardrails_applied,
                final_confidence=final_conf,
            )

            finding_id_raw = f"{p.sample_id}:{p.annotation_id or 'none'}:{obs_id}:{j_star}:{category.value}"
            finding_id = hashlib.sha256(finding_id_raw.encode("utf-8")).hexdigest()[:16]

            finding = LabelAnomalyFinding(
                finding_id=f"laf_{finding_id}",
                sample_id=p.sample_id,
                relative_path=p.relative_path,
                annotation_id=p.annotation_id,
                observed_category_id=obs_id,
                observed_category_name=obs_name,
                suggested_category_id=j_star if margin > 0.0 else None,
                suggested_category_name=latent_name if margin > 0.0 else None,
                anomaly_score=score,
                confidence=final_conf,
                category=category,
                margin=margin,
                evidence_layer="detection",
                model_id=model_id,
                model_hash=model_hash,
                contributors=(),
                limitations=limitations,
                evidence_data=evidence_data,
            )
            findings.append(finding)

        return LabelAnomalyScanResult(
            total_samples=total_samples,
            evaluated_samples=total_samples,
            anomalous_samples_count=anomalous_count,
            joint_distribution_matrix=joint_matrix,
            class_thresholds=thresholds,
            findings=tuple(findings),
            model_state=ModelState.MODEL_AVAILABLE,
            warnings=[],
            capability_info={
                "engine": "LabelAnomalyDetector",
                "version": "1.0",
                "confident_learning": "active",
            },
        )

    def detect_anomalies(
        self,
        target: Union[DatasetIngestionResult, CanonicalDatasetManifest, Sequence[CanonicalSample]],
        features: Optional[np.ndarray] = None,
        model_state: ModelState = ModelState.MODEL_AVAILABLE,
        model_id: Optional[str] = "detector_side_centroid_estimator",
        model_hash: Optional[str] = None,
        dataset_fingerprint: Optional[str] = None,
    ) -> LabelAnomalyScanResult:
        """Execute label anomaly detection and confident learning over dataset samples or features.

        Args:
            target: DatasetIngestionResult, CanonicalDatasetManifest, or sequence of CanonicalSample.
            features: Optional (N, D) array of fixed visual feature embeddings.
            model_state: Current offline model availability state.
            model_id: Model or estimator identifier.
            model_hash: SHA-256 hash of model weights if applicable.
            dataset_fingerprint: Cryptographic dataset fingerprint.

        Returns:
            Structured LabelAnomalyScanResult.
        """
        # Resolve samples from target
        if isinstance(target, DatasetIngestionResult):
            samples = target.manifest.samples
            categories = {c.category_id: c.category_name for c in target.manifest.categories}
        elif isinstance(target, CanonicalDatasetManifest):
            samples = target.samples
            categories = {c.category_id: c.category_name for c in target.categories}
        elif isinstance(target, (list, tuple)):
            samples = target
            categories = {}
        else:
            raise LabelAnomalyError(f"Unsupported target type: '{type(target).__name__}'.")

        # 1. Handle Model Availability State Failures
        if model_state != ModelState.MODEL_AVAILABLE:
            units = self.extract_analytical_units(samples)
            findings: List[LabelAnomalyFinding] = []
            
            reason_map = {
                ModelState.MODEL_UNAVAILABLE: "Offline inference model is unavailable; zero synthetic predictions generated.",
                ModelState.MODEL_INCOMPATIBLE: "Model architecture or input shape is incompatible with dataset ontology.",
                ModelState.MODEL_LOAD_FAILED: "Offline model deserialization or weight loading failed.",
            }
            warning_msg = reason_map.get(model_state, "Model unavailable in offline environment.")

            for u in units:
                finding_id = hashlib.sha256(
                    f"{u.sample_id}:{u.annotation_id or 'none'}:{u.category_id}:{model_state.value}".encode("utf-8")
                ).hexdigest()[:16]

                finding = LabelAnomalyFinding(
                    finding_id=f"laf_{finding_id}",
                    sample_id=u.sample_id,
                    relative_path=u.relative_path,
                    annotation_id=u.annotation_id,
                    observed_category_id=u.category_id,
                    observed_category_name=u.category_name,
                    suggested_category_id=None,
                    suggested_category_name=None,
                    anomaly_score=0.5,
                    confidence=0.0,
                    category=(
                        LabelAnomalyCategory.MODEL_UNAVAILABLE
                        if model_state == ModelState.MODEL_UNAVAILABLE
                        else LabelAnomalyCategory.INSUFFICIENT_EVIDENCE
                    ),
                    margin=0.0,
                    evidence_layer="detection",
                    model_id=model_id,
                    model_hash=model_hash,
                    contributors=u.contributors,
                    limitations=[warning_msg],
                )
                findings.append(finding)

            return LabelAnomalyScanResult(
                total_samples=len(units),
                evaluated_samples=0,
                anomalous_samples_count=0,
                joint_distribution_matrix=[],
                class_thresholds={},
                findings=tuple(findings),
                model_state=model_state,
                warnings=[warning_msg],
                capability_info={
                    "engine": "LabelAnomalyDetector",
                    "version": "1.0",
                    "model_state": model_state.value,
                },
            )

        # 2. Extract analytical units
        units = self.extract_analytical_units(samples)
        if not units:
            return LabelAnomalyScanResult(
                total_samples=0,
                evaluated_samples=0,
                anomalous_samples_count=0,
                model_state=ModelState.MODEL_AVAILABLE,
                warnings=["Dataset contains no valid analytical units."],
                capability_info={"engine": "LabelAnomalyDetector", "version": "1.0"},
            )

        # Separate supported units vs unsupported modalities
        valid_units = [u for u in units if not u.is_unsupported_modality]
        unsupported_units = [u for u in units if u.is_unsupported_modality]

        # Check total samples
        num_classes = max([u.category_id for u in valid_units] + [0]) + 1 if valid_units else 1
        for u in valid_units:
            if u.category_id not in categories:
                categories[u.category_id] = u.category_name

        # If features provided, compute out-of-fold predictions
        if features is not None:
            if len(features) != len(valid_units):
                raise LabelAnomalyError(
                    f"Feature array size ({len(features)}) does not match valid analytical units count ({len(valid_units)})"
                )

            labels = [u.category_id for u in valid_units]
            sample_ids = [f"{u.sample_id}_{u.annotation_id or 'img'}" for u in valid_units]

            oof_probs = compute_out_of_fold_probabilities(
                features=features,
                labels=labels,
                num_classes=num_classes,
                sample_ids=sample_ids,
                k_folds=self.config.k_folds,
                random_seed=self.config.random_seed,
                dataset_fingerprint=dataset_fingerprint,
            )

            predictions: List[LabelPrediction] = []
            for idx, u in enumerate(valid_units):
                probs_dict = {c: float(oof_probs[idx, c]) for c in range(num_classes)}
                pred_c = int(np.argmax(oof_probs[idx]))
                predictions.append(
                    LabelPrediction(
                        sample_id=u.sample_id,
                        relative_path=u.relative_path,
                        annotation_id=u.annotation_id,
                        observed_category_id=u.category_id,
                        observed_category_name=u.category_name,
                        predicted_category_id=pred_c,
                        predicted_category_name=categories.get(pred_c, f"class_{pred_c}"),
                        probabilities=probs_dict,
                        is_out_of_fold=True,
                    )
                )

            # Detect anomalies over predictions
            scan_res = self.detect_anomalies_from_predictions(
                predictions=predictions,
                num_classes=num_classes,
                category_names=categories,
                model_id=model_id,
                model_hash=model_hash,
                dataset_fingerprint=dataset_fingerprint,
            )
        else:
            # Features not provided directly: if N < min_total_samples or features missing
            # create structured INSUFFICIENT_EVIDENCE findings
            unsupported_findings: List[LabelAnomalyFinding] = []
            for u in units:
                finding_id = hashlib.sha256(
                    f"{u.sample_id}:{u.annotation_id or 'none'}:{u.category_id}:no_features".encode("utf-8")
                ).hexdigest()[:16]

                limitation = (
                    u.modality_reason
                    if u.is_unsupported_modality
                    else "Feature embeddings not provided for offline inference."
                )

                finding = LabelAnomalyFinding(
                    finding_id=f"laf_{finding_id}",
                    sample_id=u.sample_id,
                    relative_path=u.relative_path,
                    annotation_id=u.annotation_id,
                    observed_category_id=u.category_id,
                    observed_category_name=u.category_name,
                    suggested_category_id=None,
                    suggested_category_name=None,
                    anomaly_score=0.5,
                    confidence=0.0,
                    category=LabelAnomalyCategory.INSUFFICIENT_EVIDENCE,
                    margin=0.0,
                    evidence_layer="detection",
                    model_id=model_id,
                    model_hash=model_hash,
                    contributors=u.contributors,
                    limitations=[limitation],
                )
                unsupported_findings.append(finding)

            return LabelAnomalyScanResult(
                total_samples=len(units),
                evaluated_samples=0,
                anomalous_samples_count=0,
                joint_distribution_matrix=[],
                class_thresholds={},
                findings=tuple(unsupported_findings),
                model_state=ModelState.MODEL_AVAILABLE,
                warnings=["No feature embeddings provided for offline inference."],
                capability_info={"engine": "LabelAnomalyDetector", "version": "1.0"},
            )

        # Append unsupported units findings to scan_res if any
        if unsupported_units:
            all_findings = list(scan_res.findings)
            for u in unsupported_units:
                finding_id = hashlib.sha256(
                    f"{u.sample_id}:{u.annotation_id or 'none'}:{u.category_id}:unsupported".encode("utf-8")
                ).hexdigest()[:16]

                finding = LabelAnomalyFinding(
                    finding_id=f"laf_{finding_id}",
                    sample_id=u.sample_id,
                    relative_path=u.relative_path,
                    annotation_id=u.annotation_id,
                    observed_category_id=u.category_id,
                    observed_category_name=u.category_name,
                    suggested_category_id=None,
                    suggested_category_name=None,
                    anomaly_score=0.5,
                    confidence=0.0,
                    category=LabelAnomalyCategory.INSUFFICIENT_EVIDENCE,
                    margin=0.0,
                    evidence_layer="detection",
                    model_id=model_id,
                    model_hash=model_hash,
                    contributors=u.contributors,
                    limitations=[u.modality_reason or "Unsupported modality in Phase 5.5"],
                )
                all_findings.append(finding)

            scan_res = LabelAnomalyScanResult(
                total_samples=len(units),
                evaluated_samples=len(valid_units),
                anomalous_samples_count=scan_res.anomalous_samples_count,
                joint_distribution_matrix=scan_res.joint_distribution_matrix,
                class_thresholds=scan_res.class_thresholds,
                findings=tuple(all_findings),
                model_state=scan_res.model_state,
                warnings=scan_res.warnings + ["Unsupported modalities encountered and marked unverifiable."],
                capability_info=scan_res.capability_info,
            )

        return scan_res


def detect_label_anomalies(
    target: Union[DatasetIngestionResult, CanonicalDatasetManifest, Sequence[CanonicalSample], Sequence[LabelPrediction]],
    features: Optional[np.ndarray] = None,
    config: Optional[LabelAnomalyConfig] = None,
    model_state: ModelState = ModelState.MODEL_AVAILABLE,
    model_id: Optional[str] = "detector_side_centroid_estimator",
    model_hash: Optional[str] = None,
    dataset_fingerprint: Optional[str] = None,
) -> LabelAnomalyScanResult:
    """High-level functional API for detecting label anomalies and performing confident learning.

    Args:
        target: DatasetIngestionResult, CanonicalDatasetManifest, Sequence of CanonicalSample, or Sequence of LabelPrediction.
        features: Optional (N, D) numpy array of fixed feature representations.
        config: Optional LabelAnomalyConfig parameters.
        model_state: Model availability state (MODEL_AVAILABLE, MODEL_UNAVAILABLE, MODEL_INCOMPATIBLE, MODEL_LOAD_FAILED).
        model_id: Model or estimator identifier.
        model_hash: Model weight cryptographic digest.
        dataset_fingerprint: Dataset cryptographic hash.

    Returns:
        Structured LabelAnomalyScanResult.
    """
    detector = LabelAnomalyDetector(config=config)

    # If target is already a sequence of LabelPrediction
    if isinstance(target, (list, tuple)) and target and isinstance(target[0], LabelPrediction):
        return detector.detect_anomalies_from_predictions(
            predictions=target,  # type: ignore
            model_id=model_id,
            model_hash=model_hash,
            dataset_fingerprint=dataset_fingerprint,
        )

    return detector.detect_anomalies(
        target=target,  # type: ignore
        features=features,
        model_state=model_state,
        model_id=model_id,
        model_hash=model_hash,
        dataset_fingerprint=dataset_fingerprint,
    )
