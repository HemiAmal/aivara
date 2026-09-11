"""Core orchestration service for Phase 8.6 Behavioral Anomaly Detection."""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Sequence, Union

from aivara.behavioral.anomaly.enums import (
    AnomalyBaselineType,
    AnomalyFamilyType,
    AnomalyStatus,
    MetricAnomalyStatus,
    MetricDirection,
    SupportStatus,
)
from aivara.behavioral.anomaly.exceptions import (
    CrossProjectAnalysisError,
    IncompatibleAnalysisContextError,
)
from aivara.behavioral.anomaly.empirical import (
    compute_empirical_extremeness,
    compute_support_status,
)
from aivara.behavioral.anomaly.explanations import (
    format_metric_explanation,
    format_overall_explanation,
)
from aivara.behavioral.anomaly.families import (
    aggregate_family_results,
    get_metric_direction,
    get_metric_family,
)
from aivara.behavioral.anomaly.identity import compute_anomaly_analysis_id
from aivara.behavioral.anomaly.policy import (
    AnomalyThresholdPolicy,
    DEFAULT_ANOMALY_POLICY,
)
from aivara.behavioral.anomaly.schemas import (
    BaselineSummary,
    BehavioralAnomalyAnalysis,
    BehavioralAnomalyFamily,
    BehavioralAnomalyMetric,
)
from aivara.behavioral.anomaly.statistics import (
    compute_mad,
    compute_median,
    compute_robust_z,
    filter_finite_values,
)
from aivara.behavioral.stability.schemas import (
    BehavioralComparisonResult,
    PerturbationSensitivityResult,
    RepeatabilityAnalysisResult,
)


class BehavioralAnomalyEngineService:
    """Core offline analysis engine evaluating statistical behavioral anomalies."""

    def __init__(self, default_policy: Optional[AnomalyThresholdPolicy] = None) -> None:
        self.policy = default_policy or DEFAULT_ANOMALY_POLICY

    def evaluate_metric(
        self,
        metric_name: str,
        observed_value: Optional[float],
        baseline_values: Sequence[float],
        policy: Optional[AnomalyThresholdPolicy] = None,
        direction: Optional[MetricDirection] = None,
        family: Optional[AnomalyFamilyType] = None,
        validity_status: str = "VALID",
        reason: Optional[str] = None,
    ) -> BehavioralAnomalyMetric:
        """Evaluate a single scalar metric against an eligible baseline population."""
        pol = policy or self.policy
        dir_enum = direction or get_metric_direction(metric_name)
        fam_enum = family or get_metric_family(metric_name)

        # Handle non-valid metrics
        if validity_status != "VALID" or observed_value is None:
            anomaly_stat = (
                MetricAnomalyStatus.UNAVAILABLE if validity_status == "UNAVAILABLE"
                else MetricAnomalyStatus.UNVERIFIABLE if validity_status == "UNVERIFIABLE"
                else MetricAnomalyStatus.INCOMPATIBLE if validity_status == "INCOMPATIBLE"
                else MetricAnomalyStatus.UNAVAILABLE
            )
            return BehavioralAnomalyMetric(
                metric_name=metric_name,
                family=fam_enum,
                direction=dir_enum,
                observed_value=None,
                baseline_count=len(baseline_values),
                baseline_median=None,
                baseline_mad=None,
                robust_z=None,
                absolute_robust_z=None,
                empirical_extremeness=None,
                validity_status=validity_status,
                anomaly_status=anomaly_stat,
                reason=reason or f"Metric is {validity_status}",
            )

        finite_baseline = filter_finite_values(baseline_values)
        count = len(finite_baseline)

        # Check sample support
        if count < pol.min_support_count:
            med = compute_median(finite_baseline) if count > 0 else None
            mad = compute_mad(finite_baseline, med) if count > 0 else None
            return BehavioralAnomalyMetric(
                metric_name=metric_name,
                family=fam_enum,
                direction=dir_enum,
                observed_value=float(observed_value),
                baseline_count=count,
                baseline_median=med,
                baseline_mad=mad,
                robust_z=None,
                absolute_robust_z=None,
                empirical_extremeness=None,
                validity_status="VALID",
                anomaly_status=MetricAnomalyStatus.INSUFFICIENT_SUPPORT,
                reason=f"Insufficient baseline support ({count} samples < min {pol.min_support_count})",
            )

        # Sufficient support: compute robust statistics
        med = compute_median(finite_baseline)
        mad = compute_mad(finite_baseline, med)
        robust_z, abs_z = compute_robust_z(observed_value, med, mad)
        extremeness = compute_empirical_extremeness(observed_value, finite_baseline, dir_enum)

        effective_z_thresh = pol.custom_metric_thresholds.get(metric_name, pol.robust_z_threshold)
        zero_dispersion = (mad == 0.0)
        criterion_text: Optional[str] = None

        # Directional anomaly determination
        if not zero_dispersion and abs_z is not None and robust_z is not None:
            z_anomalous = False
            z_criterion: Optional[str] = None
            if dir_enum == MetricDirection.HIGHER_IS_EXTREME:
                if robust_z >= effective_z_thresh:
                    z_anomalous = True
                    z_criterion = f"upper-tail robust_z={robust_z:+.2f} >= +{effective_z_thresh:.2f}"
            elif dir_enum == MetricDirection.LOWER_IS_EXTREME:
                if robust_z <= -effective_z_thresh:
                    z_anomalous = True
                    z_criterion = f"lower-tail robust_z={robust_z:+.2f} <= -{effective_z_thresh:.2f}"
            else:  # TWO_SIDED
                if abs_z >= effective_z_thresh:
                    z_anomalous = True
                    z_criterion = f"two-sided |robust_z|={abs_z:.2f} >= {effective_z_thresh:.2f}"

            empirical_anomalous = (
                pol.tail_extremeness_threshold > 0.0
                and extremeness <= pol.tail_extremeness_threshold
            )
            emp_criterion = (
                f"empirical extremeness={extremeness:.4f} <= {pol.tail_extremeness_threshold:.4f}"
                if empirical_anomalous
                else None
            )

            if z_anomalous and emp_criterion:
                criterion_text = f"{z_criterion} and {emp_criterion}"
                anomaly_stat = MetricAnomalyStatus.ANOMALOUS
            elif z_anomalous:
                criterion_text = z_criterion
                anomaly_stat = MetricAnomalyStatus.ANOMALOUS
            elif empirical_anomalous:
                criterion_text = emp_criterion
                anomaly_stat = MetricAnomalyStatus.ANOMALOUS
            else:
                anomaly_stat = MetricAnomalyStatus.NORMAL

        elif zero_dispersion:
            if pol.allow_zero_dispersion_empirical and (observed_value != med):
                anomaly_stat = MetricAnomalyStatus.ANOMALOUS
                criterion_text = f"zero dispersion baseline difference (observed={observed_value} != median={med})"
            else:
                anomaly_stat = MetricAnomalyStatus.NORMAL
        else:
            anomaly_stat = MetricAnomalyStatus.NORMAL

        reason_text = format_metric_explanation(
            metric_name=metric_name,
            status=anomaly_stat,
            observed_value=observed_value,
            baseline_median=med,
            baseline_mad=mad,
            robust_z=robust_z,
            empirical_extremeness=extremeness,
            direction=dir_enum,
            zero_dispersion=zero_dispersion,
            reason=criterion_text,
        )

        return BehavioralAnomalyMetric(
            metric_name=metric_name,
            family=fam_enum,
            direction=dir_enum,
            observed_value=float(observed_value),
            baseline_count=count,
            baseline_median=med,
            baseline_mad=mad,
            robust_z=robust_z,
            absolute_robust_z=abs_z,
            empirical_extremeness=extremeness,
            validity_status="VALID",
            anomaly_status=anomaly_stat,
            reason=reason_text,
        )

    def analyze_metrics_dict(
        self,
        project_id: str,
        model_id: str,
        model_fingerprint: str,
        baseline_id: str,
        baseline_type: str,
        observation_id: str,
        task_type: str,
        observed_metrics: Dict[str, Optional[float]],
        baseline_distributions: Dict[str, Sequence[float]],
        policy: Optional[AnomalyThresholdPolicy] = None,
        baseline_summary: Optional[BaselineSummary] = None,
        metric_validity: Optional[Dict[str, str]] = None,
        metric_reasons: Optional[Dict[str, str]] = None,
    ) -> BehavioralAnomalyAnalysis:
        """Run complete anomaly assessment over structured metric dictionaries."""
        pol = policy or self.policy
        validity_map = metric_validity or {}
        reasons_map = metric_reasons or {}

        # Collect all declared metric names
        all_metric_names = sorted(set(observed_metrics.keys()) | set(baseline_distributions.keys()))

        evaluated_metrics: List[BehavioralAnomalyMetric] = []
        for name in all_metric_names:
            obs_val = observed_metrics.get(name)
            base_vals = baseline_distributions.get(name, [])
            val_stat = validity_map.get(name, "VALID" if obs_val is not None else "UNAVAILABLE")
            rsn = reasons_map.get(name)

            m = self.evaluate_metric(
                metric_name=name,
                observed_value=obs_val,
                baseline_values=base_vals,
                policy=pol,
                validity_status=val_stat,
                reason=rsn,
            )
            evaluated_metrics.append(m)

        # Group by family
        family_metrics_map: Dict[AnomalyFamilyType, List[BehavioralAnomalyMetric]] = {
            f: [] for f in AnomalyFamilyType
        }
        for m in evaluated_metrics:
            family_metrics_map[m.family].append(m)

        # Aggregate families
        family_results: Dict[str, BehavioralAnomalyFamily] = {}
        for fam_enum, f_metrics in family_metrics_map.items():
            if f_metrics:
                family_results[fam_enum.value] = aggregate_family_results(
                    family_name=fam_enum,
                    metrics=f_metrics,
                    policy=pol,
                )

        # Baseline summary calculation if not provided
        if baseline_summary is None:
            max_base_count = max((len(v) for v in baseline_distributions.values()), default=0)
            baseline_summary = BaselineSummary(
                baseline_id=baseline_id,
                baseline_type=baseline_type,
                total_baseline_count=max_base_count,
                eligible_baseline_count=max_base_count,
                excluded_baseline_count=0,
                exclusion_reasons={},
            )

        # Determine overall support status
        overall_support = compute_support_status(
            count=baseline_summary.eligible_baseline_count,
            min_support=pol.min_support_count,
            low_support=pol.low_support_count,
            adequate_support=pol.adequate_support_count,
        )

        # Determine overall anomaly status
        active_families = list(family_results.values())
        anomalous_families = [f.family_name.value for f in active_families if f.family_status == AnomalyStatus.ANOMALOUS]
        total_eval_metrics = sum(f.valid_metric_count for f in active_families)
        total_anom_metrics = sum(f.anomalous_metric_count for f in active_families)

        if not active_families or total_eval_metrics == 0:
            overall_status = AnomalyStatus.UNAVAILABLE
        elif anomalous_families:
            overall_status = AnomalyStatus.ANOMALOUS
        elif overall_support == SupportStatus.INSUFFICIENT_SUPPORT:
            overall_status = AnomalyStatus.INSUFFICIENT_SUPPORT
        elif all(f.family_status == AnomalyStatus.NORMAL for f in active_families):
            overall_status = AnomalyStatus.NORMAL
        else:
            overall_status = AnomalyStatus.PARTIALLY_ANALYZED

        explanation_text = format_overall_explanation(
            overall_status=overall_status,
            support_status=overall_support,
            anomalous_families=anomalous_families,
            total_metrics_evaluated=total_eval_metrics,
            anomalous_metrics_count=total_anom_metrics,
            policy_version=pol.policy_version,
        )

        # Format metrics and families dicts for deterministic hashing
        metrics_dict_list = [m.model_dump() for m in evaluated_metrics]
        families_dict = {k: v.model_dump() for k, v in family_results.items()}

        analysis_id = compute_anomaly_analysis_id(
            project_id=project_id,
            model_id=model_id,
            model_fingerprint=model_fingerprint,
            baseline_id=baseline_id,
            observation_id=observation_id,
            task_type=task_type,
            policy_version=pol.policy_version,
            threshold_policy=pol.to_dict(),
            metrics=metrics_dict_list,
            families=families_dict,
            overall_status=overall_status.value,
            support_status=overall_support.value,
            analysis_version="1.0.0",
        )

        return BehavioralAnomalyAnalysis(
            analysis_id=analysis_id,
            project_id=project_id,
            model_id=model_id,
            model_fingerprint=model_fingerprint,
            baseline_id=baseline_id,
            baseline_type=baseline_type,
            observation_id=observation_id,
            task_type=task_type,
            analysis_version="1.0.0",
            policy_version=pol.policy_version,
            overall_status=overall_status,
            support_status=overall_support,
            comparability_status="COMPARABLE",
            families=family_results,
            metrics=evaluated_metrics,
            threshold_policy=pol.to_dict(),
            baseline_summary=baseline_summary,
            explanation=explanation_text,
            limitations=[],
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def analyze_comparison(
        self,
        observation: BehavioralComparisonResult,
        baseline_comparisons: Sequence[BehavioralComparisonResult],
        baseline_id: str,
        baseline_type: str = "BASELINE_REFERENCE",
        policy: Optional[AnomalyThresholdPolicy] = None,
    ) -> BehavioralAnomalyAnalysis:
        """Analyze a Phase 8.5 BehavioralComparisonResult against a sequence of baseline comparisons."""
        pol = policy or self.policy

        # Validate project isolation
        for b in baseline_comparisons:
            if b.project_id != observation.project_id:
                raise CrossProjectAnalysisError(
                    f"Cross-project analysis rejected: observation project '{observation.project_id}' "
                    f"!= baseline project '{b.project_id}'."
                )

        # Validate context comparability
        if pol.strict_comparability:
            for b in baseline_comparisons:
                if b.task_type != observation.task_type:
                    raise IncompatibleAnalysisContextError(
                        f"Incompatible task types: observation '{observation.task_type}' != baseline '{b.task_type}'."
                    )

        observed_metrics: Dict[str, Optional[float]] = {}
        baseline_distributions: Dict[str, List[float]] = {}
        validity_map: Dict[str, str] = {}

        # Extract task metrics
        if observation.classification:
            for field_name in ("prediction_agreement", "top_k_overlap", "confidence_delta", "kl_divergence", "js_divergence", "entropy_delta", "margin_delta"):
                m_res = getattr(observation.classification, field_name, None)
                if m_res is not None:
                    observed_metrics[field_name] = m_res.value
                    validity_map[field_name] = m_res.validity_status.value
                    baseline_distributions[field_name] = []
                    for b in baseline_comparisons:
                        if b.classification:
                            b_res = getattr(b.classification, field_name, None)
                            if b_res is not None and b_res.value is not None:
                                baseline_distributions[field_name].append(b_res.value)

        elif observation.detection:
            for field_name in ("mean_matched_iou", "class_agreement_rate", "count_delta", "mean_confidence_delta", "mean_box_displacement"):
                if field_name == "count_delta":
                    observed_metrics[field_name] = float(observation.detection.count_delta)
                    validity_map[field_name] = "VALID"
                    baseline_distributions[field_name] = [float(b.detection.count_delta) for b in baseline_comparisons if b.detection]
                else:
                    m_res = getattr(observation.detection, field_name, None)
                    if m_res is not None:
                        observed_metrics[field_name] = m_res.value
                        validity_map[field_name] = m_res.validity_status.value
                        baseline_distributions[field_name] = []
                        for b in baseline_comparisons:
                            if b.detection:
                                b_res = getattr(b.detection, field_name, None)
                                if b_res is not None and b_res.value is not None:
                                    baseline_distributions[field_name].append(b_res.value)

        elif observation.segmentation:
            for field_name in ("ground_truth_miou", "reference_mask_agreement", "pixel_agreement_rate"):
                m_res = getattr(observation.segmentation, field_name, None)
                if m_res is not None:
                    observed_metrics[field_name] = m_res.value
                    validity_map[field_name] = m_res.validity_status.value
                    baseline_distributions[field_name] = []
                    for b in baseline_comparisons:
                        if b.segmentation:
                            b_res = getattr(b.segmentation, field_name, None)
                            if b_res is not None and b_res.value is not None:
                                baseline_distributions[field_name].append(b_res.value)

        elif observation.generic_tensor:
            for field_name in ("l1_distance", "l2_distance", "relative_l2_distance", "cosine_similarity", "max_absolute_difference", "mean_absolute_difference", "finite_value_agreement"):
                m_res = getattr(observation.generic_tensor, field_name, None)
                if m_res is not None:
                    observed_metrics[field_name] = m_res.value
                    validity_map[field_name] = m_res.validity_status.value
                    baseline_distributions[field_name] = []
                    for b in baseline_comparisons:
                        if b.generic_tensor:
                            b_res = getattr(b.generic_tensor, field_name, None)
                            if b_res is not None and b_res.value is not None:
                                baseline_distributions[field_name].append(b_res.value)

        return self.analyze_metrics_dict(
            project_id=observation.project_id,
            model_id=observation.target_observation_id,
            model_fingerprint="H_master",
            baseline_id=baseline_id,
            baseline_type=baseline_type,
            observation_id=observation.comparison_id,
            task_type=observation.task_type,
            observed_metrics=observed_metrics,
            baseline_distributions=baseline_distributions,
            policy=pol,
            metric_validity=validity_map,
        )

    def analyze_repeatability(
        self,
        observation: RepeatabilityAnalysisResult,
        baseline_runs: Sequence[RepeatabilityAnalysisResult],
        baseline_id: str,
        policy: Optional[AnomalyThresholdPolicy] = None,
    ) -> BehavioralAnomalyAnalysis:
        """Analyze a Phase 8.5 RepeatabilityAnalysisResult against historical repeatability runs."""
        pol = policy or self.policy

        for b in baseline_runs:
            if b.project_id != observation.project_id:
                raise CrossProjectAnalysisError(
                    f"Cross-project repeatability rejected: '{observation.project_id}' != '{b.project_id}'."
                )

        observed_metrics = {
            "prediction_agreement_rate": observation.prediction_agreement_rate,
            "max_numerical_delta": observation.max_numerical_delta,
            "mean_numerical_delta": observation.mean_numerical_delta,
        }
        baseline_distributions = {
            "prediction_agreement_rate": [b.prediction_agreement_rate for b in baseline_runs],
            "max_numerical_delta": [b.max_numerical_delta for b in baseline_runs],
            "mean_numerical_delta": [b.mean_numerical_delta for b in baseline_runs],
        }

        return self.analyze_metrics_dict(
            project_id=observation.project_id,
            model_id=observation.model_id,
            model_fingerprint=observation.model_fingerprint,
            baseline_id=baseline_id,
            baseline_type="REPEATED_EXECUTION_REFERENCE",
            observation_id=observation.analysis_id,
            task_type="repeatability",
            observed_metrics=observed_metrics,
            baseline_distributions=baseline_distributions,
            policy=pol,
        )

    def analyze_perturbation_sensitivity(
        self,
        observation: PerturbationSensitivityResult,
        baseline_responses: Sequence[PerturbationSensitivityResult],
        baseline_id: str,
        policy: Optional[AnomalyThresholdPolicy] = None,
    ) -> BehavioralAnomalyAnalysis:
        """Analyze a Phase 8.4/8.5 PerturbationSensitivityResult against reference perturbation experiments."""
        pol = policy or self.policy

        for b in baseline_responses:
            if b.project_id != observation.project_id:
                raise CrossProjectAnalysisError(
                    f"Cross-project perturbation analysis rejected: '{observation.project_id}' != '{b.project_id}'."
                )

        observed_metrics = {
            "sensitivity_ratio": observation.sensitivity_ratio,
            "output_distance_l1": observation.output_distance_l1,
            "output_distance_l2": observation.output_distance_l2,
            "prediction_changed": 1.0 if observation.prediction_changed else 0.0,
        }
        validity_map = {
            "sensitivity_ratio": "VALID" if observation.sensitivity_status == "VALID" and observation.sensitivity_ratio is not None else "UNDEFINED",
            "output_distance_l1": "VALID" if observation.output_distance_l1 is not None else "UNAVAILABLE",
            "output_distance_l2": "VALID" if observation.output_distance_l2 is not None else "UNAVAILABLE",
            "prediction_changed": "VALID",
        }
        baseline_distributions = {
            "sensitivity_ratio": [b.sensitivity_ratio for b in baseline_responses if b.sensitivity_ratio is not None],
            "output_distance_l1": [b.output_distance_l1 for b in baseline_responses if b.output_distance_l1 is not None],
            "output_distance_l2": [b.output_distance_l2 for b in baseline_responses if b.output_distance_l2 is not None],
            "prediction_changed": [1.0 if b.prediction_changed else 0.0 for b in baseline_responses],
        }

        return self.analyze_metrics_dict(
            project_id=observation.project_id,
            model_id=observation.model_id,
            model_fingerprint="H_master",
            baseline_id=baseline_id,
            baseline_type="PERTURBATION_REFERENCE",
            observation_id=observation.sensitivity_id,
            task_type="perturbation",
            observed_metrics=observed_metrics,
            baseline_distributions=baseline_distributions,
            policy=pol,
            metric_validity=validity_map,
        )
