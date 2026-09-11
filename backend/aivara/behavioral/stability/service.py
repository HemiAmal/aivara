"""Output Consistency & Stability Analysis Service (Phase 8.5)."""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

from aivara.behavioral.exceptions import BehavioralError
from aivara.behavioral.schemas import ExecutionResult, ExecutionStatus
from aivara.behavioral.stability.identity import (
    compute_comparison_id,
    compute_repeatability_analysis_id,
    compute_sensitivity_id,
)
from aivara.behavioral.stability.metrics import (
    compute_classification_stability_metrics,
    compute_detection_stability_metrics,
    compute_generic_tensor_stability_metrics,
    compute_input_distance,
    compute_segmentation_stability_metrics,
)
from aivara.behavioral.stability.schemas import (
    BehavioralComparisonResult,
    ClassificationStabilityMetrics,
    ComparisonType,
    DetectionStabilityMetrics,
    GenericTensorStabilityMetrics,
    PerturbationSensitivityResult,
    RepeatabilityAnalysisResult,
    SegmentationStabilityMetrics,
)


class OutputStabilityAnalysisService:
    """Quantitative measurement engine for output consistency, repeatability, and perturbation sensitivity."""

    def __init__(self, implementation_version: str = "1.0.0") -> None:
        self.implementation_version = implementation_version

    def analyze_repeatability(
        self,
        project_id: str,
        model_id: str,
        model_fingerprint: str,
        execution_results: List[ExecutionResult],
        task_type: str = "classification",
    ) -> RepeatabilityAnalysisResult:
        """Measure output consistency across identical repeated model executions.

        Args:
            project_id: Multi-tenant project identifier.
            model_id: Evaluated model identifier.
            model_fingerprint: Phase 7 Master Model Fingerprint.
            execution_results: List of at least 2 identical repeated ExecutionResults.
            task_type: Task domain.

        Returns:
            Sealed RepeatabilityAnalysisResult domain object.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        repeat_count = len(execution_results)
        if repeat_count < 2:
            raise ValueError(f"Repeatability analysis requires at least 2 executions (received {repeat_count})")

        successful_runs = [r for r in execution_results if r.status == ExecutionStatus.SUCCESS and r.outputs is not None]
        if len(successful_runs) < 2:
            limitations = [f"Insufficient successful runs ({len(successful_runs)}/{repeat_count}) for robust repeatability analysis."]
            analysis_id = compute_repeatability_analysis_id(
                project_id=project_id,
                model_id=model_id,
                model_fingerprint=model_fingerprint,
                repeat_count=repeat_count,
                execution_provider="UNKNOWN",
                implementation_version=self.implementation_version,
            )
            return RepeatabilityAnalysisResult(
                analysis_id=analysis_id,
                project_id=project_id,
                model_id=model_id,
                model_fingerprint=model_fingerprint,
                repeat_count=repeat_count,
                prediction_agreement_rate=0.0,
                max_numerical_delta=0.0,
                mean_numerical_delta=0.0,
                determinism_status="UNVERIFIABLE",
                execution_provider="UNKNOWN",
                device="unknown",
                runtime_version="unknown",
                precision="unknown",
                limitations=limitations,
                created_at=now_iso,
            )

        first = successful_runs[0]
        provider = first.provider
        device = first.device
        runtime_ver = first.runtime_version
        precision = first.precision

        # Extract primary tensor from outputs
        first_outputs = first.outputs or {}
        tensor_name = "logits" if "logits" in first_outputs else (list(first_outputs.keys())[0] if first_outputs else "output")

        tensors = [np.array(r.outputs[tensor_name]) for r in successful_runs if r.outputs and tensor_name in r.outputs]
        if not tensors:
            raise ValueError("No valid output tensors found in execution results for repeatability evaluation")

        # 1. Prediction Agreement (for classification/discrete outputs)
        top1_preds = [int(np.argmax(t)) for t in tensors]
        agreement_count = sum(1 for p in top1_preds if p == top1_preds[0])
        pred_agreement_rate = float(agreement_count / len(top1_preds))

        # 2. Pairwise Numerical Differences
        deltas: List[float] = []
        base_arr = tensors[0].astype(np.float64)
        for t in tensors[1:]:
            diff = np.abs(t.astype(np.float64) - base_arr)
            deltas.append(float(np.max(diff)))

        max_delta = float(np.max(deltas)) if deltas else 0.0
        mean_delta = float(np.mean(deltas)) if deltas else 0.0

        # 3. Categorize Determinism Status
        if max_delta == 0.0:
            det_status = "DETERMINISTIC"
        elif max_delta < 1e-5:
            det_status = "NUMERICALLY_STABLE"
        else:
            det_status = "NONDETERMINISTIC"

        analysis_id = compute_repeatability_analysis_id(
            project_id=project_id,
            model_id=model_id,
            model_fingerprint=model_fingerprint,
            repeat_count=repeat_count,
            execution_provider=provider,
            implementation_version=self.implementation_version,
        )

        return RepeatabilityAnalysisResult(
            analysis_id=analysis_id,
            project_id=project_id,
            model_id=model_id,
            model_fingerprint=model_fingerprint,
            repeat_count=repeat_count,
            prediction_agreement_rate=pred_agreement_rate,
            max_numerical_delta=max_delta,
            mean_numerical_delta=mean_delta,
            determinism_status=det_status,
            execution_provider=provider,
            device=device,
            runtime_version=runtime_ver,
            precision=precision,
            limitations=[],
            created_at=now_iso,
        )

    def analyze_perturbation_sensitivity(
        self,
        project_id: str,
        model_id: str,
        source_input: np.ndarray,
        perturbed_input: np.ndarray,
        source_output: Dict[str, Any],
        perturbed_output: Dict[str, Any],
        source_input_hash: str,
        perturbed_input_hash: str,
        perturbation_id: str,
        perturbation_type: str,
        task_type: str = "classification",
        is_probability: bool = True,
    ) -> PerturbationSensitivityResult:
        """Measure output change relative to controlled input change under a Phase 8.4 perturbation."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Compute Input Space Distance
        in_dist = compute_input_distance(source_input, perturbed_input)
        in_l1 = in_dist["l1"]
        in_l2 = in_dist["l2"]
        in_rmse = in_dist["rmse"]

        # 2. Extract Primary Output Tensors
        s_tensor_name = "logits" if "logits" in source_output else (list(source_output.keys())[0] if source_output else "output")
        p_tensor_name = "logits" if "logits" in perturbed_output else (list(perturbed_output.keys())[0] if perturbed_output else "output")

        s_arr = np.array(source_output.get(s_tensor_name, np.zeros((1,), dtype=np.float32)))
        p_arr = np.array(perturbed_output.get(p_tensor_name, np.zeros((1,), dtype=np.float32)))

        # 3. Compute Output Distance
        out_l1: Optional[float] = None
        out_l2: Optional[float] = None
        if s_arr.shape == p_arr.shape:
            out_diff = np.abs(s_arr.astype(np.float64) - p_arr.astype(np.float64))
            out_l1 = float(np.sum(out_diff))
            out_l2 = float(np.sqrt(np.sum(out_diff ** 2)))

        # 4. Zero-Denominator & Normalized Sensitivity Ratio Semantics
        input_unchanged = (in_l2 == 0.0)
        output_changed = (out_l2 is not None and out_l2 > 0.0)

        sens_ratio: Optional[float] = None
        sens_status = "VALID"

        if input_unchanged:
            if not output_changed:
                # Case A: input_change == 0, output_change == 0
                sens_ratio = None
                sens_status = "NOT_APPLICABLE"
            else:
                # Case B: input_change == 0, output_change > 0
                sens_ratio = None
                sens_status = "UNDEFINED_NON_FINITE_DENOMINATOR"
        else:
            if out_l2 is not None:
                # Case C (output_change == 0) & Case D (output_change > 0)
                sens_ratio = float(out_l2 / in_l2)
                sens_status = "VALID"
            else:
                sens_ratio = None
                sens_status = "UNVERIFIABLE"

        # 5. Task-Specific Consistency Metrics
        task_metrics: Dict[str, Any] = {}
        pred_changed = False
        conf_delta: Optional[float] = None

        if task_type.lower() == "classification" and s_arr.ndim <= 2:
            class_metrics = compute_classification_stability_metrics(
                candidate_output=p_arr,
                reference_output=s_arr,
                is_probability=is_probability,
            )
            pred_changed = (class_metrics.prediction_agreement.value == 0.0)
            if class_metrics.confidence_delta and class_metrics.confidence_delta.value is not None:
                conf_delta = class_metrics.confidence_delta.value
            task_metrics = class_metrics.model_dump(mode="json")

        sensitivity_id = compute_sensitivity_id(
            project_id=project_id,
            model_id=model_id,
            source_input_hash=source_input_hash,
            perturbed_input_hash=perturbed_input_hash,
            perturbation_id=perturbation_id,
            implementation_version=self.implementation_version,
        )

        return PerturbationSensitivityResult(
            sensitivity_id=sensitivity_id,
            project_id=project_id,
            model_id=model_id,
            source_input_hash=source_input_hash,
            perturbed_input_hash=perturbed_input_hash,
            perturbation_id=perturbation_id,
            perturbation_type=perturbation_type,
            input_distance_l1=in_l1,
            input_distance_l2=in_l2,
            input_distance_rmse=in_rmse,
            output_distance_l1=out_l1,
            output_distance_l2=out_l2,
            sensitivity_ratio=sens_ratio,
            input_unchanged=input_unchanged,
            output_changed=output_changed,
            sensitivity_status=sens_status,
            prediction_changed=pred_changed,
            confidence_delta=conf_delta,
            task_metrics=task_metrics,
            created_at=now_iso,
        )

    def compare_observations(
        self,
        project_id: str,
        source_observation_id: str,
        target_observation_id: str,
        source_output: Dict[str, Any],
        target_output: Dict[str, Any],
        task_type: str,
        comparison_type: ComparisonType = ComparisonType.REFERENCE_COMPARISON,
        is_probability: bool = True,
        target_project_id: Optional[str] = None,
        ground_truth_mask: Optional[np.ndarray] = None,
    ) -> BehavioralComparisonResult:
        """Perform a pairwise stability or reference consistency comparison.

        Args:
            project_id: Multi-tenant project identifier of source.
            source_observation_id: Unique identifier of reference/source observation.
            target_observation_id: Unique identifier of candidate/target observation.
            source_output: Reference model output dictionary.
            target_output: Candidate model output dictionary.
            task_type: Task domain ("classification", "object_detection", "segmentation", "generic").
            comparison_type: Context of comparison.
            is_probability: Flag indicating if classification vectors are normalized probabilities.
            target_project_id: Target project ID to verify project isolation.
            ground_truth_mask: Optional ground truth mask for segmentation Case A.

        Returns:
            Sealed BehavioralComparisonResult domain object.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        # Strict Multi-Tenant Project Isolation Check
        if target_project_id is not None and target_project_id != project_id:
            raise BehavioralError(
                f"Cross-project comparison forbidden. Source project: {project_id}, Target project: {target_project_id}",
                code="CROSS_PROJECT_COMPARISON",
            )

        task_lower = task_type.lower()
        class_metrics: Optional[ClassificationStabilityMetrics] = None
        det_metrics: Optional[DetectionStabilityMetrics] = None
        seg_metrics: Optional[SegmentationStabilityMetrics] = None
        generic_metrics: Optional[GenericTensorStabilityMetrics] = None
        limitations: List[str] = []

        if task_lower == "classification":
            s_name = "logits" if "logits" in source_output else (list(source_output.keys())[0] if source_output else "output")
            t_name = "logits" if "logits" in target_output else (list(target_output.keys())[0] if target_output else "output")
            s_arr = np.array(source_output.get(s_name, np.zeros((1,), dtype=np.float32)))
            t_arr = np.array(target_output.get(t_name, np.zeros((1,), dtype=np.float32)))
            class_metrics = compute_classification_stability_metrics(
                candidate_output=t_arr,
                reference_output=s_arr,
                is_probability=is_probability,
            )

        elif task_lower in ("object_detection", "detection"):
            det_metrics = compute_detection_stability_metrics(
                candidate_detections=target_output,
                reference_detections=source_output,
            )

        elif task_lower == "segmentation":
            s_name = "mask" if "mask" in source_output else (list(source_output.keys())[0] if source_output else "output")
            t_name = "mask" if "mask" in target_output else (list(target_output.keys())[0] if target_output else "output")
            s_mask = np.array(source_output.get(s_name, np.zeros((1, 1), dtype=np.int32))) if source_output else None
            t_mask = np.array(target_output.get(t_name, np.zeros((1, 1), dtype=np.int32)))
            seg_metrics = compute_segmentation_stability_metrics(
                candidate_mask=t_mask,
                reference_mask=s_mask,
                ground_truth_mask=ground_truth_mask,
            )

        else:
            # Generic tensor comparison
            s_name = list(source_output.keys())[0] if source_output else "output"
            t_name = list(target_output.keys())[0] if target_output else "output"
            s_arr = np.array(source_output.get(s_name, np.zeros((1,), dtype=np.float32)))
            t_arr = np.array(target_output.get(t_name, np.zeros((1,), dtype=np.float32)))
            generic_metrics = compute_generic_tensor_stability_metrics(
                candidate_tensor=t_arr,
                reference_tensor=s_arr,
            )

        comparison_id = compute_comparison_id(
            project_id=project_id,
            source_observation_id=source_observation_id,
            target_observation_id=target_observation_id,
            comparison_type=comparison_type.value,
            task_type=task_type,
            implementation_version=self.implementation_version,
        )

        return BehavioralComparisonResult(
            comparison_id=comparison_id,
            comparison_type=comparison_type,
            project_id=project_id,
            source_observation_id=source_observation_id,
            target_observation_id=target_observation_id,
            task_type=task_type,
            classification=class_metrics,
            detection=det_metrics,
            segmentation=seg_metrics,
            generic_tensor=generic_metrics,
            is_compatible=True,
            limitations=limitations,
            execution_context={"implementation_version": self.implementation_version},
            created_at=now_iso,
        )
