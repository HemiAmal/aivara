"""Task-Aware Activation Criterion Evaluation for Phase 9.4 (ADR-088)."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple, Union
import numpy as np

from aivara.backdoor.activation.enums import (
    ActivationCriterionTypeEnum,
    ActivationDecisionEnum,
)
from aivara.backdoor.activation.models import (
    ActivationCriterionSpec,
    ActivationDecisionRecord,
)
from aivara.behavioral.stability.metrics import (
    compute_detection_stability_metrics,
    compute_generic_tensor_stability_metrics,
    compute_segmentation_stability_metrics,
)


def evaluate_activation_decision(
    clean_output: Any,
    condition_output: Any,
    criterion: ActivationCriterionSpec,
    ground_truth_mask: Optional[np.ndarray] = None,
    reference_mask: Optional[np.ndarray] = None,
    reference_model_identity: Optional[str] = None,
    ground_truth_detections: Optional[Dict[str, Any]] = None,
    reference_detections: Optional[Dict[str, Any]] = None,
) -> Tuple[
    ActivationDecisionEnum,
    Optional[Union[int, str]],
    Optional[float],
    Optional[bool],
    ActivationDecisionRecord,
]:
    """Evaluate whether a condition model output meets the specified task-aware activation criterion.

    Reuses Phase 8.5 metrics for detection, segmentation, and generic tensor evaluations.
    Does NOT fabricate criteria if input format or required reference/GT is incompatible or missing.

    Returns:
      (decision, prediction_label, top_confidence, is_target_matched, decision_record)
    """
    crit_type = criterion.criterion_type
    version = criterion.criterion_version

    # =========================================================================
    # 1. Object Detection Evaluations
    # =========================================================================
    if crit_type in (
        ActivationCriterionTypeEnum.DETECTION_COUNT_DELTA,
        ActivationCriterionTypeEnum.DETECTION_IOU_DROP,
        ActivationCriterionTypeEnum.DETECTION_TARGET_CLASS_INJECTED,
    ):
        if (
            not isinstance(clean_output, dict)
            or not isinstance(condition_output, dict)
            or "boxes" not in clean_output
            or "boxes" not in condition_output
        ):
            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                decision=ActivationDecisionEnum.UNAVAILABLE,
                status="UNAVAILABLE_INCOMPATIBLE_DETECTION_FORMAT",
            )
            return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

        n_clean = len(clean_output.get("boxes", []))
        n_cond = len(condition_output.get("boxes", []))
        ref_summary = {"box_count": n_clean}
        cand_summary = {"box_count": n_cond}

        if crit_type == ActivationCriterionTypeEnum.DETECTION_COUNT_DELTA:
            signed_delta = n_cond - n_clean
            abs_delta = abs(signed_delta)
            thresh = float(criterion.count_delta_threshold)
            is_act = (abs_delta >= criterion.count_delta_threshold)
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="abs_detection_count_delta",
                comparison_operator=">=",
                threshold=thresh,
                reference_value=n_clean,
                candidate_value=n_cond,
                delta_value=signed_delta,
                reference_summary=ref_summary,
                candidate_summary=cand_summary,
                decision=decision,
                status="VALID",
            )
            return decision, None, None, None, record

        elif crit_type == ActivationCriterionTypeEnum.DETECTION_IOU_DROP:
            gt_det = (
                ground_truth_detections
                or reference_detections
                or (clean_output.get("ground_truth") if isinstance(clean_output, dict) else None)
                or (clean_output.get("gt_detections") if isinstance(clean_output, dict) else None)
            )

            thresh = criterion.iou_drop_threshold if criterion.iou_drop_threshold is not None else criterion.drop_threshold

            # Case A: Ground Truth Detections Supplied
            if gt_det is not None:
                if not isinstance(gt_det, dict) or "boxes" not in gt_det:
                    record = ActivationDecisionRecord(
                        criterion_type=crit_type,
                        criterion_version=version,
                        decision=ActivationDecisionEnum.UNAVAILABLE,
                        status="UNAVAILABLE_INCOMPATIBLE_DETECTION_FORMAT",
                    )
                    return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

                clean_metrics = compute_detection_stability_metrics(
                    candidate_detections=clean_output,
                    reference_detections=gt_det,
                    iou_threshold=criterion.iou_threshold,
                )
                cond_metrics = compute_detection_stability_metrics(
                    candidate_detections=condition_output,
                    reference_detections=gt_det,
                    iou_threshold=criterion.iou_threshold,
                )

                clean_iou = clean_metrics.mean_matched_iou.value if clean_metrics.mean_matched_iou else None
                cond_iou = cond_metrics.mean_matched_iou.value if cond_metrics.mean_matched_iou else None

                if clean_iou is None or cond_iou is None:
                    record = ActivationDecisionRecord(
                        criterion_type=crit_type,
                        criterion_version=version,
                        decision=ActivationDecisionEnum.UNAVAILABLE,
                        status="UNAVAILABLE_DETECTION_METRIC_MISSING",
                    )
                    return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

                delta_iou = float(clean_iou - cond_iou)
                is_act = (delta_iou >= (thresh - 1e-9))
                decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    metric_name="delta_detection_iou",
                    comparison_operator=">=",
                    threshold=thresh,
                    reference_value=clean_iou,
                    candidate_value=cond_iou,
                    delta_value=delta_iou,
                    reference_summary={"clean_iou": clean_iou, "box_count": n_clean},
                    candidate_summary={"condition_iou": cond_iou, "box_count": n_cond},
                    decision=decision,
                    status="VALID",
                )
                return decision, None, None, None, record

            # Case B: Direct Paired Clean-vs-Condition Comparison (Clean is the baseline)
            else:
                if n_clean == 0 and n_cond == 0:
                    clean_iou = 1.0
                    cond_iou = 1.0
                    delta_iou = 0.0
                    record = ActivationDecisionRecord(
                        criterion_type=crit_type,
                        criterion_version=version,
                        metric_name="delta_detection_iou",
                        comparison_operator=">=",
                        threshold=thresh,
                        reference_value=clean_iou,
                        candidate_value=cond_iou,
                        delta_value=delta_iou,
                        reference_summary={"clean_iou": clean_iou, "box_count": 0},
                        candidate_summary={"condition_iou": cond_iou, "box_count": 0},
                        decision=ActivationDecisionEnum.NOT_ACTIVATED,
                        status="VALID_ZERO_DETECTIONS",
                    )
                    return ActivationDecisionEnum.NOT_ACTIVATED, None, None, None, record

                clean_metrics = compute_detection_stability_metrics(
                    candidate_detections=clean_output,
                    reference_detections=clean_output,
                    iou_threshold=criterion.iou_threshold,
                )
                cond_metrics = compute_detection_stability_metrics(
                    candidate_detections=condition_output,
                    reference_detections=clean_output,
                    iou_threshold=criterion.iou_threshold,
                )

                clean_iou = clean_metrics.mean_matched_iou.value if clean_metrics.mean_matched_iou else None
                cond_iou = cond_metrics.mean_matched_iou.value if cond_metrics.mean_matched_iou else None

                if clean_iou is None or cond_iou is None:
                    record = ActivationDecisionRecord(
                        criterion_type=crit_type,
                        criterion_version=version,
                        decision=ActivationDecisionEnum.UNAVAILABLE,
                        status="UNAVAILABLE_DETECTION_METRIC_MISSING",
                    )
                    return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

                delta_iou = float(clean_iou - cond_iou)
                is_act = (delta_iou >= (thresh - 1e-9))
                decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    metric_name="delta_detection_iou",
                    comparison_operator=">=",
                    threshold=thresh,
                    reference_value=clean_iou,
                    candidate_value=cond_iou,
                    delta_value=delta_iou,
                    reference_summary={"clean_iou": clean_iou, "box_count": n_clean},
                    candidate_summary={"condition_iou": cond_iou, "box_count": n_cond},
                    decision=decision,
                    status="VALID",
                )
                return decision, None, None, None, record

        elif crit_type == ActivationCriterionTypeEnum.DETECTION_TARGET_CLASS_INJECTED:
            if criterion.target_class is None:
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    decision=ActivationDecisionEnum.NOT_APPLICABLE,
                    status="NOT_APPLICABLE_NO_TARGET",
                )
                return ActivationDecisionEnum.NOT_APPLICABLE, None, None, None, record

            target_val = str(criterion.target_class)
            c_classes = [str(c) for c in condition_output.get("classes", [])]
            r_classes = [str(c) for c in clean_output.get("classes", [])]

            target_in_cond = target_val in c_classes
            target_in_clean = target_val in r_classes
            is_act = target_in_cond and not target_in_clean
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="target_class_injection",
                comparison_operator="in_candidate_and_not_in_clean",
                threshold=None,
                reference_value=target_in_clean,
                candidate_value=target_in_cond,
                reference_summary={"has_target": target_in_clean},
                candidate_summary={"has_target": target_in_cond},
                decision=decision,
                status="VALID",
            )
            return decision, None, None, is_act, record

    # =========================================================================
    # 2. Semantic Segmentation Evaluations (Clean-Relative Degradation)
    # =========================================================================
    if crit_type in (
        ActivationCriterionTypeEnum.SEGMENTATION_GT_MIOU_DROP,
        ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP,
        ActivationCriterionTypeEnum.SEGMENTATION_TARGET_CLASS_EMERGENCE,
        ActivationCriterionTypeEnum.SEGMENTATION_MASK_DISAGREEMENT,
    ):
        # Extract clean and condition mask arrays
        clean_m = clean_output.get("mask", clean_output) if isinstance(clean_output, dict) else clean_output
        cond_m = condition_output.get("mask", condition_output) if isinstance(condition_output, dict) else condition_output

        if not (isinstance(clean_m, np.ndarray) and isinstance(cond_m, np.ndarray)):
            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                decision=ActivationDecisionEnum.UNAVAILABLE,
                status="UNAVAILABLE_INCOMPATIBLE_SEGMENTATION_FORMAT",
            )
            return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

        # 2A. SEGMENTATION_GT_MIOU_DROP (Clean-Relative Ground Truth Degradation)
        if crit_type == ActivationCriterionTypeEnum.SEGMENTATION_GT_MIOU_DROP:
            gt_m = ground_truth_mask
            if gt_m is None and isinstance(clean_output, dict):
                gt_m = clean_output.get("ground_truth", clean_output.get("gt_mask"))

            if gt_m is None or not isinstance(gt_m, np.ndarray):
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    decision=ActivationDecisionEnum.UNAVAILABLE,
                    status="UNAVAILABLE_GROUND_TRUTH_MISSING",
                )
                return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

            clean_metrics = compute_segmentation_stability_metrics(
                candidate_mask=clean_m,
                ground_truth_mask=gt_m,
            )
            cond_metrics = compute_segmentation_stability_metrics(
                candidate_mask=cond_m,
                ground_truth_mask=gt_m,
            )

            clean_miou = (
                clean_metrics.ground_truth_miou.value
                if clean_metrics.ground_truth_miou and clean_metrics.ground_truth_miou.value is not None
                else None
            )
            cond_miou = (
                cond_metrics.ground_truth_miou.value
                if cond_metrics.ground_truth_miou and cond_metrics.ground_truth_miou.value is not None
                else None
            )

            if clean_miou is None or cond_miou is None:
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    decision=ActivationDecisionEnum.UNAVAILABLE,
                    status="UNAVAILABLE_GT_MIOU_CALCULATION_FAILED",
                )
                return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

            # Exact definition: delta_miou = clean_miou - cond_miou
            delta_miou = float(clean_miou - cond_miou)
            thresh = criterion.drop_threshold
            is_act = (delta_miou >= (thresh - 1e-9))
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED

            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="delta_ground_truth_miou",
                comparison_operator=">=",
                threshold=thresh,
                reference_value=clean_miou,
                candidate_value=cond_miou,
                delta_value=delta_miou,
                reference_summary={"clean_miou": clean_miou},
                candidate_summary={"condition_miou": cond_miou},
                decision=decision,
                status="VALID",
            )
            return decision, None, None, None, record

        # 2B. SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP (Clean-Relative Reference Model Degradation)
        elif crit_type == ActivationCriterionTypeEnum.SEGMENTATION_REFERENCE_MASK_AGREEMENT_DROP:
            ref_m = reference_mask
            if ref_m is None and isinstance(clean_output, dict):
                ref_m = clean_output.get("reference_mask", clean_output.get("reference_output"))

            if ref_m is None or not isinstance(ref_m, np.ndarray):
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    decision=ActivationDecisionEnum.UNAVAILABLE,
                    status="UNAVAILABLE_REFERENCE_MODEL_MISSING",
                )
                return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

            clean_metrics = compute_segmentation_stability_metrics(
                candidate_mask=clean_m,
                reference_mask=ref_m,
            )
            cond_metrics = compute_segmentation_stability_metrics(
                candidate_mask=cond_m,
                reference_mask=ref_m,
            )

            clean_agree = (
                clean_metrics.reference_mask_agreement.value
                if clean_metrics.reference_mask_agreement and clean_metrics.reference_mask_agreement.value is not None
                else None
            )
            cond_agree = (
                cond_metrics.reference_mask_agreement.value
                if cond_metrics.reference_mask_agreement and cond_metrics.reference_mask_agreement.value is not None
                else None
            )

            if clean_agree is None or cond_agree is None:
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    decision=ActivationDecisionEnum.UNAVAILABLE,
                    status="UNAVAILABLE_REFERENCE_AGREEMENT_CALCULATION_FAILED",
                )
                return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

            # Exact definition: delta_agreement = clean_reference_agreement - cond_reference_agreement
            delta_agree = float(clean_agree - cond_agree)
            thresh = criterion.drop_threshold
            is_act = (delta_agree >= (thresh - 1e-9))
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED

            ref_identity = reference_model_identity or "REFERENCE_MODEL"

            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="delta_reference_mask_agreement",
                comparison_operator=">=",
                threshold=thresh,
                reference_value=clean_agree,
                candidate_value=cond_agree,
                delta_value=delta_agree,
                reference_model_identity=ref_identity,
                reference_summary={"clean_reference_agreement": clean_agree, "reference_model_identity": ref_identity},
                candidate_summary={"condition_reference_agreement": cond_agree},
                decision=decision,
                status="VALID",
            )
            return decision, None, None, None, record

        # 2C. SEGMENTATION_MASK_DISAGREEMENT (Direct Clean-vs-Condition Mask Disagreement)
        elif crit_type == ActivationCriterionTypeEnum.SEGMENTATION_MASK_DISAGREEMENT:
            seg_metrics = compute_segmentation_stability_metrics(
                candidate_mask=cond_m,
                reference_mask=clean_m,
            )
            agree_val = (
                seg_metrics.reference_mask_agreement.value
                if seg_metrics.reference_mask_agreement and seg_metrics.reference_mask_agreement.value is not None
                else None
            )
            if agree_val is None:
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    decision=ActivationDecisionEnum.UNAVAILABLE,
                    status="UNAVAILABLE_MASK_AGREEMENT_CALCULATION_FAILED",
                )
                return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

            disagreement = float(1.0 - agree_val)
            thresh = criterion.drop_threshold
            is_act = (disagreement >= (thresh - 1e-9))
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED

            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="clean_vs_condition_mask_disagreement",
                comparison_operator=">=",
                threshold=thresh,
                reference_value=1.0,
                candidate_value=agree_val,
                delta_value=disagreement,
                reference_summary={"reference_agreement": agree_val},
                candidate_summary={"disagreement": disagreement},
                decision=decision,
                status="VALID",
            )
            return decision, None, None, None, record

        # 2D. SEGMENTATION_TARGET_CLASS_EMERGENCE
        elif crit_type == ActivationCriterionTypeEnum.SEGMENTATION_TARGET_CLASS_EMERGENCE:
            if criterion.target_class is None:
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    decision=ActivationDecisionEnum.NOT_APPLICABLE,
                    status="NOT_APPLICABLE_NO_TARGET",
                )
                return ActivationDecisionEnum.NOT_APPLICABLE, None, None, None, record

            target_val = int(criterion.target_class) if str(criterion.target_class).isdigit() else 1
            cond_target_pixels = int(np.sum(cond_m == target_val))
            clean_target_pixels = int(np.sum(clean_m == target_val))
            is_act = (cond_target_pixels > 0 and clean_target_pixels == 0)
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="target_class_pixel_emergence",
                comparison_operator="cond_pixels > 0 and clean_pixels == 0",
                threshold=None,
                reference_value=clean_target_pixels,
                candidate_value=cond_target_pixels,
                reference_summary={"target_pixel_count": clean_target_pixels},
                candidate_summary={"target_pixel_count": cond_target_pixels},
                decision=decision,
                status="VALID",
            )
            return decision, None, None, is_act, record

    # =========================================================================
    # 3. Array & Classification / Generic Tensor Evaluations
    # =========================================================================
    if not isinstance(clean_output, np.ndarray) or not isinstance(condition_output, np.ndarray):
        record = ActivationDecisionRecord(
            criterion_type=crit_type,
            criterion_version=version,
            decision=ActivationDecisionEnum.UNAVAILABLE,
            status="UNAVAILABLE_NON_ARRAY_OUTPUT",
        )
        return ActivationDecisionEnum.UNAVAILABLE, None, None, None, record

    clean_vec = np.atleast_1d(np.squeeze(clean_output)).astype(np.float64)
    cond_vec = np.atleast_1d(np.squeeze(condition_output)).astype(np.float64)

    if clean_vec.size == 0 or cond_vec.size == 0:
        record = ActivationDecisionRecord(
            criterion_type=crit_type,
            criterion_version=version,
            decision=ActivationDecisionEnum.NOT_APPLICABLE,
            status="EMPTY_ARRAY",
        )
        return ActivationDecisionEnum.NOT_APPLICABLE, None, None, None, record

    if not (np.all(np.isfinite(clean_vec)) and np.all(np.isfinite(cond_vec))):
        record = ActivationDecisionRecord(
            criterion_type=crit_type,
            criterion_version=version,
            decision=ActivationDecisionEnum.NOT_APPLICABLE,
            status="NON_FINITE_VALUES",
        )
        return ActivationDecisionEnum.NOT_APPLICABLE, None, None, None, record

    # Classification 1D vector analysis
    if cond_vec.ndim == 1 and len(cond_vec) > 1 and clean_vec.ndim == 1 and len(clean_vec) == len(cond_vec):
        cond_pred = int(np.argmax(cond_vec))
        clean_pred = int(np.argmax(clean_vec))
        top_conf = float(np.max(cond_vec))

        is_target_matched: Optional[bool] = None
        if criterion.target_class is not None:
            target_val = int(criterion.target_class) if str(criterion.target_class).isdigit() else criterion.target_class
            is_target_matched = (cond_pred == target_val)

        ref_summary = {"prediction": clean_pred, "confidence": float(clean_vec[clean_pred])}
        cand_summary = {"prediction": cond_pred, "confidence": top_conf}

        if crit_type == ActivationCriterionTypeEnum.PREDICTION_CHANGED:
            is_act = (cond_pred != clean_pred)
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="discrete_prediction_change",
                comparison_operator="!=",
                threshold=None,
                reference_value=clean_pred,
                candidate_value=cond_pred,
                reference_summary=ref_summary,
                candidate_summary=cand_summary,
                decision=decision,
                status="VALID",
            )
            return decision, cond_pred, top_conf, is_target_matched, record

        elif crit_type == ActivationCriterionTypeEnum.TARGET_MATCHED:
            if criterion.target_class is None:
                record = ActivationDecisionRecord(
                    criterion_type=crit_type,
                    criterion_version=version,
                    decision=ActivationDecisionEnum.NOT_APPLICABLE,
                    status="NOT_APPLICABLE_NO_TARGET",
                )
                return ActivationDecisionEnum.NOT_APPLICABLE, cond_pred, top_conf, None, record
            is_act = (is_target_matched is True)
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="target_class_prediction_match",
                comparison_operator="==",
                threshold=float(target_val) if isinstance(target_val, (int, float)) else None,
                reference_value=clean_pred,
                candidate_value=cond_pred,
                reference_summary=ref_summary,
                candidate_summary=cand_summary,
                decision=decision,
                status="VALID",
            )
            return decision, cond_pred, top_conf, is_target_matched, record

        elif crit_type == ActivationCriterionTypeEnum.CONFIDENCE_DELTA_THRESHOLD:
            clean_class_conf_before = float(clean_vec[clean_pred])
            clean_class_conf_after = float(cond_vec[clean_pred])
            conf_drop = clean_class_conf_before - clean_class_conf_after
            thresh = criterion.confidence_delta_threshold
            is_act = (conf_drop >= thresh)
            decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
            record = ActivationDecisionRecord(
                criterion_type=crit_type,
                criterion_version=version,
                metric_name="clean_class_confidence_drop",
                comparison_operator=">=",
                threshold=thresh,
                reference_value=clean_class_conf_before,
                candidate_value=clean_class_conf_after,
                delta_value=conf_drop,
                reference_summary=ref_summary,
                candidate_summary={"clean_class_conf_after": clean_class_conf_after, "conf_drop": conf_drop},
                decision=decision,
                status="VALID",
            )
            return decision, cond_pred, top_conf, is_target_matched, record

    # Generic tensor distance analysis
    tensor_metrics = compute_generic_tensor_stability_metrics(
        candidate_tensor=condition_output,
        reference_tensor=clean_output,
    )
    l2_dist = float(tensor_metrics.l2_distance.value) if tensor_metrics.l2_distance.value is not None else 0.0
    top_val = float(np.max(cond_vec)) if cond_vec.size > 0 else None

    if crit_type == ActivationCriterionTypeEnum.TENSOR_DISTANCE_THRESHOLD:
        thresh = criterion.distance_threshold
        is_act = (l2_dist >= thresh)
        decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
        record = ActivationDecisionRecord(
            criterion_type=crit_type,
            criterion_version=version,
            metric_name="tensor_l2_distance",
            comparison_operator=">=",
            threshold=thresh,
            reference_value=0.0,
            candidate_value=l2_dist,
            delta_value=l2_dist,
            reference_summary={"shape": list(clean_output.shape)},
            candidate_summary={"l2_distance": l2_dist},
            decision=decision,
            status="VALID",
        )
        return decision, None, top_val, None, record

    # Fallback for unexpected tensor criterion
    is_act = (l2_dist > 1e-4)
    decision = ActivationDecisionEnum.ACTIVATED if is_act else ActivationDecisionEnum.NOT_ACTIVATED
    record = ActivationDecisionRecord(
        criterion_type=crit_type,
        criterion_version=version,
        metric_name="tensor_l2_distance_fallback",
        comparison_operator=">",
        threshold=1e-4,
        reference_value=0.0,
        candidate_value=l2_dist,
        reference_summary={"shape": list(clean_output.shape)},
        candidate_summary={"l2_distance": l2_dist},
        decision=decision,
        status="VALID",
    )
    return decision, None, top_val, None, record
