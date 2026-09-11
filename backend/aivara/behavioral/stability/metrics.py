"""Mathematical metrics, deterministic matching algorithms, and distance calculators (Phase 8.5)."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from aivara.behavioral.stability.schemas import (
    ClassificationStabilityMetrics,
    DetectionMatchRecord,
    DetectionStabilityMetrics,
    GenericTensorStabilityMetrics,
    MetricResult,
    MetricValidityStatus,
    SegmentationStabilityMetrics,
)


# =====================================================================
# 1. Classification Stability Metrics
# =====================================================================

def compute_classification_stability_metrics(
    candidate_output: np.ndarray,
    reference_output: np.ndarray,
    is_probability: bool = True,
    top_k: int = 5,
) -> ClassificationStabilityMetrics:
    """Compute mathematical consistency and divergence metrics between two classification vectors.

    Args:
        candidate_output: 1D or squeezed candidate array (logits or probabilities).
        reference_output: 1D or squeezed reference array.
        is_probability: Flag indicating whether outputs are confirmed normalized probabilities.
        top_k: Top-k boundary for set overlap analysis.

    Returns:
        ClassificationStabilityMetrics domain object.
    """
    cand = np.atleast_1d(np.squeeze(candidate_output)).astype(np.float64)
    ref = np.atleast_1d(np.squeeze(reference_output)).astype(np.float64)

    # Validate shape compatibility
    if cand.shape != ref.shape or cand.ndim != 1 or len(cand) == 0:
        agreement_res = MetricResult(
            metric_name="prediction_agreement",
            value=0.0,
            validity_status=MetricValidityStatus.INCOMPATIBLE,
        )
        return ClassificationStabilityMetrics(prediction_agreement=agreement_res)

    # Check finite values
    if not (np.all(np.isfinite(cand)) and np.all(np.isfinite(ref))):
        agreement_res = MetricResult(
            metric_name="prediction_agreement",
            value=0.0,
            validity_status=MetricValidityStatus.UNVERIFIABLE,
            details={"error": "Non-finite values present in classification outputs"},
        )
        return ClassificationStabilityMetrics(prediction_agreement=agreement_res)

    # 1. Top-1 Prediction Agreement
    cand_top1 = int(np.argmax(cand))
    ref_top1 = int(np.argmax(ref))
    pred_agreement_val = 1.0 if cand_top1 == ref_top1 else 0.0
    agreement_res = MetricResult(
        metric_name="prediction_agreement",
        value=pred_agreement_val,
        unit="binary",
        validity_status=MetricValidityStatus.VALID,
        details={"candidate_top1": cand_top1, "reference_top1": ref_top1},
    )

    # 2. Top-k Overlap (Jaccard Index)
    k_eff = min(top_k, len(cand))
    cand_topk_set = set(np.argsort(cand)[-k_eff:].tolist())
    ref_topk_set = set(np.argsort(ref)[-k_eff:].tolist())
    intersection = len(cand_topk_set.intersection(ref_topk_set))
    union = len(cand_topk_set.union(ref_topk_set))
    jaccard = float(intersection / union) if union > 0 else 1.0
    topk_res = MetricResult(
        metric_name="top_k_overlap",
        value=jaccard,
        unit="jaccard_ratio",
        validity_status=MetricValidityStatus.VALID,
        details={"k": k_eff, "overlap_count": intersection},
    )

    # 3. Confidence Delta
    cand_conf = float(cand[cand_top1])
    ref_conf = float(ref[ref_top1])
    conf_delta = float(cand_conf - ref_conf)
    conf_res = MetricResult(
        metric_name="confidence_delta",
        value=conf_delta,
        unit="score_delta",
        validity_status=MetricValidityStatus.VALID,
        details={"candidate_confidence": cand_conf, "reference_confidence": ref_conf},
    )

    # 4. Probability Divergences (KL & JS) — Strictly for valid probability distributions
    kl_res: Optional[MetricResult] = None
    js_res: Optional[MetricResult] = None
    entropy_res: Optional[MetricResult] = None

    if is_probability:
        eps = 1e-12
        p = np.clip(cand, eps, 1.0)
        p = p / np.sum(p)
        q = np.clip(ref, eps, 1.0)
        q = q / np.sum(q)

        # KL Divergence D_KL(P || Q)
        kl_val = float(np.sum(p * np.log(p / q)))
        kl_res = MetricResult(
            metric_name="kl_divergence",
            value=max(0.0, kl_val),
            unit="nats",
            validity_status=MetricValidityStatus.VALID,
        )

        # Jensen-Shannon Divergence
        m = 0.5 * (p + q)
        js_val = float(0.5 * np.sum(p * np.log(p / m)) + 0.5 * np.sum(q * np.log(q / m)))
        js_res = MetricResult(
            metric_name="js_divergence",
            value=max(0.0, js_val),
            unit="nats",
            validity_status=MetricValidityStatus.VALID,
        )

        # Entropy Delta
        ent_p = float(-np.sum(p * np.log(p)))
        ent_q = float(-np.sum(q * np.log(q)))
        entropy_res = MetricResult(
            metric_name="entropy_delta",
            value=float(abs(ent_p - ent_q)),
            unit="nats",
            validity_status=MetricValidityStatus.VALID,
            details={"candidate_entropy": ent_p, "reference_entropy": ent_q},
        )
    else:
        # Explicitly flag divergence as UNDEFINED on unnormalized logits
        kl_res = MetricResult(
            metric_name="kl_divergence",
            value=None,
            validity_status=MetricValidityStatus.UNDEFINED,
            details={"reason": "KL divergence is mathematically invalid on unnormalized logits."},
        )
        js_res = MetricResult(
            metric_name="js_divergence",
            value=None,
            validity_status=MetricValidityStatus.UNDEFINED,
            details={"reason": "JS divergence is mathematically invalid on unnormalized logits."},
        )

    # 5. Margin Delta (Top-1 minus Top-2 difference)
    margin_res: Optional[MetricResult] = None
    if len(cand) >= 2:
        cand_sorted = np.sort(cand)
        ref_sorted = np.sort(ref)
        cand_margin = float(cand_sorted[-1] - cand_sorted[-2])
        ref_margin = float(ref_sorted[-1] - ref_sorted[-2])
        margin_delta = float(cand_margin - ref_margin)
        margin_res = MetricResult(
            metric_name="margin_delta",
            value=margin_delta,
            unit="score_delta",
            validity_status=MetricValidityStatus.VALID,
            details={"candidate_margin": cand_margin, "reference_margin": ref_margin},
        )

    return ClassificationStabilityMetrics(
        prediction_agreement=agreement_res,
        top_k_overlap=topk_res,
        confidence_delta=conf_res,
        kl_divergence=kl_res,
        js_divergence=js_res,
        entropy_delta=entropy_res,
        margin_delta=margin_res,
    )


# =====================================================================
# 2. Object Detection Stability Metrics & Deterministic Matching
# =====================================================================

def compute_box_iou(box1: np.ndarray, box2: np.ndarray) -> float:
    """Compute 2D Intersection-over-Union between two bounding boxes [x1, y1, x2, y2]."""
    x1 = max(float(box1[0]), float(box2[0]))
    y1 = max(float(box1[1]), float(box2[1]))
    x2 = min(float(box1[2]), float(box2[2]))
    y2 = min(float(box1[3]), float(box2[3]))

    inter_w = max(0.0, x2 - x1)
    inter_h = max(0.0, y2 - y1)
    inter_area = inter_w * inter_h

    area1 = max(0.0, float(box1[2] - box1[0])) * max(0.0, float(box1[3] - box1[1]))
    area2 = max(0.0, float(box2[2] - box2[0])) * max(0.0, float(box2[3] - box2[1]))

    union_area = area1 + area2 - inter_area
    if union_area <= 0.0:
        return 0.0
    return float(inter_area / union_area)


def compute_detection_stability_metrics(
    candidate_detections: Dict[str, Any],
    reference_detections: Dict[str, Any],
    iou_threshold: float = 0.5,
) -> DetectionStabilityMetrics:
    """Perform deterministic greedy matching (NOT globally optimal bipartite assignment) and compute detection consistency metrics.

    Pairs candidate and reference detections by sorting potential matches on:
    (IoU desc, class_match desc, candidate_conf desc, cand_idx asc, ref_idx asc)
    and greedily accepting the highest valid pair with IoU >= iou_threshold.
    """
    c_boxes = np.array(candidate_detections.get("boxes", np.zeros((0, 4), dtype=np.float32)))
    c_scores = np.array(candidate_detections.get("scores", np.zeros((0,), dtype=np.float32)))
    c_classes = np.array(candidate_detections.get("classes", np.zeros((0,), dtype=np.int32)))

    r_boxes = np.array(reference_detections.get("boxes", np.zeros((0, 4), dtype=np.float32)))
    r_scores = np.array(reference_detections.get("scores", np.zeros((0,), dtype=np.float32)))
    r_classes = np.array(reference_detections.get("classes", np.zeros((0,), dtype=np.int32)))

    n_c = len(c_boxes)
    n_r = len(r_boxes)
    count_delta = n_c - n_r

    if n_c == 0 and n_r == 0:
        return DetectionStabilityMetrics(
            matched_detection_count=0,
            unmatched_candidate_count=0,
            unmatched_reference_count=0,
            count_delta=0,
            mean_matched_iou=MetricResult(metric_name="mean_matched_iou", value=1.0, validity_status=MetricValidityStatus.VALID),
            class_agreement_rate=MetricResult(metric_name="class_agreement_rate", value=1.0, validity_status=MetricValidityStatus.VALID),
            mean_confidence_delta=MetricResult(metric_name="mean_confidence_delta", value=0.0, validity_status=MetricValidityStatus.VALID),
            mean_box_displacement=MetricResult(metric_name="mean_box_displacement", value=0.0, validity_status=MetricValidityStatus.VALID),
            matches=[],
        )

    # 1. Compute Pairwise IoUs and Construct Potential Matches
    potential_matches = []
    for i in range(n_c):
        for j in range(n_r):
            iou = compute_box_iou(c_boxes[i], r_boxes[j])
            c_cls = str(c_classes[i]) if i < len(c_classes) else "0"
            r_cls = str(r_classes[j]) if j < len(r_classes) else "0"
            c_conf = float(c_scores[i]) if i < len(c_scores) else 1.0
            r_conf = float(r_scores[j]) if j < len(r_scores) else 1.0

            # Compute centroid displacement
            c_cx = (float(c_boxes[i][0]) + float(c_boxes[i][2])) / 2.0
            c_cy = (float(c_boxes[i][1]) + float(c_boxes[i][3])) / 2.0
            r_cx = (float(r_boxes[j][0]) + float(r_boxes[j][2])) / 2.0
            r_cy = (float(r_boxes[j][1]) + float(r_boxes[j][3])) / 2.0
            disp = math.sqrt((c_cx - r_cx) ** 2 + (c_cy - r_cy) ** 2)

            potential_matches.append({
                "cand_idx": i,
                "ref_idx": j,
                "iou": iou,
                "class_match": (c_cls == r_cls),
                "cand_class": c_cls,
                "ref_class": r_cls,
                "cand_conf": c_conf,
                "ref_conf": r_conf,
                "conf_delta": c_conf - r_conf,
                "disp": disp,
            })

    # 2. Deterministic Greedy Matching with Explicit Tie-Breaking
    # Sorting key: IoU desc, class_match desc, conf desc, cand_idx asc, ref_idx asc
    potential_matches.sort(
        key=lambda m: (m["iou"], 1 if m["class_match"] else 0, m["cand_conf"], -m["cand_idx"], -m["ref_idx"]),
        reverse=True,
    )

    matched_candidates = set()
    matched_references = set()
    matched_records: List[DetectionMatchRecord] = []

    for m in potential_matches:
        c_i = m["cand_idx"]
        r_j = m["ref_idx"]
        if c_i not in matched_candidates and r_j not in matched_references:
            if m["iou"] >= iou_threshold or (n_c == 1 and n_r == 1):
                matched_candidates.add(c_i)
                matched_references.add(r_j)
                matched_records.append(
                    DetectionMatchRecord(
                        candidate_idx=c_i,
                        reference_idx=r_j,
                        iou=m["iou"],
                        class_match=m["class_match"],
                        candidate_class=m["cand_class"],
                        reference_class=m["ref_class"],
                        candidate_confidence=m["cand_conf"],
                        reference_confidence=m["ref_conf"],
                        confidence_delta=m["conf_delta"],
                        box_displacement=m["disp"],
                    )
                )

    num_matched = len(matched_records)
    unmatched_cand = n_c - num_matched
    unmatched_ref = n_r - num_matched

    mean_iou = float(np.mean([m.iou for m in matched_records])) if num_matched > 0 else 0.0
    class_agreement = float(np.mean([1.0 if m.class_match else 0.0 for m in matched_records])) if num_matched > 0 else 0.0
    mean_conf_delta = float(np.mean([m.confidence_delta for m in matched_records])) if num_matched > 0 else 0.0
    mean_disp = float(np.mean([m.box_displacement for m in matched_records])) if num_matched > 0 else 0.0

    return DetectionStabilityMetrics(
        matched_detection_count=num_matched,
        unmatched_candidate_count=unmatched_cand,
        unmatched_reference_count=unmatched_ref,
        count_delta=count_delta,
        mean_matched_iou=MetricResult(metric_name="mean_matched_iou", value=mean_iou, validity_status=MetricValidityStatus.VALID),
        class_agreement_rate=MetricResult(metric_name="class_agreement_rate", value=class_agreement, validity_status=MetricValidityStatus.VALID),
        mean_confidence_delta=MetricResult(metric_name="mean_confidence_delta", value=mean_conf_delta, validity_status=MetricValidityStatus.VALID),
        mean_box_displacement=MetricResult(metric_name="mean_box_displacement", value=mean_disp, validity_status=MetricValidityStatus.VALID),
        matches=matched_records,
    )


# =====================================================================
# 3. Segmentation Stability Metrics
# =====================================================================

def compute_segmentation_stability_metrics(
    candidate_mask: np.ndarray,
    reference_mask: Optional[np.ndarray] = None,
    ground_truth_mask: Optional[np.ndarray] = None,
) -> SegmentationStabilityMetrics:
    """Compute exact pixel agreement and mIoU / reference agreement between categorical masks."""
    cand = np.squeeze(candidate_mask)

    # Case A: Dense Ground-Truth Mask Available
    if ground_truth_mask is not None:
        gt = np.squeeze(ground_truth_mask)
        if cand.shape != gt.shape:
            return SegmentationStabilityMetrics(
                evaluation_case="GROUND_TRUTH_mIoU",
                ground_truth_miou=MetricResult(metric_name="ground_truth_miou", value=None, validity_status=MetricValidityStatus.INCOMPATIBLE),
            )

        p_flat = cand.flatten()
        t_flat = gt.flatten()
        unique_classes = np.unique(np.concatenate([p_flat, t_flat]))
        ious: Dict[str, float] = {}
        for c in unique_classes:
            c_str = str(int(c))
            inter = int(np.sum((p_flat == c) & (t_flat == c)))
            union = int(np.sum((p_flat == c) | (t_flat == c)))
            ious[c_str] = float(inter / union) if union > 0 else 1.0

        mean_miou = float(np.mean(list(ious.values()))) if ious else 1.0
        pixel_acc = float(np.mean(p_flat == t_flat)) if len(p_flat) > 0 else 1.0

        return SegmentationStabilityMetrics(
            evaluation_case="GROUND_TRUTH_mIoU",
            ground_truth_miou=MetricResult(metric_name="ground_truth_miou", value=mean_miou, validity_status=MetricValidityStatus.VALID),
            reference_mask_agreement=None,
            pixel_agreement_rate=MetricResult(metric_name="pixel_agreement_rate", value=pixel_acc, validity_status=MetricValidityStatus.VALID),
            per_class_iou=ious,
        )

    # Case B: Reference Model Output Available (No Ground Truth)
    if reference_mask is not None:
        ref = np.squeeze(reference_mask)
        if cand.shape != ref.shape:
            return SegmentationStabilityMetrics(
                evaluation_case="REFERENCE_MASK_AGREEMENT",
                reference_mask_agreement=MetricResult(
                    metric_name="reference_mask_agreement",
                    value=None,
                    validity_status=MetricValidityStatus.INCOMPATIBLE,
                ),
            )

        p_flat = cand.flatten()
        r_flat = ref.flatten()
        unique_classes = np.unique(np.concatenate([p_flat, r_flat]))
        agreements: Dict[str, float] = {}
        for c in unique_classes:
            c_str = str(int(c))
            inter = int(np.sum((p_flat == c) & (r_flat == c)))
            union = int(np.sum((p_flat == c) | (r_flat == c)))
            agreements[c_str] = float(inter / union) if union > 0 else 1.0

        mean_agree = float(np.mean(list(agreements.values()))) if agreements else 1.0
        pixel_acc = float(np.mean(p_flat == r_flat)) if len(p_flat) > 0 else 1.0

        return SegmentationStabilityMetrics(
            evaluation_case="REFERENCE_MASK_AGREEMENT",
            ground_truth_miou=None,
            reference_mask_agreement=MetricResult(
                metric_name="reference_mask_agreement",
                value=mean_agree,
                validity_status=MetricValidityStatus.VALID,
            ),
            pixel_agreement_rate=MetricResult(metric_name="pixel_agreement_rate", value=pixel_acc, validity_status=MetricValidityStatus.VALID),
            per_class_iou=agreements,
        )

    # Case C: Neither Available
    return SegmentationStabilityMetrics(
        evaluation_case="UNAVAILABLE",
        ground_truth_miou=None,
        reference_mask_agreement=None,
    )


# =====================================================================
# 4. Generic Tensor Stability Metrics
# =====================================================================

def compute_generic_tensor_stability_metrics(
    candidate_tensor: np.ndarray,
    reference_tensor: np.ndarray,
) -> GenericTensorStabilityMetrics:
    """Compute mathematical tensor distances and consistency metrics without task assumptions."""
    shape_match = (candidate_tensor.shape == reference_tensor.shape)
    dtype_match = (candidate_tensor.dtype == reference_tensor.dtype)

    if not shape_match:
        incompat_res = MetricResult(metric_name="l1_distance", value=None, validity_status=MetricValidityStatus.INCOMPATIBLE)
        return GenericTensorStabilityMetrics(
            shape_match=False,
            dtype_match=dtype_match,
            element_count=candidate_tensor.size,
            l1_distance=incompat_res,
            l2_distance=incompat_res,
            max_absolute_difference=incompat_res,
            mean_absolute_difference=incompat_res,
            finite_value_agreement=incompat_res,
        )

    c_flat = candidate_tensor.flatten().astype(np.float64)
    r_flat = reference_tensor.flatten().astype(np.float64)

    c_finite = np.isfinite(c_flat)
    r_finite = np.isfinite(r_flat)
    finite_agree_rate = float(np.mean(c_finite == r_finite)) if len(c_flat) > 0 else 1.0

    valid_mask = c_finite & r_finite
    if np.sum(valid_mask) == 0:
        unverif = MetricResult(metric_name="l1_distance", value=None, validity_status=MetricValidityStatus.UNVERIFIABLE)
        return GenericTensorStabilityMetrics(
            shape_match=True,
            dtype_match=dtype_match,
            element_count=len(c_flat),
            l1_distance=unverif,
            l2_distance=unverif,
            max_absolute_difference=unverif,
            mean_absolute_difference=unverif,
            finite_value_agreement=MetricResult(metric_name="finite_value_agreement", value=finite_agree_rate, validity_status=MetricValidityStatus.VALID),
        )

    diff = np.abs(c_flat[valid_mask] - r_flat[valid_mask])
    l1_val = float(np.sum(diff))
    l2_val = float(np.sqrt(np.sum(diff ** 2)))
    max_diff = float(np.max(diff))
    mae = float(np.mean(diff))

    # Relative L2 (Zero Denominator Handling)
    r_norm = float(np.sqrt(np.sum(r_flat[valid_mask] ** 2)))
    if r_norm > 0:
        rel_l2_val = float(l2_val / r_norm)
        rel_l2_res = MetricResult(metric_name="relative_l2_distance", value=rel_l2_val, validity_status=MetricValidityStatus.VALID)
    elif l2_val == 0.0:
        rel_l2_res = MetricResult(metric_name="relative_l2_distance", value=0.0, validity_status=MetricValidityStatus.VALID, details={"convention": "Zero delta with zero reference norm"})
    else:
        rel_l2_res = MetricResult(
            metric_name="relative_l2_distance",
            value=None,
            validity_status=MetricValidityStatus.UNDEFINED,
            details={"reason": "Reference norm is zero (non-finite denominator)"},
        )

    # Cosine Similarity (AIVARA Defined Conventions for Undefined Zero Norms)
    # Mathematical cosine similarity is undefined when either vector has zero norm.
    # AIVARA establishes explicit safe conventions:
    # 1. Both vectors zero -> 1.0 (AIVARA convention for identical null representations)
    # 2. One-sided zero vector -> 0.0 (AIVARA safe fallback convention)
    c_norm = float(np.sqrt(np.sum(c_flat[valid_mask] ** 2)))
    if c_norm > 0 and r_norm > 0:
        cos_sim = float(np.dot(c_flat[valid_mask], r_flat[valid_mask]) / (c_norm * r_norm))
        cos_sim = float(np.clip(cos_sim, -1.0, 1.0))
        cos_res = MetricResult(metric_name="cosine_similarity", value=cos_sim, validity_status=MetricValidityStatus.VALID)
    elif c_norm == 0 and r_norm == 0:
        cos_res = MetricResult(
            metric_name="cosine_similarity",
            value=1.0,
            validity_status=MetricValidityStatus.VALID,
            details={"convention": "AIVARA convention: both vectors are zero norm"},
        )
    else:
        cos_res = MetricResult(
            metric_name="cosine_similarity",
            value=0.0,
            validity_status=MetricValidityStatus.VALID,
            details={"convention": "AIVARA safe fallback: one vector has zero norm"},
        )

    return GenericTensorStabilityMetrics(
        shape_match=True,
        dtype_match=dtype_match,
        element_count=len(c_flat),
        l1_distance=MetricResult(metric_name="l1_distance", value=l1_val, validity_status=MetricValidityStatus.VALID),
        l2_distance=MetricResult(metric_name="l2_distance", value=l2_val, validity_status=MetricValidityStatus.VALID),
        relative_l2_distance=rel_l2_res,
        cosine_similarity=cos_res,
        max_absolute_difference=MetricResult(metric_name="max_absolute_difference", value=max_diff, validity_status=MetricValidityStatus.VALID),
        mean_absolute_difference=MetricResult(metric_name="mean_absolute_difference", value=mae, validity_status=MetricValidityStatus.VALID),
        finite_value_agreement=MetricResult(metric_name="finite_value_agreement", value=finite_agree_rate, validity_status=MetricValidityStatus.VALID),
    )


# =====================================================================
# 5. Input Distance Metrics
# =====================================================================

def compute_input_distance(arr1: np.ndarray, arr2: np.ndarray) -> Dict[str, float]:
    """Compute mathematical input space distance metrics (L1, L2, RMSE, MAD)."""
    if arr1.shape != arr2.shape:
        return {"l1": float("inf"), "l2": float("inf"), "rmse": float("inf"), "mad": float("inf")}

    a1 = arr1.astype(np.float64).flatten()
    a2 = arr2.astype(np.float64).flatten()
    diff = np.abs(a1 - a2)

    l1 = float(np.sum(diff))
    l2 = float(np.sqrt(np.sum(diff ** 2)))
    rmse = float(np.sqrt(np.mean(diff ** 2)))
    mad = float(np.mean(diff))

    return {"l1": l1, "l2": l2, "rmse": rmse, "mad": mad}
