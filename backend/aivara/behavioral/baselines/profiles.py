"""Task-specific behavioral profile synthesis and statistical aggregation (Phase 8.3)."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from aivara.behavioral.baselines.schemas import (
    BehavioralProfileAggregate,
    ClassificationBehaviorProfile,
    DetectionBehaviorProfile,
    DistributionStats,
    LatencyProfile,
    NumericalProfile,
    RepeatabilityProfile,
    SegmentationBehaviorProfile,
)
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes


def compute_distribution_stats(values: List[float]) -> DistributionStats:
    """Compute deterministic, numerically stable summary statistics for a sequence of float values."""
    if len(values) == 0:
        return DistributionStats(
            count=0,
            min=0.0,
            max=0.0,
            mean=0.0,
            median=0.0,
            std=0.0,
            p25=0.0,
            p75=0.0,
            p95=0.0,
        )

    arr = np.array(values, dtype=np.float64)
    # Filter non-finite if present for robust statistical summary
    finite_arr = arr[np.isfinite(arr)]
    if len(finite_arr) == 0:
        return DistributionStats(
            count=len(values),
            min=0.0,
            max=0.0,
            mean=0.0,
            median=0.0,
            std=0.0,
            p25=0.0,
            p75=0.0,
            p95=0.0,
        )

    return DistributionStats(
        count=len(values),
        min=float(np.min(finite_arr)),
        max=float(np.max(finite_arr)),
        mean=float(np.mean(finite_arr)),
        median=float(np.median(finite_arr)),
        std=float(np.std(finite_arr)) if len(finite_arr) > 1 else 0.0,
        p25=float(np.percentile(finite_arr, 25)),
        p75=float(np.percentile(finite_arr, 75)),
        p95=float(np.percentile(finite_arr, 95)),
    )


def build_classification_profile(
    outputs: List[np.ndarray],
    output_type: str = "probabilities",
) -> ClassificationBehaviorProfile:
    """Build a deterministic ClassificationBehaviorProfile from per-sample model output vectors."""
    sample_count = len(outputs)
    if sample_count == 0:
        return ClassificationBehaviorProfile(
            output_type=output_type,
            class_count=1,
            sample_count=0,
            prediction_frequency={},
            prediction_proportions={},
            top1_distribution={},
            finite_output_rate=1.0,
        )

    class_count = outputs[0].shape[-1] if outputs[0].ndim > 0 else 1
    pred_counts: Dict[str, int] = {}
    top1_counts: Dict[str, int] = {}
    confidences: List[float] = []
    entropies: List[float] = []
    margins: List[float] = []
    finite_samples = 0

    for out in outputs:
        arr = np.atleast_1d(np.squeeze(out))
        if not np.all(np.isfinite(arr)):
            continue
        finite_samples += 1

        # Determine top-1 class
        top1_idx = int(np.argmax(arr))
        top1_str = str(top1_idx)
        top1_counts[top1_str] = top1_counts.get(top1_str, 0) + 1
        pred_counts[top1_str] = pred_counts.get(top1_str, 0) + 1

        # Confidence
        conf_val = float(arr[top1_idx])
        confidences.append(conf_val)

        # Margin & Entropy if applicable
        if arr.ndim == 1 and len(arr) > 1:
            sorted_vals = np.sort(arr)
            margin = float(sorted_vals[-1] - sorted_vals[-2])
            margins.append(margin)

            if output_type == "probabilities":
                # Compute Shannon entropy
                probs = np.clip(arr, 1e-12, 1.0)
                probs = probs / np.sum(probs)
                ent = float(-np.sum(probs * np.log(probs)))
                entropies.append(ent)

    # Compute normalized proportions
    total_valid = sum(pred_counts.values()) or 1
    proportions = {k: float(v / total_valid) for k, v in sorted(pred_counts.items())}

    return ClassificationBehaviorProfile(
        output_type=output_type,
        class_count=class_count,
        sample_count=sample_count,
        prediction_frequency=dict(sorted(pred_counts.items())),
        prediction_proportions=dict(sorted(proportions.items())),
        top1_distribution=dict(sorted(top1_counts.items())),
        confidence_stats=compute_distribution_stats(confidences) if confidences else None,
        entropy_stats=compute_distribution_stats(entropies) if entropies else None,
        margin_stats=compute_distribution_stats(margins) if margins else None,
        finite_output_rate=float(finite_samples / sample_count) if sample_count > 0 else 1.0,
    )


def build_detection_profile(
    detections: List[Dict[str, Any]],
) -> DetectionBehaviorProfile:
    """Build a deterministic DetectionBehaviorProfile from structured object detection outputs."""
    sample_count = len(detections)
    if sample_count == 0:
        return DetectionBehaviorProfile(
            sample_count=0,
            total_detections=0,
            detection_count_stats=compute_distribution_stats([]),
            class_frequency={},
            empty_detection_rate=0.0,
            finite_output_rate=1.0,
        )

    detection_counts: List[float] = []
    class_counts: Dict[str, int] = []
    class_map: Dict[str, int] = {}
    box_confidences: List[float] = []
    box_areas: List[float] = []
    empty_images = 0
    total_boxes = 0

    for det in detections:
        boxes = det.get("boxes", np.zeros((0, 4), dtype=np.float32))
        scores = det.get("scores", np.zeros((0,), dtype=np.float32))
        classes = det.get("classes", np.zeros((0,), dtype=np.int32))

        num_boxes = len(boxes)
        total_boxes += num_boxes
        detection_counts.append(float(num_boxes))

        if num_boxes == 0:
            empty_images += 1
            continue

        for i in range(num_boxes):
            c_str = str(int(classes[i])) if i < len(classes) else "0"
            class_map[c_str] = class_map.get(c_str, 0) + 1
            if i < len(scores):
                box_confidences.append(float(scores[i]))
            if i < len(boxes):
                b = boxes[i]
                area = max(0.0, float((b[2] - b[0]) * (b[3] - b[1])))
                box_areas.append(area)

    return DetectionBehaviorProfile(
        sample_count=sample_count,
        total_detections=total_boxes,
        detection_count_stats=compute_distribution_stats(detection_counts),
        class_frequency=dict(sorted(class_map.items())),
        confidence_stats=compute_distribution_stats(box_confidences) if box_confidences else None,
        box_area_stats=compute_distribution_stats(box_areas) if box_areas else None,
        empty_detection_rate=float(empty_images / sample_count) if sample_count > 0 else 0.0,
        finite_output_rate=1.0,
    )


def compute_miou_score(pred_mask: np.ndarray, target_mask: np.ndarray, num_classes: Optional[int] = None) -> float:
    """Compute exact mean Intersection-over-Union (mIoU) between two 2D categorical masks."""
    p_flat = pred_mask.flatten()
    t_flat = target_mask.flatten()
    unique_classes = np.unique(np.concatenate([p_flat, t_flat]))
    if len(unique_classes) == 0:
        return 1.0

    ious = []
    for c in unique_classes:
        intersection = np.sum((p_flat == c) & (t_flat == c))
        union = np.sum((p_flat == c) | (t_flat == c))
        if union > 0:
            ious.append(float(intersection / union))
        else:
            ious.append(1.0)

    return float(np.mean(ious)) if ious else 1.0


def build_segmentation_profile(
    masks: List[np.ndarray],
    gt_masks: Optional[List[np.ndarray]] = None,
    ref_masks: Optional[List[np.ndarray]] = None,
) -> SegmentationBehaviorProfile:
    """Build a deterministic SegmentationBehaviorProfile enforcing strict ground-truth vs reference distinction."""
    sample_count = len(masks)
    if sample_count == 0:
        return SegmentationBehaviorProfile(
            sample_count=0,
            class_pixel_counts={},
            class_area_proportions={},
            mask_shape=[0, 0],
            evaluation_case="UNAVAILABLE",
        )

    class_pixel_map: Dict[str, int] = {}
    total_pixels = 0
    mask_shape = list(masks[0].shape) if masks else [0, 0]

    for m in masks:
        unique, counts = np.unique(m, return_counts=True)
        for u, c in zip(unique, counts):
            u_str = str(int(u))
            class_pixel_map[u_str] = class_pixel_map.get(u_str, 0) + int(c)
            total_pixels += int(c)

    proportions = {k: float(v / total_pixels) for k, v in sorted(class_pixel_map.items())} if total_pixels > 0 else {}

    # Case A: Dense Ground-Truth Masks Available -> Calculate mIoU
    if gt_masks is not None and len(gt_masks) == sample_count:
        miou_list = [compute_miou_score(masks[i], gt_masks[i]) for i in range(sample_count)]
        gt_miou = float(np.mean(miou_list))
        return SegmentationBehaviorProfile(
            sample_count=sample_count,
            class_pixel_counts=dict(sorted(class_pixel_map.items())),
            class_area_proportions=dict(sorted(proportions.items())),
            mask_shape=mask_shape,
            ground_truth_miou=gt_miou,
            reference_mask_agreement=None,
            evaluation_case="GROUND_TRUTH_mIoU",
        )

    # Case B: Reference Model Output Available (No Ground Truth) -> Calculate REFERENCE_MASK_AGREEMENT
    if ref_masks is not None and len(ref_masks) == sample_count:
        agreement_list = [compute_miou_score(masks[i], ref_masks[i]) for i in range(sample_count)]
        ref_agreement = float(np.mean(agreement_list))
        return SegmentationBehaviorProfile(
            sample_count=sample_count,
            class_pixel_counts=dict(sorted(class_pixel_map.items())),
            class_area_proportions=dict(sorted(proportions.items())),
            mask_shape=mask_shape,
            ground_truth_miou=None,
            reference_mask_agreement=ref_agreement,
            evaluation_case="REFERENCE_MASK_AGREEMENT",
        )

    # Case C: Neither Ground Truth nor Reference Output Available
    return SegmentationBehaviorProfile(
        sample_count=sample_count,
        class_pixel_counts=dict(sorted(class_pixel_map.items())),
        class_area_proportions=dict(sorted(proportions.items())),
        mask_shape=mask_shape,
        ground_truth_miou=None,
        reference_mask_agreement=None,
        evaluation_case="UNAVAILABLE",
    )


def build_numerical_profile(
    outputs_list: List[Dict[str, np.ndarray]],
) -> NumericalProfile:
    """Build a summary of numerical tensor statistics across evaluated outputs."""
    tensor_names = sorted(set(k for out in outputs_list for k in out.keys()))
    tensor_stats: Dict[str, Dict[str, float]] = {}

    for name in tensor_names:
        arrays = [out[name] for out in outputs_list if name in out]
        if not arrays:
            continue
        concat = np.concatenate([a.flatten() for a in arrays])
        finite_mask = np.isfinite(concat)
        total_elems = len(concat)
        finite_count = int(np.sum(finite_mask))
        nan_count = int(np.sum(np.isnan(concat)))
        inf_count = int(np.sum(np.isinf(concat)))

        finite_vals = concat[finite_mask]
        tensor_stats[name] = {
            "min": float(np.min(finite_vals)) if len(finite_vals) > 0 else 0.0,
            "max": float(np.max(finite_vals)) if len(finite_vals) > 0 else 0.0,
            "mean": float(np.mean(finite_vals)) if len(finite_vals) > 0 else 0.0,
            "std": float(np.std(finite_vals)) if len(finite_vals) > 1 else 0.0,
            "finite_rate": float(finite_count / total_elems) if total_elems > 0 else 1.0,
            "nan_rate": float(nan_count / total_elems) if total_elems > 0 else 0.0,
            "inf_rate": float(inf_count / total_elems) if total_elems > 0 else 0.0,
        }

    return NumericalProfile(tensor_stats=tensor_stats)


def build_latency_profile(
    latencies: List[float],
    execution_provider: str = "CPUExecutionProvider",
    device: str = "cpu",
    runtime_version: str = "1.0.0",
    precision: str = "float32",
) -> LatencyProfile:
    """Build a deterministic LatencyProfile bounded by explicit execution hardware identity."""
    stats = compute_distribution_stats(latencies)
    return LatencyProfile(
        sample_count=len(latencies),
        stats=stats,
        execution_provider=execution_provider,
        device=device,
        runtime_version=runtime_version,
        precision=precision,
    )


def compute_canonical_profile_hash(profile: BehavioralProfileAggregate) -> str:
    """Compute a deterministic 64-char SHA-256 JCS digest of the aggregate behavioral profile."""
    dumped = profile.model_dump(mode="json")
    canonical_bytes = canonicalize(dumped)
    return sha256_bytes(canonical_bytes)

