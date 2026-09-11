"""Behavioral Baseline Service managing baseline creation, profile synthesis, and trust evaluation (Phase 8.3)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import numpy as np

from aivara.behavioral.baselines.comparability import validate_baseline_comparability
from aivara.behavioral.baselines.input_set import build_input_set_descriptor
from aivara.behavioral.baselines.profiles import (
    build_classification_profile,
    build_detection_profile,
    build_latency_profile,
    build_numerical_profile,
    build_segmentation_profile,
    compute_canonical_profile_hash,
    compute_distribution_stats,
)
from aivara.behavioral.baselines.schemas import (
    BaselineStatus,
    BaselineSupportStatus,
    BaselineTrustStatus,
    BaselineType,
    BehavioralBaseline,
    BehavioralProfileAggregate,
    ClassificationBehaviorProfile,
    DetectionBehaviorProfile,
    ExpectedBehaviorSpecification,
    InputSetDescriptor,
    LatencyProfile,
    NumericalProfile,
    RepeatabilityProfile,
    SegmentationBehaviorProfile,
)
from aivara.behavioral.schemas import ExecutionResult, ExecutionStatus
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import sha256_bytes

logger = logging.getLogger(__name__)


class BehavioralBaselineService:
    """Core domain service for constructing, evaluating, and managing behavioral reference baselines."""

    def compute_baseline_identity_hash(
        self,
        project_id: str,
        model_id: str,
        model_fingerprint: str,
        task_type: str,
        input_set_identity: str,
        execution_provider: str,
        baseline_type: str,
        profile_hash: str,
        preprocessing_hash: Optional[str] = None,
    ) -> str:
        """Compute the deterministic 64-character SHA-256 identity hash for a baseline."""
        payload = {
            "schema_version": "1.0",
            "project_id": str(project_id),
            "model_id": str(model_id),
            "model_fingerprint": str(model_fingerprint),
            "task_type": str(task_type).lower(),
            "input_set_identity": str(input_set_identity),
            "preprocessing_hash": str(preprocessing_hash) if preprocessing_hash else "NONE",
            "execution_provider": str(execution_provider),
            "baseline_type": str(baseline_type),
            "profile_hash": str(profile_hash),
        }
        canonical_bytes = canonicalize(payload)
        return sha256_bytes(canonical_bytes)

    def create_baseline(
        self,
        project_id: str,
        model_id: str,
        model_fingerprint: str,
        task_type: str,
        input_set: InputSetDescriptor,
        execution_results: List[ExecutionResult],
        baseline_type: BaselineType = BaselineType.REFERENCE_EXECUTION_PROFILE,
        trust_status: BaselineTrustStatus = BaselineTrustStatus.VERIFIED,
        preprocessing_hash: Optional[str] = None,
        expected_specifications: Optional[ExpectedBehaviorSpecification] = None,
        reference_model_id: Optional[str] = None,
        reference_model_fingerprint: Optional[str] = None,
        ground_truth_masks: Optional[List[np.ndarray]] = None,
        reference_masks: Optional[List[np.ndarray]] = None,
        custom_limitations: Optional[List[str]] = None,
    ) -> BehavioralBaseline:
        """Construct a validated, deterministic BehavioralBaseline from execution observations.

        Args:
            project_id: Multi-tenant project identifier.
            model_id: Evaluated model identifier.
            model_fingerprint: Phase 7 Master Model Fingerprint (H_master).
            task_type: Task domain ("classification", "object_detection", "segmentation", "generic").
            input_set: InputSetDescriptor capturing deterministic test sample identities.
            execution_results: List of successful ExecutionResults corresponding to test inputs.
            baseline_type: Origin type of baseline.
            trust_status: Cryptographic / integrity verification status.
            preprocessing_hash: Optional digest of applied preprocessing contract.
            expected_specifications: Optional user-supplied behavioral expectations.
            reference_model_id: Optional reference model asset ID.
            reference_model_fingerprint: Optional reference model H_master.
            ground_truth_masks: Optional dense ground-truth masks for mIoU (Case A).
            reference_masks: Optional reference model masks for agreement (Case B).
            custom_limitations: Optional list of identified limitations.

        Returns:
            Sealed BehavioralBaseline domain object.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        sample_count = len(execution_results)
        limitations: List[str] = list(custom_limitations or [])

        # 1. Sample Support Categorization (ADR-032 alignment)
        if sample_count < 5:
            support_status = BaselineSupportStatus.INSUFFICIENT_SUPPORT
            limitations.append(f"Sample count ({sample_count}) is below conservative statistical support threshold (N >= 5).")
        else:
            support_status = BaselineSupportStatus.ADEQUATE_SUPPORT

        # 2. Extract Valid Outputs & Telemetry
        successful_runs = [r for r in execution_results if r.status == ExecutionStatus.SUCCESS and r.outputs is not None]
        outputs_list: List[Dict[str, np.ndarray]] = [r.outputs for r in successful_runs if r.outputs is not None]
        latencies: List[float] = [r.duration_ms for r in execution_results]

        first_res = execution_results[0] if execution_results else None
        provider = first_res.provider if first_res else "CPUExecutionProvider"
        device = first_res.device if first_res else "cpu"
        runtime_version = first_res.runtime_version if first_res else "unknown"
        precision = first_res.precision if first_res else "float32"

        # 3. Build Task-Specific Profile
        task_lower = task_type.lower()
        class_prof: Optional[ClassificationBehaviorProfile] = None
        det_prof: Optional[DetectionBehaviorProfile] = None
        seg_prof: Optional[SegmentationBehaviorProfile] = None

        if task_lower == "classification":
            # Extract primary prediction arrays
            t_name = "logits" if outputs_list and "logits" in outputs_list[0] else (list(outputs_list[0].keys())[0] if outputs_list else "output")
            preds = [out[t_name] for out in outputs_list if t_name in out]
            class_prof = build_classification_profile(preds, output_type="probabilities")

        elif task_lower in ("object_detection", "detection"):
            # Extract structured detection boxes/scores/classes if present
            det_outputs: List[Dict[str, Any]] = []
            for out in outputs_list:
                boxes = out.get("boxes", np.zeros((0, 4), dtype=np.float32))
                scores = out.get("scores", np.zeros((0,), dtype=np.float32))
                classes = out.get("classes", np.zeros((0,), dtype=np.int32))
                det_outputs.append({"boxes": boxes, "scores": scores, "classes": classes})
            det_prof = build_detection_profile(det_outputs)

        elif task_lower == "segmentation":
            t_name = "mask" if outputs_list and "mask" in outputs_list[0] else (list(outputs_list[0].keys())[0] if outputs_list else "output")
            masks = [out[t_name] for out in outputs_list if t_name in out]
            seg_prof = build_segmentation_profile(
                masks=masks,
                gt_masks=ground_truth_masks,
                ref_masks=reference_masks,
            )

        # 4. Build Auxiliary Profiles (Numerical, Latency, Repeatability)
        num_prof = build_numerical_profile(outputs_list)
        lat_prof = LatencyProfile(
            sample_count=len(latencies),
            stats=compute_distribution_stats(latencies),
            execution_provider=provider,
            device=device,
            runtime_version=runtime_version,
            precision=precision,
        )

        aggregate_profile = BehavioralProfileAggregate(
            task_type=task_type,
            classification=class_prof,
            detection=det_prof,
            segmentation=seg_prof,
            numerical=num_prof,
            latency=lat_prof,
            repeatability=None,
        )

        # 5. Deterministic Profile Hash
        profile_hash = compute_canonical_profile_hash(aggregate_profile)

        # 6. Overall Baseline Status Determination
        if trust_status == BaselineTrustStatus.INVALID:
            baseline_status = BaselineStatus.INVALID
        elif trust_status == BaselineTrustStatus.UNVERIFIABLE:
            baseline_status = BaselineStatus.UNVERIFIABLE
        elif support_status == BaselineSupportStatus.INSUFFICIENT_SUPPORT:
            baseline_status = BaselineStatus.INSUFFICIENT_SUPPORT
        else:
            baseline_status = BaselineStatus.VALID

        # 7. Deterministic Baseline ID
        baseline_id = self.compute_baseline_identity_hash(
            project_id=project_id,
            model_id=model_id,
            model_fingerprint=model_fingerprint,
            task_type=task_type,
            input_set_identity=input_set.input_set_id,
            execution_provider=provider,
            baseline_type=baseline_type.value,
            profile_hash=profile_hash,
            preprocessing_hash=preprocessing_hash,
        )

        return BehavioralBaseline(
            baseline_id=baseline_id,
            baseline_type=baseline_type,
            trust_status=trust_status,
            support_status=support_status,
            baseline_status=baseline_status,
            project_id=project_id,
            model_id=model_id,
            model_fingerprint=model_fingerprint,
            task_type=task_type,
            input_set_identity=input_set.input_set_id,
            preprocessing_hash=preprocessing_hash,
            execution_provider=provider,
            device=device,
            precision=precision,
            profile=aggregate_profile,
            profile_hash=profile_hash,
            expected_specifications=expected_specifications,
            reference_model_id=reference_model_id,
            reference_model_fingerprint=reference_model_fingerprint,
            limitations=limitations,
            created_at=now_iso,
        )
