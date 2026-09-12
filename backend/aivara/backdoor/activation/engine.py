"""Deterministic Trigger Activation and Controlled Comparison Engine (Phase 9.4)."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import numpy as np

from aivara.backdoor.activation.activation import evaluate_activation_decision
from aivara.backdoor.activation.controls import (
    generate_location_shuffled_array,
    generate_magnitude_matched_noise_array,
)
from aivara.backdoor.activation.enums import (
    ActivationCriterionTypeEnum,
    ActivationDecisionEnum,
    BackdoorComparisonStatusEnum,
    BackdoorConditionEnum,
    BackdoorSupportStatusEnum,
)
from aivara.backdoor.activation.exceptions import (
    BackdoorActivationError,
    InvalidExperimentConfigError,
    SourceInputIntegrityError,
)
from aivara.backdoor.activation.identity import (
    compute_experiment_identity,
    derive_control_seed,
)
from aivara.backdoor.activation.models import (
    ActivationCriterionSpec,
    ActivationDecisionRecord,
    PairedConditionResult,
    PairedObservation,
    TriggerActivationAssessment,
)
from aivara.backdoor.candidates.models import TriggerCandidateSpec
from aivara.backdoor.transformation.engine import TriggerTransformationEngine
from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.backdoor.transformation.identity import compute_input_array_hash
from aivara.backdoor.transformation.validators import validate_input_array
from aivara.behavioral.stability.metrics import compute_classification_stability_metrics
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, sha256_bytes

ACTIVATION_ENGINE_VERSION: str = "1.0.0"
MIN_SUPPORT_SAMPLE_COUNT: int = 10
MAX_EVALUATION_SAMPLES: int = 256


class TriggerActivationEngine:
    """Orchestrates paired clean vs. triggered model evaluations and required control conditions (ADR-088)."""

    def __init__(self, version: str = ACTIVATION_ENGINE_VERSION) -> None:
        self.version = version
        self._trans_engine = TriggerTransformationEngine()

    def assess_candidate(
        self,
        project_id: str,
        model_id: str,
        input_samples: List[Tuple[str, np.ndarray]],  # List of (source_input_id, source_array)
        candidate_spec: TriggerCandidateSpec,
        model_fn: Callable[[np.ndarray], Any],
        input_layout: Optional[Union[InputLayoutEnum, str]] = None,
        criterion: Optional[ActivationCriterionSpec] = None,
        evaluate_controls: bool = True,
        reference_model_fn: Optional[Callable[[np.ndarray], Any]] = None,
    ) -> TriggerActivationAssessment:
        """Execute paired clean vs. triggered evaluation across input samples with control conditions.

        Guarantees:
          - Paired 1-to-1 comparison per sample.
          - Four conditions: CLEAN, ACTIVE_TRIGGER, LOCATION_SHUFFLED, MAGNITUDE_MATCHED_NOISE.
          - Source arrays verified for byte-level immutability.
          - No malicious intent or backdoor confirmation claimed (observations only).
          - Strict separation of statistical support (N >= 10) from behavioral activation outcome.
          - Strict separation of target-conditioned success (TSR) from untargeted activation (TAR).
        """
        if not input_samples:
            raise InvalidExperimentConfigError("input_samples list cannot be empty.")

        if len(input_samples) > MAX_EVALUATION_SAMPLES:
            raise InvalidExperimentConfigError(
                f"Evaluation sample count ({len(input_samples)}) exceeds maximum budget ({MAX_EVALUATION_SAMPLES})."
            )

        active_criterion = criterion or ActivationCriterionSpec()

        # Validate first sample layout & shape to resolve canonical layout
        sample0_id, sample0_arr = input_samples[0]
        resolved_layout, _, _, _ = validate_input_array(
            sample0_arr, candidate_spec, declared_layout=input_layout
        )

        # Compute deterministic experiment identity
        sample0_hash = compute_input_array_hash(sample0_arr)
        experiment_id = compute_experiment_identity(
            project_id=project_id,
            source_input_id=sample0_id,
            source_input_hash=sample0_hash,
            candidate_hash=candidate_spec.candidate_hash,
            input_layout=resolved_layout,
            transformation_version=self._trans_engine.version,
            condition_policy_version=self.version,
        )

        paired_observations: List[PairedObservation] = []
        activated_count = 0
        target_matched_count = 0 if active_criterion.target_class is not None else None
        eligible_count = 0

        shuffled_act_count = 0
        noise_act_count = 0
        shuffled_tgt_count = 0 if active_criterion.target_class is not None else None
        noise_tgt_count = 0 if active_criterion.target_class is not None else None

        for idx, (s_id, s_arr) in enumerate(input_samples):
            s_hash_before = compute_input_array_hash(s_arr)

            # 1. CLEAN Execution
            clean_out = model_fn(s_arr)
            clean_pred = None
            clean_conf = None
            clean_out_serializable = None

            if isinstance(clean_out, np.ndarray):
                clean_vec = np.atleast_1d(np.squeeze(clean_out)).astype(np.float64)
                clean_out_serializable = clean_vec.tolist()
                if clean_vec.ndim == 1 and clean_vec.size > 1:
                    clean_pred = int(np.argmax(clean_vec))
                    clean_conf = float(np.max(clean_vec))

            clean_res = PairedConditionResult(
                condition=BackdoorConditionEnum.CLEAN,
                observation_id=f"obs-clean-{idx}-{s_hash_before[:8]}",
                transformed_array_hash=s_hash_before,
                model_output=clean_out_serializable if clean_out_serializable is not None else clean_out,
                prediction_label=clean_pred,
                top_confidence=clean_conf,
                activation_decision=ActivationDecisionEnum.NOT_APPLICABLE,
                raw_metrics={},
            )

            # Optional Reference Model Execution
            ref_model_res: Optional[PairedConditionResult] = None
            ref_m_out = None
            if reference_model_fn is not None:
                ref_m_out = reference_model_fn(s_arr)
                ref_m_serializable = None
                if isinstance(ref_m_out, np.ndarray):
                    ref_m_serializable = np.atleast_1d(np.squeeze(ref_m_out)).astype(np.float64).tolist()
                ref_model_res = PairedConditionResult(
                    condition=BackdoorConditionEnum.REFERENCE_MODEL,
                    observation_id=f"obs-refmodel-{idx}-{s_hash_before[:8]}",
                    transformed_array_hash=s_hash_before,
                    model_output=ref_m_serializable if ref_m_serializable is not None else ref_m_out,
                    activation_decision=ActivationDecisionEnum.NOT_APPLICABLE,
                    raw_metrics={},
                )

            # 2. ACTIVE_TRIGGER Transformation & Execution
            trig_trans = self._trans_engine.transform(
                input_array=s_arr,
                candidate_spec=candidate_spec,
                input_layout=resolved_layout,
            )
            trig_out = model_fn(trig_trans.transformed_array)
            trig_out_serializable = None
            if isinstance(trig_out, np.ndarray):
                trig_vec = np.atleast_1d(np.squeeze(trig_out)).astype(np.float64)
                trig_out_serializable = trig_vec.tolist()

            # Evaluate activation
            decision, pred_label, top_conf, is_tgt, dec_rec = evaluate_activation_decision(
                clean_output=clean_out,
                condition_output=trig_out,
                criterion=active_criterion,
                reference_mask=ref_m_out,
                reference_model_identity="SUPPLIED_REFERENCE_MODEL" if reference_model_fn is not None else None,
            )

            # Compute comparative Phase 8 metrics where applicable
            comp_metrics: Dict[str, Any] = {}
            if isinstance(clean_out, np.ndarray) and isinstance(trig_out, np.ndarray):
                c_v = np.atleast_1d(np.squeeze(clean_out)).astype(np.float64)
                t_v = np.atleast_1d(np.squeeze(trig_out)).astype(np.float64)
                if c_v.ndim == 1 and c_v.size > 1 and t_v.ndim == 1 and t_v.size == c_v.size:
                    stab_metrics = compute_classification_stability_metrics(t_v, c_v)
                    comp_metrics = stab_metrics.model_dump()

            active_res = PairedConditionResult(
                condition=BackdoorConditionEnum.ACTIVE_TRIGGER,
                observation_id=f"obs-active-{idx}-{trig_trans.transformed_input_hash[:8]}",
                transformed_array_hash=trig_trans.transformed_input_hash,
                model_output=trig_out_serializable if trig_out_serializable is not None else trig_out,
                execution_id=trig_trans.transformation_id,
                prediction_label=pred_label,
                top_confidence=top_conf,
                activation_decision=decision,
                is_target_matched=is_tgt,
                decision_record=dec_rec,
                raw_metrics=comp_metrics,
            )

            is_act = (decision == ActivationDecisionEnum.ACTIVATED)
            if is_act:
                activated_count += 1
            if is_tgt is True and target_matched_count is not None:
                target_matched_count += 1
            eligible_count += 1

            shuffled_res: Optional[PairedConditionResult] = None
            noise_res: Optional[PairedConditionResult] = None

            if evaluate_controls:
                # 3. LOCATION_SHUFFLED Control
                seed_shuffled = derive_control_seed(
                    project_id=project_id,
                    source_input_id=s_id,
                    source_input_hash=s_hash_before,
                    candidate_hash=candidate_spec.candidate_hash,
                    condition_type=BackdoorConditionEnum.LOCATION_SHUFFLED.value,
                    experiment_id=experiment_id,
                    sample_index=idx,
                )
                shuff_trans, _, place_info = generate_location_shuffled_array(
                    source_array=s_arr,
                    candidate_spec=candidate_spec,
                    seed=seed_shuffled,
                    input_layout=resolved_layout,
                    engine=self._trans_engine,
                )
                shuff_out = model_fn(shuff_trans.transformed_array)
                shuff_out_serializable = None
                if isinstance(shuff_out, np.ndarray):
                    shuff_out_serializable = np.atleast_1d(np.squeeze(shuff_out)).astype(np.float64).tolist()

                shuff_dec, shuff_label, shuff_conf, shuff_tgt, shuff_rec = evaluate_activation_decision(
                    clean_output=clean_out,
                    condition_output=shuff_out,
                    criterion=active_criterion,
                    reference_mask=ref_m_out,
                    reference_model_identity="SUPPLIED_REFERENCE_MODEL" if reference_model_fn is not None else None,
                )
                if shuff_dec == ActivationDecisionEnum.ACTIVATED:
                    shuffled_act_count += 1
                if shuff_tgt is True and shuffled_tgt_count is not None:
                    shuffled_tgt_count += 1

                shuffled_res = PairedConditionResult(
                    condition=BackdoorConditionEnum.LOCATION_SHUFFLED,
                    observation_id=f"obs-shuff-{idx}-{shuff_trans.transformed_input_hash[:8]}",
                    transformed_array_hash=shuff_trans.transformed_input_hash,
                    model_output=shuff_out_serializable if shuff_out_serializable is not None else shuff_out,
                    execution_id=shuff_trans.transformation_id,
                    prediction_label=shuff_label,
                    top_confidence=shuff_conf,
                    activation_decision=shuff_dec,
                    is_target_matched=shuff_tgt,
                    decision_record=shuff_rec,
                    placement_info=place_info,
                    raw_metrics={},
                )

                # 4. MAGNITUDE_MATCHED_NOISE Control
                seed_noise = derive_control_seed(
                    project_id=project_id,
                    source_input_id=s_id,
                    source_input_hash=s_hash_before,
                    candidate_hash=candidate_spec.candidate_hash,
                    condition_type=BackdoorConditionEnum.MAGNITUDE_MATCHED_NOISE.value,
                    experiment_id=experiment_id,
                    sample_index=idx,
                )
                noise_arr, noise_hash, noise_mag_metrics = generate_magnitude_matched_noise_array(
                    source_array=s_arr,
                    active_triggered_array=trig_trans.transformed_array,
                    seed=seed_noise,
                    value_range=candidate_spec.input_constraints.value_range,
                )
                noise_out = model_fn(noise_arr)
                noise_out_serializable = None
                if isinstance(noise_out, np.ndarray):
                    noise_out_serializable = np.atleast_1d(np.squeeze(noise_out)).astype(np.float64).tolist()

                noise_dec, noise_label, noise_conf, noise_tgt, noise_rec = evaluate_activation_decision(
                    clean_output=clean_out,
                    condition_output=noise_out,
                    criterion=active_criterion,
                    reference_mask=ref_m_out,
                    reference_model_identity="SUPPLIED_REFERENCE_MODEL" if reference_model_fn is not None else None,
                )
                if noise_dec == ActivationDecisionEnum.ACTIVATED:
                    noise_act_count += 1
                if noise_tgt is True and noise_tgt_count is not None:
                    noise_tgt_count += 1

                noise_res = PairedConditionResult(
                    condition=BackdoorConditionEnum.MAGNITUDE_MATCHED_NOISE,
                    observation_id=f"obs-noise-{idx}-{noise_hash[:8]}",
                    transformed_array_hash=noise_hash,
                    model_output=noise_out_serializable if noise_out_serializable is not None else noise_out,
                    prediction_label=noise_label,
                    top_confidence=noise_conf,
                    activation_decision=noise_dec,
                    is_target_matched=noise_tgt,
                    decision_record=noise_rec,
                    magnitude_metrics=noise_mag_metrics,
                    raw_metrics={},
                )

            # Strictly verify source immutability
            s_hash_after = compute_input_array_hash(s_arr)
            if s_hash_before != s_hash_after:
                raise SourceInputIntegrityError(f"Source input '{s_id}' was mutated in place during evaluation.")

            paired_obs = PairedObservation(
                sample_index=idx,
                source_input_id=s_id,
                source_input_hash=s_hash_before,
                candidate_hash=candidate_spec.candidate_hash,
                input_layout=resolved_layout,
                clean_result=clean_res,
                active_trigger_result=active_res,
                location_shuffled_result=shuffled_res,
                magnitude_matched_noise_result=noise_res,
                reference_model_result=ref_model_res,
                target_class=active_criterion.target_class,
                activation_criterion=active_criterion,
                is_activated=is_act,
                is_target_matched=is_tgt,
            )
            paired_observations.append(paired_obs)

        # Compute TAR and TSR
        tar = (activated_count / eligible_count) if eligible_count > 0 else None
        tsr = (
            (target_matched_count / eligible_count)
            if (active_criterion.target_class is not None and eligible_count > 0)
            else None
        )

        ctrl_tar_shuff = (shuffled_act_count / eligible_count) if (evaluate_controls and eligible_count > 0) else None
        ctrl_tar_noise = (noise_act_count / eligible_count) if (evaluate_controls and eligible_count > 0) else None
        ctrl_tsr_shuff = (
            (shuffled_tgt_count / eligible_count)
            if (evaluate_controls and active_criterion.target_class is not None and eligible_count > 0)
            else None
        )
        ctrl_tsr_noise = (
            (noise_tgt_count / eligible_count)
            if (evaluate_controls and active_criterion.target_class is not None and eligible_count > 0)
            else None
        )

        # Determine Support Status & Assessment Status
        is_support_eligible = (eligible_count >= MIN_SUPPORT_SAMPLE_COUNT)
        support_status = (
            BackdoorSupportStatusEnum.SUPPORT_ELIGIBLE
            if is_support_eligible
            else BackdoorSupportStatusEnum.INSUFFICIENT_SUPPORT
        )
        status = BackdoorComparisonStatusEnum.COMPLETED

        canonical_assessment_dict = {
            "candidate_hash": candidate_spec.candidate_hash,
            "eligible_sample_count": eligible_count,
            "experiment_id": experiment_id,
            "input_layout": resolved_layout.value,
            "model_id": model_id,
            "project_id": project_id,
            "sample_count": len(input_samples),
            "schema_version": "1.0.0",
            "status": status.value,
            "support_status": support_status.value,
        }
        assessment_id = hash_canonical_data(canonical_assessment_dict)

        metadata_dict = {
            "criterion_type": active_criterion.criterion_type.value,
            "target_class": active_criterion.target_class,
            "evaluate_controls": evaluate_controls,
            "min_support_threshold": MIN_SUPPORT_SAMPLE_COUNT,
            "is_support_eligible": is_support_eligible,
            "support_status": support_status.value,
            "engine_version": self.version,
        }

        return TriggerActivationAssessment(
            schema_version="1.0.0",
            assessment_id=assessment_id,
            experiment_id=experiment_id,
            project_id=project_id,
            model_id=model_id,
            candidate_hash=candidate_spec.candidate_hash,
            candidate_family=candidate_spec.candidate_family,
            input_layout=resolved_layout,
            sample_count=len(input_samples),
            eligible_sample_count=eligible_count,
            activated_sample_count=activated_count,
            target_matched_sample_count=target_matched_count,
            support_status=support_status,
            is_support_eligible=is_support_eligible,
            tar=tar,
            tsr=tsr,
            status=status,
            control_tar_shuffled=ctrl_tar_shuff,
            control_tar_noise=ctrl_tar_noise,
            control_tsr_shuffled=ctrl_tsr_shuff,
            control_tsr_noise=ctrl_tsr_noise,
            reference_model_status="IMPLEMENTED_SUPPLIED" if reference_model_fn is not None else "OPTIONAL_RESERVED",
            paired_observations=paired_observations,
            assessment_metadata=metadata_dict,
        )
