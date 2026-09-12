"""Domain service for Phase 10.9 Replay & Consistency Verification."""

import logging
from typing import Any, Callable, Dict, List, Optional, Sequence

import numpy as np

from aivara.inference.binding.models import InputModelBinding, ModelIdentityEnvelope
from aivara.inference.execution.models import ExecutionPolicy, InferenceExecution
from aivara.inference.input.models import InputIdentity
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    TransformedInputIdentity,
)
from aivara.inference.records.models import InferenceRecord
from aivara.inference.replay.engine import (
    assess_replay_eligibility,
    execute_replay_transaction,
    verify_replay_consistency,
)
from aivara.inference.replay.enums import (
    ReplayConsistencyStatus,
    ReplayEligibilityStatus,
)
from aivara.inference.replay.models import (
    ReplayPolicy,
    ReplayVerificationResult,
)
from aivara.inference.replay.policy import DEFAULT_DETERMINISTIC_POLICY

logger = logging.getLogger("aivara.inference.replay")


class InferenceReplayService:
    """Service coordinating controlled inference replay and consistency evaluation."""

    def orchestrate_replay(
        self,
        *,
        record: InferenceRecord,
        input_identity: InputIdentity,
        binding: InputModelBinding,
        model_identity: ModelIdentityEnvelope,
        preprocessing_contract: PreprocessingContract,
        transformed_identity: TransformedInputIdentity,
        preprocessed_array: np.ndarray,
        execution_policy: Optional[ExecutionPolicy] = None,
        replay_policy: Optional[ReplayPolicy] = None,
        runner_override: Optional[Callable[[np.ndarray], Any]] = None,
        cancellation_check: Optional[Callable[[], bool]] = None,
        expected_project_id: Optional[str] = None,
        recorded_arrays: Optional[Sequence[np.ndarray]] = None,
    ) -> ReplayVerificationResult:
        """Coordinate end-to-end replay lifecycle: eligibility -> controlled execution -> consistency."""
        active_policy = replay_policy or DEFAULT_DETERMINISTIC_POLICY

        # 1. Eligibility Pre-Check
        eligibility, findings = assess_replay_eligibility(
            record, expected_project_id=expected_project_id, policy=active_policy
        )

        if eligibility != ReplayEligibilityStatus.ELIGIBLE:
            return verify_replay_consistency(
                record=record,
                replay_execution=None,
                policy=active_policy,
                expected_project_id=expected_project_id,
            )

        # 2. Controlled Replay Execution (Phase 10.5 Boundary)
        replay_arrays: List[np.ndarray] = []

        def _capturing_runner(arr: np.ndarray) -> Any:
            if runner_override is not None:
                res = runner_override(arr)
            else:
                res = arr  # Default identity fallback if no runner override
            if isinstance(res, np.ndarray):
                replay_arrays.append(res)
            elif isinstance(res, (list, tuple)):
                for item in res:
                    if isinstance(item, np.ndarray):
                        replay_arrays.append(item)
            return res

        try:
            replay_exec = execute_replay_transaction(
                project_id=record.project_id,
                input_identity=input_identity,
                binding=binding,
                model_identity=model_identity,
                preprocessing_contract=preprocessing_contract,
                transformed_identity=transformed_identity,
                preprocessed_array=preprocessed_array,
                policy=execution_policy,
                runner_override=_capturing_runner if (runner_override is not None or recorded_arrays is not None) else None,
                cancellation_check=cancellation_check,
            )
        except Exception as e:
            logger.error("Controlled replay execution raised exception: %s", str(e))
            return ReplayVerificationResult(
                record_id=record.record_id,
                project_id=record.project_id,
                inference_binding_hash=record.inference_binding_hash,
                is_consistent=False,
                consistency_status=ReplayConsistencyStatus.NON_REPRODUCIBLE,
                eligibility_status=ReplayEligibilityStatus.ELIGIBLE,
                recorded_execution_identity=record.binding.execution_identity_hash if record.binding else "",
                replay_execution_identity=None,
                environment_match=False,
                comparison=None,
                findings=[],
                failure_code="REPLAY_EXECUTION_EXCEPTION",
                explanation=f"Replay execution failed with runtime error: {str(e)}",
            )

        # 3. Consistency Evaluation
        return verify_replay_consistency(
            record=record,
            replay_execution=replay_exec,
            policy=active_policy,
            expected_project_id=expected_project_id,
            recorded_arrays=recorded_arrays,
            replay_arrays=replay_arrays if replay_arrays else None,
        )
