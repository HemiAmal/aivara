"""Pure functional execution and consistency engine for Phase 10.9 Replay & Consistency Verification."""

import hmac
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np

from aivara.inference.binding.models import InputModelBinding, ModelIdentityEnvelope
from aivara.inference.composite_binding import verify_inference_binding
from aivara.inference.enums import InferenceFindingCode, InferenceIntegrityStatus
from aivara.inference.exceptions import (
    InferenceReplayError,
    ReplayBindingInvalidError,
    ReplayEnvironmentMismatchError,
    ReplayIneligibleError,
    ReplayNumericalDivergenceError,
    ReplayProjectMismatchError,
    ReplayRecordInvalidError,
    ReplayStructuralDivergenceError,
    ReplayTimeoutError,
    ReplayVersionUnsupportedError,
)
from aivara.inference.execution.engine import execute_inference_transaction
from aivara.inference.execution.models import (
    ExecutionPolicy,
    InferenceExecution,
    RawExecutionOutput,
    RawOutputTensor,
)
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    TransformedInputIdentity,
)
from aivara.inference.records.engine import verify_inference_record
from aivara.inference.records.enums import InferenceRecordStatus
from aivara.inference.records.models import InferenceRecord
from aivara.inference.replay.comparator import compare_raw_outputs
from aivara.inference.replay.enums import (
    ComparisonStatus,
    ReplayConsistencyStatus,
    ReplayEligibilityStatus,
    ReplayMode,
)
from aivara.inference.replay.models import (
    ReplayComparisonResult,
    ReplayEnvironment,
    ReplayPolicy,
    ReplayVerificationResult,
)
from aivara.inference.replay.policy import (
    DEFAULT_DETERMINISTIC_POLICY,
    SUPPORTED_REPLAY_POLICY_VERSIONS,
    SUPPORTED_REPLAY_SCHEMA_VERSIONS,
    validate_replay_policy,
)


def assess_replay_eligibility(
    record: InferenceRecord,
    expected_project_id: Optional[str] = None,
    policy: Optional[ReplayPolicy] = None,
) -> Tuple[ReplayEligibilityStatus, List[InputFinding]]:
    """Assess whether an InferenceRecord is eligible for replay execution (fail-closed)."""
    findings: List[InputFinding] = []
    active_policy = policy or DEFAULT_DETERMINISTIC_POLICY

    # 1. Validate Policy Version
    if active_policy.policy_version not in SUPPORTED_REPLAY_POLICY_VERSIONS:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_UNSUPPORTED_VERSION.value,
                message=f"Unsupported replay policy_version: '{active_policy.policy_version}'.",
            )
        )
        return ReplayEligibilityStatus.UNSUPPORTED_VERSION, findings

    # 2. Record Null Check
    if record is None:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_RECORD_INVALID.value,
                message="Cannot replay NoneType inference record.",
            )
        )
        return ReplayEligibilityStatus.INVALID_RECORD, findings

    # 3. Project Isolation Check
    if expected_project_id and record.project_id != expected_project_id:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_PROJECT_MISMATCH.value,
                message=f"Project isolation violation: record project '{record.project_id}' != expected '{expected_project_id}'.",
                details={"record_project": record.project_id, "expected_project": expected_project_id},
            )
        )
        return ReplayEligibilityStatus.PROJECT_MISMATCH, findings

    # 4. Record Integrity Verification
    rec_verif = verify_inference_record(record, binding=record.binding, expected_project_id=expected_project_id)
    if not rec_verif.is_valid or rec_verif.status != InferenceRecordStatus.VERIFIED:
        findings.extend(rec_verif.findings)
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_RECORD_INVALID.value,
                message=f"Recorded inference record failed integrity verification with status '{rec_verif.status}'.",
            )
        )
        return ReplayEligibilityStatus.INVALID_RECORD, findings

    # 5. Underlying Phase 10.7 Binding Verification
    if record.binding is None:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_BINDING_INVALID.value,
                message="Inference record does not contain embedded Phase 10.7 binding.",
            )
        )
        return ReplayEligibilityStatus.INVALID_BINDING, findings

    binding_verif = verify_inference_binding(record.binding)
    if not binding_verif.is_valid or binding_verif.status != InferenceIntegrityStatus.VERIFIED:
        findings.extend(binding_verif.findings)
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_BINDING_INVALID.value,
                message=f"Embedded Phase 10.7 binding failed verification with status '{binding_verif.status}'.",
            )
        )
        return ReplayEligibilityStatus.INVALID_BINDING, findings

    return ReplayEligibilityStatus.ELIGIBLE, findings


def execute_replay_transaction(
    *,
    project_id: str,
    input_identity: InputIdentity,
    binding: InputModelBinding,
    model_identity: ModelIdentityEnvelope,
    preprocessing_contract: PreprocessingContract,
    transformed_identity: TransformedInputIdentity,
    preprocessed_array: np.ndarray,
    policy: Optional[ExecutionPolicy] = None,
    runner_override: Optional[Callable[[np.ndarray], Any]] = None,
    cancellation_check: Optional[Callable[[], bool]] = None,
) -> InferenceExecution:
    """Execute controlled replay using the authoritative Phase 10.5 execution engine."""
    return execute_inference_transaction(
        project_id=project_id,
        input_identity=input_identity,
        binding=binding,
        model_identity=model_identity,
        preprocessing_contract=preprocessing_contract,
        transformed_identity=transformed_identity,
        preprocessed_array=preprocessed_array,
        policy=policy,
        runner_override=runner_override,
        cancellation_check=cancellation_check,
    )


def verify_replay_consistency(
    *,
    record: InferenceRecord,
    replay_execution: Optional[InferenceExecution] = None,
    policy: Optional[ReplayPolicy] = None,
    expected_project_id: Optional[str] = None,
    recorded_arrays: Optional[Sequence[np.ndarray]] = None,
    replay_arrays: Optional[Sequence[np.ndarray]] = None,
    raise_on_divergence: bool = False,
) -> ReplayVerificationResult:
    """Compare a replayed execution output with the recorded baseline in an InferenceRecord."""
    active_policy = policy or DEFAULT_DETERMINISTIC_POLICY
    validate_replay_policy(active_policy)

    # 1. Eligibility Assessment
    eligibility_status, findings = assess_replay_eligibility(
        record, expected_project_id=expected_project_id, policy=active_policy
    )

    recorded_exec_id = record.binding.execution_identity_hash if record.binding else ""
    binding_hash = record.inference_binding_hash

    if eligibility_status != ReplayEligibilityStatus.ELIGIBLE:
        status_map = {
            ReplayEligibilityStatus.INVALID_RECORD: ReplayConsistencyStatus.INVALID_RECORD,
            ReplayEligibilityStatus.INVALID_BINDING: ReplayConsistencyStatus.INVALID_BINDING,
            ReplayEligibilityStatus.PROJECT_MISMATCH: ReplayConsistencyStatus.INELIGIBLE,
            ReplayEligibilityStatus.UNSUPPORTED_VERSION: ReplayConsistencyStatus.INELIGIBLE,
            ReplayEligibilityStatus.INELIGIBLE: ReplayConsistencyStatus.INELIGIBLE,
        }
        cons_status = status_map.get(eligibility_status, ReplayConsistencyStatus.INELIGIBLE)

        if raise_on_divergence:
            raise ReplayIneligibleError(
                f"Replay ineligible: {eligibility_status.value}",
                details={"findings": [f.model_dump() for f in findings]},
            )

        return ReplayVerificationResult(
            record_id=record.record_id if record else "unknown",
            project_id=record.project_id if record else "unknown",
            inference_binding_hash=binding_hash,
            is_consistent=False,
            consistency_status=cons_status,
            eligibility_status=eligibility_status,
            recorded_execution_identity=recorded_exec_id,
            replay_execution_identity=None,
            environment_match=False,
            comparison=None,
            findings=findings,
            failure_code=findings[0].code if findings else "REPLAY_INELIGIBLE",
            explanation=f"Replay aborted prior to forward pass: eligibility status '{eligibility_status.value}'.",
        )

    # 2. Replay Execution Check
    if replay_execution is None:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_NON_REPRODUCIBLE.value,
                message="No replay execution output was provided for comparison.",
            )
        )
        return ReplayVerificationResult(
            record_id=record.record_id,
            project_id=record.project_id,
            inference_binding_hash=binding_hash,
            is_consistent=False,
            consistency_status=ReplayConsistencyStatus.NON_REPRODUCIBLE,
            eligibility_status=eligibility_status,
            recorded_execution_identity=recorded_exec_id,
            replay_execution_identity=None,
            environment_match=False,
            comparison=None,
            findings=findings,
            failure_code=InferenceFindingCode.INFERENCE_REPLAY_NON_REPRODUCIBLE.value,
            explanation="Replay execution instance is missing or failed to execute.",
        )

    replay_exec_id = replay_execution.execution_identity_hash
    recorded_raw_hash = record.binding.raw_output_hash
    replay_raw_hash = replay_execution.raw_output.raw_output_hash

    # 3. Output Comparison
    # Extract tensor definitions for structural check
    recorded_tensors = record.binding.details.get("raw_output_tensors", []) if record.binding.details else []
    replay_tensors = replay_execution.raw_output.outputs

    comp_result = compare_raw_outputs(
        recorded_raw_hash=recorded_raw_hash,
        replay_raw_hash=replay_raw_hash,
        recorded_tensors=recorded_tensors if recorded_tensors else replay_tensors,
        replay_tensors=replay_tensors,
        policy=active_policy,
        recorded_arrays=recorded_arrays,
        replay_arrays=replay_arrays,
    )

    # 4. Consistency Classification
    if comp_result.comparison_status == ComparisonStatus.EXACT_MATCH:
        cons_status = ReplayConsistencyStatus.CONSISTENT_EXACT
        is_consistent = True
        explanation = "Replay raw output hash matches recorded baseline exactly (bitwise deterministic)."
    elif comp_result.comparison_status == ComparisonStatus.TOLERANT_MATCH:
        cons_status = ReplayConsistencyStatus.CONSISTENT_TOLERANT
        is_consistent = True
        explanation = (
            f"Replay output satisfies declared error tolerances "
            f"(max_abs_err={comp_result.max_absolute_error:.2e} <= atol={active_policy.atol:.2e}, "
            f"max_rel_err={comp_result.max_relative_error:.2e} <= rtol={active_policy.rtol:.2e})."
        )
    elif comp_result.comparison_status == ComparisonStatus.NUMERICAL_MISMATCH:
        cons_status = ReplayConsistencyStatus.NUMERICAL_DIVERGENCE
        is_consistent = False
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_NUMERICAL_DIVERGENCE.value,
                message=f"Replay output diverged numerically: {comp_result.mismatch_count} element(s) exceeded tolerance.",
                details={
                    "max_absolute_error": comp_result.max_absolute_error,
                    "max_relative_error": comp_result.max_relative_error,
                    "atol": active_policy.atol,
                    "rtol": active_policy.rtol,
                },
            )
        )
        explanation = (
            f"Numerical divergence: {comp_result.mismatch_count} elements exceeded tolerances "
            f"(max_abs_err={comp_result.max_absolute_error:.2e} > atol={active_policy.atol:.2e})."
        )
        if raise_on_divergence:
            raise ReplayNumericalDivergenceError(explanation, details={"comparison": comp_result.model_dump()})
    else:
        # Structural Mismatch
        cons_status = ReplayConsistencyStatus.STRUCTURAL_DIVERGENCE
        is_consistent = False
        findings.append(
            InputFinding(
                code=InferenceFindingCode.INFERENCE_REPLAY_STRUCTURAL_DIVERGENCE.value,
                message=f"Replay output diverged structurally ({comp_result.comparison_status.value}).",
                details=comp_result.details,
            )
        )
        explanation = f"Structural divergence detected: {comp_result.comparison_status.value}."
        if raise_on_divergence:
            raise ReplayStructuralDivergenceError(explanation, details={"comparison": comp_result.model_dump()})

    return ReplayVerificationResult(
        record_id=record.record_id,
        project_id=record.project_id,
        inference_binding_hash=binding_hash,
        is_consistent=is_consistent,
        consistency_status=cons_status,
        eligibility_status=eligibility_status,
        recorded_execution_identity=recorded_exec_id,
        replay_execution_identity=replay_exec_id,
        environment_match=True,
        comparison=comp_result,
        findings=findings,
        failure_code=findings[0].code if (findings and not is_consistent) else None,
        explanation=explanation,
        details={
            "policy_mode": active_policy.mode.value,
            "atol": active_policy.atol,
            "rtol": active_policy.rtol,
        },
    )
