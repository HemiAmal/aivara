"""Core deterministic execution and verification engine for Inference Execution Integrity (Phase 10.5)."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np

from aivara.crypto.canonical import canonicalize
from aivara.inference.binding.engine import (
    verify_input_model_binding,
    verify_master_fingerprint_consistency,
)
from aivara.inference.binding.models import InputModelBinding, ModelIdentityEnvelope
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputLayout,
)

from aivara.inference.exceptions import (
    ExecutionCancelledError,
    ExecutionPolicyError,
    ExecutionProviderUnavailableError,
    ExecutionResourceLimitError,
    ExecutionTimeoutError,
    InferenceExecutionError,
    InvalidHashFormatError,
    ModelExecutionIntegrityError,
    ProjectMismatchError,
)
from aivara.inference.execution.enums import (
    ExecutionDevice,
    ExecutionLifecycle,
    ExecutionProvider,
    NumericalSanityStatus,
)
from aivara.inference.execution.models import (
    ExecutionPolicy,
    ExecutionVerificationResult,
    InferenceExecution,
    RawExecutionOutput,
    RawOutputTensor,
)
from aivara.inference.input.models import InputFinding, InputIdentity
from aivara.inference.preprocessing.engine import verify_preprocessing_contract
from aivara.inference.preprocessing.models import (
    PreprocessingContract,
    TransformedInputIdentity,
)

HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def get_available_execution_providers() -> List[str]:
    """Return available ONNX Runtime execution providers on the current system."""
    try:
        import onnxruntime as ort
        return ort.get_available_providers()
    except Exception:
        return ["CPUExecutionProvider"]


def is_cuda_available() -> bool:
    """Return True if CUDA execution provider is available on the local host."""
    return "CUDAExecutionProvider" in get_available_execution_providers()


def build_canonical_execution_descriptor(
    project_id: str,
    input_id: str,
    binding_hash: str,
    preprocessing_contract_hash: str,
    transformed_input_hash: str,
    model_id: str,
    model_master_fingerprint: str,
    execution_provider: str,
    execution_policy: ExecutionPolicy,
    execution_version: str = "1.0",
    schema_version: str = "1.0",
) -> Dict[str, Any]:
    """Construct the deterministic execution descriptor dictionary for RFC 8785 JCS canonicalization."""
    policy_prov = (
        execution_policy.provider.value
        if isinstance(execution_policy.provider, ExecutionProvider)
        else str(execution_policy.provider)
    )

    return {
        "binding_hash": str(binding_hash),
        "execution_policy": {
            "deterministic": bool(execution_policy.deterministic),
            "max_batch_size": int(execution_policy.max_batch_size),
            "max_output_bytes": int(execution_policy.max_output_bytes),
            "max_tensor_elements": int(execution_policy.max_tensor_elements),
            "memory_limit_bytes": int(execution_policy.memory_limit_bytes),
            "provider": policy_prov,
            "timeout_seconds": float(execution_policy.timeout_seconds),
        },
        "execution_provider": str(execution_provider),
        "execution_version": str(execution_version),
        "input_id": str(input_id),
        "model_id": str(model_id),
        "model_master_fingerprint": str(model_master_fingerprint),
        "preprocessing_contract_hash": str(preprocessing_contract_hash),
        "project_id": str(project_id),
        "schema_version": str(schema_version),
        "transformed_input_hash": str(transformed_input_hash),
    }


def compute_execution_identity_hash(descriptor: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest over canonical execution descriptor."""
    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def build_canonical_raw_output_descriptor(outputs: List[RawOutputTensor]) -> Dict[str, Any]:
    """Construct deterministic raw output descriptor preserving model-declared output ordering."""
    return {
        "outputs": [
            {
                "byte_hash": str(out.c_contiguous_byte_hash),
                "byte_size": int(out.byte_size),
                "dtype": str(out.dtype),
                "element_count": int(out.element_count),
                "index": int(out.index),
                "is_finite": bool(out.is_finite),
                "name": str(out.name),
                "shape": [int(s) for s in out.shape],
            }
            for out in outputs
        ],
        "schema_version": "1.0",
    }


def compute_raw_output_hash(outputs: List[RawOutputTensor]) -> str:
    """Compute deterministic SHA-256 digest over canonical raw output descriptor."""
    descriptor = build_canonical_raw_output_descriptor(outputs)
    canonical_bytes = canonicalize(descriptor)
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_execution_identity(execution: InferenceExecution) -> ExecutionVerificationResult:
    """Pure, side-effect-free recomputation and cryptographic verification of an InferenceExecution."""
    findings: List[InputFinding] = []

    # 1. Validate hash format
    if not HEX64_PATTERN.match(execution.execution_identity_hash):
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_HASH_MISMATCH.value,
                message="Malformed execution_identity_hash. Must be a 64-character lowercase hex SHA-256 digest.",
                details={"execution_identity_hash": execution.execution_identity_hash},
            )
        )
        return ExecutionVerificationResult(
            is_valid=False,
            status=InferenceIntegrityStatus.INVALID,
            computed_execution_hash="",
            expected_execution_hash=execution.execution_identity_hash,
            findings=findings,
            details={"error": "Malformed execution identity hash"},
        )

    # 2. Recompute execution descriptor
    descriptor = build_canonical_execution_descriptor(
        project_id=execution.project_id,
        input_id=execution.input_id,
        binding_hash=execution.binding_hash,
        preprocessing_contract_hash=execution.preprocessing_contract_hash,
        transformed_input_hash=execution.transformed_input_hash,
        model_id=execution.model_id,
        model_master_fingerprint=execution.model_master_fingerprint,
        execution_provider=execution.execution_provider,
        execution_policy=execution.execution_policy,
        execution_version=execution.execution_version,
        schema_version=execution.schema_version,
    )
    computed_exec_hash = compute_execution_identity_hash(descriptor)

    is_exec_match = hmac.compare_digest(computed_exec_hash, execution.execution_identity_hash)
    if not is_exec_match:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_HASH_MISMATCH.value,
                message=f"Execution identity hash mismatch. Computed '{computed_exec_hash}', recorded '{execution.execution_identity_hash}'.",
                details={"computed": computed_exec_hash, "recorded": execution.execution_identity_hash},
            )
        )

    # 3. Verify raw output hash if present
    computed_raw_hash: Optional[str] = None
    if execution.raw_output is not None:
        computed_raw_hash = compute_raw_output_hash(execution.raw_output.outputs)
        if execution.raw_output_hash is not None:
            is_raw_match = hmac.compare_digest(computed_raw_hash, execution.raw_output_hash)
            if not is_raw_match:
                findings.append(
                    InputFinding(
                        code=InferenceFindingCode.EXECUTION_HASH_MISMATCH.value,
                        message=f"Raw output hash mismatch. Computed '{computed_raw_hash}', recorded '{execution.raw_output_hash}'.",
                        details={"computed": computed_raw_hash, "recorded": execution.raw_output_hash},
                    )
                )

    is_valid = is_exec_match and (findings == [])
    status = InferenceIntegrityStatus.VERIFIED if is_valid else InferenceIntegrityStatus.MISMATCHED

    return ExecutionVerificationResult(
        is_valid=is_valid,
        status=status,
        computed_execution_hash=computed_exec_hash,
        expected_execution_hash=execution.execution_identity_hash,
        computed_raw_output_hash=computed_raw_hash,
        expected_raw_output_hash=execution.raw_output_hash,
        findings=findings,
        details={"algorithm": "SHA-256", "canonicalization": "RFC 8785 JCS"},
    )


def execute_inference_transaction(
    input_identity: InputIdentity,
    binding: InputModelBinding,
    model_identity: ModelIdentityEnvelope,
    preprocessing_contract: PreprocessingContract,
    transformed_identity: TransformedInputIdentity,
    preprocessed_array: np.ndarray,
    project_id: str,
    policy: Optional[ExecutionPolicy] = None,
    model_path: Optional[str] = None,
    runner_override: Optional[Callable[[np.ndarray], Union[np.ndarray, List[np.ndarray], Dict[str, np.ndarray]]]] = None,
    cancellation_check: Optional[Callable[[], bool]] = None,
) -> InferenceExecution:
    """Execute model inference within the controlled observation boundary.

    Validates all prerequisite cryptographic identities, verifies project isolation,
    enforces execution policy, captures raw outputs in declared order, and computes
    canonical execution and raw output identities.
    """
    exec_policy = policy or ExecutionPolicy()
    findings: List[InputFinding] = []

    # 1. Project Tenant Isolation Verification
    if (
        project_id != binding.project_id
        or project_id != model_identity.project_id
        or binding.project_id != model_identity.project_id
    ):
        findings.append(
            InputFinding(
                code=InferenceFindingCode.BINDING_PROJECT_MISMATCH.value,
                message=f"Project boundary violation: requested '{project_id}', binding '{binding.project_id}', model '{model_identity.project_id}'.",
                details={"project_id": project_id, "binding_project": binding.project_id, "model_project": model_identity.project_id},
            )
        )
        raise ProjectMismatchError(
            f"Project mismatch in execution: '{project_id}' vs binding '{binding.project_id}'.",
            details={"project_id": project_id, "binding_project": binding.project_id},
        )

    # 2. Model Identity & Master Fingerprint Verification
    if model_identity.status != "verified":
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_MODEL_INVALID.value,
                message=f"Referenced model status is '{model_identity.status}'. Execution requires verified model identity.",
                details={"model_id": model_identity.model_id, "status": model_identity.status},
            )
        )
        raise ModelExecutionIntegrityError(
            f"Cannot execute model with unverified status '{model_identity.status}'.",
            details={"status": model_identity.status},
        )

    if not verify_master_fingerprint_consistency(
        artifact_hash=model_identity.artifact_hash,
        structural_hash=model_identity.structural_hash,
        contract_hash=model_identity.contract_hash,
        master_fingerprint=model_identity.master_fingerprint,
    ):
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_MODEL_INVALID.value,
                message="Model master fingerprint fails cryptographic consistency check.",
                details={"model_id": model_identity.model_id},
            )
        )
        raise ModelExecutionIntegrityError(
            "Model master fingerprint does not match artifact/structural/contract hashes.",
            details={"model_id": model_identity.model_id},
        )


    # 3. Input Model Binding Verification
    binding_res = verify_input_model_binding(binding)
    if not binding_res.is_valid:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_INPUT_MISMATCH.value,
                message="InputModelBinding failed cryptographic verification.",
                details={"binding_hash": binding.binding_hash},
            )
        )
        raise ModelExecutionIntegrityError(
            "Supplied InputModelBinding is invalid.",
            details={"binding_hash": binding.binding_hash},
        )

    if binding.model_master_fingerprint != model_identity.master_fingerprint:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_MODEL_INVALID.value,
                message="Binding model master fingerprint contradicts model identity envelope.",
                details={"binding_fp": binding.model_master_fingerprint, "model_fp": model_identity.master_fingerprint},
            )
        )
        raise ModelExecutionIntegrityError(
            "Binding model fingerprint contradicts model envelope.",
            details={"binding_fp": binding.model_master_fingerprint, "model_fp": model_identity.master_fingerprint},
        )

    # 4. Preprocessing Contract Verification
    preproc_res = verify_preprocessing_contract(preprocessing_contract)
    if not preproc_res.is_valid:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_PREPROCESSING_MISMATCH.value,
                message="PreprocessingContract failed cryptographic verification.",
                details={"contract_hash": preprocessing_contract.contract_hash},
            )
        )
        raise ModelExecutionIntegrityError(
            "Supplied PreprocessingContract is invalid.",
            details={"contract_hash": preprocessing_contract.contract_hash},
        )

    # 5. Transformed Input Identity Verification
    if transformed_identity.contract_hash != preprocessing_contract.contract_hash:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_PREPROCESSING_MISMATCH.value,
                message="Transformed input contract_hash contradicts PreprocessingContract.",
                details={"transformed_contract_hash": transformed_identity.contract_hash, "contract_hash": preprocessing_contract.contract_hash},
            )
        )
        raise ModelExecutionIntegrityError(
            "Transformed input contract_hash contradicts PreprocessingContract.",
            details={"transformed_contract_hash": transformed_identity.contract_hash},
        )

    # Verify byte hash of array matches transformed_identity
    array_bytes = np.ascontiguousarray(preprocessed_array).tobytes()
    computed_array_hash = hashlib.sha256(array_bytes).hexdigest()
    if not hmac.compare_digest(computed_array_hash, transformed_identity.transformed_canonical_hash):
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_INPUT_MISMATCH.value,
                message="Preprocessed input array bytes do not match TransformedInputIdentity hash.",
                details={"computed_array_hash": computed_array_hash, "expected": transformed_identity.transformed_canonical_hash},
            )
        )
        raise ModelExecutionIntegrityError(
            "Preprocessed input array bytes do not match TransformedInputIdentity.",
            details={"computed_array_hash": computed_array_hash},
        )

    # 6. Policy & Provider Enforcement
    provider_str = (
        exec_policy.provider.value
        if isinstance(exec_policy.provider, ExecutionProvider)
        else str(exec_policy.provider)
    )

    if provider_str == ExecutionProvider.CUDA.value:
        if not is_cuda_available():
            findings.append(
                InputFinding(
                    code=InferenceFindingCode.EXECUTION_PROVIDER_UNAVAILABLE.value,
                    message="CUDAExecutionProvider was explicitly requested but is unavailable on this host.",
                    details={"requested_provider": provider_str},
                )
            )
            raise ExecutionProviderUnavailableError(
                "CUDAExecutionProvider is unavailable. AIVARA forbids silent fallback to CPU.",
                details={"requested_provider": provider_str},
            )

    # Batch and Element Bounds
    input_shape = list(preprocessed_array.shape)
    if input_identity.layout in (InputLayout.NHWC, InputLayout.NCHW, InputLayout.BATCH_VECTOR_2D):
        batch_size = input_shape[0]
    elif len(input_shape) == 4:
        batch_size = input_shape[0]
    else:
        batch_size = 1

    if batch_size > exec_policy.max_batch_size:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_RESOURCE_EXCEEDED.value,
                message=f"Batch size {batch_size} exceeds policy maximum of {exec_policy.max_batch_size}.",
                details={"batch_size": batch_size, "max_batch_size": exec_policy.max_batch_size},
            )
        )
        raise ExecutionResourceLimitError(
            f"Batch size {batch_size} exceeds maximum {exec_policy.max_batch_size}.",
            details={"batch_size": batch_size},
        )

    element_count = int(np.prod(input_shape))
    if element_count > exec_policy.max_tensor_elements:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_RESOURCE_EXCEEDED.value,
                message=f"Input elements {element_count} exceeds maximum {exec_policy.max_tensor_elements}.",
                details={"element_count": element_count, "max_elements": exec_policy.max_tensor_elements},
            )
        )
        raise ExecutionResourceLimitError(
            f"Input tensor elements {element_count} exceeds maximum {exec_policy.max_tensor_elements}.",
            details={"element_count": element_count},
        )

    # 7. Check Cooperative Cancellation Prior to Execution
    if cancellation_check and cancellation_check():
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_CANCELLED.value,
                message="Execution was cancelled prior to forward pass.",
                details={"cancelled": True},
            )
        )
        raise ExecutionCancelledError("Inference execution was cancelled.")

    # 8. Deterministic Execution Descriptor & Identity Hash
    descriptor = build_canonical_execution_descriptor(
        project_id=project_id,
        input_id=input_identity.input_id,
        binding_hash=binding.binding_hash,
        preprocessing_contract_hash=preprocessing_contract.contract_hash,
        transformed_input_hash=transformed_identity.transformed_canonical_hash,
        model_id=model_identity.model_id,
        model_master_fingerprint=model_identity.master_fingerprint,
        execution_provider=provider_str,
        execution_policy=exec_policy,
    )
    execution_identity_hash = compute_execution_identity_hash(descriptor)

    # Deterministic Execution ID = SHA256 of execution identity hash + project + binding
    exec_id_desc = {
        "execution_identity_hash": execution_identity_hash,
        "project_id": project_id,
        "schema_version": "1.0",
    }
    execution_id = hashlib.sha256(canonicalize(exec_id_desc)).hexdigest()

    # 9. Model Execution
    start_time = time.perf_counter()
    raw_outputs_list: List[Tuple[str, np.ndarray]] = []

    if runner_override is not None:
        # Use provided test runner
        runner_res = runner_override(preprocessed_array)
        if isinstance(runner_res, np.ndarray):
            raw_outputs_list.append(("output_0", runner_res))
        elif isinstance(runner_res, list):
            for i, arr in enumerate(runner_res):
                raw_outputs_list.append((f"output_{i}", arr))
        elif isinstance(runner_res, dict):
            for k, v in runner_res.items():
                raw_outputs_list.append((str(k), v))
        else:
            raise InferenceExecutionError(f"Unexpected runner output type: {type(runner_res).__name__}")
    elif model_path is not None:
        # ONNX Runtime Execution
        import onnxruntime as ort

        # Sanitize model path
        if not os.path.exists(model_path):
            raise ModelExecutionIntegrityError(f"Model path '{model_path}' does not exist.")

        sess_options = ort.SessionOptions()
        sess_options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        if exec_policy.deterministic:
            sess_options.intra_op_num_threads = 1
            sess_options.inter_op_num_threads = 1

        providers = [provider_str]
        session = ort.InferenceSession(model_path, sess_options=sess_options, providers=providers)

        # Build input feed
        input_name = session.get_inputs()[0].name
        feed = {input_name: preprocessed_array}

        # Run with timeout check
        results = session.run(None, feed)
        output_names = [o.name for o in session.get_outputs()]
        for name, res_arr in zip(output_names, results):
            raw_outputs_list.append((name, res_arr))
    else:
        # Default pass-through mock for unit testing when no model_path or runner is supplied
        raw_outputs_list.append(("output_0", np.copy(preprocessed_array)))

    elapsed = time.perf_counter() - start_time
    if elapsed > exec_policy.timeout_seconds:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_TIMEOUT.value,
                message=f"Execution duration {elapsed:.4f}s exceeded timeout ceiling {exec_policy.timeout_seconds}s.",
                details={"elapsed_seconds": elapsed, "timeout_seconds": exec_policy.timeout_seconds},
            )
        )
        raise ExecutionTimeoutError(
            f"Execution timed out ({elapsed:.4f}s > {exec_policy.timeout_seconds}s).",
            details={"elapsed": elapsed, "timeout": exec_policy.timeout_seconds},
        )

    # 10. Process Raw Output Tensors
    output_tensor_models: List[RawOutputTensor] = []
    total_output_bytes = 0
    all_finite = True

    for idx, (out_name, out_arr) in enumerate(raw_outputs_list):
        if not isinstance(out_arr, np.ndarray):
            out_arr = np.asarray(out_arr)

        out_c_bytes = np.ascontiguousarray(out_arr).tobytes()
        out_byte_hash = hashlib.sha256(out_c_bytes).hexdigest()
        out_elements = int(np.prod(out_arr.shape))
        out_bytes = len(out_c_bytes)
        total_output_bytes += out_bytes

        is_tensor_finite = True
        if np.issubdtype(out_arr.dtype, np.floating):
            is_tensor_finite = bool(np.isfinite(out_arr).all())
            if not is_tensor_finite:
                all_finite = False

        output_tensor_models.append(
            RawOutputTensor(
                name=out_name,
                index=idx,
                dtype=str(out_arr.dtype),
                shape=list(out_arr.shape),
                byte_size=out_bytes,
                element_count=out_elements,
                c_contiguous_byte_hash=out_byte_hash,
                is_finite=is_tensor_finite,
            )
        )

    if total_output_bytes > exec_policy.max_output_bytes:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_RESOURCE_EXCEEDED.value,
                message=f"Total output bytes {total_output_bytes} exceeds limit {exec_policy.max_output_bytes}.",
                details={"output_bytes": total_output_bytes, "max_output_bytes": exec_policy.max_output_bytes},
            )
        )
        raise ExecutionResourceLimitError(
            f"Total output bytes {total_output_bytes} exceeds maximum {exec_policy.max_output_bytes}.",
            details={"output_bytes": total_output_bytes},
        )

    if not all_finite:
        findings.append(
            InputFinding(
                code=InferenceFindingCode.EXECUTION_NONFINITE_OUTPUT.value,
                message="Execution produced raw output tensors containing non-finite values (NaN / Inf).",
                details={"all_finite": False},
            )
        )

    raw_output_hash = compute_raw_output_hash(output_tensor_models)
    numerical_sanity = NumericalSanityStatus.FINITE if all_finite else NumericalSanityStatus.NONFINITE

    raw_execution_output = RawExecutionOutput(
        outputs=output_tensor_models,
        raw_output_hash=raw_output_hash,
        numerical_sanity=numerical_sanity,
    )

    return InferenceExecution(
        schema_version="1.0",
        execution_version="1.0",
        execution_id=execution_id,
        project_id=project_id,
        input_id=input_identity.input_id,
        binding_hash=binding.binding_hash,
        preprocessing_contract_hash=preprocessing_contract.contract_hash,
        transformed_input_hash=transformed_identity.transformed_canonical_hash,
        model_id=model_identity.model_id,
        model_master_fingerprint=model_identity.master_fingerprint,
        execution_provider=provider_str,
        execution_policy=exec_policy,
        lifecycle=ExecutionLifecycle.SUCCEEDED,
        status=InferenceIntegrityStatus.VERIFIED if all_finite else InferenceIntegrityStatus.INVALID,
        execution_identity_hash=execution_identity_hash,
        raw_output=raw_execution_output,
        raw_output_hash=raw_output_hash,
        findings=findings,
        details={"duration_seconds": elapsed, "output_count": len(output_tensor_models)},
    )
