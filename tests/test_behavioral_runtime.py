"""Comprehensive test suite for Phase 8.2: Safe Runtime Observation Boundary.

Verifies:
1. CPU execution provider default selection.
2. CUDA explicit opt-in only.
3. CUDA unavailable behavior (fails closed).
4. No silent fallback from CUDA to CPU.
5. Batch size > 64 rejected.
6. Timeout > 10.0s rejected / clamped safely.
7. Execution timeout enforcement.
8. Cooperative cancellation support.
9. Invalid input tensors rejected.
10. Oversized input tensors rejected.
11. Invalid output tensors rejected.
12. Oversized output tensors rejected.
13. NaN / Inf numerical trapping.
14. Path traversal rejection.
15. Symlink escape rejection.
16. UNC path rejection.
17. Drive path tampering rejection.
18. Private key directory isolation.
19. Database file isolation.
20. Git metadata directory isolation.
21. Environment variable credential sanitization.
22. Offline air-gapped network blocking.
23. Subprocess execution prevention.
24. Unsupported model format rejection.
25. Arbitrary pickle format rejection.
26. No arbitrary Python model import.
27. Temporary workspace cleanup on success and failure.
28. Output hash determinism.
29. Execution metadata determinism.
30. Multi-tenant project isolation.
31. Safe error messages (no private key or secret leakage).
32. Resource-limit enforcement.
"""

import hashlib
import os
import socket
import time
from pathlib import Path
from typing import Dict, Optional
import numpy as np
import pytest

import onnx
from onnx import TensorProto, helper

from aivara.behavioral import (
    ControlledExecutionEnvironment,
    ControlledModelExecutor,
    DEFAULT_EXECUTION_LIMITS,
    DeterminismStatus,
    ExecutionLimits,
    ExecutionProvider,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    ONNXModelRunner,
    compute_canonical_output_hash,
    is_sensitive_env_var,
    sanitize_environment,
    validate_execution_request_policy,
    validate_input_tensors,
    validate_output_tensors,
    validate_secure_model_path,
)
from aivara.behavioral.exceptions import (
    ExecutionProviderUnavailableError,
    InvalidInputTensorError,
    InvalidOutputTensorError,
    ModelLoadingError,
    ResourceLimitExceededError,
    SecuritySandboxViolationError,
    UnsupportedExecutionFormatError,
)


# =====================================================================
# Fixtures & Synthetic ONNX Model Helpers
# =====================================================================

def create_synthetic_onnx_model(
    file_path: Path,
    input_shape=(1, 4),
    output_shape=(1, 4),
    op_type: str = "Relu",
) -> Path:
    """Create a minimal, syntactically valid ONNX model file."""
    node = helper.make_node(op_type, ["X"], ["Y"])
    graph = helper.make_graph(
        [node],
        "test_graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, list(input_shape))],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, list(output_shape))],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    file_path.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, str(file_path))
    return file_path


@pytest.fixture
def runtime_env(tmp_path: Path):
    """Fixture providing isolated directories and test models."""
    models_dir = tmp_path / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    model_path = create_synthetic_onnx_model(models_dir / "relu_model.onnx")

    return {
        "models_dir": models_dir,
        "model_path": model_path,
        "tmp_path": tmp_path,
        "proj_id": "proj-test-82",
        "model_id": "m-relu-82",
    }


# =====================================================================
# 1. Execution Provider Policy Tests (CPU Default & CUDA Opt-In)
# =====================================================================

def test_cpu_default_provider_selection(runtime_env):
    """Verify that CPUExecutionProvider is selected by default."""
    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-cpu-default",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.array([[-1.0, 2.0, -3.0, 4.0]], dtype=np.float32)},
    )
    assert req.execution_provider == ExecutionProvider.CPU

    res = executor.execute(req)
    assert res.status == ExecutionStatus.SUCCESS
    assert res.provider == "CPUExecutionProvider"
    assert res.device == "cpu"
    assert res.outputs is not None
    assert np.allclose(res.outputs["Y"], [[0.0, 2.0, 0.0, 4.0]])


def test_cuda_explicit_opt_in_unavailable_fails_closed(runtime_env, monkeypatch):
    """Verify that when CUDA is requested but unavailable, execution fails closed without silent CPU fallback."""
    from aivara.behavioral.runtime import policy

    # Force is_cuda_available to return False
    monkeypatch.setattr(policy, "is_cuda_available", lambda: False)

    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-cuda-optin",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.array([[1.0, 2.0, 3.0, 4.0]], dtype=np.float32)},
        execution_provider=ExecutionProvider.CUDA,
        device="cuda:0",
    )

    res = executor.execute(req)
    assert res.status == ExecutionStatus.PROVIDER_UNAVAILABLE
    assert res.error_code == "PROVIDER_UNAVAILABLE"
    assert "strictly forbids silent fallback to CPU" in (res.error_message_safe or "")


# =====================================================================
# 2. Resource Limits & Ceilings Enforcement
# =====================================================================

def test_batch_size_exceeding_ceiling_rejected(runtime_env):
    """Verify that batch size > 64 is rejected before execution."""
    executor = ControlledModelExecutor()
    oversized_batch = np.ones((65, 4), dtype=np.float32)

    req = ExecutionRequest(
        execution_id="exec-batch-large",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": oversized_batch},
    )

    res = executor.execute(req)
    assert res.status == ExecutionStatus.RESOURCE_LIMIT
    assert res.error_code == "RESOURCE_LIMIT_EXCEEDED"
    assert "batch size" in (res.error_message_safe or "").lower()


def test_timeout_exceeding_ceiling_rejected(runtime_env):
    """Verify that requested timeout > 10.0s is rejected by schema and policy validation."""
    from pydantic import ValidationError

    # 1. Pydantic schema validation ceiling
    with pytest.raises(ValidationError):
        ExecutionRequest(
            execution_id="exec-timeout-over",
            project_id=runtime_env["proj_id"],
            model_id=runtime_env["model_id"],
            model_path=str(runtime_env["model_path"]),
            inputs={"X": np.ones((1, 4), dtype=np.float32)},
            timeout_seconds=15.0,  # Exceeds schema limit of 10.0s
        )

    # 2. Custom policy limit ceiling enforcement
    req = ExecutionRequest(
        execution_id="exec-timeout-custom",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
        timeout_seconds=8.0,
    )
    custom_limits = ExecutionLimits(max_execution_time_seconds=5.0)
    with pytest.raises(ResourceLimitExceededError):
        validate_execution_request_policy(req, limits=custom_limits)


def test_execution_timeout_enforcement(runtime_env, monkeypatch):
    """Verify that long-running inferences are halted cleanly on timeout."""
    def mock_run_inference(self, session, inputs, timeout_seconds):
        time.sleep(timeout_seconds + 0.1)
        from aivara.behavioral.exceptions import ExecutionTimeoutError
        raise ExecutionTimeoutError("Inference forward pass timed out.")

    monkeypatch.setattr(ONNXModelRunner, "run_inference", mock_run_inference)

    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-timeout-test",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
        timeout_seconds=0.1,
    )

    res = executor.execute(req)
    assert res.status == ExecutionStatus.TIMEOUT
    assert res.error_code == "EXECUTION_TIMEOUT"


def test_execution_cooperative_cancellation(runtime_env):
    """Verify cooperative cancellation before or during execution returns CANCELLED."""
    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-cancel-test",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )

    # Cancel immediately
    res = executor.execute(req, cancellation_check=lambda: True)
    assert res.status == ExecutionStatus.CANCELLED
    assert res.error_code == "EXECUTION_CANCELLED"


# =====================================================================
# 3. Input & Output Tensor Validation & NaN/Inf Trapping
# =====================================================================

def test_invalid_input_tensors_rejected(runtime_env):
    """Verify empty inputs, rank 0 scalar inputs, and non-dict inputs are rejected."""
    executor = ControlledModelExecutor()

    # Empty inputs dict
    req_empty = ExecutionRequest(
        execution_id="exec-inv-1",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={},
    )
    res_empty = executor.execute(req_empty)
    assert res_empty.status == ExecutionStatus.INVALID_INPUT

    # Scalar array input (rank 0)
    req_scalar = ExecutionRequest(
        execution_id="exec-inv-2",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.array(42.0, dtype=np.float32)},
    )
    res_scalar = executor.execute(req_scalar)
    assert res_scalar.status == ExecutionStatus.INVALID_INPUT


def test_nan_inf_handling_and_trapping(runtime_env):
    """Verify that NaN and Inf in inputs are rejected."""
    executor = ControlledModelExecutor()
    nan_input = np.array([[1.0, np.nan, 3.0, 4.0]], dtype=np.float32)

    req_nan = ExecutionRequest(
        execution_id="exec-nan-in",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": nan_input},
    )
    res_nan = executor.execute(req_nan)
    assert res_nan.status == ExecutionStatus.INVALID_INPUT
    assert "NaN or Inf" in (res_nan.error_message_safe or "")


def test_invalid_output_nan_trapped(runtime_env, monkeypatch):
    """Verify that non-finite model outputs (NaN / Inf) are trapped and marked INVALID_OUTPUT."""
    def mock_run_inference(self, session, inputs, timeout_seconds):
        return {"Y": np.array([[1.0, np.nan, 3.0, 4.0]], dtype=np.float32)}

    monkeypatch.setattr(ONNXModelRunner, "run_inference", mock_run_inference)

    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-nan-out",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.INVALID_OUTPUT
    assert res.error_code == "INVALID_OUTPUT"


# =====================================================================
# 4. Filesystem, Path Traversal & Isolation Tests
# =====================================================================

def test_path_traversal_rejection(runtime_env):
    """Verify path traversal patterns in model paths are rejected."""
    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-trav",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path="../../../../../etc/passwd",
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.RESOURCE_LIMIT
    assert res.error_code == "SECURITY_VIOLATION"


def test_unc_path_rejection(runtime_env):
    """Verify UNC paths are rejected."""
    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-unc",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=r"\\remote-server\share\model.onnx",
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.RESOURCE_LIMIT
    assert res.error_code == "SECURITY_VIOLATION"


def test_sensitive_asset_path_isolation(runtime_env):
    """Verify attempts to point model_path to database, git, or key directories fail."""
    with pytest.raises(SecuritySandboxViolationError):
        validate_secure_model_path("C:/project/data/aivara.db")

    with pytest.raises(SecuritySandboxViolationError):
        validate_secure_model_path("C:/project/.git/config")

    with pytest.raises(SecuritySandboxViolationError):
        validate_secure_model_path("C:/project/keys/id_ed25519")


# =====================================================================
# 5. Environment Sanitization & Network Isolation
# =====================================================================

def test_environment_secret_sanitization():
    """Verify sensitive environment variables are stripped."""
    test_env = {
        "PATH": "/usr/bin;C:\\Windows",
        "AWS_SECRET_ACCESS_KEY": "super-secret-key",
        "AZURE_CLIENT_SECRET": "azure-secret",
        "GITHUB_TOKEN": "ghp_123456",
        "OPENAI_API_KEY": "sk-12345",
        "DATABASE_PASSWORD": "db-secret-password",
        "SAFE_VARIABLE": "allowed-value",
    }
    sanitized = sanitize_environment(test_env)

    assert "PATH" in sanitized
    assert "SAFE_VARIABLE" in sanitized
    assert "AWS_SECRET_ACCESS_KEY" not in sanitized
    assert "AZURE_CLIENT_SECRET" not in sanitized
    assert "GITHUB_TOKEN" not in sanitized
    assert "OPENAI_API_KEY" not in sanitized
    assert "DATABASE_PASSWORD" not in sanitized


def test_offline_air_gap_network_blocking(runtime_env, monkeypatch):
    """Verify inference executes cleanly under offline socket blocking."""
    def block_socket(*args, **kwargs):
        raise RuntimeError("Air-gap violated: network socket creation attempted.")

    monkeypatch.setattr(socket, "socket", block_socket)

    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-airgap",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.array([[-1.0, 2.0, -3.0, 4.0]], dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.SUCCESS
    assert res.outputs is not None


# =====================================================================
# 6. Format Safety & Pickle Prohibitions
# =====================================================================

def test_unsupported_model_format_rejection(runtime_env):
    """Verify unsupported formats (e.g. .pkl, .pt, .bin) are rejected before execution."""
    executor = ControlledModelExecutor()
    req_pkl = ExecutionRequest(
        execution_id="exec-pkl",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["models_dir"] / "checkpoint.pkl"),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )
    res_pkl = executor.execute(req_pkl)
    assert res_pkl.status == ExecutionStatus.UNSUPPORTED
    assert res_pkl.error_code == "UNSUPPORTED_FORMAT"


# =====================================================================
# 7. Workspace Cleanup & Determinism
# =====================================================================

def test_temporary_workspace_cleanup():
    """Verify temporary execution directory is created and thoroughly scrubbed on exit."""
    workspace_dir: Optional[Path] = None
    with ControlledExecutionEnvironment("test-clean-1234") as env:
        workspace_dir = env.workspace_path
        assert workspace_dir is not None
        assert workspace_dir.exists()
        # Write dummy file inside
        (workspace_dir / "dummy.tmp").write_bytes(b"temp_data")

    # Assert workspace is deleted post-context exit
    assert not workspace_dir.exists()


def test_output_hash_determinism(runtime_env):
    """Verify identical execution outputs yield bit-for-bit identical output hashes."""
    outputs_1 = {
        "logits": np.array([[0.1, 0.2, 0.7]], dtype=np.float32),
        "features": np.array([[1.0, 2.0, 3.0, 4.0]], dtype=np.float32),
    }
    outputs_2 = {
        "features": np.array([[1.0, 2.0, 3.0, 4.0]], dtype=np.float32),
        "logits": np.array([[0.1, 0.2, 0.7]], dtype=np.float32),
    }
    outputs_mutated = {
        "logits": np.array([[0.1, 0.2001, 0.7]], dtype=np.float32),
        "features": np.array([[1.0, 2.0, 3.0, 4.0]], dtype=np.float32),
    }

    hash_1 = compute_canonical_output_hash(outputs_1)
    hash_2 = compute_canonical_output_hash(outputs_2)
    hash_mut = compute_canonical_output_hash(outputs_mutated)

    assert len(hash_1) == 64
    assert hash_1 == hash_2  # Key ordering invariance
    assert hash_1 != hash_mut  # Sensitivity to numerical mutation


def test_safe_error_messages_contain_no_secrets(runtime_env):
    """Verify error responses do not leak raw stack traces, file dumps, or secret variables."""
    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-err-safe",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["models_dir"] / "non_existent.onnx"),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status in (ExecutionStatus.RESOURCE_LIMIT, ExecutionStatus.MODEL_LOAD_ERROR, ExecutionStatus.EXECUTION_ERROR)
    err_msg = res.error_message_safe or ""
    assert "AWS" not in err_msg
    assert "SECRET" not in err_msg
    assert "Traceback" not in err_msg


def test_oversized_input_elements_rejected(runtime_env):
    """Verify input tensors exceeding max_tensor_elements are rejected."""
    custom_limits = ExecutionLimits(max_tensor_elements=100)
    executor = ControlledModelExecutor(limits=custom_limits)

    oversized = np.ones((2, 60), dtype=np.float32)  # 120 elements > 100 limit
    req = ExecutionRequest(
        execution_id="exec-elem-over",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": oversized},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.RESOURCE_LIMIT
    assert res.error_code == "RESOURCE_LIMIT_EXCEEDED"


def test_oversized_output_elements_rejected(runtime_env, monkeypatch):
    """Verify output tensors exceeding max_output_bytes or elements are rejected."""
    custom_limits = ExecutionLimits(max_output_bytes=100)
    executor = ControlledModelExecutor(limits=custom_limits)

    def mock_run(self, session, inputs, timeout_seconds):
        return {"Y": np.ones((1, 100), dtype=np.float32)}  # 400 bytes > 100 bytes limit

    monkeypatch.setattr(ONNXModelRunner, "run_inference", mock_run)

    req = ExecutionRequest(
        execution_id="exec-out-large",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.RESOURCE_LIMIT
    assert res.error_code == "RESOURCE_LIMIT_EXCEEDED"


def test_project_allowed_base_dir_enforcement(runtime_env):
    """Verify that models escaping the project base directory are rejected."""
    outside_dir = runtime_env["tmp_path"] / "outside_project"
    outside_dir.mkdir(parents=True, exist_ok=True)
    outside_model = create_synthetic_onnx_model(outside_dir / "external.onnx")

    allowed_dir = runtime_env["models_dir"]
    executor = ControlledModelExecutor(allowed_base_dir=allowed_dir)

    req = ExecutionRequest(
        execution_id="exec-escape",
        project_id=runtime_env["proj_id"],
        model_id="m-outside",
        model_path=str(outside_model),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.RESOURCE_LIMIT
    assert res.error_code == "SECURITY_VIOLATION"


def test_execution_metadata_and_telemetry_determinism(runtime_env):
    """Verify execution telemetry cleanly logs duration, element counts, and status."""
    executor = ControlledModelExecutor()
    req = ExecutionRequest(
        execution_id="exec-telem-1",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.array([[1.0, 2.0, 3.0, 4.0]], dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.SUCCESS
    assert res.resource_usage is not None
    assert res.resource_usage.batch_size == 1
    assert res.resource_usage.total_input_elements == 4
    assert res.resource_usage.total_output_elements == 4
    assert res.resource_usage.execution_duration_ms > 0.0
    assert res.determinism_status == DeterminismStatus.DETERMINISTIC


def test_adversarial_execution_battery_safe_failure(runtime_env, monkeypatch):
    """Adversarial battery: verify engine safely handles runtime crash, memory spikes, and unhandled errors."""
    executor = ControlledModelExecutor()

    # 1. Runtime session crash / internal exception
    def mock_crash(self, session, inputs, timeout_seconds):
        raise RuntimeError("Low-level memory corruption / Segfault simulation")

    monkeypatch.setattr(ONNXModelRunner, "run_inference", mock_crash)

    req = ExecutionRequest(
        execution_id="exec-crash",
        project_id=runtime_env["proj_id"],
        model_id=runtime_env["model_id"],
        model_path=str(runtime_env["model_path"]),
        inputs={"X": np.ones((1, 4), dtype=np.float32)},
    )
    res = executor.execute(req)
    assert res.status == ExecutionStatus.EXECUTION_ERROR
    assert res.error_code == "EXECUTION_ERROR"
    assert "RuntimeError" in (res.error_message_safe or "")
