"""Controlled Model Executor orchestrating safe local inference (Phase 8.2)."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from aivara.behavioral.exceptions import (
    BehavioralError,
    ExecutionCancelledError,
    ExecutionProviderUnavailableError,
    ExecutionTimeoutError,
    InvalidInputTensorError,
    InvalidOutputTensorError,
    ModelExecutionError,
    ModelLoadingError,
    ResourceLimitExceededError,
    SecuritySandboxViolationError,
    UnsupportedExecutionFormatError,
)
from aivara.behavioral.limits import DEFAULT_EXECUTION_LIMITS, ExecutionLimits
from aivara.behavioral.runtime.onnx_runtime import ONNXModelRunner
from aivara.behavioral.runtime.policy import validate_execution_request_policy
from aivara.behavioral.runtime.process import (
    ControlledExecutionEnvironment,
    validate_secure_model_path,
)
from aivara.behavioral.runtime.validation import (
    compute_canonical_output_hash,
    validate_input_tensors,
    validate_output_tensors,
)
from aivara.behavioral.schemas import (
    DeterminismStatus,
    ExecutionProvider,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    ResourceUsage,
)

logger = logging.getLogger(__name__)


class ControlledModelExecutor:
    """Orchestrates controlled local model execution within the safe observation boundary."""

    def __init__(
        self,
        limits: Optional[ExecutionLimits] = None,
        allowed_base_dir: Optional[Path] = None,
    ) -> None:
        self.limits = limits or DEFAULT_EXECUTION_LIMITS
        self.allowed_base_dir = allowed_base_dir

    def execute(
        self,
        request: ExecutionRequest,
        cancellation_check: Optional[Any] = None,
    ) -> ExecutionResult:
        """Execute model forward pass synchronously within the controlled runtime boundary."""
        start_time = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Check cooperative cancellation
        if cancellation_check and cancellation_check():
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.CANCELLED,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="EXECUTION_CANCELLED",
                error_message_safe="Model execution was cancelled before launch.",
                timestamp=now_iso,
            )

        try:
            # 1. Policy & Request Parameter Validation
            validate_execution_request_policy(request, self.limits)

            # 2. Filesystem Path Validation
            model_path = validate_secure_model_path(
                request.model_path,
                allowed_base_dir=self.allowed_base_dir,
            )

            # 3. Enter Controlled Isolated Workspace
            with ControlledExecutionEnvironment(execution_id=request.execution_id) as env:
                # 4. Input Validation
                validated_inputs = validate_input_tensors(request.inputs, self.limits)
                total_input_elements = sum(arr.size for arr in validated_inputs.values())

                # Check cancellation again prior to loading
                if cancellation_check and cancellation_check():
                    raise ExecutionCancelledError("Execution cancelled prior to model loading.")

                # 5. Format Dispatch & Runner Instantiation
                suffix = model_path.suffix.lower()
                if suffix == ".onnx":
                    runner = ONNXModelRunner()
                    runtime_version = "onnxruntime"
                else:
                    raise UnsupportedExecutionFormatError(
                        f"Format with extension '{suffix}' is unsupported for execution in Phase 8.2.",
                        details={"suffix": suffix},
                    )

                # 6. Session Loading
                session = runner.load_session(
                    model_path=model_path,
                    provider=request.execution_provider,
                    limits=self.limits,
                    seed=request.seed,
                )

                # 7. Forward Pass Execution with Timeout
                raw_outputs = runner.run_inference(
                    session=session,
                    inputs=validated_inputs,
                    timeout_seconds=request.timeout_seconds,
                )

                # 8. Output Validation & Finite Value Check
                output_metadata, total_output_elements = validate_output_tensors(
                    raw_outputs,
                    self.limits,
                    require_finite=True,
                )

                # 9. Deterministic Output Hash Computation
                output_hash = compute_canonical_output_hash(raw_outputs)

                duration_ms = (time.perf_counter() - start_time) * 1000.0
                first_input = next(iter(validated_inputs.values()))
                batch_size = first_input.shape[0] if first_input.ndim > 0 else 1

                resource_usage = ResourceUsage(
                    execution_duration_ms=duration_ms,
                    batch_size=batch_size,
                    total_input_elements=total_input_elements,
                    total_output_elements=total_output_elements,
                )

                return ExecutionResult(
                    execution_id=request.execution_id,
                    status=ExecutionStatus.SUCCESS,
                    provider=request.execution_provider.value,
                    device=request.device,
                    runtime_version=runtime_version,
                    precision=request.precision,
                    duration_ms=duration_ms,
                    output_metadata=output_metadata,
                    outputs=raw_outputs,
                    output_hash=output_hash,
                    determinism_status=DeterminismStatus.DETERMINISTIC,
                    resource_usage=resource_usage,
                    timestamp=now_iso,
                )

        except ExecutionTimeoutError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("Execution timed out: %s", err)
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.TIMEOUT,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="EXECUTION_TIMEOUT",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except ExecutionCancelledError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.CANCELLED,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="EXECUTION_CANCELLED",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except ExecutionProviderUnavailableError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.PROVIDER_UNAVAILABLE,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="PROVIDER_UNAVAILABLE",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except ResourceLimitExceededError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.RESOURCE_LIMIT,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="RESOURCE_LIMIT_EXCEEDED",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except InvalidInputTensorError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.INVALID_INPUT,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="INVALID_INPUT",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except InvalidOutputTensorError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.INVALID_OUTPUT,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="INVALID_OUTPUT",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except ModelLoadingError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.MODEL_LOAD_ERROR,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="MODEL_LOAD_ERROR",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except UnsupportedExecutionFormatError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.UNSUPPORTED,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="UNSUPPORTED_FORMAT",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except SecuritySandboxViolationError as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.RESOURCE_LIMIT,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="SECURITY_VIOLATION",
                error_message_safe=str(err),
                timestamp=now_iso,
            )

        except Exception as err:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.exception("Unexpected error during controlled model execution: %s", err)
            return ExecutionResult(
                execution_id=request.execution_id,
                status=ExecutionStatus.EXECUTION_ERROR,
                provider=request.execution_provider.value,
                device=request.device,
                runtime_version="unknown",
                precision=request.precision,
                duration_ms=duration_ms,
                error_code="EXECUTION_ERROR",
                error_message_safe=f"Internal model execution error occurred: {type(err).__name__}",
                timestamp=now_iso,
            )
