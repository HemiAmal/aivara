"""Runtime execution package for AIVARA Behavioral Analysis (Phase 8.2)."""

from aivara.behavioral.runtime.base import BaseModelRunner
from aivara.behavioral.runtime.executor import ControlledModelExecutor
from aivara.behavioral.runtime.onnx_runtime import ONNXModelRunner
from aivara.behavioral.runtime.policy import (
    get_available_execution_providers,
    is_cuda_available,
    validate_execution_request_policy,
)
from aivara.behavioral.runtime.process import (
    ControlledExecutionEnvironment,
    is_sensitive_env_var,
    sanitize_environment,
    validate_secure_model_path,
)
from aivara.behavioral.runtime.validation import (
    compute_canonical_output_hash,
    validate_input_tensors,
    validate_output_tensors,
)

__all__ = [
    "BaseModelRunner",
    "ONNXModelRunner",
    "ControlledModelExecutor",
    "ControlledExecutionEnvironment",
    "validate_secure_model_path",
    "sanitize_environment",
    "is_sensitive_env_var",
    "validate_execution_request_policy",
    "get_available_execution_providers",
    "is_cuda_available",
    "validate_input_tensors",
    "validate_output_tensors",
    "compute_canonical_output_hash",
]
