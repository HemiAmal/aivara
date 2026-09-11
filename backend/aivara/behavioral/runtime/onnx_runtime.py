"""ONNX Runtime Execution Runner for AIVARA Behavioral Analysis (Phase 8.2)."""

from __future__ import annotations

import concurrent.futures
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

from aivara.behavioral.exceptions import (
    ExecutionProviderUnavailableError,
    ExecutionTimeoutError,
    ModelExecutionError,
    ModelLoadingError,
    UnsupportedExecutionFormatError,
)
from aivara.behavioral.limits import ExecutionLimits
from aivara.behavioral.runtime.base import BaseModelRunner
from aivara.behavioral.runtime.policy import is_cuda_available
from aivara.behavioral.schemas import ExecutionProvider

logger = logging.getLogger(__name__)


class ONNXModelRunner(BaseModelRunner):
    """Execution runner for Open Neural Network Exchange (ONNX) format models using ONNX Runtime."""

    def __init__(self) -> None:
        try:
            import onnxruntime as ort
            self._ort = ort
        except ImportError as err:
            raise ModelLoadingError(
                "onnxruntime package is not installed. Safe ONNX execution requires onnxruntime.",
                details={"error": str(err)},
            ) from err

    def validate_artifact(self, model_path: Path, limits: ExecutionLimits) -> None:
        """Validate artifact extension and size before loading."""
        if not model_path.exists():
            raise ModelLoadingError(f"Model file does not exist: {model_path}")

        if model_path.suffix.lower() != ".onnx":
            raise UnsupportedExecutionFormatError(
                f"Expected .onnx artifact extension, received '{model_path.suffix}'.",
                details={"path": str(model_path), "suffix": model_path.suffix},
            )

        file_size = model_path.stat().st_size
        if file_size > limits.max_temporary_storage_bytes:
            raise ModelLoadingError(
                f"Model file size ({file_size} bytes) exceeds maximum limit of {limits.max_temporary_storage_bytes} bytes.",
                details={"file_size": file_size, "limit": limits.max_temporary_storage_bytes},
            )

    def load_session(
        self,
        model_path: Path,
        provider: ExecutionProvider,
        limits: ExecutionLimits,
        seed: Optional[int] = None,
    ) -> Any:
        """Initialize an isolated ONNX Runtime InferenceSession under the specified provider."""
        self.validate_artifact(model_path, limits)

        sess_options = self._ort.SessionOptions()
        sess_options.log_severity_level = 3  # Error/Fatal only
        sess_options.enable_profiling = False
        sess_options.execution_mode = self._ort.ExecutionMode.ORT_SEQUENTIAL
        sess_options.intra_op_num_threads = 4
        sess_options.inter_op_num_threads = 1

        if provider == ExecutionProvider.CUDA:
            if not is_cuda_available():
                raise ExecutionProviderUnavailableError(
                    "CUDAExecutionProvider requested but unavailable in local runtime.",
                    details={"requested_provider": provider.value},
                )
            providers = ["CUDAExecutionProvider"]
        elif provider == ExecutionProvider.CPU:
            providers = ["CPUExecutionProvider"]
        else:
            raise ExecutionProviderUnavailableError(f"Unsupported provider '{provider}'.")

        try:
            session = self._ort.InferenceSession(
                str(model_path),
                sess_options=sess_options,
                providers=providers,
            )
            return session
        except Exception as err:
            raise ModelLoadingError(
                f"Failed to initialize ONNX Runtime session for '{model_path.name}': {err}",
                details={"model_path": str(model_path), "error": str(err)},
            ) from err

    def run_inference(
        self,
        session: Any,
        inputs: Dict[str, np.ndarray],
        timeout_seconds: float,
    ) -> Dict[str, np.ndarray]:
        """Execute inference synchronously with thread pool timeout enforcement."""
        output_names = [out.name for out in session.get_outputs()]

        def _execute() -> List[np.ndarray]:
            return session.run(output_names, inputs)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_execute)
            try:
                raw_outputs = future.result(timeout=timeout_seconds)
            except concurrent.futures.TimeoutError as err:
                raise ExecutionTimeoutError(
                    f"Inference forward pass timed out after {timeout_seconds}s.",
                    details={"timeout_seconds": timeout_seconds},
                ) from err
            except Exception as err:
                raise ModelExecutionError(
                    f"Inference execution failed: {err}",
                    details={"error": str(err)},
                ) from err

        return {name: raw_outputs[i] for i, name in enumerate(output_names)}
