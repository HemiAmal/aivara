"""Abstract base classes for runtime model runners in AIVARA Behavioral Analysis."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional
import numpy as np

from aivara.behavioral.limits import ExecutionLimits
from aivara.behavioral.schemas import ExecutionProvider


class BaseModelRunner(ABC):
    """Abstract interface defining the execution contract for a model format runtime."""

    @abstractmethod
    def validate_artifact(self, model_path: Path, limits: ExecutionLimits) -> None:
        """Validate artifact existence, format constraints, and safety bounds prior to loading."""
        pass

    @abstractmethod
    def load_session(
        self,
        model_path: Path,
        provider: ExecutionProvider,
        limits: ExecutionLimits,
        seed: Optional[int] = None,
    ) -> Any:
        """Load the model into the execution engine under the specified provider."""
        pass

    @abstractmethod
    def run_inference(
        self,
        session: Any,
        inputs: Dict[str, np.ndarray],
        timeout_seconds: float,
    ) -> Dict[str, np.ndarray]:
        """Execute model forward pass synchronously within the allocated timeout."""
        pass
