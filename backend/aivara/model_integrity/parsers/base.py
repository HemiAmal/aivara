"""Abstract base class and data containers for format-specific model parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List
from pydantic import BaseModel, ConfigDict, Field

from aivara.model_integrity.limits import DEFAULT_LIMITS, ModelIngestionLimits
from aivara.model_integrity.schemas import (
    InputContractDescriptor,
    ModelFormat,
    OperatorDescriptor,
    OutputContractDescriptor,
    ReasonCode,
    TensorDescriptor,
)


class ParsedModelData(BaseModel):
    """Raw structured data extracted from a format-specific static parser."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format: ModelFormat
    tensors: List[TensorDescriptor] = Field(default_factory=list)
    inputs: List[InputContractDescriptor] = Field(default_factory=list)
    outputs: List[OutputContractDescriptor] = Field(default_factory=list)
    operators: List[OperatorDescriptor] = Field(default_factory=list)
    metadata_props: Dict[str, str] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    reason_codes: List[ReasonCode] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class BaseModelParser(ABC):
    """Abstract interface for safe static model parsers."""

    @abstractmethod
    def parse(
        self,
        artifact_path: Path,
        limits: ModelIngestionLimits = DEFAULT_LIMITS,
    ) -> ParsedModelData:
        """Parse model artifact statically and return extracted metadata.

        Args:
            artifact_path: Validated Path to model artifact.
            limits: Resource limits to enforce.

        Returns:
            ParsedModelData containing extracted descriptors and diagnostics.

        Raises:
            ModelIntegrityError: On format violation, corruption, or resource limit.
        """
        raise NotImplementedError
