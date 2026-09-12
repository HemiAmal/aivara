"""Immutable Result and Metadata Models for Trigger Transformation Engine (Phase 9.3)."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from aivara.backdoor.candidates.enums import TriggerFamilyEnum
from aivara.backdoor.candidates.models import PlacementSpec
from aivara.backdoor.transformation.enums import InputLayoutEnum


class TransformationMetadata(BaseModel):
    """Structured deterministic metadata describing the transformation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    transformation_id: str = Field(..., description="Deterministic transformation hash")
    transformation_version: str = Field("1.0.0", description="Transformation algorithm version")
    candidate_hash: str = Field(..., description="Trigger candidate identity hash")
    candidate_family: TriggerFamilyEnum = Field(..., description="Trigger candidate family")
    source_input_hash: str = Field(..., description="SHA-256 hash of source input array")
    transformed_input_hash: str = Field(..., description="SHA-256 hash of transformed output array")
    input_shape: Tuple[int, ...] = Field(..., description="Shape of input array")
    output_shape: Tuple[int, ...] = Field(..., description="Shape of output array")
    input_dtype: str = Field(..., description="Dtype string of input array")
    output_dtype: str = Field(..., description="Dtype string of output array")
    input_layout: InputLayoutEnum = Field(..., description="Explicit input tensor layout (ADR-087)")
    output_layout: InputLayoutEnum = Field(..., description="Explicit output tensor layout (ADR-087)")
    placement: PlacementSpec = Field(..., description="Effective placement specification")
    clipping_occurred: bool = Field(False, description="Whether output values were clipped to domain bounds")
    random_seed: Optional[int] = Field(None, description="Random seed used if stochastic transformation")


class TransformationResult:
    """Immutable result container representing a transformed array and its cryptographic provenance."""

    def __init__(
        self,
        transformation_id: str,
        transformation_version: str,
        source_input_hash: str,
        transformed_input_hash: str,
        candidate_hash: str,
        candidate_family: TriggerFamilyEnum,
        input_shape: Tuple[int, ...],
        output_shape: Tuple[int, ...],
        input_dtype: str,
        output_dtype: str,
        input_layout: InputLayoutEnum,
        output_layout: InputLayoutEnum,
        placement: PlacementSpec,
        clipping_occurred: bool,
        transformed_array: np.ndarray,
        transformation_metadata: Dict[str, Any],
        schema_version: str = "1.0.0",
    ) -> None:
        self._schema_version = schema_version
        self._transformation_id = transformation_id
        self._transformation_version = transformation_version
        self._source_input_hash = source_input_hash
        self._transformed_input_hash = transformed_input_hash
        self._candidate_hash = candidate_hash
        self._candidate_family = candidate_family
        self._input_shape = input_shape
        self._output_shape = output_shape
        self._input_dtype = input_dtype
        self._output_dtype = output_dtype
        self._input_layout = input_layout
        self._output_layout = output_layout
        self._placement = placement
        self._clipping_occurred = clipping_occurred
        # Make transformed array immutable (read-only) and contiguous
        c_arr = np.ascontiguousarray(transformed_array)
        c_arr.flags.writeable = False
        self._transformed_array = c_arr
        self._transformation_metadata = dict(transformation_metadata)

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def transformation_id(self) -> str:
        return self._transformation_id

    @property
    def transformation_version(self) -> str:
        return self._transformation_version

    @property
    def source_input_hash(self) -> str:
        return self._source_input_hash

    @property
    def transformed_input_hash(self) -> str:
        return self._transformed_input_hash

    @property
    def candidate_hash(self) -> str:
        return self._candidate_hash

    @property
    def candidate_family(self) -> TriggerFamilyEnum:
        return self._candidate_family

    @property
    def input_shape(self) -> Tuple[int, ...]:
        return self._input_shape

    @property
    def output_shape(self) -> Tuple[int, ...]:
        return self._output_shape

    @property
    def input_dtype(self) -> str:
        return self._input_dtype

    @property
    def output_dtype(self) -> str:
        return self._output_dtype

    @property
    def input_layout(self) -> InputLayoutEnum:
        return self._input_layout

    @property
    def output_layout(self) -> InputLayoutEnum:
        return self._output_layout

    @property
    def placement(self) -> PlacementSpec:
        return self._placement

    @property
    def clipping_occurred(self) -> bool:
        return self._clipping_occurred

    @property
    def transformed_array(self) -> np.ndarray:
        return self._transformed_array

    @property
    def array(self) -> np.ndarray:
        """Convenience alias for transformed_array."""
        return self._transformed_array

    @property
    def transformation_metadata(self) -> Dict[str, Any]:
        return dict(self._transformation_metadata)

    def to_metadata_model(self) -> TransformationMetadata:
        """Convert result summary into typed Pydantic TransformationMetadata."""
        return TransformationMetadata(
            transformation_id=self._transformation_id,
            transformation_version=self._transformation_version,
            candidate_hash=self._candidate_hash,
            candidate_family=self._candidate_family,
            source_input_hash=self._source_input_hash,
            transformed_input_hash=self._transformed_input_hash,
            input_shape=self._input_shape,
            output_shape=self._output_shape,
            input_dtype=self._input_dtype,
            output_dtype=self._output_dtype,
            input_layout=self._input_layout,
            output_layout=self._output_layout,
            placement=self._placement,
            clipping_occurred=self._clipping_occurred,
            random_seed=self._transformation_metadata.get("random_seed"),
        )
