"""Canonical 7x7 Inter-Domain Correlation Matrix for Universal Risk Engine (Phase 12.5)."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Sequence
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aivara.universal.enums import SubsystemDomain
from aivara.universal.hashing import compute_canonical_jcs_bytes, compute_sha256_digest
from aivara.universal.correlation.enums import CorrelationSchemaVersion
from aivara.universal.correlation.exceptions import (
    AsymmetricMatrixError,
    CorrelationOutOfRangeError,
    InvalidCorrelationMatrixError,
    InvalidDomainOrderError,
    NonFiniteCorrelationError,
    NonZeroDiagonalError,
)

CANONICAL_DOMAIN_ORDER: List[SubsystemDomain] = [
    SubsystemDomain.DATASET_INTEGRITY,    # 0
    SubsystemDomain.CONTRIBUTOR_RISK,     # 1
    SubsystemDomain.MODEL_INTEGRITY,      # 2
    SubsystemDomain.BEHAVIORAL_ANALYSIS,  # 3
    SubsystemDomain.BACKDOOR_TRIGGER,     # 4
    SubsystemDomain.INFERENCE_INTEGRITY,   # 5
    SubsystemDomain.DISTRIBUTION_SHIFT,   # 6
]

DOMAIN_INDEX_MAP: Dict[SubsystemDomain, int] = {
    domain: idx for idx, domain in enumerate(CANONICAL_DOMAIN_ORDER)
}


class CorrelationMatrix(BaseModel):
    """Immutable, content-addressed 7x7 inter-domain correlation matrix."""
    model_config = ConfigDict(frozen=True)

    schema_version: str = Field(default=CorrelationSchemaVersion.V1_0.value)
    dimension: int = Field(default=7, ge=7, le=7)
    domain_order: List[SubsystemDomain] = Field(default_factory=lambda: list(CANONICAL_DOMAIN_ORDER))
    matrix_values: List[List[float]]
    matrix_hash: str = Field(default="", max_length=64)

    @field_validator("domain_order")
    @classmethod
    def validate_domain_order(cls, v: List[SubsystemDomain]) -> List[SubsystemDomain]:
        if len(v) != 7 or [d.value for d in v] != [d.value for d in CANONICAL_DOMAIN_ORDER]:
            raise InvalidDomainOrderError(
                f"Domain order must match canonical 7 domains exactly: {[d.value for d in CANONICAL_DOMAIN_ORDER]}"
            )
        return v

    @field_validator("matrix_values")
    @classmethod
    def validate_matrix_structure(cls, v: List[List[float]]) -> List[List[float]]:
        if len(v) != 7:
            raise InvalidCorrelationMatrixError(f"Matrix must have exactly 7 rows, got {len(v)}")
        
        for i, row in enumerate(v):
            if len(row) != 7:
                raise InvalidCorrelationMatrixError(f"Row {i} must have exactly 7 columns, got {len(row)}")
            for j, val in enumerate(row):
                if math.isnan(val) or math.isinf(val):
                    raise NonFiniteCorrelationError(f"Cell ({i}, {j}) contains non-finite value {val}")
                if val < 0.0 or val > 1.0:
                    raise CorrelationOutOfRangeError(f"Cell ({i}, {j}) value {val} out of range [0.0, 1.0]")

        # Check zero diagonal
        for i in range(7):
            if abs(v[i][i]) > 1e-9:
                raise NonZeroDiagonalError(f"Diagonal cell ({i}, {i}) must be 0.0, got {v[i][i]}")

        # Check symmetry
        for i in range(7):
            for j in range(i + 1, 7):
                if abs(v[i][j] - v[j][i]) > 1e-9:
                    raise AsymmetricMatrixError(
                        f"Matrix is asymmetric at ({i}, {j})={v[i][j]} vs ({j}, {i})={v[j][i]}"
                    )

        # Round to 6 decimal places for exact reproducibility
        return [[round(float(val), 6) for val in row] for row in v]

    @model_validator(mode="after")
    def compute_matrix_hash(self) -> CorrelationMatrix:
        if not self.matrix_hash:
            canonical_dict = self.to_canonical_dict()
            computed = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
            object.__setattr__(self, "matrix_hash", computed)
        return self

    def get_correlation(self, domain_a: SubsystemDomain, domain_b: SubsystemDomain) -> float:
        """Get correlation coefficient C[i][j] between two domains."""
        idx_a = DOMAIN_INDEX_MAP[domain_a]
        idx_b = DOMAIN_INDEX_MAP[domain_b]
        return float(self.matrix_values[idx_a][idx_b])

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension,
            "domain_order": [d.value for d in self.domain_order],
            "matrix_values": [[float(val) for val in row] for row in self.matrix_values],
            "schema_version": self.schema_version,
        }

    @classmethod
    def create_zero_matrix(cls) -> CorrelationMatrix:
        """Create a 7x7 matrix with all zero correlations (independent domains)."""
        zeros = [[0.0 for _ in range(7)] for _ in range(7)]
        return cls(matrix_values=zeros)

    @classmethod
    def create_default_canonical_matrix(cls) -> CorrelationMatrix:
        """Create the authoritative default Phase 12.1 7x7 correlation matrix."""
        # 0: DATASET_INTEGRITY
        # 1: CONTRIBUTOR_RISK
        # 2: MODEL_INTEGRITY
        # 3: BEHAVIORAL_ANALYSIS
        # 4: BACKDOOR_TRIGGER
        # 5: INFERENCE_INTEGRITY
        # 6: DISTRIBUTION_SHIFT
        mat = [
            # 0      1      2      3      4      5      6
            [0.00,  0.30,  0.25,  0.15,  0.40,  0.10,  0.35],  # 0: DATASET_INTEGRITY
            [0.30,  0.00,  0.20,  0.10,  0.35,  0.05,  0.15],  # 1: CONTRIBUTOR_RISK
            [0.25,  0.20,  0.00,  0.45,  0.40,  0.30,  0.25],  # 2: MODEL_INTEGRITY
            [0.15,  0.10,  0.45,  0.00,  0.35,  0.40,  0.30],  # 3: BEHAVIORAL_ANALYSIS
            [0.40,  0.35,  0.40,  0.35,  0.00,  0.25,  0.20],  # 4: BACKDOOR_TRIGGER
            [0.10,  0.05,  0.30,  0.40,  0.25,  0.00,  0.35],  # 5: INFERENCE_INTEGRITY
            [0.35,  0.15,  0.25,  0.30,  0.20,  0.35,  0.00],  # 6: DISTRIBUTION_SHIFT
        ]
        return cls(matrix_values=mat)
