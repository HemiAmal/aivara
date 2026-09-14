"""Cross-Subsystem Correlation & Dependency Damping Engine (Phase 12.5)."""

from aivara.universal.correlation.engine import CrossDomainCorrelationEngine
from aivara.universal.correlation.enums import (
    CorrelationSchemaVersion,
    CorrelationStatus,
)
from aivara.universal.correlation.exceptions import (
    AsymmetricMatrixError,
    CorrelationOutOfRangeError,
    InvalidCorrelationMatrixError,
    InvalidDomainOrderError,
    NonFiniteCorrelationError,
    NonZeroDiagonalError,
    UniversalCorrelationError,
)
from aivara.universal.correlation.matrix import (
    CANONICAL_DOMAIN_ORDER,
    DOMAIN_INDEX_MAP,
    CorrelationMatrix,
)
from aivara.universal.correlation.schemas import (
    CrossDomainContributionTrace,
    CrossDomainCorrelationAssessment,
    DomainCorrelationSummary,
)

__all__ = [
    "CANONICAL_DOMAIN_ORDER",
    "CorrelationMatrix",
    "CorrelationSchemaVersion",
    "CorrelationStatus",
    "CrossDomainContributionTrace",
    "CrossDomainCorrelationAssessment",
    "CrossDomainCorrelationEngine",
    "DOMAIN_INDEX_MAP",
    "DomainCorrelationSummary",
    "AsymmetricMatrixError",
    "CorrelationOutOfRangeError",
    "InvalidCorrelationMatrixError",
    "InvalidDomainOrderError",
    "NonFiniteCorrelationError",
    "NonZeroDiagonalError",
    "UniversalCorrelationError",
]
