"""Universal Evidence Normalization & Multi-Domain Adapters package (Phase 12.2).

Provides:
- Canonical UniversalEvidenceEnvelope schema.
- Domain adapters for all 7 frozen upstream assurance domains.
- Deterministic AdapterRegistry and UniversalEvidenceNormalizer.
- Strict RFC 8785 JCS + SHA-256 cryptographic identity binding.
"""

from aivara.universal.enums import (
    AncestryStatus,
    EnvelopeVersion,
    NormalizationStatus,
    SchemaVersion,
    SubsystemDomain,
)
from aivara.universal.exceptions import (
    AdapterMismatchError,
    AncestryIntegrityError,
    DuplicateAdapterError,
    InvalidEvidenceError,
    PayloadSizeExceededError,
    ProjectMismatchError,
    UniversalEvidenceError,
    UniversalResourceLimitExceededError,
    UnknownDomainError,
)
from aivara.universal.schemas import (
    AncestryPath,
    NormalizationReport,
    UniversalEvidenceEnvelope,
)
from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.adapters.registry import (
    AdapterRegistry,
    get_default_adapter_registry,
)

__all__ = [
    "SubsystemDomain",
    "AncestryStatus",
    "NormalizationStatus",
    "EnvelopeVersion",
    "SchemaVersion",
    "UniversalEvidenceError",
    "ProjectMismatchError",
    "InvalidEvidenceError",
    "UnknownDomainError",
    "DuplicateAdapterError",
    "AdapterMismatchError",
    "AncestryIntegrityError",
    "UniversalResourceLimitExceededError",
    "PayloadSizeExceededError",
    "AncestryPath",
    "UniversalEvidenceEnvelope",
    "NormalizationReport",
    "UniversalEvidenceNormalizer",
    "AdapterRegistry",
    "get_default_adapter_registry",
]
