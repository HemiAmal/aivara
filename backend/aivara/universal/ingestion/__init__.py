"""Phase 12.4 Cross-Subsystem Evidence Ingestion Module.

Authoritative package for ingesting upstream assurance evidence from Phases 5-11
into Universal Evidence Normalization (Phase 12.2) and Graph Architecture (Phase 12.3).
"""

from aivara.universal.ingestion.enums import (
    IngestionErrorType,
    IngestionSchemaVersion,
    IngestionStatus,
)
from aivara.universal.ingestion.exceptions import (
    AncestryConflictIngestionError,
    DomainMismatchIngestionError,
    IngestionResourceLimitError,
    IngestionValidationError,
    ProjectBoundaryIngestionError,
    SourceHashMismatchIngestionError,
    UniversalIngestionError,
)
from aivara.universal.ingestion.handlers import (
    BackdoorIngestionHandler,
    BaseDomainIngestionHandler,
    BehavioralIngestionHandler,
    ContributorIngestionHandler,
    DatasetIngestionHandler,
    DistributionIngestionHandler,
    InferenceIngestionHandler,
    ModelIngestionHandler,
)
from aivara.universal.ingestion.registry import IngestionHandlerRegistry
from aivara.universal.ingestion.schemas import (
    EvidenceIngestionRecord,
    IngestionReport,
    UpstreamEvidenceItem,
)
from aivara.universal.ingestion.service import CrossSubsystemEvidenceIngestionService

__all__ = [
    # Enums
    "IngestionSchemaVersion",
    "IngestionStatus",
    "IngestionErrorType",
    # Exceptions
    "UniversalIngestionError",
    "IngestionValidationError",
    "DomainMismatchIngestionError",
    "ProjectBoundaryIngestionError",
    "SourceHashMismatchIngestionError",
    "AncestryConflictIngestionError",
    "IngestionResourceLimitError",
    # Schemas
    "UpstreamEvidenceItem",
    "EvidenceIngestionRecord",
    "IngestionReport",
    # Handlers
    "BaseDomainIngestionHandler",
    "DatasetIngestionHandler",
    "ContributorIngestionHandler",
    "ModelIngestionHandler",
    "BehavioralIngestionHandler",
    "BackdoorIngestionHandler",
    "InferenceIngestionHandler",
    "DistributionIngestionHandler",
    # Registry
    "IngestionHandlerRegistry",
    # Service
    "CrossSubsystemEvidenceIngestionService",
]
