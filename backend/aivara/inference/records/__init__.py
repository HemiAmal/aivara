"""Phase 10.8 Inference Record Integrity and Persistence subsystem."""

from aivara.inference.records.engine import (
    build_canonical_record_descriptor,
    compute_record_integrity_hash,
    create_inference_record,
    validate_record_hash_format,
    verify_inference_record,
)
from aivara.inference.records.enums import (
    InferenceRecordStatus,
    InferenceRecordType,
)
from aivara.inference.records.models import (
    InferenceRecord,
    InferenceRecordCreate,
    InferenceRecordVerificationResult,
)
from aivara.inference.records.repository import (
    InferenceRecordRepository,
)
from aivara.inference.records.service import (
    InferenceRecordService,
)

__all__ = [
    # Enums
    "InferenceRecordStatus",
    "InferenceRecordType",
    # Models
    "InferenceRecord",
    "InferenceRecordVerificationResult",
    "InferenceRecordCreate",
    # Engine Functions
    "build_canonical_record_descriptor",
    "compute_record_integrity_hash",
    "create_inference_record",
    "verify_inference_record",
    "validate_record_hash_format",
    # Repository & Service
    "InferenceRecordRepository",
    "InferenceRecordService",
]
