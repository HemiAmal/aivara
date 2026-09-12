"""Domain service for Phase 10.8 Inference Record Integrity and Persistence."""

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.enums import InferenceFindingCode, InferenceIntegrityStatus
from aivara.inference.exceptions import (
    InferenceRecordBindingInvalidError,
    InferenceRecordNotFoundError,
    InferenceRecordPersistenceError,
    InferenceRecordProjectMismatchError,
    InferenceRecordTamperedError,
)
from aivara.inference.input.models import InputFinding
from aivara.inference.records.engine import (
    create_inference_record,
    verify_inference_record,
)
from aivara.inference.records.enums import InferenceRecordStatus, InferenceRecordType
from aivara.inference.records.models import (
    InferenceRecord,
    InferenceRecordVerificationResult,
)
from aivara.inference.records.repository import InferenceRecordRepository

logger = logging.getLogger("aivara.inference.records")


class InferenceRecordService:
    """Service orchestrating validation, transactional persistence, and read-back verification of Inference Records."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.repository = InferenceRecordRepository(db)

    def persist_inference_record(
        self,
        *,
        project_id: str,
        binding: InferenceBinding,
        record_id: Optional[str] = None,
        record_type: InferenceRecordType = InferenceRecordType.STANDARD,
        record_version: str = "1.0",
        schema_version: str = "1.0",
    ) -> InferenceRecord:
        """Create, persist, and read-back verify an InferenceRecord entity within a transaction."""
        # 1. Construct and validate domain record
        domain_record = create_inference_record(
            project_id=project_id,
            binding=binding,
            record_id=record_id,
            record_type=record_type,
            record_version=record_version,
            schema_version=schema_version,
            raise_on_error=True,
        )

        # 2. Transactional persistence
        try:
            self.repository.create(domain_record)
            self.db.commit()
        except IntegrityError as e:
            self.db.rollback()
            err_msg = f"Database integrity error persisting inference record: {str(e)}"
            logger.error(err_msg)
            raise InferenceRecordPersistenceError(err_msg, details={"record_id": domain_record.record_id}) from e
        except Exception as e:
            self.db.rollback()
            err_msg = f"Unexpected error persisting inference record: {str(e)}"
            logger.error(err_msg)
            raise InferenceRecordPersistenceError(err_msg, details={"record_id": domain_record.record_id}) from e

        # 3. Read-back verification
        persisted_model = self.repository.get_by_id(domain_record.record_id, project_id=project_id)
        if persisted_model is None:
            raise InferenceRecordPersistenceError(
                "Read-back verification failed: record not found immediately after commit.",
                details={"record_id": domain_record.record_id, "project_id": project_id},
            )

        read_back_record = self.repository.to_domain(persisted_model)
        verif_result = verify_inference_record(
            read_back_record,
            binding=binding,
            expected_project_id=project_id,
        )

        if not verif_result.is_valid or verif_result.status != InferenceRecordStatus.VERIFIED:
            raise InferenceRecordPersistenceError(
                f"Read-back verification failed with status '{verif_result.status}'.",
                details={
                    "record_id": domain_record.record_id,
                    "findings": [f.model_dump() for f in verif_result.findings],
                },
            )

        return read_back_record

    def get_and_verify_record(
        self,
        record_id: str,
        project_id: str,
        raise_on_tamper: bool = False,
    ) -> InferenceRecordVerificationResult:
        """Retrieve an InferenceRecord by ID and project, evaluating integrity against canonical descriptor."""
        model = self.repository.get_by_id(record_id, project_id=project_id)
        if model is None:
            return InferenceRecordVerificationResult(
                is_valid=False,
                status=InferenceRecordStatus.INVALID,
                record_id=record_id,
                project_id=project_id,
                stored_integrity_hash="",
                computed_integrity_hash="",
                inference_binding_hash="",
                binding_verification_status=InferenceIntegrityStatus.INVALID,
                findings=[
                    InputFinding(
                        code=InferenceFindingCode.INFERENCE_RECORD_NOT_FOUND.value,
                        message=f"Inference record '{record_id}' not found for project '{project_id}'.",
                    )
                ],
                details={"not_found": True},
            )

        domain_record = self.repository.to_domain(model)
        verif_result = verify_inference_record(
            domain_record,
            binding=domain_record.binding,
            expected_project_id=project_id,
        )

        if raise_on_tamper and verif_result.status == InferenceRecordStatus.TAMPERED:
            raise InferenceRecordTamperedError(
                f"Inference record '{record_id}' failed integrity verification (TAMPERED).",
                details={"findings": [f.model_dump() for f in verif_result.findings]},
            )

        return verif_result
