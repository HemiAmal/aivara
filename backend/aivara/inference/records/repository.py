"""SQLAlchemy repository for Phase 10.8 InferenceRecordModel persistence."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from aivara.database.models import InferenceRecordModel
from aivara.inference.composite_binding.models import InferenceBinding
from aivara.inference.records.enums import InferenceRecordStatus, InferenceRecordType
from aivara.inference.records.models import InferenceRecord


class InferenceRecordRepository:
    """Repository handling SQL operations for InferenceRecordModel entities."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(
        self,
        record: InferenceRecord,
        sequence_number: Optional[int] = None,
    ) -> InferenceRecordModel:
        """Persist a new InferenceRecord entity into database storage."""
        model_id = record.binding.model_id if record.binding else "unknown_model"
        input_hash = record.binding.input_canonical_hash if record.binding else "00" * 32
        input_path = record.binding.input_id if record.binding else "input"
        prep_hash = record.binding.preprocessing_contract_hash if record.binding else None
        config_hash = record.binding.execution_identity_hash if record.binding else None
        output_hash = record.binding.raw_output_hash if record.binding else "00" * 32

        if sequence_number is None:
            max_seq = (
                self.db.query(func.max(InferenceRecordModel.sequence_number))
                .filter_by(project_id=record.project_id, model_id=model_id)
                .scalar()
            )
            seq = (max_seq + 1) if max_seq is not None else 0
        else:
            seq = sequence_number

        output_json_payload: Dict[str, Any] = {
            "schema_version": record.schema_version,
            "record_version": record.record_version,
            "record_id": record.record_id,
            "project_id": record.project_id,
            "record_type": record.record_type.value if hasattr(record.record_type, "value") else str(record.record_type),
            "binding_version": record.binding_version,
            "inference_binding_hash": record.inference_binding_hash,
            "record_integrity_hash": record.record_integrity_hash,
            "record_status": record.record_status.value if hasattr(record.record_status, "value") else str(record.record_status),
            "created_at": record.created_at,
            "binding": record.binding.model_dump() if record.binding else None,
            "details": record.details,
        }

        db_record = InferenceRecordModel(
            id=record.record_id,
            project_id=record.project_id,
            model_id=model_id,
            input_hash=input_hash,
            input_path=input_path,
            preprocessing_hash=prep_hash,
            config_hash=config_hash,
            output_json=output_json_payload,
            output_hash=output_hash,
            sequence_number=seq,
            record_hash=record.record_integrity_hash,
            verification_status=record.record_status.value if hasattr(record.record_status, "value") else str(record.record_status),
        )

        self.db.add(db_record)
        self.db.flush()
        return db_record

    def get_by_id(
        self,
        record_id: str,
        project_id: Optional[str] = None,
    ) -> Optional[InferenceRecordModel]:
        """Retrieve an InferenceRecordModel by ID with optional project boundary filter."""
        query = self.db.query(InferenceRecordModel).filter(InferenceRecordModel.id == record_id)
        if project_id is not None:
            query = query.filter(InferenceRecordModel.project_id == project_id)
        return query.first()

    def list_by_project(
        self,
        project_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[InferenceRecordModel]:
        """List InferenceRecordModel entities for a project ordered by sequence."""
        return (
            self.db.query(InferenceRecordModel)
            .filter(InferenceRecordModel.project_id == project_id)
            .order_by(InferenceRecordModel.sequence_number.asc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def to_domain(self, model: InferenceRecordModel) -> InferenceRecord:
        """Transform a database InferenceRecordModel into an immutable domain InferenceRecord."""
        raw_json = model.output_json or {}

        binding_data = raw_json.get("binding")
        binding_obj = InferenceBinding(**binding_data) if binding_data else None

        record_type_raw = raw_json.get("record_type", "STANDARD")
        try:
            rec_type = InferenceRecordType(record_type_raw)
        except ValueError:
            rec_type = InferenceRecordType.STANDARD

        status_raw = model.verification_status or raw_json.get("record_status", "VERIFIED")
        try:
            rec_status = InferenceRecordStatus(status_raw)
        except ValueError:
            rec_status = InferenceRecordStatus.INVALID

        created_at_str = raw_json.get("created_at") or (
            model.created_at.isoformat() if model.created_at else datetime.now(timezone.utc).isoformat()
        )

        return InferenceRecord(
            schema_version=raw_json.get("schema_version", "1.0"),
            record_version=raw_json.get("record_version", "1.0"),
            record_id=model.id,
            project_id=model.project_id,
            record_type=rec_type,
            binding_version=raw_json.get("binding_version", "1.0"),
            inference_binding_hash=raw_json.get("inference_binding_hash", model.output_hash or ""),
            record_integrity_hash=model.record_hash or raw_json.get("record_integrity_hash", ""),
            record_status=rec_status,
            created_at=created_at_str,
            binding=binding_obj,
            findings=[],
            details=raw_json.get("details", {}),
        )
