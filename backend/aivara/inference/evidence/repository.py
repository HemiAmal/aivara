"""Repository adapter for querying existing Phase 4/5/10 persistent records.

Zero database schema modifications: strictly utilizes existing EvidenceModel,
FindingModel, ProvenanceRecordModel, and InferenceRecordModel tables.
"""

from __future__ import annotations

from typing import List, Optional
from sqlalchemy.orm import Session

from aivara.database.models import (
    EvidenceModel,
    FindingModel,
    InferenceRecordModel,
    ProvenanceRecordModel,
)


class InferenceEvidenceRepository:
    """Read/Query adapter for persistent inference assurance artifacts."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_inference_record(self, record_id: str, project_id: Optional[str] = None) -> Optional[InferenceRecordModel]:
        """Fetch persisted InferenceRecordModel row."""
        query = self.db.query(InferenceRecordModel).filter(InferenceRecordModel.id == record_id)
        if project_id is not None:
            query = query.filter(InferenceRecordModel.project_id == project_id)
        return query.first()

    def get_provenance_record(self, provenance_id: str, project_id: Optional[str] = None) -> Optional[ProvenanceRecordModel]:
        """Fetch persisted ProvenanceRecordModel row."""
        query = self.db.query(ProvenanceRecordModel).filter(ProvenanceRecordModel.id == provenance_id)
        if project_id is not None:
            query = query.filter(ProvenanceRecordModel.project_id == project_id)
        return query.first()

    def get_evidence_by_hash(self, evidence_hash: str) -> Optional[EvidenceModel]:
        """Fetch persisted EvidenceModel by canonical evidence_hash."""
        return self.db.query(EvidenceModel).filter(EvidenceModel.evidence_hash == evidence_hash).first()

    def get_findings_for_asset(self, asset_id: str, project_id: Optional[str] = None) -> List[FindingModel]:
        """Fetch all FindingModel rows for an asset."""
        query = self.db.query(FindingModel).filter(FindingModel.affected_asset_id == asset_id)
        if project_id is not None:
            query = query.filter(FindingModel.project_id == project_id)
        return query.all()
