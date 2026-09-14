"""SQLAlchemy ORM models for Universal Evidence Graph & Finding-Evidence Junction (Phase 12.3)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Index, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.types import JSON

UniversalBase = declarative_base()


def utcnow() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class FindingEvidenceModel(UniversalBase):
    """Additive, non-breaking N:M persistent junction linking findings and evidence items."""

    __tablename__ = "finding_evidence"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), nullable=False)
    finding_id = Column(String(36), nullable=False)
    evidence_id = Column(String(36), nullable=False)
    relationship_type = Column(String(50), default="SUPPORTS", nullable=False)
    relevance_weight = Column(Float, default=1.0, nullable=False)
    binding_hash = Column(String(64), nullable=True)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_finding_evidence_project_id", "project_id"),
        Index("ix_finding_evidence_finding_id", "finding_id"),
        Index("ix_finding_evidence_evidence_id", "evidence_id"),
        Index("ix_finding_evidence_binding_unique", "finding_id", "evidence_id", "relationship_type", unique=True),
    )
