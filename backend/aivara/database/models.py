"""SQLAlchemy ORM models for AIVARA domain entities.

All 14 foundational entities are defined here, following the ER diagram
from docs/ARCHITECTURE.md and the schema amendments in ADR-028 and ADR-029.

Relationships use RESTRICT on delete for audit/provenance data to prevent
accidental deletion of assurance evidence chains. Non-critical children
(e.g., dataset versions when a dataset is deleted) use CASCADE where
architectural documentation allows it.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.types import JSON
from sqlalchemy.orm import relationship

from aivara.database.connection import Base


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Project
# ---------------------------------------------------------------------------

class ProjectModel(Base):
    """An AIVARA assurance assessment project."""

    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=new_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="active", nullable=False)
    genesis_nonce = Column(String(64), nullable=True)
    config_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    contributors = relationship(
        "ContributorModel", back_populates="project",
        cascade="all, delete-orphan", passive_deletes=True, lazy="dynamic"
    )
    datasets = relationship(
        "DatasetModel", back_populates="project",
        cascade="all, delete-orphan", passive_deletes=True, lazy="dynamic"
    )
    models = relationship(
        "AIModelModel", back_populates="project",
        cascade="all, delete-orphan", passive_deletes=True, lazy="dynamic"
    )
    inference_records = relationship(
        "InferenceRecordModel", back_populates="project", lazy="dynamic"
    )
    findings = relationship(
        "FindingModel", back_populates="project", lazy="dynamic"
    )
    risk_assessments = relationship(
        "RiskAssessmentModel", back_populates="project", lazy="dynamic"
    )
    audit_events = relationship(
        "AuditEventModel", back_populates="project", lazy="dynamic"
    )
    provenance_records = relationship(
        "ProvenanceRecordModel", back_populates="project", lazy="dynamic"
    )
    reports = relationship(
        "ReportModel", back_populates="project", lazy="dynamic"
    )


# ---------------------------------------------------------------------------
# Contributor (ADR-029)
# ---------------------------------------------------------------------------

class ContributorModel(Base):
    """A dataset or model source / contributing entity."""

    __tablename__ = "contributors"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    external_id = Column(String(255), nullable=False)
    name = Column(String(255), nullable=True)
    source = Column(String(255), nullable=True)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="contributors")
    sample_contributions = relationship(
        "SampleContributorModel", back_populates="contributor", lazy="dynamic"
    )

    __table_args__ = (
        Index("ix_contributors_project_id", "project_id"),
        Index("ix_contributors_external_id", "project_id", "external_id", unique=True),
    )


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class DatasetModel(Base):
    """An imported dataset within a project."""

    __tablename__ = "datasets"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    format = Column(String(50), nullable=False)  # coco, yolo, imagefolder, generic
    source = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="imported", nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="datasets")
    versions = relationship(
        "DatasetVersionModel", back_populates="dataset",
        cascade="all, delete-orphan", passive_deletes=True, lazy="dynamic"
    )

    __table_args__ = (
        Index("ix_datasets_project_id", "project_id"),
    )


# ---------------------------------------------------------------------------
# Dataset Version
# ---------------------------------------------------------------------------

class DatasetVersionModel(Base):
    """A specific version of a dataset, enabling independent auditing."""

    __tablename__ = "dataset_versions"

    id = Column(String(36), primary_key=True, default=new_uuid)
    dataset_id = Column(String(36), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False)
    version_label = Column(String(100), nullable=False)
    dataset_hash = Column(String(64), nullable=True)
    sample_count = Column(Integer, default=0, nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    dataset = relationship("DatasetModel", back_populates="versions")
    samples = relationship(
        "SampleModel", back_populates="dataset_version",
        cascade="all, delete-orphan", passive_deletes=True, lazy="dynamic"
    )

    __table_args__ = (
        Index("ix_dataset_versions_dataset_id", "dataset_id"),
        Index("ix_dataset_versions_label", "dataset_id", "version_label", unique=True),
    )


# ---------------------------------------------------------------------------
# Sample (image within a dataset version)
# ---------------------------------------------------------------------------

class SampleModel(Base):
    """An individual dataset image / sample."""

    __tablename__ = "samples"

    id = Column(String(36), primary_key=True, default=new_uuid)
    dataset_version_id = Column(
        String(36), ForeignKey("dataset_versions.id", ondelete="CASCADE"), nullable=False
    )
    file_path = Column(Text, nullable=False)
    file_hash_sha256 = Column(String(64), nullable=False)
    perceptual_hash = Column(String(64), nullable=True)
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    channels = Column(Integer, nullable=True)
    batch_id = Column(String(100), nullable=True)
    label_json = Column(JSON, default=dict, nullable=False)
    annotation_json = Column(JSON, default=dict, nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    dataset_version = relationship("DatasetVersionModel", back_populates="samples")
    contributor_links = relationship(
        "SampleContributorModel", back_populates="sample",
        cascade="all, delete-orphan", passive_deletes=True, lazy="dynamic"
    )

    __table_args__ = (
        Index("ix_samples_dataset_version_id", "dataset_version_id"),
        Index("ix_samples_file_hash", "file_hash_sha256"),
        Index("ix_samples_perceptual_hash", "perceptual_hash"),
    )


# ---------------------------------------------------------------------------
# Sample ↔ Contributor junction (ADR-029 ImageContributor)
# ---------------------------------------------------------------------------

class SampleContributorModel(Base):
    """Junction table linking samples to their contributors."""

    __tablename__ = "sample_contributors"

    id = Column(String(36), primary_key=True, default=new_uuid)
    sample_id = Column(String(36), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    contributor_id = Column(String(36), ForeignKey("contributors.id", ondelete="RESTRICT"), nullable=False)
    contribution_type = Column(String(50), default="annotator", nullable=False)

    # Relationships
    sample = relationship("SampleModel", back_populates="contributor_links")
    contributor = relationship("ContributorModel", back_populates="sample_contributions")

    __table_args__ = (
        Index("ix_sample_contributors_sample", "sample_id"),
        Index("ix_sample_contributors_contributor", "contributor_id"),
    )


# ---------------------------------------------------------------------------
# AI Model (named AIModelModel to avoid conflict with Pydantic BaseModel)
# ---------------------------------------------------------------------------

class AIModelModel(Base):
    """A contributed or reference AI model."""

    __tablename__ = "ai_models"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    format = Column(String(50), nullable=False)  # onnx, pytorch, torchscript
    architecture = Column(String(255), nullable=True)
    version = Column(String(100), nullable=True)
    file_path = Column(Text, nullable=False)
    file_hash_sha256 = Column(String(64), nullable=False)
    file_size_bytes = Column(Integer, default=0, nullable=False)
    access_level = Column(String(50), default="white_box", nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="models")
    fingerprints = relationship(
        "ModelFingerprintModel", back_populates="model",
        cascade="all, delete-orphan", passive_deletes=True, lazy="dynamic"
    )
    inference_records = relationship(
        "InferenceRecordModel", back_populates="model", lazy="dynamic"
    )

    __table_args__ = (
        Index("ix_ai_models_project_id", "project_id"),
        Index("ix_ai_models_file_hash", "file_hash_sha256"),
    )


# ---------------------------------------------------------------------------
# Model Fingerprint
# ---------------------------------------------------------------------------

class ModelFingerprintModel(Base):
    """A structural, statistical, or behavioural fingerprint of a model."""

    __tablename__ = "model_fingerprints"

    id = Column(String(36), primary_key=True, default=new_uuid)
    model_id = Column(String(36), ForeignKey("ai_models.id", ondelete="CASCADE"), nullable=False)
    fingerprint_type = Column(String(50), nullable=False)  # structural, statistical, behavioural
    fingerprint_version = Column(String(50), default="1", nullable=False)
    fingerprint_value = Column(Text, nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    model = relationship("AIModelModel", back_populates="fingerprints")

    __table_args__ = (
        Index("ix_model_fingerprints_model_id", "model_id"),
    )


# ---------------------------------------------------------------------------
# Inference Record (provenance chain storage — no crypto yet)
# ---------------------------------------------------------------------------

class InferenceRecordModel(Base):
    """A sealed inference execution record for provenance tracking."""

    __tablename__ = "inference_records"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    model_id = Column(String(36), ForeignKey("ai_models.id", ondelete="RESTRICT"), nullable=False)
    input_hash = Column(String(64), nullable=False)
    input_path = Column(Text, nullable=False)
    preprocessing_hash = Column(String(64), nullable=True)
    config_hash = Column(String(64), nullable=True)
    output_json = Column(JSON, default=dict, nullable=False)
    output_hash = Column(String(64), nullable=False)
    sequence_number = Column(Integer, nullable=False)
    nonce = Column(String(64), nullable=True)
    signature = Column(Text, nullable=True)
    previous_record_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=True)
    verification_status = Column(String(50), default="unverified", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="inference_records")
    model = relationship("AIModelModel", back_populates="inference_records")

    __table_args__ = (
        Index("ix_inference_records_project_id", "project_id"),
        Index("ix_inference_records_model_id", "model_id"),
        Index("ix_inference_records_sequence", "project_id", "model_id", "sequence_number", unique=True),
    )


# ---------------------------------------------------------------------------
# Finding (ADR-028: evidence_layer enforcement)
# ---------------------------------------------------------------------------

class FindingModel(Base):
    """An assurance observation produced by a detection engine."""

    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    audit_run_id = Column(String(36), nullable=True)
    engine_id = Column(String(100), nullable=False)
    engine_version = Column(String(50), nullable=True)
    evidence_layer = Column(String(20), nullable=False)  # detection | proof
    finding_type = Column(String(100), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    confidence = Column(Float, nullable=False)
    affected_asset_type = Column(String(50), nullable=False)
    affected_asset_id = Column(String(36), nullable=False)
    disposition = Column(String(20), nullable=False)  # accept, review, quarantine
    analysis_mode = Column(String(20), default="not_applicable", nullable=False)
    recommendation = Column(Text, nullable=True)
    status = Column(String(50), default="open", nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="findings")
    evidence_items = relationship(
        "EvidenceModel", back_populates="finding",
        cascade="all, delete-orphan", passive_deletes=True, lazy="dynamic"
    )

    __table_args__ = (
        Index("ix_findings_project_id", "project_id"),
        Index("ix_findings_audit_run_id", "audit_run_id"),
        Index("ix_findings_affected_asset", "affected_asset_type", "affected_asset_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_evidence_layer", "evidence_layer"),
    )


# ---------------------------------------------------------------------------
# Evidence (ADR-028: evidence_layer enforcement)
# ---------------------------------------------------------------------------

class EvidenceModel(Base):
    """Supporting evidence for a finding."""

    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=new_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="RESTRICT"), nullable=False)
    evidence_layer = Column(String(20), nullable=False)  # detection | proof
    evidence_type = Column(String(100), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    data_json = Column(JSON, default=dict, nullable=False)
    artifact_path = Column(Text, nullable=True)
    artifact_hash = Column(String(64), nullable=True)
    confidence = Column(Float, nullable=True)
    evidence_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    finding = relationship("FindingModel", back_populates="evidence_items")

    __table_args__ = (
        Index("ix_evidence_finding_id", "finding_id"),
        Index("ix_evidence_layer", "evidence_layer"),
    )


# ---------------------------------------------------------------------------
# Risk Assessment
# ---------------------------------------------------------------------------

class RiskAssessmentModel(Base):
    """An AIVARA risk assessment with disposition decision."""

    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    audit_run_id = Column(String(36), nullable=True)
    scope = Column(String(50), nullable=False)  # dataset, model, project
    target_id = Column(String(36), nullable=False)
    overall_risk_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)  # critical, high, medium, low, minimal
    disposition = Column(String(20), nullable=False)  # accept, review, quarantine
    component_scores_json = Column(JSON, default=dict, nullable=False)
    rationale = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="risk_assessments")

    __table_args__ = (
        Index("ix_risk_assessments_project_id", "project_id"),
        Index("ix_risk_assessments_target", "scope", "target_id"),
    )


# ---------------------------------------------------------------------------
# Audit Event
# ---------------------------------------------------------------------------

class AuditEventModel(Base):
    """An important system event for audit trail purposes."""

    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    event_type = Column(String(100), nullable=False)
    actor = Column(String(255), default="system", nullable=False)
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(36), nullable=True)
    description = Column(Text, nullable=True)
    metadata_json = Column(JSON, default=dict, nullable=False)
    event_hash = Column(String(64), nullable=True)  # placeholder for Phase 4 tamper-evidence
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_events_project_id", "project_id"),
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_created_at", "created_at"),
    )


# ---------------------------------------------------------------------------
# Provenance Record (hash chain storage — no crypto yet)
# ---------------------------------------------------------------------------

class ProvenanceRecordModel(Base):
    """A provenance record in the hash-linked chain."""

    __tablename__ = "provenance_records"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    record_type = Column(String(100), nullable=False)
    actor = Column(String(255), default="system", nullable=False)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(36), nullable=True)
    input_hash = Column(String(64), nullable=True)
    output_hash = Column(String(64), nullable=True)
    metadata_json = Column(JSON, default=dict, nullable=False)
    signature = Column(Text, nullable=True)  # placeholder for Phase 4 Ed25519
    previous_record_hash = Column(String(64), nullable=True)
    record_hash = Column(String(64), nullable=True)
    sequence_number = Column(Integer, nullable=True)
    blockchain_tx_id = Column(String(128), nullable=True)  # ADR-005 amended: nullable forward-compat
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="provenance_records")

    __table_args__ = (
        Index("ix_provenance_records_project_id", "project_id"),
        Index("ix_provenance_records_sequence", "project_id", "sequence_number"),
        Index("ix_provenance_records_record_type", "record_type"),
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class ReportModel(Base):
    """A generated assurance report."""

    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=new_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    report_type = Column(String(50), nullable=False)  # full, summary, dataset, model
    format = Column(String(20), nullable=False)  # pdf, html, json
    file_path = Column(Text, nullable=True)
    risk_assessment_id = Column(String(36), ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    project = relationship("ProjectModel", back_populates="reports")
    risk_assessment = relationship("RiskAssessmentModel")

    __table_args__ = (
        Index("ix_reports_project_id", "project_id"),
    )
