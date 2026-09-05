"""Pydantic domain schemas and API contracts for AIVARA.

Maintains strict separation between SQLAlchemy persistence models
(database/models.py) and these API/business-layer schemas.

Naming convention:
  - XxxBase: shared fields for create and read
  - XxxCreate: input schema for creation
  - XxxRead: full output schema (includes id, timestamps)
  - XxxUpdate: optional-field schema for partial updates

Note on 'metadata_json' vs 'metadata':
  ORM models use column name 'metadata_json' to avoid collision with
  SQLAlchemy's Base.metadata class attribute. Pydantic schemas use
  validation_alias="metadata_json" so that from_attributes reads the
  correct ORM column, while the API-facing field name remains 'metadata_json'
  for consistency.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# =====================================================================
# Core Domain Enums
# =====================================================================

class Disposition(str, Enum):
    ACCEPT = "accept"
    REVIEW = "review"
    QUARANTINE = "quarantine"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceLayer(str, Enum):
    DETECTION = "detection"
    PROOF = "proof"


class AnalysisMode(str, Enum):
    WHITE_BOX = "white_box"
    BLACK_BOX = "black_box"
    NOT_APPLICABLE = "not_applicable"


class DatasetFormat(str, Enum):
    COCO = "coco"
    YOLO = "yolo"
    IMAGEFOLDER = "imagefolder"
    GENERIC = "generic"


class ModelFormat(str, Enum):
    ONNX = "onnx"
    PYTORCH = "pytorch"
    TORCHSCRIPT = "torchscript"


class AccessLevel(str, Enum):
    WHITE_BOX = "white_box"
    BLACK_BOX = "black_box"


class FingerprintType(str, Enum):
    STRUCTURAL = "structural"
    STATISTICAL = "statistical"
    BEHAVIOURAL = "behavioural"


# =====================================================================
# Project
# =====================================================================

class ProjectBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    config: Dict[str, Any] = Field(default_factory=dict)


class ProjectCreate(ProjectBase):
    pass


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class ProjectRead(ProjectBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str = "active"
    genesis_nonce: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# Backward compat alias
Project = ProjectRead


# =====================================================================
# Contributor
# =====================================================================

class ContributorBase(BaseModel):
    external_id: str = Field(..., min_length=1, max_length=255)
    name: Optional[str] = Field(None, max_length=255)
    source: Optional[str] = Field(None, max_length=255)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class ContributorCreate(ContributorBase):
    project_id: str


class ContributorRead(ContributorBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    created_at: datetime


Contributor = ContributorRead


# =====================================================================
# Dataset
# =====================================================================

class DatasetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    format: DatasetFormat
    source: Optional[str] = None
    description: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class DatasetCreate(DatasetBase):
    project_id: str


class DatasetRead(DatasetBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    status: str = "imported"
    created_at: datetime
    updated_at: datetime


Dataset = DatasetRead


# =====================================================================
# Dataset Version
# =====================================================================

class DatasetVersionBase(BaseModel):
    version_label: str = Field(..., min_length=1, max_length=100)
    dataset_hash: Optional[str] = Field(None, max_length=64)
    sample_count: int = Field(default=0, ge=0)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class DatasetVersionCreate(DatasetVersionBase):
    dataset_id: str


class DatasetVersionRead(DatasetVersionBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    dataset_id: str
    created_at: datetime


DatasetVersion = DatasetVersionRead


# =====================================================================
# Sample
# =====================================================================

class SampleBase(BaseModel):
    file_path: str = Field(..., min_length=1)
    file_hash_sha256: str = Field(..., min_length=64, max_length=64)
    perceptual_hash: Optional[str] = Field(None, max_length=64)
    width: Optional[int] = Field(None, ge=1)
    height: Optional[int] = Field(None, ge=1)
    channels: Optional[int] = Field(None, ge=1)
    batch_id: Optional[str] = Field(None, max_length=100)
    label_json: Dict[str, Any] = Field(default_factory=dict)
    annotation_json: Dict[str, Any] = Field(default_factory=dict)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class SampleCreate(SampleBase):
    dataset_version_id: str


class SampleRead(SampleBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    dataset_version_id: str
    created_at: datetime


Sample = SampleRead


# =====================================================================
# AI Model
# =====================================================================

class AIModelBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    format: ModelFormat
    architecture: Optional[str] = Field(None, max_length=255)
    version: Optional[str] = Field(None, max_length=100)
    file_path: str = Field(..., min_length=1)
    file_hash_sha256: str = Field(..., min_length=64, max_length=64)
    file_size_bytes: int = Field(default=0, ge=0)
    access_level: AccessLevel = AccessLevel.WHITE_BOX
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class AIModelCreate(AIModelBase):
    project_id: str


class AIModelRead(AIModelBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    created_at: datetime
    updated_at: datetime


# Keep 'Model' as legacy alias for backward compat with Phase 2 tests
Model = AIModelRead


# =====================================================================
# Model Fingerprint
# =====================================================================

class ModelFingerprintBase(BaseModel):
    fingerprint_type: FingerprintType
    fingerprint_version: str = Field(default="1", max_length=50)
    fingerprint_value: str = Field(..., min_length=1)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class ModelFingerprintCreate(ModelFingerprintBase):
    model_id: str


class ModelFingerprintRead(ModelFingerprintBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    model_id: str
    created_at: datetime


ModelFingerprint = ModelFingerprintRead


# =====================================================================
# Inference Record
# =====================================================================

class InferenceRecordBase(BaseModel):
    input_hash: str = Field(..., min_length=1, max_length=64)
    input_path: str = Field(..., min_length=1)
    preprocessing_hash: Optional[str] = Field(None, max_length=64)
    config_hash: Optional[str] = Field(None, max_length=64)
    output_json: Dict[str, Any] = Field(default_factory=dict)
    output_hash: str = Field(..., min_length=1, max_length=64)
    sequence_number: int = Field(..., ge=0)


class InferenceRecordCreate(InferenceRecordBase):
    project_id: str
    model_id: str


class InferenceRecordRead(InferenceRecordBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    model_id: str
    nonce: Optional[str] = None
    signature: Optional[str] = None
    previous_record_hash: Optional[str] = None
    record_hash: Optional[str] = None
    verification_status: str = "unverified"
    created_at: datetime


InferenceRecord = InferenceRecordRead


# =====================================================================
# Finding (ADR-028: evidence_layer enforcement)
# =====================================================================

class FindingBase(BaseModel):
    engine_id: str = Field(..., min_length=1, max_length=100)
    engine_version: Optional[str] = Field(None, max_length=50)
    evidence_layer: EvidenceLayer
    finding_type: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    affected_asset_type: str = Field(..., min_length=1, max_length=50)
    affected_asset_id: str = Field(..., min_length=1, max_length=36)
    disposition: Disposition
    analysis_mode: AnalysisMode = AnalysisMode.NOT_APPLICABLE
    recommendation: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def proof_layer_must_have_full_confidence(self):
        """ADR-028: Proof-layer findings MUST have confidence = 1.0."""
        if self.evidence_layer == EvidenceLayer.PROOF and self.confidence != 1.0:
            raise ValueError("Proof-layer findings must have confidence = 1.0")
        return self


class FindingCreate(FindingBase):
    project_id: str
    audit_run_id: Optional[str] = None


class FindingRead(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    audit_run_id: Optional[str] = None
    status: str = "open"
    created_at: datetime


Finding = FindingRead


# =====================================================================
# Evidence (ADR-028: evidence_layer enforcement)
# =====================================================================

class EvidenceBase(BaseModel):
    evidence_layer: EvidenceLayer
    evidence_type: str = Field(..., min_length=1, max_length=100)
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    data_json: Dict[str, Any] = Field(default_factory=dict)
    artifact_path: Optional[str] = None
    artifact_hash: Optional[str] = Field(None, max_length=64)
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    evidence_hash: Optional[str] = Field(None, max_length=64)


class EvidenceCreate(EvidenceBase):
    finding_id: str


class EvidenceRead(EvidenceBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    created_at: datetime


Evidence = EvidenceRead


# =====================================================================
# Risk Assessment
# =====================================================================

class RiskAssessmentBase(BaseModel):
    scope: str = Field(..., min_length=1, max_length=50)
    target_id: str = Field(..., min_length=1, max_length=36)
    overall_risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str = Field(..., min_length=1, max_length=20)
    disposition: Disposition
    component_scores_json: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(..., min_length=1)


class RiskAssessmentCreate(RiskAssessmentBase):
    project_id: str
    audit_run_id: Optional[str] = None


class RiskAssessmentRead(RiskAssessmentBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    audit_run_id: Optional[str] = None
    created_at: datetime


RiskAssessment = RiskAssessmentRead


# =====================================================================
# Audit Event
# =====================================================================

class AuditEventBase(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=100)
    actor: str = Field(default="system", max_length=255)
    target_type: Optional[str] = Field(None, max_length=50)
    target_id: Optional[str] = Field(None, max_length=36)
    description: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class AuditEventCreate(AuditEventBase):
    project_id: str


class AuditEventRead(AuditEventBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    event_hash: Optional[str] = None
    created_at: datetime


AuditEvent = AuditEventRead


# =====================================================================
# Provenance Record
# =====================================================================

class ProvenanceRecordBase(BaseModel):
    record_type: str = Field(..., min_length=1, max_length=100)
    actor: str = Field(default="system", max_length=255)
    action: str = Field(..., min_length=1, max_length=100)
    target_type: Optional[str] = Field(None, max_length=50)
    target_id: Optional[str] = Field(None, max_length=36)
    input_hash: Optional[str] = Field(None, max_length=64)
    output_hash: Optional[str] = Field(None, max_length=64)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    nonce: Optional[str] = Field(None, max_length=64)
    signer_key_id: Optional[str] = Field(None, max_length=64)
    signature: Optional[str] = None
    previous_record_hash: Optional[str] = Field(None, max_length=64)
    record_hash: Optional[str] = Field(None, max_length=64)
    sequence_number: Optional[int] = Field(None, ge=0)


class ProvenanceRecordCreate(ProvenanceRecordBase):
    project_id: str


class ProvenanceRecordRead(ProvenanceRecordBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    blockchain_tx_id: Optional[str] = None
    created_at: datetime


ProvenanceRecord = ProvenanceRecordRead


# =====================================================================
# Report
# =====================================================================

class ReportBase(BaseModel):
    report_type: str = Field(..., min_length=1, max_length=50)
    format: str = Field(..., min_length=1, max_length=20)
    file_path: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class ReportCreate(ReportBase):
    project_id: str
    risk_assessment_id: Optional[str] = None


class ReportRead(ReportBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    risk_assessment_id: Optional[str] = None
    created_at: datetime


Report = ReportRead
