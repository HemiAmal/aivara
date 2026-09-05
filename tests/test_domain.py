"""Tests for domain schemas and data validation."""

import uuid
import pytest
from pydantic import ValidationError
from aivara.domain.schemas import (
    Disposition,
    Severity,
    EvidenceLayer,
    ProjectCreate,
    FindingCreate,
    EvidenceCreate,
    RiskAssessmentCreate,
)


def test_project_create_schema_validation():
    """Verify ProjectCreate schema requirements."""
    project = ProjectCreate(name="Vision Assurance Engagement")
    assert project.name == "Vision Assurance Engagement"

    with pytest.raises(ValidationError):
        ProjectCreate(name="")  # min_length=1 constraint


def test_finding_and_evidence_layers():
    """Verify Finding and Evidence enforce EvidenceLayer and valid dispositions."""
    uid = str(uuid.uuid4())
    finding = FindingCreate(
        project_id=uid,
        engine_id="dataset_integrity",
        engine_version="0.1.0",
        evidence_layer=EvidenceLayer.DETECTION,
        finding_type="duplicate_flood",
        title="Excessive near-duplicates detected",
        description="Identified 120 near-duplicate image pairs in training set.",
        severity=Severity.HIGH,
        confidence=0.85,
        affected_asset_type="dataset",
        affected_asset_id=uid,
        disposition=Disposition.REVIEW,
    )
    assert finding.severity == Severity.HIGH
    assert finding.evidence_layer == EvidenceLayer.DETECTION
    assert finding.disposition == Disposition.REVIEW

    evidence = EvidenceCreate(
        finding_id=uid,
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="similarity_map",
        title="Pairwise perceptual similarity matrix",
        description="pHash distance histogram",
        evidence_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    )
    assert evidence.finding_id == uid


def test_risk_assessment_threshold_bounds():
    """Verify RiskAssessment score must be between 0.0 and 1.0."""
    valid_ra = RiskAssessmentCreate(
        project_id=str(uuid.uuid4()),
        scope="dataset",
        target_id=str(uuid.uuid4()),
        overall_risk_score=0.45,
        risk_level="medium",
        disposition=Disposition.REVIEW,
        rationale="Borderline class imbalance and near-duplicates present.",
    )
    assert valid_ra.overall_risk_score == 0.45

    with pytest.raises(ValidationError):
        RiskAssessmentCreate(
            project_id=str(uuid.uuid4()),
            scope="dataset",
            target_id=str(uuid.uuid4()),
            overall_risk_score=1.5,  # Out of bounds (> 1.0)
            risk_level="critical",
            disposition=Disposition.QUARANTINE,
            rationale="Invalid score test",
        )
