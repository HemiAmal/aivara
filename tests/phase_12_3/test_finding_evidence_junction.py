"""Verification Test Suite for Finding-Evidence N:M Persistent Junction Model (Phase 12.3)."""

import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from aivara.database.connection import Base
from aivara.database.models import (
    AIModelModel,
    DatasetModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
)
from aivara.universal.graph import FindingEvidenceModel, UniversalBase


@pytest.fixture
def db_session():
    """In-memory SQLite database session fixture."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    UniversalBase.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_finding_evidence_nm_persistence(db_session):
    """Verify N:M relationship persistence in finding_evidence junction table."""
    proj = ProjectModel(name="Test Proj", description="NM test")
    db_session.add(proj)
    db_session.flush()

    f1 = FindingModel(
        project_id=proj.id,
        engine_id="eng_ds",
        evidence_layer="detection",
        finding_type="quality_noise",
        title="Noise finding 1",
        severity="medium",
        confidence=0.90,
        affected_asset_type="dataset",
        affected_asset_id="ds_1",
        disposition="review",
    )
    f2 = FindingModel(
        project_id=proj.id,
        engine_id="eng_ds",
        evidence_layer="detection",
        finding_type="quality_noise",
        title="Noise finding 2",
        severity="high",
        confidence=0.85,
        affected_asset_type="dataset",
        affected_asset_id="ds_1",
        disposition="quarantine",
    )
    db_session.add_all([f1, f2])
    db_session.flush()

    # N:M junction bindings: F1 -> E1, F1 -> E2, F2 -> E1
    b1 = FindingEvidenceModel(project_id=proj.id, finding_id=f1.id, evidence_id="ev_001", relationship_type="SUPPORTS")
    b2 = FindingEvidenceModel(project_id=proj.id, finding_id=f1.id, evidence_id="ev_002", relationship_type="SUPPORTS")
    b3 = FindingEvidenceModel(project_id=proj.id, finding_id=f2.id, evidence_id="ev_001", relationship_type="SUPPORTS")
    db_session.add_all([b1, b2, b3])
    db_session.commit()

    # Query bindings for F1
    f1_bindings = db_session.query(FindingEvidenceModel).filter_by(finding_id=f1.id).all()
    assert len(f1_bindings) == 2
    ev_ids_for_f1 = {b.evidence_id for b in f1_bindings}
    assert ev_ids_for_f1 == {"ev_001", "ev_002"}

    # Query findings supported by ev_001
    ev1_bindings = db_session.query(FindingEvidenceModel).filter_by(evidence_id="ev_001").all()
    assert len(ev1_bindings) == 2
    f_ids_for_ev1 = {b.finding_id for b in ev1_bindings}
    assert f_ids_for_ev1 == {f1.id, f2.id}


def test_finding_evidence_unique_constraint(db_session):
    """Verify unique constraint on (finding_id, evidence_id, relationship_type) prevents duplicate bindings."""
    proj = ProjectModel(name="Test Proj", description="NM unique test")
    db_session.add(proj)
    db_session.flush()

    f1 = FindingModel(
        project_id=proj.id,
        engine_id="eng_ds",
        evidence_layer="detection",
        finding_type="quality_noise",
        title="Noise finding 1",
        severity="medium",
        confidence=0.90,
        affected_asset_type="dataset",
        affected_asset_id="ds_1",
        disposition="review",
    )
    db_session.add(f1)
    db_session.flush()

    b1 = FindingEvidenceModel(project_id=proj.id, finding_id=f1.id, evidence_id="ev_001", relationship_type="SUPPORTS")
    db_session.add(b1)
    db_session.commit()

    # Duplicate insertion should fail
    b1_dup = FindingEvidenceModel(project_id=proj.id, finding_id=f1.id, evidence_id="ev_001", relationship_type="SUPPORTS")
    db_session.add(b1_dup)
    with pytest.raises(IntegrityError):
        db_session.commit()
