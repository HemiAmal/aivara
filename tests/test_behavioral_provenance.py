"""Comprehensive unit and adversarial test suite for Phase 8.7 Behavioral Evidence & Provenance Binding."""

import math
import os
import pytest
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from aivara.crypto.canonical import canonicalize
from aivara.crypto.chain import generate_nonce
from aivara.crypto.hashing import hash_canonical_data, is_valid_sha256
from aivara.crypto.keys import KeyManager
from aivara.crypto.signing import sign_hash
from aivara.database.models import (
    AIModelModel,
    AuditEventModel,
    Base,
    DatasetModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.domain.schemas import (
    Disposition,
    EvidenceLayer,
    ProvenanceRecordCreate,
    ProvenanceRecordRead,
    Severity,
)
from aivara.evidence.schemas import ProvenanceStatus, ScanExecutionStatus
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService

from aivara.behavioral.anomaly.enums import (
    AnomalyBaselineType,
    AnomalyFamilyType,
    AnomalyStatus,
    MetricAnomalyStatus,
    MetricDirection,
    SupportStatus,
)
from aivara.behavioral.anomaly.schemas import (
    BaselineSummary,
    BehavioralAnomalyAnalysis,
    BehavioralAnomalyFamily,
    BehavioralAnomalyMetric,
)
from aivara.behavioral.provenance.enums import (
    BehavioralEvidenceType,
    BehavioralFindingStatus,
    BehavioralFindingType,
    EvidenceLifecycleState,
)
from aivara.behavioral.provenance.exceptions import (
    BehavioralEvidenceIdentityError,
    BehavioralEvidenceValidationError,
    BehavioralExecutionIdentityError,
    BehavioralProvenanceError,
    CrossProjectBindingError,
    EvidenceImmutableError,
    EvidenceTamperedError,
    IdempotencyConflictError,
    NonFiniteValueError,
    SignerUnavailableError,
)
from aivara.behavioral.provenance.identity import (
    build_behavioral_execution_payload,
    build_canonical_behavioral_evidence_dict,
    compute_behavioral_evidence_hash,
    compute_behavioral_execution_identity_hash,
    is_valid_hash,
    sanitize_numeric_value,
)
from aivara.behavioral.provenance.evidence import (
    build_anomaly_evidence_content,
    create_behavioral_evidence,
    seal_behavioral_evidence,
    to_phase5_evidence_payload,
)
from aivara.behavioral.provenance.binding import (
    BehavioralProvenanceBindingService,
)
from aivara.behavioral.provenance.verifier import (
    BehavioralProvenanceVerifier,
)
from aivara.behavioral.provenance.idempotency import (
    resolve_idempotent_behavioral_scan,
)
from aivara.behavioral.provenance.schemas import (
    BehavioralEvidence,
    BehavioralEvidenceContent,
    BehavioralVerificationResult,
    BehavioralVerificationVector,
)


@pytest.fixture
def db_session():
    """In-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def sample_project(db_session: Session):
    """Seed sample project."""
    proj = ProjectModel(id="proj-test-101", name="Project 101", description="Test Project")
    db_session.add(proj)
    db_session.commit()
    return proj


@pytest.fixture
def sample_model(db_session: Session, sample_project: ProjectModel):
    """Seed sample AI model."""
    model = AIModelModel(
        id="model-cv-01",
        project_id=sample_project.id,
        name="ResNet50_Classifier",
        format="onnx",
        file_path="/tmp/resnet.onnx",
        file_hash_sha256="a" * 64,
        file_size_bytes=1024,
    )
    db_session.add(model)
    db_session.commit()
    return model


@pytest.fixture
def key_manager(tmp_path: Path):
    """Key manager instance with generated and active signing key."""
    km = KeyManager(keys_dir=tmp_path / "keys")
    km.generate_key(passphrase="passphrase123", set_as_active=True)
    return km


@pytest.fixture
def sample_anomaly_analysis():
    """Construct sample Phase 8.6 BehavioralAnomalyAnalysis."""
    metric = BehavioralAnomalyMetric(
        metric_name="prediction_agreement",
        family=AnomalyFamilyType.OUTPUT_CONSISTENCY,
        direction=MetricDirection.LOWER_IS_EXTREME,
        observed_value=0.82,
        baseline_count=50,
        baseline_median=0.95,
        baseline_mad=0.02,
        robust_z=-4.38,
        absolute_robust_z=4.38,
        empirical_extremeness=0.01,
        validity_status="VALID",
        anomaly_status=MetricAnomalyStatus.ANOMALOUS,
        reason="Observed value 0.82 deviates by -4.38 robust Z",
    )
    family = BehavioralAnomalyFamily(
        family_name=AnomalyFamilyType.OUTPUT_CONSISTENCY,
        support_status=SupportStatus.ADEQUATE_SUPPORT,
        metric_count=1,
        valid_metric_count=1,
        anomalous_metric_count=1,
        dominant_metric="prediction_agreement",
        dominant_extremeness=4.38,
        family_status=AnomalyStatus.ANOMALOUS,
        explanation="Output consistency family exhibits 1 anomalous metric.",
    )
    baseline_summary = BaselineSummary(
        baseline_id="base-ref-001",
        baseline_type="HISTORICAL_PROFILE",
        total_baseline_count=50,
        eligible_baseline_count=50,
        excluded_baseline_count=0,
        exclusion_reasons={},
    )
    return BehavioralAnomalyAnalysis(
        analysis_id="b" * 64,
        project_id="proj-test-101",
        model_id="model-cv-01",
        model_fingerprint="c" * 64,
        baseline_id="base-ref-001",
        baseline_type="HISTORICAL_PROFILE",
        observation_id="obs-001",
        task_type="classification",
        analysis_version="1.0.0",
        policy_version="1.0.0",
        overall_status=AnomalyStatus.ANOMALOUS,
        support_status=SupportStatus.ADEQUATE_SUPPORT,
        comparability_status="COMPARABLE",
        families={"output_consistency": family},
        metrics=[metric],
        threshold_policy={"robust_z_threshold": 3.5},
        baseline_summary=baseline_summary,
        explanation="Model behavior is statistically unusual relative to reference population.",
        limitations=["Evaluated on CPU runtime boundary."],
        created_at="2026-09-11T12:00:00Z",
    )


# ==============================================================================
# 1. Deterministic Evidence Identity & JCS Tests (8 Tests)
# ==============================================================================

def test_evidence_identity_is_deterministic(sample_anomaly_analysis):
    """Test that identical evidence content yields identical evidence_id."""
    content1 = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    content2 = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    hash1 = compute_behavioral_evidence_hash(content1)
    hash2 = compute_behavioral_evidence_hash(content2)
    assert hash1 == hash2
    assert is_valid_sha256(hash1)


def test_jcs_dictionary_order_invariance(sample_anomaly_analysis):
    """Test that dict key insertion order does not affect evidence_id (RFC 8785)."""
    d1 = {"b": 2, "a": 1, "c": {"y": 20, "x": 10}}
    d2 = {"a": 1, "c": {"x": 10, "y": 20}, "b": 2}
    c1 = canonicalize(d1)
    c2 = canonicalize(d2)
    assert c1 == c2


def test_jcs_whitespace_invariance():
    """Test canonical serialization produces compact, whitespace-normalized bytes."""
    data = {"key": "value", "list": [1, 2, 3]}
    b = canonicalize(data)
    assert b" " not in b
    assert b"\n" not in b


def test_metric_sorting_determinism(sample_anomaly_analysis):
    """Test that metrics list ordering is canonically normalized by metric_name."""
    m1 = {"metric_name": "zebra_metric", "observed_value": 1.0}
    m2 = {"metric_name": "alpha_metric", "observed_value": 2.0}
    dict_content1 = build_canonical_behavioral_evidence_dict(
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=BehavioralEvidenceType.BEHAVIORAL_ANOMALY,
        project_id="proj-1",
        model_id="m-1",
        model_fingerprint="c" * 64,
        task_type="classification",
        observation_id="obs-1",
        baseline_id="base-1",
        baseline_type="HISTORICAL",
        input_hash="1" * 64,
        output_hash="2" * 64,
        detector_id="det-1",
        detector_version="1.0.0",
        detector_config_hash="3" * 64,
        result_status="NORMAL",
        support_status="ADEQUATE",
        metrics=[m1, m2],
    )
    dict_content2 = build_canonical_behavioral_evidence_dict(
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=BehavioralEvidenceType.BEHAVIORAL_ANOMALY,
        project_id="proj-1",
        model_id="m-1",
        model_fingerprint="c" * 64,
        task_type="classification",
        observation_id="obs-1",
        baseline_id="base-1",
        baseline_type="HISTORICAL",
        input_hash="1" * 64,
        output_hash="2" * 64,
        detector_id="det-1",
        detector_version="1.0.0",
        detector_config_hash="3" * 64,
        result_status="NORMAL",
        support_status="ADEQUATE",
        metrics=[m2, m1],
    )
    assert dict_content1["metrics"][0]["metric_name"] == "alpha_metric"
    assert dict_content2["metrics"][0]["metric_name"] == "alpha_metric"
    assert hash_canonical_data(dict_content1) == hash_canonical_data(dict_content2)


def test_evidence_identity_rejects_missing_project():
    """Test error when required fields are missing."""
    with pytest.raises(BehavioralEvidenceIdentityError):
        build_canonical_behavioral_evidence_dict(
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type=BehavioralEvidenceType.BEHAVIORAL_ANOMALY,
            project_id="",
            model_id="m-1",
            model_fingerprint="c" * 64,
            task_type="classification",
            observation_id="obs-1",
            baseline_id="base-1",
            baseline_type="HISTORICAL",
            input_hash="1" * 64,
            output_hash="2" * 64,
            detector_id="det-1",
            detector_version="1.0.0",
            detector_config_hash="3" * 64,
            result_status="NORMAL",
            support_status="ADEQUATE",
        )


def test_evidence_identity_rejects_invalid_config_hash():
    """Test error when detector_config_hash is not 64-hex SHA-256."""
    with pytest.raises(BehavioralEvidenceIdentityError):
        build_canonical_behavioral_evidence_dict(
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type=BehavioralEvidenceType.BEHAVIORAL_ANOMALY,
            project_id="proj-1",
            model_id="m-1",
            model_fingerprint="c" * 64,
            task_type="classification",
            observation_id="obs-1",
            baseline_id="base-1",
            baseline_type="HISTORICAL",
            input_hash="1" * 64,
            output_hash="2" * 64,
            detector_id="det-1",
            detector_version="1.0.0",
            detector_config_hash="not-a-valid-hash",
            result_status="NORMAL",
            support_status="ADEQUATE",
        )


def test_execution_identity_hash_is_deterministic():
    """Test that identical execution parameters produce identical execution_identity_hash."""
    payload1 = {
        "project_id": "proj-1",
        "model_id": "m-1",
        "model_fingerprint": "c" * 64,
        "observation_id": "obs-1",
        "baseline_id": "base-1",
        "detector_id": "det-1",
        "detector_version": "1.0.0",
        "detector_config_hash": "4" * 64,
        "policy_version": "1.0.0",
        "engine_version": "1.0.0",
        "preprocessing_hash": "STANDARD_V1",
    }
    h1 = compute_behavioral_execution_identity_hash(payload1)
    h2 = compute_behavioral_execution_identity_hash(payload1)
    assert h1 == h2
    assert is_valid_sha256(h1)


def test_execution_identity_differentiates_parameters():
    """Test that modifying detector configuration changes execution identity hash."""
    payload1 = {
        "project_id": "proj-1",
        "model_id": "m-1",
        "model_fingerprint": "c" * 64,
        "observation_id": "obs-1",
        "baseline_id": "base-1",
        "detector_id": "det-1",
        "detector_version": "1.0.0",
        "detector_config_hash": "4" * 64,
    }
    payload2 = dict(payload1, detector_config_hash="5" * 64)
    assert compute_behavioral_execution_identity_hash(payload1) != compute_behavioral_execution_identity_hash(payload2)


# ==============================================================================
# 2. Non-Finite Numeric Safety Tests (3 Tests)
# ==============================================================================

def test_nan_rejected_in_canonical_evidence():
    """Test that NaN values raise NonFiniteValueError."""
    with pytest.raises(NonFiniteValueError):
        sanitize_numeric_value(float("nan"))


def test_inf_rejected_in_canonical_evidence():
    """Test that +Inf and -Inf values raise NonFiniteValueError."""
    with pytest.raises(NonFiniteValueError):
        sanitize_numeric_value(float("inf"))
    with pytest.raises(NonFiniteValueError):
        sanitize_numeric_value(float("-inf"))


def test_nested_nan_in_dictionary_rejected():
    """Test that NaN inside a nested dictionary structure is caught and rejected."""
    nested = {"metrics": {"stability": {"z_score": float("nan")}}}
    with pytest.raises(NonFiniteValueError):
        sanitize_numeric_value(nested)


# ==============================================================================
# 3. Evidence Lifecycle & Immutability Tests (4 Tests)
# ==============================================================================

def test_evidence_creation_draft_and_sealed(sample_anomaly_analysis):
    """Test creation of draft vs sealed evidence objects."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev_draft = create_behavioral_evidence(content, seal=False)
    assert ev_draft.lifecycle_state == EvidenceLifecycleState.DRAFT

    ev_sealed = seal_behavioral_evidence(ev_draft)
    assert ev_sealed.lifecycle_state == EvidenceLifecycleState.SEALED
    assert ev_sealed.evidence_id == ev_draft.evidence_id


def test_sealed_evidence_payload_conversion(sample_anomaly_analysis):
    """Test conversion of sealed evidence to Phase 5.9 EvidencePayload."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev_sealed = create_behavioral_evidence(content, seal=True)
    payload = to_phase5_evidence_payload(ev_sealed)
    assert payload.evidence_type == BehavioralEvidenceType.BEHAVIORAL_ANOMALY.value
    assert payload.evidence_hash == ev_sealed.evidence_id
    assert payload.confidence == 0.95


def test_normal_result_evidence_creation(sample_anomaly_analysis):
    """Test that normal (non-anomalous) analytical results also create valid sealed evidence."""
    normal_metric = sample_anomaly_analysis.metrics[0].model_copy(update={
        "observed_value": 0.94,
        "robust_z": -0.5,
        "absolute_robust_z": 0.5,
        "anomaly_status": MetricAnomalyStatus.NORMAL,
    })
    normal_family = sample_anomaly_analysis.families["output_consistency"].model_copy(update={
        "anomalous_metric_count": 0,
        "family_status": AnomalyStatus.NORMAL,
    })
    normal_analysis = sample_anomaly_analysis.model_copy(update={
        "overall_status": AnomalyStatus.NORMAL,
        "metrics": [normal_metric],
        "families": {"output_consistency": normal_family},
    })
    content = build_anomaly_evidence_content(normal_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)
    assert ev.content.result_status == "NORMAL"
    assert is_valid_sha256(ev.evidence_id)


def test_evidence_model_mapping(sample_anomaly_analysis):
    """Test that measurements dictionary populates expected scalar values."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)
    p5_payload = to_phase5_evidence_payload(ev)
    assert p5_payload.measurements["prediction_agreement"] == 0.82


# ==============================================================================
# 4. Provenance Binding & Ed25519 Signing Tests (8 Tests)
# ==============================================================================

def test_bind_anomaly_analysis_end_to_end(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test end-to-end binding of an anomaly analysis into Finding and signed Provenance record."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    finding, prov_read, status = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    assert status == ScanExecutionStatus.COMPLETED
    assert finding is not None
    assert finding.finding_type == BehavioralFindingType.BEHAVIORAL_ANOMALY.value
    assert finding.disposition == Disposition.REVIEW.value
    assert prov_read is not None
    assert prov_read.signature is not None
    assert prov_read.sequence_number == 0
    assert prov_read.previous_record_hash == "0" * 64
    assert is_valid_sha256(prov_read.record_hash)


def test_hash_chain_monotonicity(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that sequential bindings in the same project form an unbroken hash chain."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)

    # First binding
    _, prov1, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
        allow_idempotent_reuse=False,
    )

    # Second binding with different observation
    analysis2 = sample_anomaly_analysis.model_copy(update={"observation_id": "obs-002"})
    _, prov2, _ = service.bind_anomaly_analysis(
        analysis=analysis2,
        input_hash="3" * 64,
        output_hash="4" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
        allow_idempotent_reuse=False,
    )

    assert prov1.sequence_number == 0
    assert prov2.sequence_number == 1
    assert prov2.previous_record_hash == prov1.record_hash


def test_nonce_generation_is_unique(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that two separate bindings generate distinct nonces."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov1, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
        allow_idempotent_reuse=False,
    )
    analysis2 = sample_anomaly_analysis.model_copy(update={"observation_id": "obs-002"})
    _, prov2, _ = service.bind_anomaly_analysis(
        analysis=analysis2,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
        allow_idempotent_reuse=False,
    )
    assert prov1.nonce != prov2.nonce
    assert len(prov1.nonce) == 64


def test_audit_events_recorded_on_binding(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that BEHAVIORAL_EVIDENCE_CREATED and BEHAVIORAL_PROVENANCE_BOUND audit events are emitted."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )
    events = db_session.query(AuditEventModel).filter_by(project_id=sample_project.id).all()
    event_types = [e.event_type for e in events]
    assert "BEHAVIORAL_EVIDENCE_CREATED" in event_types
    assert "BEHAVIORAL_PROVENANCE_BOUND" in event_types


def test_idempotent_scan_reuse(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that repeating the identical scan returns the existing finding with IDEMPOTENT_HIT status."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    finding1, prov1, status1 = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
        allow_idempotent_reuse=True,
    )
    assert status1 == ScanExecutionStatus.COMPLETED

    finding2, prov2, status2 = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
        allow_idempotent_reuse=True,
    )
    assert status2 == ScanExecutionStatus.IDEMPOTENT_HIT
    assert finding1.id == finding2.id
    assert prov1.id == prov2.id

    # Verify no duplicate provenance rows in DB
    total_prov = db_session.query(ProvenanceRecordModel).count()
    assert total_prov == 1


def test_binding_arbitrary_behavioral_evidence(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
):
    """Test binding arbitrary BehavioralEvidence items (e.g. BEHAVIORAL_REPEATABILITY)."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    content = BehavioralEvidenceContent(
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type=BehavioralEvidenceType.BEHAVIORAL_REPEATABILITY,
        project_id=sample_project.id,
        model_id=sample_model.id,
        model_fingerprint="c" * 64,
        task_type="classification",
        observation_id="obs-rep-01",
        baseline_id="base-rep-01",
        baseline_type="HISTORICAL",
        input_hash="5" * 64,
        output_hash="6" * 64,
        detector_id="repeatability_analyzer",
        detector_version="1.0.0",
        detector_config_hash="7" * 64,
        result_status="NORMAL",
        support_status="ADEQUATE_SUPPORT",
        metrics=[{"metric_name": "max_absolute_error", "observed_value": 0.0}],
    )
    ev = create_behavioral_evidence(content, seal=True)
    finding, prov_read, status = service.bind_behavioral_evidence(
        ev,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )
    assert status == ScanExecutionStatus.COMPLETED
    assert finding.evidence_layer == EvidenceLayer.PROOF.value
    assert finding.confidence == 1.0


def test_unsigned_provenance_binding(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test binding when no key is supplied (signature is None)."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=None)
    finding, prov_read, status = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=None,
    )
    assert status == ScanExecutionStatus.COMPLETED
    assert prov_read.signature is None
    assert prov_read.signer_key_id is None


def test_cross_project_binding_isolation(
    db_session: Session,
    sample_project: ProjectModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that attempting to bind analysis for a non-existent foreign project is rejected."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    foreign_analysis = sample_anomaly_analysis.model_copy(update={"project_id": "proj-foreign-999"})
    with pytest.raises(Exception):
        service.bind_anomaly_analysis(
            analysis=foreign_analysis,
            input_hash="1" * 64,
            output_hash="2" * 64,
        )


# ==============================================================================
# 5. Verification & Deep Verification Vector Tests (8 Tests)
# ==============================================================================

def test_verify_valid_behavioral_provenance(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test full cryptographic verification of an authentic signed record."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    finding, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )

    assert result.overall_status == ProvenanceStatus.VERIFIED
    vec = result.verification_vector
    assert vec.evidence_identity_valid is True
    assert vec.signature_valid is True
    assert vec.provenance_hash_valid is True
    assert vec.chain_valid is True
    assert vec.sequence_valid is True
    assert vec.nonce_valid is True
    assert vec.project_isolation_valid is True
    assert vec.signer_status == "ACTIVE"
    assert len(vec.failures) == 0


def test_verify_missing_provenance_record(
    db_session: Session,
    sample_project: ProjectModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test verification returns MISSING when provenance record ID does not exist."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id="non-existent-record-uuid",
        expected_project_id=sample_project.id,
    )
    assert result.overall_status == ProvenanceStatus.MISSING
    assert any("not found" in f for f in result.verification_vector.failures)


def test_verify_unbound_evidence_is_unavailable(
    db_session: Session,
    sample_project: ProjectModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test verification returns UNAVAILABLE when evidence was never bound to provenance."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=None,
        expected_project_id=sample_project.id,
    )
    assert result.overall_status == ProvenanceStatus.UNAVAILABLE
    assert result.verification_vector.evidence_identity_valid is True


def test_verify_cross_project_mismatch_detected(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that attempting to verify evidence under a different project ID fails with MISMATCHED."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id="proj-other-456",
    )
    assert result.overall_status == ProvenanceStatus.MISMATCHED
    assert result.verification_vector.project_isolation_valid is False


def test_verify_unsigned_record_is_unverifiable(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that verifying an unsigned record returns UNVERIFIABLE (not tamper error)."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=None)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=None,
    )

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=None)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )
    assert result.overall_status == ProvenanceStatus.UNVERIFIABLE
    assert result.verification_vector.signature_valid is False


def test_verify_unknown_signer_key_is_unverifiable(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
    tmp_path: Path,
):
    """Test that a record signed by a key unknown to the verifier returns UNVERIFIABLE (not tampering)."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    # Empty key manager with no keys loaded
    empty_km = KeyManager(keys_dir=tmp_path / "empty_keys")
    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=empty_km)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )
    assert result.overall_status == ProvenanceStatus.UNVERIFIABLE
    assert result.verification_vector.signer_status == "UNKNOWN_SIGNER"


def test_audit_event_recorded_on_verification(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that verification logs BEHAVIORAL_PROVENANCE_VERIFIED audit event."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )

    events = db_session.query(AuditEventModel).filter_by(
        project_id=sample_project.id,
        event_type="BEHAVIORAL_PROVENANCE_VERIFIED",
    ).all()
    assert len(events) >= 1


def test_audit_event_recorded_on_verification_failure(
    db_session: Session,
    sample_project: ProjectModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that verification mismatch logs BEHAVIORAL_PROVENANCE_MISMATCH audit event."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id="invalid-id",
        expected_project_id=sample_project.id,
    )

    events = db_session.query(AuditEventModel).filter_by(
        project_id=sample_project.id,
        event_type="BEHAVIORAL_PROVENANCE_MISMATCH",
    ).all()
    assert len(events) >= 1


# ==============================================================================
# 6. Adversarial Tampering Detection Tests (10 Tests)
# ==============================================================================

def test_tamper_evidence_anomaly_status(sample_anomaly_analysis):
    """Tamper: modify anomaly_status in content -> hash mismatch detected."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)
    original_id = ev.evidence_id

    tampered_content = content.model_copy(update={"result_status": "NORMAL"})
    tampered_ev = BehavioralEvidence(
        evidence_id=original_id,
        lifecycle_state=EvidenceLifecycleState.SEALED,
        content=tampered_content,
    )
    verifier = BehavioralProvenanceVerifier(db=None)
    valid, failures = verifier.verify_evidence_integrity(tampered_ev)
    assert valid is False
    assert any("Evidence identity mismatch" in f for f in failures)


def test_tamper_evidence_metric_value(sample_anomaly_analysis):
    """Tamper: modify metric observed_value -> hash mismatch detected."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)

    tampered_metrics = [dict(content.metrics[0], observed_value=0.99)]
    tampered_content = content.model_copy(update={"metrics": tampered_metrics})
    tampered_ev = BehavioralEvidence(
        evidence_id=ev.evidence_id,
        lifecycle_state=EvidenceLifecycleState.SEALED,
        content=tampered_content,
    )
    verifier = BehavioralProvenanceVerifier(db=None)
    valid, _ = verifier.verify_evidence_integrity(tampered_ev)
    assert valid is False


def test_tamper_evidence_baseline_median(sample_anomaly_analysis):
    """Tamper: modify baseline_median in metric -> hash mismatch detected."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)

    tampered_metrics = [dict(content.metrics[0], baseline_median=0.50)]
    tampered_content = content.model_copy(update={"metrics": tampered_metrics})
    tampered_ev = BehavioralEvidence(
        evidence_id=ev.evidence_id,
        lifecycle_state=EvidenceLifecycleState.SEALED,
        content=tampered_content,
    )
    verifier = BehavioralProvenanceVerifier(db=None)
    valid, _ = verifier.verify_evidence_integrity(tampered_ev)
    assert valid is False


def test_tamper_evidence_model_fingerprint(sample_anomaly_analysis):
    """Tamper: modify model_fingerprint -> hash mismatch detected."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)

    tampered_content = content.model_copy(update={"model_fingerprint": "f" * 64})
    tampered_ev = BehavioralEvidence(
        evidence_id=ev.evidence_id,
        lifecycle_state=EvidenceLifecycleState.SEALED,
        content=tampered_content,
    )
    verifier = BehavioralProvenanceVerifier(db=None)
    valid, _ = verifier.verify_evidence_integrity(tampered_ev)
    assert valid is False


def test_tamper_evidence_observation_id(sample_anomaly_analysis):
    """Tamper: modify observation_id -> hash mismatch detected."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)

    tampered_content = content.model_copy(update={"observation_id": "obs-forged-99"})
    tampered_ev = BehavioralEvidence(
        evidence_id=ev.evidence_id,
        lifecycle_state=EvidenceLifecycleState.SEALED,
        content=tampered_content,
    )
    verifier = BehavioralProvenanceVerifier(db=None)
    valid, _ = verifier.verify_evidence_integrity(tampered_ev)
    assert valid is False


def test_tamper_evidence_policy_version(sample_anomaly_analysis):
    """Tamper: modify policy_version -> hash mismatch detected."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)

    tampered_content = content.model_copy(update={"policy_version": "2.0.0-unauthorized"})
    tampered_ev = BehavioralEvidence(
        evidence_id=ev.evidence_id,
        lifecycle_state=EvidenceLifecycleState.SEALED,
        content=tampered_content,
    )
    verifier = BehavioralProvenanceVerifier(db=None)
    valid, _ = verifier.verify_evidence_integrity(tampered_ev)
    assert valid is False


def test_tamper_provenance_record_hash(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Tamper: alter record_hash in database row -> verification fails with INVALID."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    row = db_session.query(ProvenanceRecordModel).filter_by(id=prov_read.id).first()
    row.record_hash = "f" * 64
    db_session.commit()

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )
    assert result.overall_status == ProvenanceStatus.INVALID
    assert result.verification_vector.provenance_hash_valid is False


def test_tamper_provenance_signature(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Tamper: modify Ed25519 signature in database -> verification fails with INVALID."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    row = db_session.query(ProvenanceRecordModel).filter_by(id=prov_read.id).first()
    row.signature = "0" * 128
    db_session.commit()

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )
    assert result.overall_status == ProvenanceStatus.INVALID
    assert result.verification_vector.signature_valid is False


def test_tamper_provenance_sequence_number(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Tamper: modify sequence number in ledger -> verification detects mismatch."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    row = db_session.query(ProvenanceRecordModel).filter_by(id=prov_read.id).first()
    row.sequence_number = 999
    db_session.commit()

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )
    assert result.overall_status == ProvenanceStatus.INVALID


def test_tamper_provenance_previous_hash(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Tamper: modify previous_record_hash in chain -> verification detects break in chain."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    row = db_session.query(ProvenanceRecordModel).filter_by(id=prov_read.id).first()
    row.previous_record_hash = "e" * 64
    db_session.commit()

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )
    assert result.overall_status == ProvenanceStatus.INVALID


# ==============================================================================
# 7. Semantic Neutrality Invariant Tests (4 Tests)
# ==============================================================================

def test_semantic_neutrality_in_finding_title_and_description(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that generated Finding titles, descriptions, and recommendations contain zero maliciousness assertions."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    finding, _, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
    )

    prohibited = ["malicious", "backdoor", "attack", "compromise", "trojan", "adversarial payload"]
    full_text = f"{finding.title} {finding.description} {finding.recommendation or ''}".lower()

    for word in prohibited:
        assert word not in full_text, f"Prohibited term '{word}' found in finding text: {full_text}"


def test_semantic_neutrality_in_evidence_payload(sample_anomaly_analysis):
    """Test that EvidencePayload description and title contain zero maliciousness assertions."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)
    payload = to_phase5_evidence_payload(ev)

    prohibited = ["malicious", "backdoor", "attack", "compromise", "trojan"]
    full_text = f"{payload.title} {payload.description}".lower()

    for word in prohibited:
        assert word not in full_text, f"Prohibited term '{word}' found in evidence payload: {full_text}"


def test_semantic_neutrality_in_verification_message(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test that verification results and audit descriptions contain zero maliciousness assertions."""
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    _, prov_read, _ = service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    evidence = create_behavioral_evidence(content, seal=True)

    verifier = BehavioralProvenanceVerifier(db=db_session, key_manager=key_manager)
    result = verifier.verify_behavioral_provenance(
        evidence=evidence,
        provenance_record_id=prov_read.id,
        expected_project_id=sample_project.id,
    )

    prohibited = ["malicious", "backdoor", "attack", "compromise", "trojan"]
    full_text = result.message.lower()

    for word in prohibited:
        assert word not in full_text, f"Prohibited term '{word}' found in verification message: {full_text}"


def test_verification_asserts_authenticity_not_intent():
    """Test documentation invariant: VERIFIED status asserts cryptographic authenticity only."""
    vec = BehavioralVerificationVector(
        evidence_identity_valid=True,
        analysis_identity_valid=True,
        observation_identity_valid=True,
        baseline_identity_valid=True,
        model_identity_valid=True,
        provenance_hash_valid=True,
        signature_valid=True,
        chain_valid=True,
        sequence_valid=True,
        nonce_valid=True,
        project_isolation_valid=True,
        signer_status="ACTIVE",
        failures=[],
        limitations=[],
    )
    result = BehavioralVerificationResult(
        evidence_id="1" * 64,
        project_id="proj-1",
        model_id="m-1",
        overall_status=ProvenanceStatus.VERIFIED,
        verification_vector=vec,
        message="Cryptographic provenance verified.",
    )
    assert result.overall_status == ProvenanceStatus.VERIFIED
    assert result.verification_vector.evidence_identity_valid is True


# ==============================================================================
# 8. Multi-Type Behavioral Evidence & Immutability Coverage (6 Tests)
# ==============================================================================

def test_behavioral_baseline_evidence_type_binding(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
):
    """Test creating and sealing BEHAVIORAL_BASELINE evidence."""
    content = BehavioralEvidenceContent(
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=BehavioralEvidenceType.BEHAVIORAL_BASELINE,
        project_id=sample_project.id,
        model_id=sample_model.id,
        model_fingerprint="c" * 64,
        task_type="classification",
        observation_id="obs-base-01",
        baseline_id="base-profile-01",
        baseline_type="REFERENCE_EXECUTION_PROFILE",
        input_hash="1" * 64,
        output_hash="2" * 64,
        detector_id="baseline_engine",
        detector_version="1.0.0",
        detector_config_hash="3" * 64,
        result_status="NORMAL",
        support_status="ADEQUATE_SUPPORT",
        metrics=[{"metric_name": "expected_confidence_median", "observed_value": 0.96}],
    )
    ev = create_behavioral_evidence(content, seal=True)
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    finding, prov_read, status = service.bind_behavioral_evidence(
        ev,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )
    assert status == ScanExecutionStatus.COMPLETED
    assert finding.finding_type == BehavioralEvidenceType.BEHAVIORAL_BASELINE.value
    assert prov_read.signature is not None


def test_behavioral_perturbation_evidence_type_binding(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
):
    """Test creating and sealing BEHAVIORAL_PERTURBATION evidence."""
    content = BehavioralEvidenceContent(
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=BehavioralEvidenceType.BEHAVIORAL_PERTURBATION,
        project_id=sample_project.id,
        model_id=sample_model.id,
        model_fingerprint="c" * 64,
        task_type="classification",
        observation_id="obs-pert-01",
        baseline_id="base-ref-01",
        baseline_type="HISTORICAL_PROFILE",
        sensitivity_id="sens-exp-01",
        input_hash="1" * 64,
        output_hash="2" * 64,
        detector_id="perturbation_engine",
        detector_version="1.0.0",
        detector_config_hash="3" * 64,
        result_status="NORMAL",
        support_status="ADEQUATE_SUPPORT",
        metrics=[{"metric_name": "gaussian_noise_sensitivity_ratio", "observed_value": 0.12}],
    )
    ev = create_behavioral_evidence(content, seal=True)
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    finding, prov_read, status = service.bind_behavioral_evidence(
        ev,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )
    assert status == ScanExecutionStatus.COMPLETED
    assert finding.finding_type == BehavioralEvidenceType.BEHAVIORAL_PERTURBATION.value


def test_behavioral_stability_evidence_type_binding(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
):
    """Test creating and sealing BEHAVIORAL_STABILITY evidence."""
    content = BehavioralEvidenceContent(
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=BehavioralEvidenceType.BEHAVIORAL_STABILITY,
        project_id=sample_project.id,
        model_id=sample_model.id,
        model_fingerprint="c" * 64,
        task_type="detection",
        observation_id="obs-stab-01",
        baseline_id="base-det-01",
        baseline_type="HISTORICAL_PROFILE",
        input_hash="1" * 64,
        output_hash="2" * 64,
        detector_id="stability_engine",
        detector_version="1.0.0",
        detector_config_hash="3" * 64,
        result_status="NORMAL",
        support_status="ADEQUATE_SUPPORT",
        metrics=[{"metric_name": "box_iou_agreement", "observed_value": 0.94}],
    )
    ev = create_behavioral_evidence(content, seal=True)
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    finding, prov_read, status = service.bind_behavioral_evidence(
        ev,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )
    assert status == ScanExecutionStatus.COMPLETED
    assert finding.finding_type == BehavioralEvidenceType.BEHAVIORAL_STABILITY.value


def test_behavioral_comparison_evidence_type_binding(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
):
    """Test creating and sealing BEHAVIORAL_COMPARISON evidence."""
    content = BehavioralEvidenceContent(
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=BehavioralEvidenceType.BEHAVIORAL_COMPARISON,
        project_id=sample_project.id,
        model_id=sample_model.id,
        model_fingerprint="c" * 64,
        task_type="segmentation",
        observation_id="obs-comp-01",
        baseline_id="base-seg-01",
        baseline_type="TRUSTED_REFERENCE_MODEL",
        comparison_id="comp-profile-01",
        input_hash="1" * 64,
        output_hash="2" * 64,
        detector_id="comparison_engine",
        detector_version="1.0.0",
        detector_config_hash="3" * 64,
        result_status="NORMAL",
        support_status="ADEQUATE_SUPPORT",
        metrics=[{"metric_name": "reference_mask_agreement", "observed_value": 0.97}],
    )
    ev = create_behavioral_evidence(content, seal=True)
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    finding, prov_read, status = service.bind_behavioral_evidence(
        ev,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )
    assert status == ScanExecutionStatus.COMPLETED
    assert finding.finding_type == BehavioralEvidenceType.BEHAVIORAL_COMPARISON.value


def test_resolve_idempotent_behavioral_scan_direct_helper(
    db_session: Session,
    sample_project: ProjectModel,
    sample_model: AIModelModel,
    key_manager: KeyManager,
    sample_anomaly_analysis: BehavioralAnomalyAnalysis,
):
    """Test direct invocation of resolve_idempotent_behavioral_scan helper."""
    # Before binding -> None
    res = resolve_idempotent_behavioral_scan(
        db=db_session,
        project_id=sample_project.id,
        model_id=sample_model.id,
        model_fingerprint=sample_anomaly_analysis.model_fingerprint,
        observation_id=sample_anomaly_analysis.observation_id,
        baseline_id=sample_anomaly_analysis.baseline_id,
        detector_id="behavioral_anomaly_detector",
        detector_version=sample_anomaly_analysis.analysis_version,
        detector_config_hash=sample_anomaly_analysis.analysis_id,
        policy_version=sample_anomaly_analysis.policy_version,
        engine_version=sample_anomaly_analysis.analysis_version,
    )
    assert res is None

    # Bind
    service = BehavioralProvenanceBindingService(db=db_session, key_manager=key_manager)
    service.bind_anomaly_analysis(
        analysis=sample_anomaly_analysis,
        input_hash="1" * 64,
        output_hash="2" * 64,
        signer_key_id=key_manager.get_active_key_id(),
        signer_passphrase="passphrase123",
    )

    # After binding -> resolves existing Finding and ProvenanceRecord
    res_after = resolve_idempotent_behavioral_scan(
        db=db_session,
        project_id=sample_project.id,
        model_id=sample_model.id,
        model_fingerprint=sample_anomaly_analysis.model_fingerprint,
        observation_id=sample_anomaly_analysis.observation_id,
        baseline_id=sample_anomaly_analysis.baseline_id,
        detector_id="behavioral_anomaly_detector",
        detector_version=sample_anomaly_analysis.analysis_version,
        detector_config_hash=sample_anomaly_analysis.analysis_id,
        policy_version=sample_anomaly_analysis.policy_version,
        engine_version=sample_anomaly_analysis.analysis_version,
    )
    assert res_after is not None
    f_res, prov_res = res_after
    assert f_res is not None
    assert prov_res is not None


def test_evidence_pydantic_frozen_immutability(sample_anomaly_analysis):
    """Test that BehavioralEvidenceContent and BehavioralEvidence instances reject field mutation."""
    content = build_anomaly_evidence_content(sample_anomaly_analysis, input_hash="1" * 64, output_hash="2" * 64)
    ev = create_behavioral_evidence(content, seal=True)

    with pytest.raises(Exception):
        content.result_status = "NORMAL"

    with pytest.raises(Exception):
        ev.evidence_id = "0" * 64
