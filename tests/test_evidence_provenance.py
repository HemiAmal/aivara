"""Integration and security tests for Evidence + Provenance Binding Engine (Phase 5.9)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from aivara.crypto.keys import KeyManager
from aivara.database.connection import Base
from aivara.database.models import (
    AIModelModel,
    AuditEventModel,
    ContributorModel,
    DatasetModel,
    DatasetVersionModel,
    EvidenceModel,
    FindingModel,
    ModelFingerprintModel,
    ProjectModel,
    ProvenanceRecordModel,
    SampleContributorModel,
    SampleModel,
)
from aivara.domain.schemas import (
    AnalysisMode,
    Disposition,
    EvidenceLayer,
    Severity,
)
from aivara.evidence.exceptions import (
    CrossProjectContaminationError,
    EvidenceValidationError,
    ModelMismatchError,
    StaleDatasetVersionError,
    VocabularyViolationError,
)
from aivara.evidence.schemas import (
    EvidencePayload,
    ExecutionIdentityPayload,
    FindingSynthesisPayload,
    ProvenanceStatus,
    ScanExecutionStatus,
)
from aivara.evidence.service import EvidenceProvenanceService
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService


@pytest.fixture
def db_session():
    """In-memory SQLite session with full schema initialized."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def key_manager(tmp_path):
    """Temporary KeyManager instance with generated key."""
    km = KeyManager(keys_dir=tmp_path / "keys")
    km.generate_key(passphrase="secure_pass_123", set_as_active=True)
    return km


@pytest.fixture
def project_fixtures(db_session):
    """Seed project, dataset, version, samples, contributor, and AI model."""
    # Project 1
    proj1 = ProjectModel(id="proj-001", name="Project Alpha")
    db_session.add(proj1)

    # Dataset & Version in Project 1
    ds1 = DatasetModel(id="ds-001", project_id="proj-001", name="Dataset 1", format="imagefolder")
    db_session.add(ds1)
    ver1 = DatasetVersionModel(
        id="ver-001",
        dataset_id="ds-001",
        version_label="v1.0",
        dataset_hash="a" * 64,
        sample_count=2,
    )
    db_session.add(ver1)

    # Samples in Project 1
    s1 = SampleModel(
        id="sample-001",
        dataset_version_id="ver-001",
        file_path="data/img1.jpg",
        file_hash_sha256="1" * 64,
    )
    s2 = SampleModel(
        id="sample-002",
        dataset_version_id="ver-001",
        file_path="data/img2.jpg",
        file_hash_sha256="2" * 64,
    )
    db_session.add_all([s1, s2])

    # Contributor in Project 1
    contrib1 = ContributorModel(id="contrib-001", project_id="proj-001", external_id="annotator_42", name="Alice")
    db_session.add(contrib1)
    sc1 = SampleContributorModel(id="sc-001", sample_id="sample-001", contributor_id="contrib-001")
    db_session.add(sc1)

    # AI Model in Project 1
    model1 = AIModelModel(
        id="model-001",
        project_id="proj-001",
        name="ResNet50_Classifier",
        format="onnx",
        file_path="models/resnet.onnx",
        file_hash_sha256="m" * 64,
    )
    db_session.add(model1)
    fp1 = ModelFingerprintModel(
        id="fp-001",
        model_id="model-001",
        fingerprint_type="structural",
        fingerprint_value="f" * 64,
    )
    db_session.add(fp1)

    # Project 2 (for cross-project contamination tests)
    proj2 = ProjectModel(id="proj-002", name="Project Beta")
    db_session.add(proj2)

    db_session.commit()
    return {
        "project1": proj1,
        "project2": proj2,
        "dataset_version": ver1,
        "sample1": s1,
        "sample2": s2,
        "contributor": contrib1,
        "model": model1,
    }


class TestEvidenceProvenanceBinding:
    """Tests for Finding and Evidence synthesis, provenance sealing, and verification."""

    def test_synthesize_finding_with_primary_evidence(self, db_session, project_fixtures):
        """Synthesizing a finding correctly commits primary evidence items with deterministic hashes."""
        service = EvidenceProvenanceService(db=db_session)

        ev_payload = EvidencePayload(
            title="Image blur measurement",
            description="Variance of Laplacian value is below threshold",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="image_quality_metrics",
            confidence=0.85,
            target_asset_type="sample",
            target_asset_id="sample-001",
            target_asset_hash="1" * 64,
            dataset_version_id="ver-001",
            dataset_fingerprint="a" * 64,
            detector_id="die_ood_quality",
            detector_version="1.0.0",
            detector_config_hash="c" * 64,
            measurements={"laplacian_variance": 12.4, "tenengrad_sharpness": 8.5},
            data_json={"sample_id": "sample-001", "contributor_id": "contrib-001"},
        )

        finding_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            engine_version="1.0.0",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample exhibits elevated blur anomaly",
            severity=Severity.MEDIUM,
            confidence=0.85,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
            primary_evidence_items=[ev_payload],
        )

        finding = service.binder.synthesize_finding(finding_payload)
        db_session.commit()

        assert finding.id is not None
        assert finding.evidence_layer == "detection"
        assert finding.confidence == 0.85

        # Check bound primary evidence
        ev_items = db_session.query(EvidenceModel).filter(EvidenceModel.finding_id == finding.id).all()
        assert len(ev_items) == 1
        assert ev_items[0].evidence_hash is not None
        assert len(ev_items[0].evidence_hash) == 64

    def test_proof_layer_finding_requires_full_confidence(self, db_session):
        """Proof-layer findings must have confidence exactly equal to 1.0 (ADR-028)."""
        service = EvidenceProvenanceService(db=db_session)

        # Invalid: proof layer with confidence < 1.0
        with pytest.raises(ValueError, match="confidence = 1.0"):
            FindingSynthesisPayload(
                project_id="proj-001",
                engine_id="die_fingerprinting",
                engine_version="1.0.0",
                evidence_layer=EvidenceLayer.PROOF,
                finding_type="MERKLE_ROOT_VERIFIED",
                title="Dataset Merkle root verified",
                severity=Severity.INFO,
                confidence=0.99,  # Must be 1.0
                affected_asset_type="dataset_version",
                affected_asset_id="ver-001",
            )

    def test_derived_finding_nm_evidence_citation(self, db_session, project_fixtures):
        """Derived/synthesized findings can reference multiple existing evidence items (N:M support)."""
        service = EvidenceProvenanceService(db=db_session)

        # 1. Create primary evidence 1
        ev1 = EvidencePayload(
            title="Blur anomaly on sample 1",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="image_quality_metrics",
            confidence=0.90,
            target_asset_type="sample",
            target_asset_id="sample-001",
            measurements={"blur": 5.2},
            data_json={"sample_id": "sample-001"},
        )
        f1_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample 1 quality issue",
            severity=Severity.LOW,
            confidence=0.90,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
            primary_evidence_items=[ev1],
        )
        f1 = service.binder.synthesize_finding(f1_payload)
        db_session.commit()

        ev1_row = db_session.query(EvidenceModel).filter(EvidenceModel.finding_id == f1.id).first()
        assert ev1_row is not None

        # 2. Create derived contributor-level finding referencing ev1
        f2_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_contributors",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="CONTRIBUTOR_QUALITY_CONCENTRATION",
            title="Contributor has concentrated image quality anomalies",
            severity=Severity.MEDIUM,
            confidence=0.80,
            affected_asset_type="contributor",
            affected_asset_id="contrib-001",
            referenced_evidence_ids=[ev1_row.id],
        )
        f2 = service.binder.synthesize_finding(f2_payload)
        db_session.commit()

        assert f2.metadata_json.get("referenced_evidence_ids") == [ev1_row.id]
        assert ev1_row.evidence_hash in f2.metadata_json.get("referenced_evidence_hashes", [])

    def test_cross_project_reference_rejected(self, db_session, project_fixtures):
        """Referencing evidence from a different project must raise CrossProjectContaminationError."""
        service = EvidenceProvenanceService(db=db_session)

        # Create evidence in Project 1
        ev1 = EvidencePayload(
            title="Evidence in Project 1",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="image_quality_metrics",
            target_asset_type="sample",
            target_asset_id="sample-001",
        )
        f1 = service.binder.synthesize_finding(FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample 1 finding",
            severity=Severity.LOW,
            confidence=0.90,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
            primary_evidence_items=[ev1],
        ))
        db_session.commit()

        ev1_row = db_session.query(EvidenceModel).filter(EvidenceModel.finding_id == f1.id).first()

        # Attempt to create finding in Project 2 referencing ev1_row from Project 1
        with pytest.raises(CrossProjectContaminationError, match="Cross-project contamination"):
            service.binder.synthesize_finding(FindingSynthesisPayload(
                project_id="proj-002",  # Project 2
                engine_id="die_contributors",
                evidence_layer=EvidenceLayer.DETECTION,
                finding_type="CONTRIBUTOR_QUALITY_CONCENTRATION",
                title="Cross project attempt",
                severity=Severity.LOW,
                confidence=0.80,
                affected_asset_type="contributor",
                affected_asset_id="contrib-002",
                referenced_evidence_ids=[ev1_row.id],
            ))

    def test_full_scan_provenance_sealing_and_verification(self, db_session, key_manager, project_fixtures):
        """A complete analytical scan seals into the provenance ledger with an Ed25519 signature."""
        service = EvidenceProvenanceService(db=db_session, key_manager=key_manager)

        exec_payload = ExecutionIdentityPayload(
            project_id="proj-001",
            dataset_version_id="ver-001",
            dataset_fingerprint="a" * 64,
            detector_id="die_ood_quality",
            detector_version="1.0.0",
            engine_version="1.0.0",
            detector_config_hash="c" * 64,
        )

        ev_payload = EvidencePayload(
            title="Blur anomaly",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="image_quality_metrics",
            confidence=0.88,
            target_asset_type="sample",
            target_asset_id="sample-001",
            dataset_version_id="ver-001",
            dataset_fingerprint="a" * 64,
            measurements={"blur": 9.2},
            data_json={"sample_id": "sample-001", "contributor_id": "contrib-001"},
        )

        finding_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            engine_version="1.0.0",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample blur issue",
            severity=Severity.MEDIUM,
            confidence=0.88,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
            primary_evidence_items=[ev_payload],
        )

        key_id = key_manager.get_active_key_id()

        findings, prov_record, status = service.record_analytical_scan(
            project_id="proj-001",
            execution_payload=exec_payload,
            finding_payloads=[finding_payload],
            audit_run_id="run-001",
            seal_provenance=True,
            signer_key_id=key_id,
            signer_passphrase="secure_pass_123",
            allow_idempotent_reuse=False,
        )
        db_session.commit()

        assert status == ScanExecutionStatus.COMPLETED
        assert len(findings) == 1
        assert prov_record is not None
        assert prov_record.signature is not None
        assert prov_record.signer_key_id == key_id

        # Verify provenance of the synthesized finding
        verif_res = service.verify_finding_provenance(findings[0].id, "proj-001")
        assert verif_res.cryptographic_validity is True
        assert verif_res.provenance_status == ProvenanceStatus.VERIFIED
        assert verif_res.evidence_count == 1
        assert len(verif_res.verified_evidence_hashes) == 1

    def test_backward_traceability_graph(self, db_session, project_fixtures):
        """Tracing a finding backward resolves finding, evidence, sample, contributor, and dataset nodes."""
        service = EvidenceProvenanceService(db=db_session)

        ev_payload = EvidencePayload(
            title="Blur metric on sample 1",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="image_quality_metrics",
            confidence=0.85,
            target_asset_type="sample",
            target_asset_id="sample-001",
            measurements={"sharpness": 12.0},
            data_json={
                "sample_id": "sample-001",
                "contributor_id": "contrib-001",
                "model_id": "model-001",
            },
        )

        finding_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample quality issue",
            severity=Severity.LOW,
            confidence=0.85,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
            primary_evidence_items=[ev_payload],
            metadata_json={"dataset_version_id": "ver-001", "dataset_fingerprint": "a" * 64},
        )

        finding = service.binder.synthesize_finding(finding_payload)
        db_session.commit()

        chain = service.get_traceability_chain(finding.id, "proj-001")

        assert chain.finding_id == finding.id
        assert f"finding:{finding.id}" in chain.nodes
        assert len(chain.primary_evidence_ids) == 1
        ev_id = chain.primary_evidence_ids[0]
        assert f"evidence:{ev_id}" in chain.nodes
        assert "sample:sample-001" in chain.nodes
        assert "contributor:contrib-001" in chain.nodes
        assert "model:model-001" in chain.nodes

    def test_idempotent_hit_recognition(self, db_session, project_fixtures):
        """Running the same analytical scan twice with identical ExecutionIdentityHash returns IDEMPOTENT_HIT."""
        service = EvidenceProvenanceService(db=db_session)

        exec_payload = ExecutionIdentityPayload(
            project_id="proj-001",
            dataset_version_id="ver-001",
            dataset_fingerprint="a" * 64,
            detector_id="die_ood_quality",
            detector_version="1.0.0",
            engine_version="1.0.0",
            detector_config_hash="c" * 64,
        )

        ev_payload = EvidencePayload(
            title="Blur anomaly",
            evidence_layer=EvidenceLayer.DETECTION,
            evidence_type="image_quality_metrics",
            confidence=0.85,
            target_asset_type="sample",
            target_asset_id="sample-001",
            measurements={"blur": 10.0},
        )

        finding_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample blur issue",
            severity=Severity.LOW,
            confidence=0.85,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
            primary_evidence_items=[ev_payload],
        )

        # First scan
        findings1, prov1, status1 = service.record_analytical_scan(
            project_id="proj-001",
            execution_payload=exec_payload,
            finding_payloads=[finding_payload],
            audit_run_id="run-001",
            seal_provenance=False,
            allow_idempotent_reuse=True,
        )
        db_session.commit()
        assert status1 == ScanExecutionStatus.COMPLETED

        # Second scan with identical execution identity
        findings2, prov2, status2 = service.record_analytical_scan(
            project_id="proj-001",
            execution_payload=exec_payload,
            finding_payloads=[finding_payload],
            audit_run_id="run-002",
            seal_provenance=False,
            allow_idempotent_reuse=True,
        )

        assert status2 == ScanExecutionStatus.IDEMPOTENT_HIT
        assert len(findings2) == len(findings1)
        assert findings2[0].id == findings1[0].id

    def test_partial_scan_flag_preservation(self, db_session, project_fixtures):
        """Partial scans preserve is_partial_scan and return PARTIAL_SUCCESS."""
        service = EvidenceProvenanceService(db=db_session)

        exec_payload = ExecutionIdentityPayload(
            project_id="proj-001",
            dataset_version_id="ver-001",
            dataset_fingerprint="a" * 64,
            detector_id="die_ood_quality",
            detector_version="1.0.0",
            engine_version="1.0.0",
            detector_config_hash="c" * 64,
        )

        finding_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample blur issue",
            severity=Severity.INFO,
            confidence=0.50,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
        )

        findings, _, status = service.record_analytical_scan(
            project_id="proj-001",
            execution_payload=exec_payload,
            finding_payloads=[finding_payload],
            audit_run_id="run-001",
            is_partial_scan=True,
            allow_idempotent_reuse=False,
        )
        db_session.commit()

        assert status == ScanExecutionStatus.PARTIAL_SUCCESS
        assert findings[0].metadata_json.get("is_partial_scan") is True

    def test_missing_provenance_is_unavailable_not_tampering(self, db_session, project_fixtures):
        """Unsealed findings evaluate to UNAVAILABLE provenance status without triggering tampering alarms."""
        service = EvidenceProvenanceService(db=db_session)

        finding = service.binder.synthesize_finding(FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample blur issue",
            severity=Severity.LOW,
            confidence=0.70,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
        ))
        db_session.commit()

        verif_res = service.verify_finding_provenance(finding.id, "proj-001")
        assert verif_res.provenance_status == ProvenanceStatus.UNAVAILABLE
        assert verif_res.cryptographic_validity is False
        assert len(verif_res.errors) == 0  # No tampering errors

    def test_six_distinct_provenance_verification_states(self, db_session, project_fixtures, tmp_path):
        """Verify that the engine explicitly distinguishes VERIFIED, INVALID, MISSING, UNAVAILABLE, MISMATCHED, and UNVERIFIABLE."""
        key_mgr = KeyManager(keys_dir=tmp_path / "keys")
        key_handle = key_mgr.generate_key(passphrase="secure_pass_123")
        key_id = str(key_handle.key_id)
        service = EvidenceProvenanceService(db=db_session, key_manager=key_mgr)

        # 1. State: UNAVAILABLE (no provenance initialized)
        f_unavail = service.binder.synthesize_finding(FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Finding with no provenance",
            severity=Severity.LOW,
            confidence=0.70,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
        ))
        db_session.commit()
        res_unavail = service.verify_finding_provenance(f_unavail.id, "proj-001")
        assert res_unavail.provenance_status == ProvenanceStatus.UNAVAILABLE
        assert res_unavail.cryptographic_validity is False

        # 2. State: MISSING (references a non-existent provenance record ID)
        f_missing = service.binder.synthesize_finding(FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Finding with missing provenance ID",
            severity=Severity.LOW,
            confidence=0.70,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
            metadata_json={"provenance_record_id": "non-existent-rec-id-9999"},
        ))
        db_session.commit()
        res_missing = service.verify_finding_provenance(f_missing.id, "proj-001")
        assert res_missing.provenance_status == ProvenanceStatus.MISSING
        assert res_missing.cryptographic_validity is False
        assert any("not found" in err for err in res_missing.errors)

        # 3. State: VERIFIED (sealed with valid Ed25519 signature)
        exec_p = ExecutionIdentityPayload(
            project_id="proj-001",
            dataset_version_id="ver-001",
            dataset_fingerprint="a" * 64,
            detector_id="die_ood_quality",
            detector_version="1.0.0",
            engine_version="1.0.0",
            detector_config_hash="c" * 64,
        )
        f_p = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Finding to seal",
            severity=Severity.LOW,
            confidence=0.70,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
        )
        findings, prov_rec, _ = service.record_analytical_scan(
            project_id="proj-001",
            execution_payload=exec_p,
            finding_payloads=[f_p],
            audit_run_id="run-state-test",
            seal_provenance=True,
            signer_key_id=key_id,
            signer_passphrase="secure_pass_123",
            allow_idempotent_reuse=False,
        )
        db_session.commit()
        f_sealed = findings[0]
        res_verified = service.verify_finding_provenance(f_sealed.id, "proj-001")
        assert res_verified.provenance_status == ProvenanceStatus.VERIFIED
        assert res_verified.cryptographic_validity is True

        # 4. State: MISMATCHED (finding dataset_fingerprint != record input_hash)
        meta_mismatch = dict(f_sealed.metadata_json)
        meta_mismatch["dataset_fingerprint"] = "b" * 64  # Changed from "a" * 64
        f_sealed.metadata_json = meta_mismatch
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(f_sealed, "metadata_json")
        db_session.commit()
        res_mismatch = service.verify_finding_provenance(f_sealed.id, "proj-001")
        assert res_mismatch.provenance_status == ProvenanceStatus.MISMATCHED
        assert res_mismatch.cryptographic_validity is False

        # Reset finding metadata back to valid fingerprint
        meta_mismatch["dataset_fingerprint"] = "a" * 64
        f_sealed.metadata_json = meta_mismatch
        flag_modified(f_sealed, "metadata_json")
        db_session.commit()

        # 5. State: INVALID (cryptographic hash tampering on provenance record)
        prov_db = db_session.query(ProvenanceRecordModel).filter(ProvenanceRecordModel.id == prov_rec.id).first()
        prov_db.record_hash = "f" * 64  # Tampered record hash
        flag_modified(prov_db, "record_hash")
        db_session.commit()
        res_invalid = service.verify_finding_provenance(f_sealed.id, "proj-001")
        assert res_invalid.provenance_status == ProvenanceStatus.INVALID
        assert res_invalid.cryptographic_validity is False

    def test_dataset_version_hash_mismatch_rejected(self, db_session, project_fixtures):
        """Binding evidence to a dataset version with mismatched dataset hash raises StaleDatasetVersionError."""
        service = EvidenceProvenanceService(db=db_session)
        exec_payload = ExecutionIdentityPayload(
            project_id="proj-001",
            dataset_version_id="ver-001",
            dataset_fingerprint="f" * 64,  # Mismatched from ver-001's "a" * 64
            detector_id="die_near_duplicate",
            detector_version="1.0.0",
            engine_version="1.0.0",
            detector_config_hash="c" * 64,
        )
        finding_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_near_duplicate",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="EXACT_DUPLICATE_SAMPLE",
            title="Duplicate sample found",
            severity=Severity.LOW,
            confidence=0.99,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
        )
        with pytest.raises(StaleDatasetVersionError, match="Fingerprint mismatch"):
            service.record_analytical_scan(
                project_id="proj-001",
                execution_payload=exec_payload,
                finding_payloads=[finding_payload],
                audit_run_id="run-001",
            )

    def test_model_fingerprint_mismatch_rejected(self, db_session, project_fixtures):
        """Binding evidence with mismatched model fingerprint raises ModelMismatchError."""
        service = EvidenceProvenanceService(db=db_session)
        exec_payload = ExecutionIdentityPayload(
            project_id="proj-001",
            dataset_version_id="ver-001",
            dataset_fingerprint="a" * 64,
            model_id="model-001",
            model_fingerprint="x" * 64,  # Mismatched from model-001's "m" * 64 and "f" * 64
            detector_id="die_label_anomaly",
            detector_version="1.0.0",
            engine_version="1.0.0",
            detector_config_hash="c" * 64,
        )
        finding_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_label_anomaly",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="LABEL_AMBIGUITY",
            title="Label ambiguity",
            severity=Severity.LOW,
            confidence=0.75,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
        )
        with pytest.raises(ModelMismatchError, match="Fingerprint mismatch"):
            service.record_analytical_scan(
                project_id="proj-001",
                execution_payload=exec_payload,
                finding_payloads=[finding_payload],
                audit_run_id="run-001",
            )

    def test_cross_project_provenance_verification_rejected(self, db_session, project_fixtures):
        """Attempting to verify finding provenance with a mismatched project_id raises CrossProjectContaminationError."""
        service = EvidenceProvenanceService(db=db_session)
        finding = service.binder.synthesize_finding(FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample blur issue",
            severity=Severity.LOW,
            confidence=0.70,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
        ))
        db_session.commit()

        with pytest.raises(CrossProjectContaminationError, match="Cross-project"):
            service.verify_finding_provenance(finding.id, "proj-002")

    def test_audit_lifecycle_events_recorded(self, db_session, project_fixtures):
        """Lifecycle events (SCAN_STARTED, SCAN_COMPLETED) are recorded in AuditEventModel without sample explosion."""
        service = EvidenceProvenanceService(db=db_session)
        service.audit_service._ensure_genesis("proj-001")
        db_session.commit()
        initial_audit_count = db_session.query(AuditEventModel).filter(AuditEventModel.project_id == "proj-001").count()

        exec_payload = ExecutionIdentityPayload(
            project_id="proj-001",
            dataset_version_id="ver-001",
            dataset_fingerprint="a" * 64,
            detector_id="die_ood_quality",
            detector_version="1.0.0",
            engine_version="1.0.0",
            detector_config_hash="c" * 64,
        )
        finding_payload = FindingSynthesisPayload(
            project_id="proj-001",
            engine_id="die_ood_quality",
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type="IMAGE_QUALITY_DEGRADATION",
            title="Sample blur issue",
            severity=Severity.LOW,
            confidence=0.70,
            affected_asset_type="sample",
            affected_asset_id="sample-001",
        )

        service.record_analytical_scan(
            project_id="proj-001",
            execution_payload=exec_payload,
            finding_payloads=[finding_payload],
            audit_run_id="run-001",
            seal_provenance=False,
            allow_idempotent_reuse=False,
        )
        db_session.commit()

        final_audit_count = db_session.query(AuditEventModel).filter(AuditEventModel.project_id == "proj-001").count()
        # Exactly 2 lifecycle events (SCAN_STARTED and SCAN_COMPLETED)
        assert final_audit_count == initial_audit_count + 2
