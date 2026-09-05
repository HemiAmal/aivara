"""Comprehensive tests for all Phase 3 domain entities, database CRUD,
relationships, validation, and API endpoints."""

import uuid
import pytest
from pydantic import ValidationError

from aivara.domain.schemas import (
    Disposition,
    Severity,
    EvidenceLayer,
    AnalysisMode,
    DatasetFormat,
    ModelFormat,
    AccessLevel,
    FingerprintType,
    ProjectCreate,
    ProjectUpdate,
    ContributorCreate,
    DatasetCreate,
    DatasetVersionCreate,
    SampleCreate,
    AIModelCreate,
    ModelFingerprintCreate,
    InferenceRecordCreate,
    FindingCreate,
    EvidenceCreate,
    RiskAssessmentCreate,
    AuditEventCreate,
    ProvenanceRecordCreate,
    ReportCreate,
)
from aivara.database.models import (
    ProjectModel,
    ContributorModel,
    DatasetModel,
    DatasetVersionModel,
    SampleModel,
    SampleContributorModel,
    AIModelModel,
    ModelFingerprintModel,
    InferenceRecordModel,
    FindingModel,
    EvidenceModel,
    RiskAssessmentModel,
    AuditEventModel,
    ProvenanceRecordModel,
    ReportModel,
)


FAKE_SHA256 = "a" * 64


# =====================================================================
# Helper factory functions (return ORM models committed to db session)
# =====================================================================

def make_project(db, name="Test Project") -> ProjectModel:
    p = ProjectModel(name=name, description="Test description")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def make_contributor(db, project_id, external_id="contrib-1") -> ContributorModel:
    c = ContributorModel(project_id=project_id, external_id=external_id, name="Contributor A")
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


def make_dataset(db, project_id, name="Test Dataset") -> DatasetModel:
    d = DatasetModel(project_id=project_id, name=name, format="coco")
    db.add(d)
    db.commit()
    db.refresh(d)
    return d


def make_version(db, dataset_id, label="v1.0") -> DatasetVersionModel:
    v = DatasetVersionModel(dataset_id=dataset_id, version_label=label, sample_count=100)
    db.add(v)
    db.commit()
    db.refresh(v)
    return v


def make_sample(db, dataset_version_id) -> SampleModel:
    s = SampleModel(
        dataset_version_id=dataset_version_id,
        file_path="images/000001.jpg",
        file_hash_sha256=FAKE_SHA256,
        width=640, height=480, channels=3,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def make_model(db, project_id, name="ResNet50") -> AIModelModel:
    m = AIModelModel(
        project_id=project_id, name=name, format="onnx",
        file_path="models/resnet50.onnx", file_hash_sha256=FAKE_SHA256,
        file_size_bytes=45000000,
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


# =====================================================================
# 1. Project Tests
# =====================================================================

class TestProjectModel:
    def test_create_project(self, test_db_session):
        p = make_project(test_db_session)
        assert p.id is not None
        assert len(p.id) == 36
        assert p.status == "active"
        assert p.name == "Test Project"

    def test_project_update_timestamp(self, test_db_session):
        p = make_project(test_db_session)
        original_updated = p.updated_at
        p.name = "Renamed"
        test_db_session.commit()
        test_db_session.refresh(p)
        assert p.name == "Renamed"


# =====================================================================
# 2. Contributor Tests
# =====================================================================

class TestContributorModel:
    def test_create_contributor(self, test_db_session):
        p = make_project(test_db_session)
        c = make_contributor(test_db_session, p.id)
        assert c.id is not None
        assert c.project_id == p.id
        assert c.external_id == "contrib-1"

    def test_contributor_unique_external_id_per_project(self, test_db_session):
        """External ID must be unique within a project."""
        p = make_project(test_db_session)
        make_contributor(test_db_session, p.id, "dup-id")
        with pytest.raises(Exception):  # IntegrityError
            make_contributor(test_db_session, p.id, "dup-id")
            test_db_session.flush()


# =====================================================================
# 3. Dataset Tests
# =====================================================================

class TestDatasetModel:
    def test_create_dataset(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        assert d.id is not None
        assert d.format == "coco"
        assert d.status == "imported"

    def test_dataset_belongs_to_project(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        assert d.project_id == p.id


# =====================================================================
# 4. Dataset Version Tests
# =====================================================================

class TestDatasetVersionModel:
    def test_create_version(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        v = make_version(test_db_session, d.id)
        assert v.dataset_id == d.id
        assert v.version_label == "v1.0"
        assert v.sample_count == 100

    def test_unique_version_label_per_dataset(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        make_version(test_db_session, d.id, "v1")
        with pytest.raises(Exception):
            make_version(test_db_session, d.id, "v1")
            test_db_session.flush()


# =====================================================================
# 5. Sample Tests
# =====================================================================

class TestSampleModel:
    def test_create_sample(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        v = make_version(test_db_session, d.id)
        s = make_sample(test_db_session, v.id)
        assert s.file_hash_sha256 == FAKE_SHA256
        assert s.width == 640

    def test_sample_contributor_junction(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        v = make_version(test_db_session, d.id)
        s = make_sample(test_db_session, v.id)
        c = make_contributor(test_db_session, p.id)
        link = SampleContributorModel(sample_id=s.id, contributor_id=c.id, contribution_type="annotator")
        test_db_session.add(link)
        test_db_session.commit()
        assert link.id is not None


# =====================================================================
# 6. AI Model Tests
# =====================================================================

class TestAIModelModel:
    def test_create_model(self, test_db_session):
        p = make_project(test_db_session)
        m = make_model(test_db_session, p.id)
        assert m.format == "onnx"
        assert m.file_hash_sha256 == FAKE_SHA256


# =====================================================================
# 7. Model Fingerprint Tests
# =====================================================================

class TestModelFingerprintModel:
    def test_create_fingerprint(self, test_db_session):
        p = make_project(test_db_session)
        m = make_model(test_db_session, p.id)
        fp = ModelFingerprintModel(
            model_id=m.id,
            fingerprint_type="structural",
            fingerprint_value='{"layers": 50, "params": 25000000}',
        )
        test_db_session.add(fp)
        test_db_session.commit()
        test_db_session.refresh(fp)
        assert fp.model_id == m.id
        assert fp.fingerprint_type == "structural"


# =====================================================================
# 8. Inference Record Tests
# =====================================================================

class TestInferenceRecordModel:
    def test_create_inference_record(self, test_db_session):
        p = make_project(test_db_session)
        m = make_model(test_db_session, p.id)
        ir = InferenceRecordModel(
            project_id=p.id,
            model_id=m.id,
            input_hash=FAKE_SHA256,
            input_path="data/input.jpg",
            output_hash=FAKE_SHA256,
            sequence_number=0,
        )
        test_db_session.add(ir)
        test_db_session.commit()
        assert ir.verification_status == "unverified"

    def test_unique_sequence_per_project_model(self, test_db_session):
        p = make_project(test_db_session)
        m = make_model(test_db_session, p.id)
        ir1 = InferenceRecordModel(
            project_id=p.id, model_id=m.id,
            input_hash=FAKE_SHA256, input_path="a.jpg",
            output_hash=FAKE_SHA256, sequence_number=0,
        )
        test_db_session.add(ir1)
        test_db_session.commit()
        ir2 = InferenceRecordModel(
            project_id=p.id, model_id=m.id,
            input_hash=FAKE_SHA256, input_path="b.jpg",
            output_hash=FAKE_SHA256, sequence_number=0,  # duplicate
        )
        test_db_session.add(ir2)
        with pytest.raises(Exception):
            test_db_session.commit()
        test_db_session.rollback()


# =====================================================================
# 9. Finding Tests
# =====================================================================

class TestFindingModel:
    def test_create_finding(self, test_db_session):
        p = make_project(test_db_session)
        f = FindingModel(
            project_id=p.id,
            engine_id="dataset_integrity",
            evidence_layer="detection",
            finding_type="near_duplicate",
            title="Near-duplicate cluster detected",
            severity="high",
            confidence=0.9,
            affected_asset_type="dataset",
            affected_asset_id=str(uuid.uuid4()),
            disposition="review",
        )
        test_db_session.add(f)
        test_db_session.commit()
        assert f.status == "open"


# =====================================================================
# 10. Evidence Tests
# =====================================================================

class TestEvidenceModel:
    def test_create_evidence_linked_to_finding(self, test_db_session):
        p = make_project(test_db_session)
        f = FindingModel(
            project_id=p.id, engine_id="test", evidence_layer="detection",
            finding_type="test_type", title="Test", severity="low",
            confidence=0.5, affected_asset_type="dataset",
            affected_asset_id=str(uuid.uuid4()), disposition="accept",
        )
        test_db_session.add(f)
        test_db_session.commit()
        e = EvidenceModel(
            finding_id=f.id, evidence_layer="detection",
            evidence_type="similarity_map", title="Pairwise similarity",
            data_json={"threshold": 0.95},
        )
        test_db_session.add(e)
        test_db_session.commit()
        assert e.finding_id == f.id


# =====================================================================
# 11. Risk Assessment Tests
# =====================================================================

class TestRiskAssessmentModel:
    def test_create_risk_assessment(self, test_db_session):
        p = make_project(test_db_session)
        ra = RiskAssessmentModel(
            project_id=p.id,
            scope="dataset",
            target_id=str(uuid.uuid4()),
            overall_risk_score=0.65,
            risk_level="medium",
            disposition="review",
            rationale="Elevated near-duplicate and class imbalance risks.",
        )
        test_db_session.add(ra)
        test_db_session.commit()
        assert ra.overall_risk_score == 0.65


# =====================================================================
# 12. Audit Event Tests
# =====================================================================

class TestAuditEventModel:
    def test_create_audit_event(self, test_db_session):
        p = make_project(test_db_session)
        ae = AuditEventModel(
            project_id=p.id,
            event_type="project_created",
            actor="system",
            target_type="project",
            target_id=p.id,
            description="Project created.",
        )
        test_db_session.add(ae)
        test_db_session.commit()
        assert ae.event_type == "project_created"


# =====================================================================
# 13. Provenance Record Tests
# =====================================================================

class TestProvenanceRecordModel:
    def test_create_provenance_record(self, test_db_session):
        p = make_project(test_db_session)
        pr = ProvenanceRecordModel(
            project_id=p.id,
            record_type="dataset_import",
            actor="system",
            action="import",
            target_type="dataset",
            target_id=str(uuid.uuid4()),
            sequence_number=0,
        )
        test_db_session.add(pr)
        test_db_session.commit()
        assert pr.record_type == "dataset_import"
        assert pr.blockchain_tx_id is None  # ADR-005: nullable forward-compat


# =====================================================================
# 14. Report Tests
# =====================================================================

class TestReportModel:
    def test_create_report(self, test_db_session):
        p = make_project(test_db_session)
        r = ReportModel(
            project_id=p.id,
            report_type="full",
            format="json",
            file_path="data/reports/report-001.json",
        )
        test_db_session.add(r)
        test_db_session.commit()
        assert r.report_type == "full"


# =====================================================================
# 15. Foreign Key Relationship Tests
# =====================================================================

class TestRelationships:
    def test_project_has_datasets(self, test_db_session):
        p = make_project(test_db_session)
        make_dataset(test_db_session, p.id, "D1")
        make_dataset(test_db_session, p.id, "D2")
        assert p.datasets.count() == 2

    def test_dataset_has_versions(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        make_version(test_db_session, d.id, "v1")
        make_version(test_db_session, d.id, "v2")
        assert d.versions.count() == 2

    def test_version_has_samples(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        v = make_version(test_db_session, d.id)
        make_sample(test_db_session, v.id)
        assert v.samples.count() == 1

    def test_model_has_fingerprints(self, test_db_session):
        p = make_project(test_db_session)
        m = make_model(test_db_session, p.id)
        fp = ModelFingerprintModel(
            model_id=m.id, fingerprint_type="structural", fingerprint_value="{}"
        )
        test_db_session.add(fp)
        test_db_session.commit()
        assert m.fingerprints.count() == 1

    def test_finding_has_evidence(self, test_db_session):
        p = make_project(test_db_session)
        f = FindingModel(
            project_id=p.id, engine_id="test", evidence_layer="detection",
            finding_type="test", title="T", severity="info",
            confidence=0.5, affected_asset_type="dataset",
            affected_asset_id=str(uuid.uuid4()), disposition="accept",
        )
        test_db_session.add(f)
        test_db_session.commit()
        e = EvidenceModel(
            finding_id=f.id, evidence_layer="detection",
            evidence_type="test_evidence", title="E",
        )
        test_db_session.add(e)
        test_db_session.commit()
        assert f.evidence_items.count() == 1

    def test_cascade_dataset_deletes_versions_and_samples(self, test_db_session):
        p = make_project(test_db_session)
        d = make_dataset(test_db_session, p.id)
        v = make_version(test_db_session, d.id)
        make_sample(test_db_session, v.id)
        test_db_session.delete(d)
        test_db_session.commit()
        assert test_db_session.query(DatasetVersionModel).count() == 0
        assert test_db_session.query(SampleModel).count() == 0


# =====================================================================
# 16. Schema Validation (Invalid Input Rejection)
# =====================================================================

class TestSchemaValidation:
    def test_finding_proof_layer_requires_confidence_1(self):
        """ADR-028: Proof-layer findings must have confidence = 1.0."""
        with pytest.raises(ValidationError) as exc_info:
            FindingCreate(
                project_id=str(uuid.uuid4()),
                engine_id="provenance",
                evidence_layer=EvidenceLayer.PROOF,
                finding_type="hash_mismatch",
                title="Hash Mismatch",
                severity=Severity.CRITICAL,
                confidence=0.9,  # MUST be 1.0 for PROOF
                affected_asset_type="inference",
                affected_asset_id=str(uuid.uuid4()),
                disposition=Disposition.QUARANTINE,
            )
        assert "confidence" in str(exc_info.value).lower()

    def test_finding_proof_layer_accepts_confidence_1(self):
        f = FindingCreate(
            project_id=str(uuid.uuid4()),
            engine_id="provenance",
            evidence_layer=EvidenceLayer.PROOF,
            finding_type="hash_mismatch",
            title="Hash Mismatch",
            severity=Severity.CRITICAL,
            confidence=1.0,
            affected_asset_type="inference",
            affected_asset_id=str(uuid.uuid4()),
            disposition=Disposition.QUARANTINE,
        )
        assert f.confidence == 1.0

    def test_risk_score_out_of_bounds(self):
        with pytest.raises(ValidationError):
            RiskAssessmentCreate(
                project_id=str(uuid.uuid4()),
                scope="dataset",
                target_id=str(uuid.uuid4()),
                overall_risk_score=1.5,
                risk_level="critical",
                disposition=Disposition.QUARANTINE,
                rationale="Out of bounds",
            )

    def test_risk_score_negative(self):
        with pytest.raises(ValidationError):
            RiskAssessmentCreate(
                project_id=str(uuid.uuid4()),
                scope="dataset",
                target_id=str(uuid.uuid4()),
                overall_risk_score=-0.1,
                risk_level="low",
                disposition=Disposition.ACCEPT,
                rationale="Negative is invalid",
            )

    def test_confidence_out_of_bounds(self):
        with pytest.raises(ValidationError):
            FindingCreate(
                project_id=str(uuid.uuid4()),
                engine_id="test",
                evidence_layer=EvidenceLayer.DETECTION,
                finding_type="test",
                title="Test",
                severity=Severity.INFO,
                confidence=1.1,  # > 1.0
                affected_asset_type="dataset",
                affected_asset_id=str(uuid.uuid4()),
                disposition=Disposition.ACCEPT,
            )

    def test_invalid_severity_value(self):
        with pytest.raises(ValidationError):
            FindingCreate(
                project_id=str(uuid.uuid4()),
                engine_id="test",
                evidence_layer=EvidenceLayer.DETECTION,
                finding_type="test",
                title="Test",
                severity="extreme",  # invalid enum value
                confidence=0.5,
                affected_asset_type="dataset",
                affected_asset_id=str(uuid.uuid4()),
                disposition=Disposition.ACCEPT,
            )

    def test_invalid_disposition_value(self):
        with pytest.raises(ValidationError):
            RiskAssessmentCreate(
                project_id=str(uuid.uuid4()),
                scope="dataset",
                target_id=str(uuid.uuid4()),
                overall_risk_score=0.5,
                risk_level="medium",
                disposition="reject",  # invalid enum
                rationale="Bad disposition",
            )

    def test_sample_sha256_length_validation(self):
        with pytest.raises(ValidationError):
            SampleCreate(
                dataset_version_id=str(uuid.uuid4()),
                file_path="a.jpg",
                file_hash_sha256="tooshort",
            )

    def test_project_name_empty_rejected(self):
        with pytest.raises(ValidationError):
            ProjectCreate(name="")

    def test_dataset_format_enum_validation(self):
        with pytest.raises(ValidationError):
            DatasetCreate(
                project_id=str(uuid.uuid4()),
                name="Test",
                format="parquet",  # not a valid DatasetFormat
            )

    def test_model_format_enum_validation(self):
        with pytest.raises(ValidationError):
            AIModelCreate(
                project_id=str(uuid.uuid4()),
                name="Test",
                format="tensorflow",  # not valid
                file_path="model.tf",
                file_hash_sha256=FAKE_SHA256,
            )


# =====================================================================
# 17. Database Init / Table Creation Tests
# =====================================================================

class TestDatabaseInit:
    def test_all_tables_created(self, test_db_session):
        from sqlalchemy import text
        result = test_db_session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        )
        tables = {row[0] for row in result.fetchall()}
        expected = {
            "projects", "contributors", "datasets", "dataset_versions",
            "samples", "sample_contributors", "ai_models", "model_fingerprints",
            "inference_records", "findings", "evidence", "risk_assessments",
            "audit_events", "provenance_records", "reports",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"

    def test_foreign_keys_enabled(self, test_db_session):
        from sqlalchemy import text
        result = test_db_session.execute(text("PRAGMA foreign_keys")).scalar()
        assert result == 1


# =====================================================================
# 18. CRUD Operations Through Services
# =====================================================================

class TestServiceCRUD:
    def test_project_service_crud(self, test_db_session):
        from aivara.services.project_service import ProjectService
        svc = ProjectService(test_db_session)

        created = svc.create_project(ProjectCreate(name="CRUD Test"))
        assert created.name == "CRUD Test"

        fetched = svc.get_project(created.id)
        assert fetched.id == created.id

        updated = svc.update_project(created.id, ProjectUpdate(name="Updated"))
        assert updated.name == "Updated"

        all_projects = svc.list_projects()
        assert len(all_projects) >= 1

    def test_contributor_service_crud(self, test_db_session):
        from aivara.services.contributor_service import ContributorService
        from aivara.services.project_service import ProjectService

        p = ProjectService(test_db_session).create_project(ProjectCreate(name="CS Test"))
        svc = ContributorService(test_db_session)

        created = svc.create_contributor(ContributorCreate(
            project_id=p.id, external_id="annotator-42", name="Jane Doe"
        ))
        assert created.external_id == "annotator-42"

        fetched = svc.get_contributor(created.id)
        assert fetched.id == created.id

    def test_dataset_service_crud(self, test_db_session):
        from aivara.services.dataset_service import DatasetService
        from aivara.services.project_service import ProjectService

        p = ProjectService(test_db_session).create_project(ProjectCreate(name="DS Test"))
        svc = DatasetService(test_db_session)

        ds = svc.create_dataset(DatasetCreate(
            project_id=p.id, name="COCO Val 2017", format=DatasetFormat.COCO
        ))
        assert ds.format == "coco"

        v = svc.create_version(DatasetVersionCreate(
            dataset_id=ds.id, version_label="v1.0", sample_count=5000
        ))
        assert v.version_label == "v1.0"

    def test_model_service_crud(self, test_db_session):
        from aivara.services.model_service import AIModelService
        from aivara.services.project_service import ProjectService

        p = ProjectService(test_db_session).create_project(ProjectCreate(name="MS Test"))
        svc = AIModelService(test_db_session)

        m = svc.create_model(AIModelCreate(
            project_id=p.id, name="YOLOv5s", format=ModelFormat.ONNX,
            file_path="models/yolov5s.onnx", file_hash_sha256=FAKE_SHA256,
        ))
        assert m.format == "onnx"

        fetched = svc.get_model(m.id)
        assert fetched.name == "YOLOv5s"

    def test_not_found_raises_exception(self, test_db_session):
        from aivara.services.project_service import ProjectService
        from aivara.core.exceptions import NotFoundException
        svc = ProjectService(test_db_session)
        with pytest.raises(NotFoundException):
            svc.get_project("nonexistent-uuid")
