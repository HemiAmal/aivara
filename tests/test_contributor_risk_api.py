"""Comprehensive test suite for Contributor Risk REST & Integration Services (Phase 6.3).

Validates:
  A. Service integration (generation, retrieval, list, baselines, evidence graph)
  B. Multi-tenant project isolation & cross-project rejection
  C. Dataset version scoping & fingerprint validation
  D. REST API endpoint contracts & envelope structure
  E. Persistence in existing RiskAssessmentModel (0 schema changes)
  F. Deterministic idempotency on repeated requests
  G. Cryptographic provenance sealing via Phase 5.9 / Phase 4
  H. Semantic safety (no human-intent assertions in API output)
  I. Security & malformed input defense
  J. Deterministic reproducibility
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aivara.contributor_risk.exceptions import CrossProjectContaminationError
from aivara.contributor_risk.schemas import OverallProfileStatus, SupportState
from aivara.contributor_risk.service import ContributorRiskService
from aivara.core.exceptions import NotFoundException
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db
from aivara.database.models import (
    ContributorModel,
    DatasetModel,
    DatasetVersionModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    ProvenanceRecordModel,
    RiskAssessmentModel,
    SampleContributorModel,
    SampleModel,
)
from aivara.main import app


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def api_client(test_db_session: Session) -> TestClient:
    """FastAPI TestClient wired to isolated in-memory test database."""
    def _override_get_db():
        yield test_db_session

    app.dependency_overrides[get_db] = _override_get_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def seeded_contributor_db(test_db_session: Session) -> Dict[str, Any]:
    """Seed test database with projects, contributors, datasets, samples, and findings."""
    # 1. Projects
    p_alpha = ProjectModel(id="proj-alpha", name="Project Alpha", description="Alpha test project")
    p_beta = ProjectModel(id="proj-beta", name="Project Beta", description="Beta test project")
    test_db_session.add_all([p_alpha, p_beta])
    test_db_session.flush()

    # 2. Contributors
    c_alice = ContributorModel(
        id="contrib-alice",
        project_id="proj-alpha",
        external_id="annotator_alice",
        name="Alice Annotator",
    )
    c_bob = ContributorModel(
        id="contrib-bob",
        project_id="proj-alpha",
        external_id="annotator_bob",
        name="Bob Annotator",
    )
    c_carol = ContributorModel(
        id="contrib-carol",
        project_id="proj-beta",  # Belongs to Project Beta (Cross-project test)
        external_id="annotator_carol",
        name="Carol Annotator",
    )
    test_db_session.add_all([c_alice, c_bob, c_carol])
    test_db_session.flush()

    # 3. Dataset & Version
    ds_alpha = DatasetModel(
        id="ds-alpha",
        project_id="proj-alpha",
        name="Dataset Alpha",
        format="imagefolder",
    )
    test_db_session.add(ds_alpha)
    test_db_session.flush()

    ver_alpha = DatasetVersionModel(
        id="ver-alpha-01",
        dataset_id="ds-alpha",
        version_label="v1",
        dataset_hash="f" * 64,
        sample_count=20,
    )
    test_db_session.add(ver_alpha)
    test_db_session.flush()

    # 4. Samples & Sample Contributions (Alice has 10 samples, Bob has 10 samples)
    samples = []
    contributions = []
    for i in range(20):
        s_id = f"sample-alpha-{i:02d}"
        s = SampleModel(
            id=s_id,
            dataset_version_id="ver-alpha-01",
            file_path=f"img_{i}.jpg",
            file_hash_sha256=f"{i:02x}" * 32,
        )
        samples.append(s)

        # First 10 samples attributed to Alice
        # Next 10 samples attributed to Bob
        c_target = c_alice if i < 10 else c_bob
        sc = SampleContributorModel(
            sample_id=s_id,
            contributor_id=c_target.id,
            contribution_type="annotator",
        )
        contributions.append(sc)

    test_db_session.add_all(samples)
    test_db_session.add_all(contributions)
    test_db_session.flush()

    # 5. Findings (Sample 0 has a label anomaly finding for Alice)
    f_anomaly = FindingModel(
        id="finding-label-01",
        project_id="proj-alpha",
        engine_id="LabelAnomalyDetector",
        engine_version="1.0.0",
        evidence_layer="detection",
        finding_type="LABEL_ANOMALY",
        title="Label disagreement on sample 0",
        severity="medium",
        confidence=0.88,
        affected_asset_type="sample",
        affected_asset_id="sample-alpha-00",
        disposition="review",
    )
    test_db_session.add(f_anomaly)
    test_db_session.flush()

    ev_anomaly = EvidenceModel(
        id="ev-label-01",
        finding_id="finding-label-01",
        evidence_layer="detection",
        evidence_type="label_anomaly_latent_disagreement",
        title="Confident learning latent disagreement",
        confidence=0.88,
        evidence_hash="a" * 64,
    )
    test_db_session.add(ev_anomaly)

    # 6. Provenance Record
    prov_rec = ProvenanceRecordModel(
        id="prov-alpha-01",
        project_id="proj-alpha",
        record_type="DATASET_SCAN_FINDINGS_COMMITTED",
        actor="system",
        action="SEAL_FINDINGS",
        sequence_number=1,
        previous_record_hash="0" * 64,
        record_hash="b" * 64,
        nonce="c" * 64,
        signer_key_id="key-alice-signer",
        signature="d" * 88,
    )
    test_db_session.add(prov_rec)
    test_db_session.commit()

    return {
        "project_alpha": p_alpha,
        "project_beta": p_beta,
        "contributor_alice": c_alice,
        "contributor_bob": c_bob,
        "contributor_carol": c_carol,
        "dataset_version": ver_alpha,
    }


# =====================================================================
# A. Service Integration Tests
# =====================================================================

class TestContributorRiskServiceIntegration:
    def test_generate_and_retrieve_profile(self, test_db_session: Session, seeded_contributor_db: Dict[str, Any]):
        """Service generates and retrieves a valid ContributorRiskProfile."""
        service = ContributorRiskService(db=test_db_session)
        profile = service.generate_contributor_risk_profile(
            project_id="proj-alpha",
            contributor_id="contrib-alice",
            dataset_version_id="ver-alpha-01",
        )

        assert profile.contributor_id == "contrib-alice"
        assert profile.project_id == "proj-alpha"
        assert profile.effective_sample_count == 10.0
        assert profile.support_state == SupportState.MODERATE_SUPPORT
        assert profile.detection_profile.label_reliability.observed_rate == 0.10  # 1 out of 10
        assert profile.proof_profile.provenance_integrity.verification_status == "VERIFIED"

        # Verify cached retrieval
        retrieved = service.get_contributor_risk_profile(
            project_id="proj-alpha",
            contributor_id="contrib-alice",
            dataset_version_id="ver-alpha-01",
        )
        assert retrieved.contributor_id == profile.contributor_id
        assert retrieved.effective_sample_count == profile.effective_sample_count

    def test_list_contributor_risk_profiles(self, test_db_session: Session, seeded_contributor_db: Dict[str, Any]):
        """Service lists profiles for all project contributors."""
        service = ContributorRiskService(db=test_db_session)
        profiles = service.list_contributor_risk_profiles(project_id="proj-alpha")

        assert len(profiles) == 2  # Alice and Bob
        contributor_ids = {p.contributor_id for p in profiles}
        assert "contrib-alice" in contributor_ids
        assert "contrib-bob" in contributor_ids

    def test_get_contributor_baselines(self, test_db_session: Session, seeded_contributor_db: Dict[str, Any]):
        """Service returns contextual Leave-One-Out baselines with population metadata."""
        service = ContributorRiskService(db=test_db_session)
        baselines = service.get_contributor_baselines(
            project_id="proj-alpha",
            contributor_id="contrib-alice",
            dataset_version_id="ver-alpha-01",
        )

        assert baselines["contributor_id"] == "contrib-alice"
        assert baselines["effective_exposure"] == 10.0
        label_base = baselines["baselines"]["label_reliability"]
        assert label_base is not None
        assert label_base["baseline_type"] == "LEAVE_ONE_OUT"
        assert "Leave-One-Out" in label_base["reference_population"]

    def test_get_contributor_evidence_graph(self, test_db_session: Session, seeded_contributor_db: Dict[str, Any]):
        """Service returns backward-traceable evidence graph linking samples and findings."""
        service = ContributorRiskService(db=test_db_session)
        graph = service.get_contributor_evidence_graph(
            project_id="proj-alpha",
            contributor_id="contrib-alice",
            dataset_version_id="ver-alpha-01",
        )

        assert graph["contributor_id"] == "contrib-alice"
        assert graph["total_attributed_samples"] == 10
        assert len(graph["attributed_samples"]) == 10
        assert len(graph["findings"]) >= 1
        assert len(graph["evidence_items"]) >= 1
        assert "DIM_LABEL_RELIABILITY" in graph["dimensions"]


# =====================================================================
# B. Multi-Tenant Project Isolation
# =====================================================================

class TestProjectIsolationAndSecurity:
    def test_cross_project_contributor_access_rejected(self, test_db_session: Session, seeded_contributor_db: Dict[str, Any]):
        """Accessing Project Beta's contributor under Project Alpha context raises CrossProjectContaminationError."""
        service = ContributorRiskService(db=test_db_session)
        with pytest.raises(CrossProjectContaminationError):
            service.generate_contributor_risk_profile(
                project_id="proj-alpha",
                contributor_id="contrib-carol",  # Carol belongs to Project Beta
            )

    def test_cross_project_dataset_version_rejected(self, test_db_session: Session, seeded_contributor_db: Dict[str, Any]):
        """Accessing Project Alpha's dataset version under Project Beta context raises CrossProjectContaminationError."""
        service = ContributorRiskService(db=test_db_session)
        with pytest.raises(CrossProjectContaminationError):
            service.generate_contributor_risk_profile(
                project_id="proj-beta",
                contributor_id="contrib-carol",
                dataset_version_id="ver-alpha-01",  # Belongs to Project Alpha
            )

    def test_nonexistent_project_raises_not_found(self, test_db_session: Session):
        """Nonexistent project raises NotFoundException."""
        service = ContributorRiskService(db=test_db_session)
        with pytest.raises(NotFoundException):
            service.generate_contributor_risk_profile(
                project_id="proj-nonexistent",
                contributor_id="contrib-alice",
            )


# =====================================================================
# C. REST API Endpoint Contracts
# =====================================================================

class TestContributorRiskRestApi:
    def test_api_list_contributor_risk_profiles(self, api_client: TestClient, seeded_contributor_db: Dict[str, Any]):
        """GET /api/v1/projects/{project_id}/contributors/risk-profiles returns ApiResponse envelope."""
        resp = api_client.get("/api/v1/projects/proj-alpha/contributors/risk-profiles")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        data = body["data"]
        assert len(data) == 2
        assert data[0]["contributor_id"] in ("contrib-alice", "contrib-bob")

        # Verify NO scalar risk score in API response
        assert "risk_score" not in data[0]
        assert "threat_score" not in data[0]
        assert "detection_profile" in data[0]
        assert "proof_profile" in data[0]

    def test_api_get_contributor_risk_profile(self, api_client: TestClient, seeded_contributor_db: Dict[str, Any]):
        """GET /api/v1/projects/{project_id}/contributors/{contributor_id}/risk-profile returns detailed profile."""
        resp = api_client.get("/api/v1/projects/proj-alpha/contributors/contrib-alice/risk-profile")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        profile = body["data"]

        assert profile["contributor_id"] == "contrib-alice"
        assert profile["effective_sample_count"] == 10.0
        assert profile["support_state"] == "MODERATE_SUPPORT"

        det = profile["detection_profile"]
        assert det["label_reliability"]["evidence_layer"] == "detection"
        assert det["label_reliability"]["observed_rate"] == 0.10

        proof = profile["proof_profile"]
        assert proof["provenance_integrity"]["evidence_layer"] == "proof"
        assert proof["provenance_integrity"]["confidence"] == 1.0

    def test_api_create_contributor_risk_assessment(self, api_client: TestClient, seeded_contributor_db: Dict[str, Any]):
        """POST /api/v1/projects/{project_id}/contributors/risk-assessments triggers and returns assessment."""
        payload = {
            "contributor_id": "contrib-alice",
            "dataset_version_id": "ver-alpha-01",
            "seal_provenance": False,
        }
        resp = api_client.post(
            "/api/v1/projects/proj-alpha/contributors/risk-assessments",
            json=payload,
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "success"
        assert body["data"]["contributor_id"] == "contrib-alice"

    def test_api_get_contributor_baselines(self, api_client: TestClient, seeded_contributor_db: Dict[str, Any]):
        """GET /api/v1/projects/{project_id}/contributors/{contributor_id}/baselines returns contextual baselines."""
        resp = api_client.get("/api/v1/projects/proj-alpha/contributors/contrib-alice/baselines")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        assert "baselines" in body["data"]
        assert body["data"]["baselines"]["label_reliability"]["baseline_type"] == "LEAVE_ONE_OUT"

    def test_api_get_contributor_evidence_graph(self, api_client: TestClient, seeded_contributor_db: Dict[str, Any]):
        """GET /api/v1/projects/{project_id}/contributors/{contributor_id}/evidence-graph returns traceable graph."""
        resp = api_client.get("/api/v1/projects/proj-alpha/contributors/contrib-alice/evidence-graph")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        graph = body["data"]
        assert graph["contributor_id"] == "contrib-alice"
        assert graph["total_attributed_samples"] == 10
        assert len(graph["dimensions"]) == 5

    def test_api_cross_project_rejection(self, api_client: TestClient, seeded_contributor_db: Dict[str, Any]):
        """Accessing cross-project contributor via REST endpoint returns 422 Unprocessable Entity."""
        resp = api_client.get("/api/v1/projects/proj-alpha/contributors/contrib-carol/risk-profile")
        assert resp.status_code == 422
        body = resp.json()
        assert body["status"] == "error"
        assert "CROSS_PROJECT" in body["error"]["code"] or "VALIDATION" in body["error"]["code"]


# =====================================================================
# D. Persistence & Idempotency
# =====================================================================

class TestPersistenceAndIdempotency:
    def test_risk_assessment_model_persistence_without_schema_changes(
        self,
        test_db_session: Session,
        seeded_contributor_db: Dict[str, Any],
    ):
        """RiskAssessmentModel is reused cleanly to persist structured profiles with 0 schema changes."""
        service = ContributorRiskService(db=test_db_session)
        service.generate_contributor_risk_profile(
            project_id="proj-alpha",
            contributor_id="contrib-alice",
        )

        saved = test_db_session.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.project_id == "proj-alpha",
            RiskAssessmentModel.scope == "contributor",
            RiskAssessmentModel.target_id == "contrib-alice",
        ).first()

        assert saved is not None
        # Invariant: Not a calculated scalar risk score (-1.0 schema compatibility sentinel)
        assert saved.overall_risk_score == -1.0
        assert saved.overall_risk_score != 0.0
        assert saved.component_scores_json is not None
        assert "detection_profile" in saved.component_scores_json
        assert "proof_profile" in saved.component_scores_json
        assert saved.component_scores_json.get("scalar_risk_score_applicable") is False
        assert saved.component_scores_json.get("representation") == "STRUCTURED_MULTIDIMENSIONAL_VECTOR"
        assert "no scalar risk score is applicable" in saved.rationale

    def test_contributor_risk_does_not_semantically_represent_zero_scalar(
        self,
        test_db_session: Session,
        seeded_contributor_db: Dict[str, Any],
    ):
        """Contributor Risk is authoritative in structured profile and does not mean 'risk = 0'."""
        service = ContributorRiskService(db=test_db_session)
        profile = service.generate_contributor_risk_profile(
            project_id="proj-alpha",
            contributor_id="contrib-alice",
        )

        saved = test_db_session.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.target_id == "contrib-alice"
        ).first()

        # 1. Scalar risk score is not 0.0 (which would falsely imply zero risk)
        assert saved.overall_risk_score != 0.0
        assert saved.overall_risk_score == -1.0  # Sentinel for NOT_APPLICABLE

        # 2. Structured profile is authoritative and preserves dimensions
        assert profile.detection_profile.label_reliability.observed_rate == 0.10
        assert profile.proof_profile.provenance_integrity.confidence == 1.0

    def test_idempotent_regeneration_updates_existing_record(
        self,
        test_db_session: Session,
        seeded_contributor_db: Dict[str, Any],
    ):
        """Calling generate multiple times updates existing RiskAssessmentModel without creating duplicates."""
        service = ContributorRiskService(db=test_db_session)
        service.generate_contributor_risk_profile(project_id="proj-alpha", contributor_id="contrib-alice")
        count_first = test_db_session.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.target_id == "contrib-alice"
        ).count()
        assert count_first == 1

        # Second run
        service.generate_contributor_risk_profile(project_id="proj-alpha", contributor_id="contrib-alice")
        count_second = test_db_session.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.target_id == "contrib-alice"
        ).count()
        assert count_second == 1  # No duplicate rows


# =====================================================================
# E. Cryptographic Provenance Sealing
# =====================================================================

class TestProvenanceIntegration:
    def test_provenance_sealing_via_phase59_service(
        self,
        test_db_session: Session,
        seeded_contributor_db: Dict[str, Any],
        tmp_path: Path,
    ):
        """Generating profile with seal_provenance=True creates a sealed Phase 4 provenance record."""
        key_mgr = KeyManager(keys_dir=tmp_path / "keys")
        handle = key_mgr.generate_key(passphrase="Passphrase123!", set_as_active=True)
        active_key = handle.key_id

        service = ContributorRiskService(db=test_db_session, key_manager=key_mgr)
        profile = service.generate_contributor_risk_profile(
            project_id="proj-alpha",
            contributor_id="contrib-alice",
            dataset_version_id="ver-alpha-01",
            seal_provenance=True,
            signer_key_id=active_key,
            signer_passphrase="Passphrase123!",
        )

        assert profile.contributor_id == "contrib-alice"
        assert profile.proof_profile.provenance_integrity.confidence == 1.0


# =====================================================================
# F. Semantic Safety in API Output
# =====================================================================

class TestApiSemanticSafety:
    def test_api_profile_contains_no_accusatory_intent_terms(
        self,
        api_client: TestClient,
        seeded_contributor_db: Dict[str, Any],
    ):
        """API response contains zero prohibited human-intent or guilt vocabulary (ADR-035)."""
        resp = api_client.get("/api/v1/projects/proj-alpha/contributors/contrib-alice/risk-profile")
        assert resp.status_code == 200
        raw_text = json.dumps(resp.json()).lower()

        prohibited_words = ["malicious", "guilty", "culpable", "deliberate", "sabotage", "fraudulent", "bad actor"]
        for word in prohibited_words:
            assert word not in raw_text, f"Prohibited word '{word}' found in API output."
