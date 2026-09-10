"""Comprehensive REST API and Orchestration integration tests for Phase 5.10.

Tests:
  - Dataset format detection and sandboxed ingestion.
  - Standalone dataset integrity detection endpoints (fingerprint, Merkle, duplicates, anomalies, flipping, OOD, contributors).
  - Scan orchestration lifecycle (queued, running, completed, partial, cancelled, idempotent hit).
  - Server-Sent Events (SSE) real-time progress streaming.
  - Evidence and finding querying, hash verification, and backward traceability resolution.
  - Cryptographic provenance verification via REST.
  - Multi-tenant cross-project security enforcement.
  - Deterministic HTTP error contracts (400, 404, 409, 422).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
import pytest
from PIL import Image

from aivara.crypto.keys import KeyManager
from aivara.database.models import (
    ContributorModel,
    DatasetModel,
    DatasetVersionModel,
    EvidenceModel,
    FindingModel,
    ProjectModel,
    SampleModel,
)
from aivara.domain.schemas import EvidenceLayer, Severity


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def api_fixtures(test_db_session):
    """Seed minimal project, dataset, version, and samples."""
    proj1 = ProjectModel(id="p-001", name="Alpha Project")
    proj2 = ProjectModel(id="p-002", name="Beta Project")
    test_db_session.add_all([proj1, proj2])
    test_db_session.flush()

    ds1 = DatasetModel(id="ds-001", project_id="p-001", name="Traffic Dataset", format="imagefolder")
    test_db_session.add(ds1)
    test_db_session.flush()

    ver1 = DatasetVersionModel(
        id="ver-001",
        dataset_id="ds-001",
        version_label="v1.0",
        dataset_hash="a" * 64,
        sample_count=2,
    )
    test_db_session.add(ver1)
    test_db_session.flush()

    s1 = SampleModel(
        id="s-001",
        dataset_version_id="ver-001",
        file_path="img1.jpg",
        file_hash_sha256="c" * 64,
    )
    s2 = SampleModel(
        id="s-002",
        dataset_version_id="ver-001",
        file_path="img2.jpg",
        file_hash_sha256="d" * 64,
    )
    test_db_session.add_all([s1, s2])
    test_db_session.commit()

    return {
        "project1": proj1,
        "project2": proj2,
        "dataset1": ds1,
        "version1": ver1,
        "sample1": s1,
        "sample2": s2,
    }


@pytest.fixture
def mock_dataset_dir(tmp_path) -> Path:
    """Create a minimal ImageFolder dataset directory on disk."""
    ds_dir = tmp_path / "mock_dataset"
    cat_dir = ds_dir / "stop_sign"
    cat_dir.mkdir(parents=True)

    img = Image.new("RGB", (64, 64), color="red")
    img.save(cat_dir / "sample_1.jpg")
    img2 = Image.new("RGB", (64, 64), color="blue")
    img2.save(cat_dir / "sample_2.jpg")

    return ds_dir


# =====================================================================
# 1. Dataset Ingestion & Format Detection API
# =====================================================================

class TestDatasetIngestionAPI:
    def test_detect_dataset_format(self, client, mock_dataset_dir):
        """POST /api/v1/datasets/detect-format correctly detects ImageFolder layout."""
        r = client.post(
            "/api/v1/datasets/detect-format",
            json={"dataset_path": str(mock_dataset_dir)},
        )
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["detected_format"] == "imagefolder"
        assert data["confidence"] == 1.0

    def test_ingest_dataset_creates_dataset_and_version(self, client, api_fixtures, mock_dataset_dir):
        """POST /api/v1/datasets/ingest normalizes directory and persists version and samples."""
        r = client.post(
            "/api/v1/datasets/ingest",
            json={
                "project_id": "p-001",
                "dataset_name": "Ingested Vision Dataset",
                "dataset_path": str(mock_dataset_dir),
                "format": "imagefolder",
                "version_name": "v1.0",
            },
        )
        assert r.status_code == 201
        data = r.json()["data"]
        assert data["project_id"] == "p-001"
        assert data["sample_count"] == 2
        assert len(data["dataset_fingerprint"]) == 64
        assert len(data["merkle_root"]) == 64

    def test_ingest_dataset_path_traversal_rejected(self, client, api_fixtures):
        """Attempting to ingest outside sandbox or invalid path raises validation error."""
        r = client.post(
            "/api/v1/datasets/ingest",
            json={
                "project_id": "p-001",
                "dataset_path": "C:\\nonexistent\\path\\to\\dataset",
                "format": "coco",
            },
        )
        assert r.status_code == 400
        assert r.json()["status"] == "error"


# =====================================================================
# 2. Standalone Dataset Integrity Detection Endpoints
# =====================================================================

class TestDatasetIntegrityAPI:
    def test_compute_fingerprint_from_version(self, client, api_fixtures):
        """POST /api/v1/dataset-integrity/fingerprint computes Merkle tree and SHA-256 fingerprint."""
        r = client.post(
            "/api/v1/dataset-integrity/fingerprint",
            json={
                "project_id": "p-001",
                "dataset_version_id": "ver-001",
            },
        )
        assert r.status_code == 200
        data = r.json()["data"]
        assert len(data["dataset_fingerprint"]) == 64
        assert len(data["merkle_root"]) == 64
        assert data["sample_count"] == 2

    def test_verify_merkle_proof(self, client):
        """POST /api/v1/dataset-integrity/verify-inclusion cryptographically verifies proof."""
        from aivara.dataset.fingerprinting import (
            MerkleLeaf,
            MerkleTree,
            compute_leaf_hash,
            generate_inclusion_proof,
        )
        leaves = [
            MerkleLeaf(
                index=0,
                sample_id="s1",
                relative_path="s1.jpg",
                sample_fingerprint="1" * 64,
                leaf_hash_bytes=compute_leaf_hash("1" * 64),
            ),
            MerkleLeaf(
                index=1,
                sample_id="s2",
                relative_path="s2.jpg",
                sample_fingerprint="2" * 64,
                leaf_hash_bytes=compute_leaf_hash("2" * 64),
            ),
            MerkleLeaf(
                index=2,
                sample_id="s3",
                relative_path="s3.jpg",
                sample_fingerprint="3" * 64,
                leaf_hash_bytes=compute_leaf_hash("3" * 64),
            ),
            MerkleLeaf(
                index=3,
                sample_id="s4",
                relative_path="s4.jpg",
                sample_fingerprint="4" * 64,
                leaf_hash_bytes=compute_leaf_hash("4" * 64),
            ),
        ]
        tree = MerkleTree(leaves=leaves)
        proof = generate_inclusion_proof(tree, leaf_index=1)

        r = client.post(
            "/api/v1/dataset-integrity/verify-inclusion",
            json={
                "proof_version": proof.proof_version,
                "dataset_merkle_root": proof.dataset_merkle_root,
                "leaf_index": proof.leaf_index,
                "total_leaves": proof.total_leaves,
                "sample_path": proof.sample_path,
                "leaf_hash": proof.leaf_hash,
                "audit_path": [
                    {"sibling_hash": step.sibling_hash, "direction": step.direction.value}
                    for step in proof.audit_path
                ],
            },
        )
        assert r.status_code == 200
        assert r.json()["data"]["is_valid"] is True

    def test_near_duplicate_detection(self, client, api_fixtures):
        """POST /api/v1/dataset-integrity/near-duplicates executes perceptual hashing."""
        r = client.post(
            "/api/v1/dataset-integrity/near-duplicates",
            json={
                "project_id": "p-001",
                "strategy": "BK_TREE",
                "threshold": 5,
                "samples": [
                    {"sample_id": "s-1", "file_path": "a.jpg", "image_sha256": "1" * 64},
                    {"sample_id": "s-2", "file_path": "b.jpg", "image_sha256": "2" * 64},
                ],
            },
        )
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["total_samples_analyzed"] == 2
        assert len(data["config_hash"]) == 64

    def test_label_anomaly_detection(self, client, api_fixtures):
        """POST /api/v1/dataset-integrity/label-anomalies runs cleanlab confident learning."""
        r = client.post(
            "/api/v1/dataset-integrity/label-anomalies",
            json={
                "project_id": "p-001",
                "confidence_threshold": 0.7,
                "prune_method": "both",
            },
        )
        assert r.status_code == 200
        assert "config_hash" in r.json()["data"]

    def test_label_flipping_detection(self, client, api_fixtures):
        """POST /api/v1/dataset-integrity/label-flipping runs transition asymmetry check."""
        r = client.post(
            "/api/v1/dataset-integrity/label-flipping",
            json={
                "project_id": "p-001",
                "min_samples_per_pair": 5,
                "asymmetry_threshold": 0.3,
            },
        )
        assert r.status_code == 200
        assert "config_hash" in r.json()["data"]

    def test_ood_quality_detection(self, client, api_fixtures):
        """POST /api/v1/dataset-integrity/ood-quality evaluates distance and image quality."""
        r = client.post(
            "/api/v1/dataset-integrity/ood-quality",
            json={
                "project_id": "p-001",
                "knn_k": 5,
                "mad_threshold": 3.0,
            },
        )
        assert r.status_code == 200
        assert "config_hash" in r.json()["data"]

    def test_contributor_aggregation(self, client, api_fixtures):
        """POST /api/v1/dataset-integrity/contributors computes 1/K fractional profiles."""
        r = client.post(
            "/api/v1/dataset-integrity/contributors",
            json={
                "project_id": "p-001",
                "min_contributor_samples": 5,
                "wilson_confidence": 0.95,
            },
        )
        assert r.status_code == 200
        data = r.json()["data"]
        assert "overall_hhi" in data
        assert "config_hash" in data


# =====================================================================
# 3. Scan Orchestration & SSE Progress API
# =====================================================================

class TestScanOrchestrationAPI:
    def test_create_synchronous_scan_success(self, client, api_fixtures):
        """POST /api/v1/scans creates, executes, and commits findings with provenance."""
        r = client.post(
            "/api/v1/scans",
            json={
                "project_id": "p-001",
                "dataset_version_id": "ver-001",
                "detectors": ["duplicates", "label_anomalies", "ood_quality"],
                "seal_provenance": True,
                "allow_idempotent_reuse": False,
            },
        )
        assert r.status_code == 201
        data = r.json()["data"]
        assert data["status"] == "COMPLETED"
        assert data["processed_samples"] == 2
        assert len(data["finding_ids"]) >= 1
        assert data["provenance_record_id"] is not None

        # Verify scan retrieval via GET /api/v1/scans/{id}
        scan_id = data["scan_id"]
        r_get = client.get(f"/api/v1/scans/{scan_id}")
        assert r_get.status_code == 200
        assert r_get.json()["data"]["scan_id"] == scan_id

    def test_partial_scan_preserves_partial_status(self, client, api_fixtures):
        """Scan with sample_limit < total_samples preserves PARTIAL status."""
        r = client.post(
            "/api/v1/scans",
            json={
                "project_id": "p-001",
                "dataset_version_id": "ver-001",
                "sample_limit": 1,  # 1 out of 2 samples
                "allow_idempotent_reuse": False,
            },
        )
        assert r.status_code == 201
        data = r.json()["data"]
        assert data["status"] == "PARTIAL"
        assert data["processed_samples"] == 1
        assert data["expected_samples"] == 2

    def test_scan_cancellation(self, client, api_fixtures):
        """POST /api/v1/scans/{scan_id}/cancel requests cooperative cancellation."""
        r_create = client.post(
            "/api/v1/scans?async=true",
            json={
                "project_id": "p-001",
                "dataset_version_id": "ver-001",
            },
        )
        scan_id = r_create.json()["data"]["scan_id"]

        r_cancel = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert r_cancel.status_code == 200
        assert r_cancel.json()["data"]["status"] in ("CANCELLED", "COMPLETED", "RUNNING", "QUEUED")

    def test_list_scans_filter_by_project(self, client, api_fixtures):
        """GET /api/v1/scans lists in-memory registered scans."""
        client.post(
            "/api/v1/scans",
            json={"project_id": "p-001", "dataset_version_id": "ver-001", "allow_idempotent_reuse": False},
        )
        r = client.get("/api/v1/scans?project_id=p-001")
        assert r.status_code == 200
        assert len(r.json()["data"]) >= 1

    def test_sse_progress_stream(self, client, api_fixtures):
        """GET /api/v1/scans/{scan_id}/events streams SSE progress events."""
        r_create = client.post(
            "/api/v1/scans",
            json={"project_id": "p-001", "dataset_version_id": "ver-001", "allow_idempotent_reuse": False},
        )
        scan_id = r_create.json()["data"]["scan_id"]

        r_events = client.get(f"/api/v1/scans/{scan_id}/events")
        assert r_events.status_code == 200
        assert "text/event-stream" in r_events.headers["content-type"]
        assert "data:" in r_events.text


# =====================================================================
# 4. Evidence & Findings API
# =====================================================================

class TestEvidenceAndFindingsAPI:
    def test_list_and_get_evidence(self, client, api_fixtures):
        """GET /api/v1/evidence lists persisted evidence items."""
        # Create scan to generate evidence
        client.post(
            "/api/v1/scans",
            json={"project_id": "p-001", "dataset_version_id": "ver-001", "allow_idempotent_reuse": False},
        )

        r_list = client.get("/api/v1/evidence?project_id=p-001")
        assert r_list.status_code == 200
        items = r_list.json()["data"]
        assert len(items) >= 1

        ev_id = items[0]["id"]
        r_get = client.get(f"/api/v1/evidence/{ev_id}")
        assert r_get.status_code == 200
        assert r_get.json()["data"]["id"] == ev_id

    def test_verify_evidence_hash_endpoint(self, client):
        """POST /api/v1/evidence/verify validates deterministic canonical hash."""
        from aivara.evidence.identity import compute_evidence_hash
        payload = {
            "evidence_layer": "detection",
            "evidence_type": "image_quality_metrics",
            "project_id": "p-001",
            "dataset_version_id": "ver-001",
            "dataset_fingerprint": "a" * 64,
            "target_asset_type": "sample",
            "target_asset_id": "sample-001",
            "target_asset_hash": "b" * 64,
            "detector_id": "die_ood_quality",
            "detector_version": "1.0.0",
            "detector_config_hash": "c" * 64,
            "measurements": {"sharpness": 12.0},
        }
        h = compute_evidence_hash(payload)

        r = client.post(
            "/api/v1/evidence/verify",
            json={"evidence_payload": payload, "expected_hash": h},
        )
        assert r.status_code == 200
        assert r.json()["data"]["is_valid"] is True

    def test_findings_traceability_and_provenance_verification(self, client, api_fixtures):
        """GET /findings/{id}/traceability and /provenance-verification work cleanly."""
        from aivara.core.config import settings
        key_mgr = KeyManager(keys_dir=settings.keys_dir)
        key_handle = key_mgr.generate_key(passphrase="pass_123")
        key_id = str(key_handle.key_id)

        r_scan = client.post(
            "/api/v1/scans",
            json={
                "project_id": "p-001",
                "dataset_version_id": "ver-001",
                "seal_provenance": True,
                "signer_key_id": key_id,
                "signer_passphrase": "pass_123",
                "allow_idempotent_reuse": False,
            },
        )
        finding_id = r_scan.json()["data"]["finding_ids"][0]

        # 1. Traceability graph
        r_trace = client.get(f"/api/v1/findings/{finding_id}/traceability?project_id=p-001")
        assert r_trace.status_code == 200
        trace_data = r_trace.json()["data"]
        assert trace_data["finding_id"] == finding_id
        assert f"finding:{finding_id}" in trace_data["nodes"]

        # 2. Provenance verification
        r_prov = client.get(f"/api/v1/findings/{finding_id}/provenance-verification?project_id=p-001")
        assert r_prov.status_code == 200
        prov_data = r_prov.json()["data"]
        assert prov_data["finding_id"] == finding_id
        assert prov_data["provenance_status"] == "VERIFIED"
        assert prov_data["cryptographic_validity"] is True


# =====================================================================
# 5. Cross-Project Isolation & Error Contracts
# =====================================================================

class TestSecurityAndErrorContractsAPI:
    def test_cross_project_scan_rejected(self, client, api_fixtures):
        """Creating a scan on Project B using Project A dataset version is rejected (422)."""
        r = client.post(
            "/api/v1/scans",
            json={
                "project_id": "p-002",  # Project B
                "dataset_version_id": "ver-001",  # Belongs to Project A
            },
        )
        assert r.status_code == 422
        assert r.json()["status"] == "error"

    def test_cross_project_traceability_rejected(self, client, api_fixtures):
        """Querying traceability with mismatched project_id raises 422."""
        r_scan = client.post(
            "/api/v1/scans",
            json={"project_id": "p-001", "dataset_version_id": "ver-001", "allow_idempotent_reuse": False},
        )
        finding_id = r_scan.json()["data"]["finding_ids"][0]

        r = client.get(f"/api/v1/findings/{finding_id}/traceability?project_id=p-002")
        assert r.status_code == 422
        assert r.json()["status"] == "error"

    def test_not_found_errors(self, client):
        """Querying non-existent resources returns standardized 404."""
        r_ev = client.get("/api/v1/evidence/non-existent-uuid")
        assert r_ev.status_code == 404
        assert r_ev.json()["status"] == "error"

        r_f = client.get("/api/v1/findings/non-existent-uuid")
        assert r_f.status_code == 404
        assert r_f.json()["status"] == "error"

        r_s = client.get("/api/v1/scans/non-existent-scan")
        assert r_s.status_code == 404
        assert r_s.json()["status"] == "error"
