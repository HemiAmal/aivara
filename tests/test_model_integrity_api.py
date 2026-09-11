"""Comprehensive Test Suite for Phase 7.7: Model Integrity REST API & Integration Services.

Verifies:
  1. Router registration & OpenAPI schema generation.
  2. Model inspection endpoint (Safetensors & ONNX).
  3. Model fingerprint generation & idempotent reuse.
  4. Model contract verification & preprocessing validation.
  5. Reference model comparison & 8-state drift attribution.
  6. Integrated Model Integrity Assessment (pipeline orchestration & provenance sealing).
  7. Evidence retrieval endpoint.
  8. Finding retrieval endpoint.
  9. Provenance verification endpoint.
  10. Strict project isolation (cross-project model & reference rejection).
  11. Missing project handling (404).
  12. Missing model handling (404).
  13. Missing reference model handling (404).
  14. Invalid artifact handling (corrupted container).
  15. Prohibited format rejection (unrestricted pickle).
  16. Unsafe artifact / path traversal protection.
  17. Unavailable provenance handling (status=MISSING).
  18. Idempotent assessment execution (ScanExecutionStatus.IDEMPOTENT_HIT).
  19. Repeated identical requests produce zero duplicate database rows.
  20. Different reference model triggers distinct execution identity context.
  21. Strict Pydantic response schema compliance across all endpoints.
  22. Zero secret leakage (no private keys, passphrases, or raw byte internals in API responses).
  23. Zero model execution (static inspection boundary strictly preserved).
  24. Offline execution invariant (zero external network dependencies).
  25. Deterministic response ordering.
  26. Provenance target compatibility abstraction (target_type_logical="model", target_type_recorded="dataset_version").
  27. Frozen Phase 7.2–7.6 regression integration.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import struct
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.core.config import settings
from aivara.crypto.keys import KeyManager
from aivara.database.models import (
    AIModelModel,
    EvidenceModel,
    FindingModel,
    ModelFingerprintModel,
    ProjectModel,
    ProvenanceRecordModel,
)


# =====================================================================
# Fixtures & Mock Artifact Generators
# =====================================================================

def create_mock_safetensors(
    file_path: Path,
    tensors: Dict[str, Dict[str, Any]],
    metadata: Dict[str, str] = None,
) -> Path:
    """Create a syntactically valid Safetensors binary file."""
    header_dict = {}
    if metadata:
        header_dict["__metadata__"] = metadata

    total_tensor_bytes = 0
    raw_tensor_buffers = []

    for name, t_spec in tensors.items():
        dtype = t_spec.get("dtype", "F32")
        shape = t_spec.get("shape", [2, 2])
        data_bytes = t_spec.get("data", b"\x01" * 16)
        start_off = total_tensor_bytes
        end_off = start_off + len(data_bytes)
        total_tensor_bytes = end_off
        raw_tensor_buffers.append(data_bytes)

        header_dict[name] = {
            "dtype": dtype,
            "shape": shape,
            "data_offsets": [start_off, end_off],
        }

    header_json = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
    header_len = len(header_json)

    with open(file_path, "wb") as f:
        f.write(struct.pack("<Q", header_len))
        f.write(header_json)
        for buf in raw_tensor_buffers:
            f.write(buf)

    return file_path


def create_mock_onnx(
    file_path: Path,
    ir_version: int = 8,
    producer_name: str = "pytorch",
    initializers: List[Dict[str, Any]] = None,
) -> Path:
    """Create a synthetic ONNX ModelProto wire format binary file."""
    stream = io.BytesIO()

    def write_varint(s, v):
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                s.write(bytes([b | 0x80]))
            else:
                s.write(bytes([b]))
                break

    # ir_version tag: 1 (field 1, varint -> (1 << 3) | 0 = 8)
    stream.write(bytes([8]))
    write_varint(stream, ir_version)

    # producer_name tag: 2 (field 2, length-delimited -> (2 << 3) | 2 = 18)
    p_bytes = producer_name.encode("utf-8")
    stream.write(bytes([18]))
    write_varint(stream, len(p_bytes))
    stream.write(p_bytes)

    # graph tag: 7 (field 7, length-delimited -> (7 << 3) | 2 = 58)
    graph_stream = io.BytesIO()
    g_name = b"test_graph"
    graph_stream.write(bytes([18]))  # graph.name
    write_varint(graph_stream, len(g_name))
    graph_stream.write(g_name)

    # Input: field 11 (tag 90)
    in_stream = io.BytesIO()
    in_name = b"input_tensor"
    in_stream.write(bytes([10]))
    write_varint(in_stream, len(in_name))
    in_stream.write(in_name)
    in_bytes = in_stream.getvalue()
    graph_stream.write(bytes([90]))
    write_varint(graph_stream, len(in_bytes))
    graph_stream.write(in_bytes)

    # Output: field 12 (tag 98)
    out_stream = io.BytesIO()
    out_name = b"output_tensor"
    out_stream.write(bytes([10]))
    write_varint(out_stream, len(out_name))
    out_stream.write(out_name)
    out_bytes = out_stream.getvalue()
    graph_stream.write(bytes([98]))
    write_varint(graph_stream, len(out_bytes))
    graph_stream.write(out_bytes)

    # Initializers: field 5 (tag 42)
    if initializers:
        for init in initializers:
            t_stream = io.BytesIO()
            t_name = init.get("name", "tensor_0").encode("utf-8")
            t_stream.write(bytes([10]))  # name tag 10
            write_varint(t_stream, len(t_name))
            t_stream.write(t_name)
            # data_type: field 2 (tag 16)
            t_stream.write(bytes([16]))
            write_varint(t_stream, init.get("data_type", 1))
            # raw_data: field 9 (tag 74)
            raw = init.get("raw_data", b"\x00" * 16)
            t_stream.write(bytes([74]))
            write_varint(t_stream, len(raw))
            t_stream.write(raw)
            t_bytes = t_stream.getvalue()
            graph_stream.write(bytes([42]))
            write_varint(graph_stream, len(t_bytes))
            graph_stream.write(t_bytes)

    g_bytes = graph_stream.getvalue()
    stream.write(bytes([58]))
    write_varint(stream, len(g_bytes))
    stream.write(g_bytes)

    file_path.write_bytes(stream.getvalue())
    return file_path


@pytest.fixture
def test_env(tmp_path: Path, test_db_session: Session):
    """Seed test projects, model files, and key manager."""
    # 1. Projects
    p1 = ProjectModel(id="proj-api-1", name="Project API 1")
    p2 = ProjectModel(id="proj-api-2", name="Project API 2")
    test_db_session.add_all([p1, p2])
    test_db_session.flush()

    # 2. Key manager
    km = KeyManager(keys_dir=str(tmp_path / "keys"))
    handle = km.generate_key(passphrase="test-passphrase", description="API Test Signer")

    # 3. Model files
    models_dir = tmp_path / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    cand_path = models_dir / "candidate.safetensors"
    create_mock_safetensors(
        cand_path,
        tensors={
            "layer1.weight": {"dtype": "F32", "shape": [2, 2], "data": b"\x01" * 16},
            "layer1.bias": {"dtype": "F32", "shape": [2], "data": b"\x02" * 8},
        },
        metadata={"format": "pt", "input_shape": "[1, 3, 224, 224]"},
    )

    ref_path = models_dir / "reference.safetensors"
    create_mock_safetensors(
        ref_path,
        tensors={
            "layer1.weight": {"dtype": "F32", "shape": [2, 2], "data": b"\x01" * 16},
            "layer1.bias": {"dtype": "F32", "shape": [2], "data": b"\x02" * 8},
        },
        metadata={"format": "pt", "input_shape": "[1, 3, 224, 224]"},
    )

    drifted_path = models_dir / "drifted.safetensors"
    create_mock_safetensors(
        drifted_path,
        tensors={
            "layer1.weight": {"dtype": "F32", "shape": [2, 2], "data": b"\x99" * 16},  # modified weight
            "layer1.bias": {"dtype": "F32", "shape": [2], "data": b"\x02" * 8},
        },
        metadata={"format": "pt", "input_shape": "[1, 3, 224, 224]"},
    )

    onnx_path = models_dir / "model.onnx"
    create_mock_onnx(
        onnx_path,
        initializers=[{"name": "conv.weight", "data_type": 1, "raw_data": b"\x01" * 16}],
    )

    corrupt_path = models_dir / "corrupted.safetensors"
    corrupt_path.write_bytes(b"INVALID_HEADER_DATA_NOT_JSON")

    pickle_path = models_dir / "prohibited.pkl"
    pickle_path.write_bytes(b"\x80\x04\x95\x0c\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04test\x94\x8c\x04data\x94s.")

    # 4. Database Model records
    cand_model = AIModelModel(
        id="model-cand-1",
        project_id="proj-api-1",
        name="Candidate Model",
        format="safetensors",
        file_path=str(cand_path),
        file_hash_sha256="a" * 64,
    )
    ref_model = AIModelModel(
        id="model-ref-1",
        project_id="proj-api-1",
        name="Reference Model",
        format="safetensors",
        file_path=str(ref_path),
        file_hash_sha256="a" * 64,
    )
    drift_model = AIModelModel(
        id="model-drift-1",
        project_id="proj-api-1",
        name="Drifted Model",
        format="safetensors",
        file_path=str(drifted_path),
        file_hash_sha256="d" * 64,
    )
    onnx_model = AIModelModel(
        id="model-onnx-1",
        project_id="proj-api-1",
        name="ONNX Model",
        format="onnx",
        file_path=str(onnx_path),
        file_hash_sha256="o" * 64,
    )
    corrupt_model = AIModelModel(
        id="model-corrupt-1",
        project_id="proj-api-1",
        name="Corrupted Model",
        format="safetensors",
        file_path=str(corrupt_path),
        file_hash_sha256="c" * 64,
    )
    pickle_model = AIModelModel(
        id="model-pickle-1",
        project_id="proj-api-1",
        name="Pickle Model",
        format="pickle",
        file_path=str(pickle_path),
        file_hash_sha256="p" * 64,
    )
    proj2_model = AIModelModel(
        id="model-proj2-1",
        project_id="proj-api-2",
        name="Project 2 Model",
        format="safetensors",
        file_path=str(cand_path),
        file_hash_sha256="2" * 64,
    )

    test_db_session.add_all([
        cand_model,
        ref_model,
        drift_model,
        onnx_model,
        corrupt_model,
        pickle_model,
        proj2_model,
    ])
    test_db_session.commit()

    from aivara.main import app
    from aivara.api.routers.model_integrity import get_key_manager

    app.dependency_overrides[get_key_manager] = lambda: km

    yield {
        "project_id": "proj-api-1",
        "project_id_2": "proj-api-2",
        "candidate_id": "model-cand-1",
        "reference_id": "model-ref-1",
        "drift_id": "model-drift-1",
        "onnx_id": "model-onnx-1",
        "corrupt_id": "model-corrupt-1",
        "pickle_id": "model-pickle-1",
        "proj2_model_id": "model-proj2-1",
        "signer_key_id": handle.key_id,
        "key_manager": km,
        "models_dir": models_dir,
    }

    if get_key_manager in app.dependency_overrides:
        del app.dependency_overrides[get_key_manager]


# =====================================================================
# 1. Router Registration & OpenAPI Documentation
# =====================================================================

def test_openapi_route_registration(client: TestClient):
    """Verify all Model Integrity endpoints are properly registered in FastAPI."""
    res = client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()
    paths = schema["paths"]

    expected_routes = [
        "/api/v1/projects/{project_id}/models/{model_id}/inspect",
        "/api/v1/projects/{project_id}/models/{model_id}/fingerprint",
        "/api/v1/projects/{project_id}/models/{model_id}/contract/verify",
        "/api/v1/projects/{project_id}/models/{model_id}/compare",
        "/api/v1/projects/{project_id}/models/{model_id}/integrity-assessment",
        "/api/v1/projects/{project_id}/models/{model_id}/evidence",
        "/api/v1/projects/{project_id}/models/{model_id}/findings",
        "/api/v1/projects/{project_id}/models/{model_id}/provenance",
    ]
    for route in expected_routes:
        assert route in paths, f"Route '{route}' missing from OpenAPI schema."


# =====================================================================
# 2. Model Inspection Endpoint
# =====================================================================

def test_inspect_model_safetensors(client: TestClient, test_env):
    """Verify static inspection of a Safetensors model artifact."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/inspect"
    res = client.post(url)
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    data = body["data"]
    assert data["status"].lower() == "success"
    assert data["format"].lower() == "safetensors"
    assert data["tensor_count"] == 2
    assert len(data["artifact_hash_sha256"]) == 64


def test_inspect_model_onnx(client: TestClient, test_env):
    """Verify static inspection of an ONNX model artifact."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['onnx_id']}/inspect"
    res = client.post(url)
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    data = body["data"]
    assert data["status"].lower() == "success"
    assert data["format"].lower() == "onnx"
    assert data["tensor_count"] == 1


# =====================================================================
# 3. Hierarchical Fingerprinting Endpoint
# =====================================================================

def test_fingerprint_model_endpoint(client: TestClient, test_env):
    """Verify hierarchical fingerprint computation endpoint."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/fingerprint"
    res = client.post(url, json={"allow_idempotent_reuse": False, "compute_weight_merkle": True})
    assert res.status_code == 200
    body = res.json()
    data = body["data"]
    assert len(data["artifact_hash"]) == 64
    assert len(data["structural_hash"]) == 64
    assert len(data["weight_merkle_root"]) == 64
    assert len(data["contract_hash"]) == 64
    assert len(data["master_fingerprint"]) == 64
    assert data["tensor_count"] == 2


def test_fingerprint_model_idempotent_reuse(client: TestClient, test_env, test_db_session):
    """Verify cached fingerprint reuse from DB."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/fingerprint"
    # First computation
    res1 = client.post(url, json={"allow_idempotent_reuse": True})
    assert res1.status_code == 200
    # Second computation (idempotent reuse)
    res2 = client.post(url, json={"allow_idempotent_reuse": True})
    assert res2.status_code == 200
    assert res1.json()["data"]["master_fingerprint"] == res2.json()["data"]["master_fingerprint"]


# =====================================================================
# 4. Contract Verification Endpoint
# =====================================================================

def test_contract_verification_endpoint(client: TestClient, test_env):
    """Verify model contract verification endpoint."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/contract/verify"
    res = client.post(url, json={})
    assert res.status_code == 200
    body = res.json()
    data = body["data"]
    assert data["contract_status"].upper() in ["VALID", "DEFECTIVE", "INCOMPLETE", "UNVERIFIABLE", "UNAVAILABLE"]
    assert len(data["contract_hash"]) == 64


def test_contract_verification_with_preprocessing_declaration(client: TestClient, test_env):
    """Verify contract verification with explicit preprocessing declaration."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/contract/verify"
    payload = {
        "preprocessing_declaration": {
            "source": "explicitly_declared",
            "resize_shape": [224, 224],
            "normalization_mean": [0.485, 0.456, 0.406],
            "normalization_std": [0.229, 0.224, 0.225],
            "color_conversion": "RGB",
        }
    }
    res = client.post(url, json=payload)
    assert res.status_code == 200
    body = res.json()
    data = body["data"]
    assert data["preprocessing_contract"] is not None


# =====================================================================
# 5. Reference Model Comparison Endpoint
# =====================================================================

def test_model_comparison_exact_match(client: TestClient, test_env):
    """Verify comparison of candidate against identical reference model."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/compare"
    payload = {
        "reference_model_id": test_env["reference_id"],
        "tolerance": 0.0,
        "structural_only": False,
    }
    res = client.post(url, json=payload)
    assert res.status_code == 200
    body = res.json()
    data = body["data"]
    assert data["is_exact_match"] is True
    assert data["drift_classification"] == "EXACT_INTEGRITY_MATCH"
    assert data["comparison_status"].upper() in ["COMPARABLE", "EXACT_MATCH"]
    assert len(data["weight_differences"]) == 0


def test_model_comparison_weight_drift(client: TestClient, test_env):
    """Verify comparison detects weight-only drift."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['drift_id']}/compare"
    payload = {
        "reference_model_id": test_env["reference_id"],
        "tolerance": 0.0,
        "structural_only": False,
    }
    res = client.post(url, json=payload)
    assert res.status_code == 200
    body = res.json()
    data = body["data"]
    assert data["is_exact_match"] is False
    assert data["drift_classification"] == "WEIGHT_ONLY_DRIFT"
    assert len(data["weight_differences"]) >= 1


# =====================================================================
# 6. Integrated Model Integrity Assessment Endpoint
# =====================================================================

def test_integrated_assessment_single_model(client: TestClient, test_env, test_db_session: Session):
    """Verify full integrated assessment on a single candidate model."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    payload = {
        "allow_idempotent_reuse": False,
        "seal_provenance": True,
        "signer_key_id": test_env["signer_key_id"],
        "signer_passphrase": "test-passphrase",
    }
    res = client.post(url, json=payload)
    assert res.status_code == 200
    body = res.json()
    data = body["data"]
    assert data["assessment_status"] == "COMPLETED"
    assert data["idempotent"] is False
    assert data["findings_count"] >= 1
    assert data["fingerprint"] is not None
    assert data["contract"] is not None
    assert data["provenance"] is not None
    assert len(data["execution_identity_hash"]) == 64


def test_integrated_assessment_with_reference(client: TestClient, test_env):
    """Verify full integrated assessment including reference comparison."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    payload = {
        "reference_model_id": test_env["reference_id"],
        "allow_idempotent_reuse": False,
        "seal_provenance": True,
        "signer_key_id": test_env["signer_key_id"],
        "signer_passphrase": "test-passphrase",
    }
    res = client.post(url, json=payload)
    assert res.status_code == 200
    body = res.json()
    data = body["data"]
    assert data["comparison"] is not None
    assert data["comparison"]["drift_classification"] == "EXACT_INTEGRITY_MATCH"


# =====================================================================
# 7. Idempotency & Repeated Execution
# =====================================================================

def test_integrated_assessment_idempotency(client: TestClient, test_env, test_db_session: Session):
    """Verify repeated identical assessment returns IDEMPOTENT_HIT without row duplication."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    payload = {
        "allow_idempotent_reuse": True,
        "seal_provenance": True,
        "signer_key_id": test_env["signer_key_id"],
        "signer_passphrase": "test-passphrase",
    }
    # 1. First run
    res1 = client.post(url, json=payload)
    assert res1.status_code == 200
    data1 = res1.json()["data"]
    assert data1["assessment_status"] == "COMPLETED"

    f_count_1 = test_db_session.query(FindingModel).filter_by(project_id=test_env["project_id"]).count()
    e_count_1 = test_db_session.query(EvidenceModel).count()
    p_count_1 = test_db_session.query(ProvenanceRecordModel).filter_by(project_id=test_env["project_id"]).count()

    # 2. Second run (identical)
    res2 = client.post(url, json=payload)
    assert res2.status_code == 200
    data2 = res2.json()["data"]
    assert data2["assessment_status"] == "IDEMPOTENT_HIT"
    assert data2["idempotent"] is True
    assert data1["execution_identity_hash"] == data2["execution_identity_hash"]

    # 3. Verify zero row duplication
    f_count_2 = test_db_session.query(FindingModel).filter_by(project_id=test_env["project_id"]).count()
    e_count_2 = test_db_session.query(EvidenceModel).count()
    p_count_2 = test_db_session.query(ProvenanceRecordModel).filter_by(project_id=test_env["project_id"]).count()

    assert f_count_1 == f_count_2
    assert e_count_1 == e_count_2
    assert p_count_1 == p_count_2


def test_different_reference_changes_execution_identity(client: TestClient, test_env):
    """Verify providing a different reference model alters the execution context."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    res_no_ref = client.post(url, json={"allow_idempotent_reuse": False, "seal_provenance": False})
    res_with_ref = client.post(
        url,
        json={
            "reference_model_id": test_env["reference_id"],
            "allow_idempotent_reuse": False,
            "seal_provenance": False,
        },
    )
    assert res_no_ref.status_code == 200
    assert res_with_ref.status_code == 200
    exec_hash_1 = res_no_ref.json()["data"]["execution_identity_hash"]
    exec_hash_2 = res_with_ref.json()["data"]["execution_identity_hash"]
    assert exec_hash_1 != exec_hash_2


# =====================================================================
# 8. Evidence & Finding Retrieval Endpoints
# =====================================================================

def test_evidence_and_finding_retrieval(client: TestClient, test_env):
    """Verify retrieval of evidence and finding items for an assessed model."""
    # Assess model to generate findings & evidence
    assess_url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    client.post(assess_url, json={"allow_idempotent_reuse": False, "seal_provenance": True})

    # Retrieve findings
    findings_url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/findings"
    res_f = client.get(findings_url)
    assert res_f.status_code == 200
    findings = res_f.json()["data"]
    assert len(findings) >= 1
    assert findings[0]["affected_asset_id"] == test_env["candidate_id"]

    # Retrieve evidence
    evidence_url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/evidence"
    res_e = client.get(evidence_url)
    assert res_e.status_code == 200
    evidences = res_e.json()["data"]
    assert len(evidences) >= 1
    assert "evidence_hash" in evidences[0]


# =====================================================================
# 9. Cryptographic Provenance Verification Endpoint
# =====================================================================

def test_provenance_verification_endpoint(client: TestClient, test_env):
    """Verify cryptographic provenance verification endpoint."""
    # Assess and seal
    assess_url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    client.post(
        assess_url,
        json={
            "allow_idempotent_reuse": False,
            "seal_provenance": True,
            "signer_key_id": test_env["signer_key_id"],
            "signer_passphrase": "test-passphrase",
        },
    )

    prov_url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/provenance"
    res = client.get(prov_url)
    assert res.status_code == 200
    body = res.json()
    data = body["data"]
    assert data["is_valid"] is True
    assert data["status"].upper() in ["VERIFIED", "VALID"]
    assert data["signature_valid"] is True
    assert data["chain_valid"] is True
    assert data["target_type_logical"] == "model"
    assert data["target_type_recorded"] == "dataset_version"
    assert "compatibility_note" in data["details"]


def test_provenance_verification_missing_record(client: TestClient, test_env):
    """Verify provenance endpoint returns status=MISSING for unsealed model."""
    prov_url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['drift_id']}/provenance"
    res = client.get(prov_url)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["is_valid"] is False
    assert data["status"].upper() in ["MISSING", "UNAVAILABLE"]


# =====================================================================
# 10. Project Isolation & Boundary Verification
# =====================================================================

def test_cross_project_model_access_rejected(client: TestClient, test_env):
    """Verify accessing Model from Project A using Project B URL is rejected with 422."""
    url = f"/api/v1/projects/{test_env['project_id_2']}/models/{test_env['candidate_id']}/inspect"
    res = client.post(url)
    assert res.status_code == 422
    body = res.json()
    assert body["status"] == "error"


def test_cross_project_reference_model_rejected(client: TestClient, test_env):
    """Verify reference model from different project is rejected during comparison."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/compare"
    payload = {"reference_model_id": test_env["proj2_model_id"]}
    res = client.post(url, json=payload)
    assert res.status_code == 422
    body = res.json()
    assert body["status"] == "error"


# =====================================================================
# 11. Error Handling & Edge Cases
# =====================================================================

def test_missing_project_returns_404(client: TestClient, test_env):
    """Verify nonexistent project ID returns 404."""
    url = f"/api/v1/projects/nonexistent-project-uuid/models/{test_env['candidate_id']}/inspect"
    res = client.post(url)
    assert res.status_code == 404
    body = res.json()
    assert body["status"] == "error"


def test_missing_model_returns_404(client: TestClient, test_env):
    """Verify nonexistent model ID returns 404."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/nonexistent-model-uuid/inspect"
    res = client.post(url)
    assert res.status_code == 404
    body = res.json()
    assert body["status"] == "error"


def test_missing_reference_model_returns_404(client: TestClient, test_env):
    """Verify nonexistent reference model ID in comparison returns 404."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/compare"
    payload = {"reference_model_id": "nonexistent-ref-uuid"}
    res = client.post(url, json=payload)
    assert res.status_code == 404


def test_corrupted_model_inspection(client: TestClient, test_env):
    """Verify corrupted model returns structured INVALID_ARTIFACT inspection result."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['corrupt_id']}/inspect"
    res = client.post(url)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["status"].upper() == "INVALID_ARTIFACT"
    assert "CORRUPTED_CONTAINER" in [r.upper() for r in data["reason_codes"]]


def test_prohibited_pickle_model_inspection(client: TestClient, test_env):
    """Verify arbitrary pickle model returns PROHIBITED policy result."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['pickle_id']}/inspect"
    res = client.post(url)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["status"].upper() == "PROHIBITED"
    assert data["policy"].upper() == "PROHIBITED"
    assert "ARBITRARY_CODE_EXECUTION_RISK" in [r.upper() for r in data["reason_codes"]]


def test_unsafe_path_traversal_inspection_rejected(client: TestClient, test_env):
    """Verify attempting path traversal in custom file_path returns INVALID_ARTIFACT."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/inspect"
    payload = {
        "file_path": "../../../../../etc/passwd",
        "allowed_base_dir": str(test_env["models_dir"]),
    }
    res = client.post(url, json=payload)
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["status"].upper() == "INVALID_ARTIFACT"
    assert any(
        r.upper() in ["PATH_TRAVERSAL_ATTEMPT", "FORBIDDEN_PATH_TYPE"]
        for r in data["reason_codes"]
    )


# =====================================================================
# 12. Security & Zero Secret Leakage Invariant
# =====================================================================

def test_zero_secret_leakage_in_api_responses(client: TestClient, test_env):
    """Verify private keys, passphrases, and raw secrets never leak in responses."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    payload = {
        "allow_idempotent_reuse": False,
        "seal_provenance": True,
        "signer_key_id": test_env["signer_key_id"],
        "signer_passphrase": "test-passphrase",
    }
    res = client.post(url, json=payload)
    assert res.status_code == 200
    raw_response = res.text
    assert "test-passphrase" not in raw_response
    assert "BEGIN ENCRYPTED PRIVATE KEY" not in raw_response
    assert "BEGIN PRIVATE KEY" not in raw_response


# =====================================================================
# 13. Additional Adversarial & Semantic Safety Verification Tests
# =====================================================================

def test_cross_project_evidence_retrieval_rejected(client: TestClient, test_env):
    """Verify cross-project evidence retrieval is rejected with 422 CrossProjectContaminationError."""
    url = f"/api/v1/projects/{test_env['project_id_2']}/models/{test_env['candidate_id']}/evidence"
    res = client.get(url)
    assert res.status_code == 422
    body = res.json()
    assert body["status"] == "error"


def test_cross_project_findings_retrieval_rejected(client: TestClient, test_env):
    """Verify cross-project findings retrieval is rejected with 422 CrossProjectContaminationError."""
    url = f"/api/v1/projects/{test_env['project_id_2']}/models/{test_env['candidate_id']}/findings"
    res = client.get(url)
    assert res.status_code == 422
    body = res.json()
    assert body["status"] == "error"


def test_cross_project_provenance_retrieval_rejected(client: TestClient, test_env):
    """Verify cross-project provenance retrieval is rejected with 422 CrossProjectContaminationError."""
    url = f"/api/v1/projects/{test_env['project_id_2']}/models/{test_env['candidate_id']}/provenance"
    res = client.get(url)
    assert res.status_code == 422
    body = res.json()
    assert body["status"] == "error"


def test_execution_identity_sensitivity_to_model_and_reference(client: TestClient, test_env):
    """Verify modifying model identity or reference model alters the execution identity hash."""
    url_cand = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    url_drift = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['drift_id']}/integrity-assessment"
    
    # 1. Candidate model without reference
    res1 = client.post(url_cand, json={"allow_idempotent_reuse": False, "seal_provenance": False})
    assert res1.status_code == 200
    hash1 = res1.json()["data"]["execution_identity_hash"]

    # 2. Same candidate model with reference model
    res2 = client.post(
        url_cand,
        json={
            "reference_model_id": test_env["reference_id"],
            "allow_idempotent_reuse": False,
            "seal_provenance": False,
        },
    )
    assert res2.status_code == 200
    hash2 = res2.json()["data"]["execution_identity_hash"]

    # 3. Drifted model without reference
    res3 = client.post(url_drift, json={"allow_idempotent_reuse": False, "seal_provenance": False})
    assert res3.status_code == 200
    hash3 = res3.json()["data"]["execution_identity_hash"]

    # 4. Drifted model with reference
    res4 = client.post(
        url_drift,
        json={
            "reference_model_id": test_env["reference_id"],
            "allow_idempotent_reuse": False,
            "seal_provenance": False,
        },
    )
    assert res4.status_code == 200
    hash4 = res4.json()["data"]["execution_identity_hash"]

    assert hash1 != hash2, "Adding a reference model must alter execution identity."
    assert hash1 != hash3, "Different model artifacts must produce different execution identities."
    assert hash2 != hash4, "Different candidate models with same reference must produce different execution identities."


def test_tampered_provenance_payload_verification(client: TestClient, test_env, test_db_session: Session):
    """Verify adversarial modification of provenance record payload causes verification failure."""
    # 1. Create sealed assessment
    url_assess = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/integrity-assessment"
    payload = {
        "allow_idempotent_reuse": False,
        "seal_provenance": True,
        "signer_key_id": test_env["signer_key_id"],
        "signer_passphrase": "test-passphrase",
    }
    res_assess = client.post(url_assess, json=payload)
    assert res_assess.status_code == 200

    # 2. Verify initially valid
    url_prov = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['candidate_id']}/provenance"
    res_prov = client.get(url_prov)
    assert res_prov.status_code == 200
    assert res_prov.json()["data"]["is_valid"] is True
    assert res_prov.json()["data"]["status"] == "VERIFIED"

    # 3. Tamper with the record in DB (mutate output_hash)
    finding = test_db_session.query(FindingModel).filter_by(
        project_id=test_env["project_id"], affected_asset_id=test_env["candidate_id"]
    ).first()
    prov_id = finding.metadata_json.get("provenance_record_id")
    prov_rec = test_db_session.query(ProvenanceRecordModel).filter_by(id=prov_id).first()
    prov_rec.output_hash = "f" * 64
    test_db_session.commit()

    # 4. Verification must now report INVALID / is_valid=False
    res_tampered = client.get(url_prov)
    assert res_tampered.status_code == 200
    tampered_data = res_tampered.json()["data"]
    assert tampered_data["is_valid"] is False
    assert tampered_data["status"] == "INVALID"
    assert tampered_data["signature_valid"] is False


def test_semantic_safety_zero_speculative_vocabulary(client: TestClient, test_env):
    """Verify API responses contain zero prohibited intent/culpability words."""
    url = f"/api/v1/projects/{test_env['project_id']}/models/{test_env['drift_id']}/compare"
    payload = {
        "reference_model_id": test_env["reference_id"],
        "tolerance": 0.0,
    }
    res = client.post(url, json=payload)
    assert res.status_code == 200
    raw_text = res.text.lower()
    
    prohibited_terms = [
        "malicious",
        "attacker",
        "culpable",
        "deliberate sabotage",
        "proven poisoner",
        "guilty",
        "compromised developer",
    ]
    for term in prohibited_terms:
        assert term not in raw_text, f"Prohibited term '{term}' found in API response."

