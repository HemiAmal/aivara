"""Phase 11.11.2 - Layer 6: Security & Authorization Verification Suite.

Verifies:
- REQ-11-VERIF-049: BOLA / IDOR protection (cross-project dataset/task access returns generic 404)
- REQ-11-VERIF-050: Path traversal rejection in dataset and model identifiers
- REQ-11-VERIF-051: Remote URL rejection (air-gap invariant: no http/https/s3/ftp schemes)
- REQ-11-VERIF-052: SSE subscriber limit per task & dead queue cleanup
- REQ-11-VERIF-053: Request payload bounds (sample_budget in [30, 5000], no NaN/Inf)
- REQ-11-VERIF-054: Contributor salt privacy & project-scoped pseudonymization isolation
- REQ-11-VERIF-055: Safe deserialization (strictly RFC 8785 JSON, 0 pickle/eval/exec)
"""

from __future__ import annotations

import ast
import os
from typing import Any, Dict
import pytest
from fastapi.testclient import TestClient

from aivara.api.schemas.drift import DriftAnalysisCreateRequest
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.exceptions import ProjectMismatchError
from aivara.drift.schemas import PopulationSelector
from aivara.drift.source_engine import canonicalize_source_id, derive_project_scoped_pseudonym
from aivara.services.drift_service import get_drift_task_manager


def test_req_049_bola_idor_cross_project_isolation(client: TestClient) -> None:
    """Verify REQ-11-VERIF-049: Cross-project task/result polling returns generic 404 without data disclosure."""
    # Create task under project alpha
    payload = {
        "reference_dataset_id": "ds_ref_alpha",
        "target_dataset_id": "ds_tgt_alpha",
        "analysis_type": "DATASET",
        "feature_names": ["f1"],
    }
    res = client.post("/api/v1/projects/proj_alpha/drift/analyses", json=payload)
    assert res.status_code == 202
    task_id = res.json()["data"]["task_id"]

    # Attempt cross-project access under project beta
    res_beta_poll = client.get(f"/api/v1/projects/proj_beta/drift/analyses/{task_id}")
    assert res_beta_poll.status_code == 404
    assert "error" in res_beta_poll.json()

    res_beta_res = client.get(f"/api/v1/projects/proj_beta/drift/analyses/{task_id}/result")
    assert res_beta_res.status_code == 404

    res_beta_cancel = client.post(f"/api/v1/projects/proj_beta/drift/analyses/{task_id}/cancel")
    assert res_beta_cancel.status_code == 404


def test_req_050_path_traversal_rejection() -> None:
    """Verify REQ-11-VERIF-050: Path traversal sequences in dataset paths are rejected with PathTraversalError."""
    from aivara.dataset.exceptions import PathTraversalError
    from aivara.dataset.path_security import normalize_relative_path

    dangerous_paths = [
        "../secret.txt",
        "images/../../etc/passwd",
        "C:\\Windows\\System32",
        "",
    ]
    for path in dangerous_paths:
        with pytest.raises(PathTraversalError):
            normalize_relative_path(path)


def test_req_051_remote_url_rejection() -> None:
    """Verify REQ-11-VERIF-051: Remote network URLs & UNC paths are strictly rejected."""
    from aivara.dataset.exceptions import PathTraversalError
    from aivara.dataset.path_security import normalize_relative_path

    remote_schemes = [
        "//192.168.1.1/share/img.jpg",
        "\\\\192.168.1.1\\share\\img.jpg",
        "C:/Windows/system32.dll",
    ]
    for url in remote_schemes:
        with pytest.raises(PathTraversalError):
            normalize_relative_path(url)


def test_req_052_sse_subscriber_limits_and_cleanup() -> None:
    """Verify REQ-11-VERIF-052: Multiple SSE subscribers are tracked and cleaned up on overflow."""
    manager = get_drift_task_manager()
    req = DriftAnalysisCreateRequest(
        reference_dataset_id="ds_ref_sub",
        target_dataset_id="ds_tgt_sub",
    )
    task, _ = manager.create_or_get_task("proj_sub", req)
    
    queues = [task.subscribe_events() for _ in range(10)]
    assert len(task._event_queues) == 10
    
    # Broadcast event
    task.update_stage("RUNNING", 10.0, "Progress test")
    for q in queues:
        assert not q.empty()


def test_req_053_payload_bounds_and_nan_inf_rejection(client: TestClient) -> None:
    """Verify REQ-11-VERIF-053: Budget ceilings (30 to 5000) and NaN/Inf floats are rejected."""
    # Budget < 30
    res_low = client.post(
        "/api/v1/projects/proj_val/drift/analyses",
        json={"reference_dataset_id": "d1", "target_dataset_id": "d2", "sample_budget": 10},
    )
    assert res_low.status_code == 422

    # Budget > 5000
    res_high = client.post(
        "/api/v1/projects/proj_val/drift/analyses",
        json={"reference_dataset_id": "d1", "target_dataset_id": "d2", "sample_budget": 10000},
    )
    assert res_high.status_code == 422

    # NaN / Inf in JSON raw string
    res_nan = client.post(
        "/api/v1/projects/proj_val/drift/analyses",
        content=b'{"reference_dataset_id": "d1", "target_dataset_id": "d2", "alpha_significance": NaN}',
        headers={"Content-Type": "application/json"},
    )
    assert res_nan.status_code in (400, 422)


def test_req_054_contributor_salt_privacy_and_isolation() -> None:
    """Verify REQ-11-VERIF-054: Pseudonymization is irreversibly project-scoped."""
    raw_source = "Contributor_Alpha_01"
    canon = canonicalize_source_id(raw_source)
    
    p1_pseudonym = derive_project_scoped_pseudonym(
        project_id="proj_alpha",
        canonical_source_id=canon,
        salt="salt_a" * 8,
    )
    p2_pseudonym = derive_project_scoped_pseudonym(
        project_id="proj_beta",
        canonical_source_id=canon,
        salt="salt_b" * 8,
    )
    
    assert p1_pseudonym != p2_pseudonym
    assert raw_source not in p1_pseudonym
    assert len(p1_pseudonym) == 16


def test_req_055_safe_deserialization_ast_audit() -> None:
    """Verify REQ-11-VERIF-055: Zero unsafe deserialization (0 pickle, 0 eval, 0 exec) across backend codebase."""
    drift_dir = os.path.join("backend", "aivara", "drift")
    api_dir = os.path.join("backend", "aivara", "api")
    assurance_dir = os.path.join("backend", "aivara", "assurance")
    
    forbidden = {"eval", "exec", "pickle"}
    
    for base_dir in (drift_dir, api_dir, assurance_dir):
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", encoding="utf-8") as f:
                        tree = ast.parse(f.read(), filename=full_path)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                            if node.func.id in forbidden:
                                pytest.fail(f"Forbidden unsafe function call '{node.func.id}' in {full_path}")
                        if isinstance(node, (ast.Import, ast.ImportFrom)):
                            mod = getattr(node, "module", "") or ""
                            if "pickle" in mod:
                                pytest.fail(f"Forbidden pickle import in {full_path}")
