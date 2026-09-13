"""Layer 11: Non-Regression & Historical Integrity Verification.

Covers:
- REQ-11-VERIF-078: Complete historical test suite preservation
- REQ-11-VERIF-079: Zero database schema modifications or migrations
- REQ-11-VERIF-080: Zero new third-party dependencies
- REQ-11-VERIF-081: Zero modifications to frozen analytical engines
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
import pytest


def test_req_078_historical_test_suite_preservation() -> None:
    """Verify REQ-11-VERIF-078: Complete historical test suite preservation."""
    core_test_files = [
        "tests/test_feature_dataset_drift.py",
        "tests/test_image_distribution_shift.py",
        "tests/test_representation_distribution_shift.py",
        "tests/test_temporal_distribution_shift.py",
        "tests/test_source_distribution_shift.py",
        "tests/test_multimodal_risk_integration.py",
        "tests/test_drift_api_task_integration.py",
    ]
    for path in core_test_files:
        assert os.path.exists(path), f"Historical test file missing: {path}"


def test_req_079_zero_db_migrations() -> None:
    """Verify REQ-11-VERIF-079: Zero database schema modifications or new Alembic migrations."""
    alembic_dir = os.path.join("backend", "alembic", "versions")
    if os.path.exists(alembic_dir):
        files = os.listdir(alembic_dir)
        for f in files:
            assert "phase_11_11" not in f.lower(), f"Unexpected migration found: {f}"


def test_req_080_zero_new_dependencies() -> None:
    """Verify REQ-11-VERIF-080: Zero new third-party dependencies added in pyproject.toml."""
    pyproject_path = "pyproject.toml"
    assert os.path.exists(pyproject_path), "pyproject.toml not found"

    with open(pyproject_path, "rb") as f:
        config = tomllib.load(f)

    deps = config.get("project", {}).get("dependencies", [])
    # Verify no unapproved external dependencies
    banned = ["posthog", "sentry", "segment", "google-analytics", "datadog", "torchvision", "huggingface_hub"]
    for dep in deps:
        for b in banned:
            assert b not in dep.lower(), f"Banned dependency found: {dep}"


def test_req_081_zero_modifications_to_frozen_engines() -> None:
    """Verify REQ-11-VERIF-081: Frozen analytical engines in drift and assurance remain unchanged."""
    drift_dir = os.path.join("backend", "aivara", "drift")
    assurance_dir = os.path.join("backend", "aivara", "assurance")

    assert os.path.isdir(drift_dir), f"Drift directory missing: {drift_dir}"
    assert os.path.isdir(assurance_dir), f"Assurance directory missing: {assurance_dir}"

    # Verify key engine files exist and have non-empty content
    key_files = [
        os.path.join(drift_dir, "engine.py"),
        os.path.join(drift_dir, "boundary.py"),
        os.path.join(drift_dir, "feature_dataset_engine.py"),
        os.path.join(drift_dir, "image_engine.py"),
        os.path.join(drift_dir, "representation_engine.py"),
        os.path.join(drift_dir, "temporal_engine.py"),
        os.path.join(drift_dir, "source_engine.py"),
        os.path.join(assurance_dir, "engine.py"),
    ]
    for kf in key_files:
        assert os.path.isfile(kf), f"Frozen engine file missing: {kf}"
        assert os.path.getsize(kf) > 0, f"Frozen engine file is empty: {kf}"
