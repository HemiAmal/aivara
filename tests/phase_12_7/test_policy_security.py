"""Tests for Phase 12.7 Security, AST Inspection, and Air-Gap Compliance (REQ-12-POL-007, 015, 016, 017, 018)."""

import ast
from pathlib import Path
import pytest


def get_policy_source_files():
    """Retrieve all Python source files in the policy package."""
    policy_dir = Path(__file__).resolve().parent.parent.parent / "backend" / "aivara" / "universal" / "policy"
    assert policy_dir.exists(), f"Directory not found: {policy_dir}"
    return list(policy_dir.glob("*.py"))


def test_zero_dynamic_code_execution_in_policy():
    """Verify via AST that policy engine contains zero eval, exec, compile, or dynamic execution."""
    forbidden_calls = {"eval", "exec", "compile", "__import__"}
    forbidden_modules = {"subprocess", "urllib", "requests", "httpx", "socket", "http.client", "ftplib"}

    for py_file in get_policy_source_files():
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            # Check for forbidden function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                    pytest.fail(f"Forbidden call '{node.func.id}' detected in {py_file.name}:{node.lineno}")

            # Check for forbidden imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in forbidden_modules:
                        pytest.fail(f"Forbidden import '{alias.name}' detected in {py_file.name}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                if node.module and any(node.module.startswith(m) for m in forbidden_modules):
                    pytest.fail(f"Forbidden import from '{node.module}' detected in {py_file.name}:{node.lineno}")


def test_zero_proof_verification_in_phase_12_7():
    """Verify that Phase 12.7 does not import cryptographic signature verifiers or proof ledgers (Phase 12.8 boundary)."""
    forbidden_proof_imports = {
        "aivara.crypto.signatures",
        "aivara.evidence.ledger",
        "aivara.crypto.ed25519",
    }

    for py_file in get_policy_source_files():
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in forbidden_proof_imports:
                pytest.fail(f"Phase 12.8 Proof module '{node.module}' imported in {py_file.name}:{node.lineno}")


def test_zero_database_models_in_phase_12_7():
    """Verify that Phase 12.7 does not import SQLAlchemy models or introduce database mutations."""
    forbidden_db_imports = {
        "sqlalchemy",
        "aivara.database",
        "aivara.database.models",
    }

    for py_file in get_policy_source_files():
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in forbidden_db_imports:
                pytest.fail(f"Database module '{node.module}' imported in {py_file.name}:{node.lineno}")
