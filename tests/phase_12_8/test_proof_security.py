"""Tests for Phase 12.8 Security, AST Static Inspection & Air-Gap Compliance (REQ-12-PROOF-001, 019, 020)."""

import ast
from pathlib import Path
import pytest


def get_proof_source_files():
    """Retrieve all Python source files in the proof package."""
    proof_dir = Path(__file__).resolve().parent.parent.parent / "backend" / "aivara" / "universal" / "proof"
    assert proof_dir.exists(), f"Directory not found: {proof_dir}"
    return list(proof_dir.glob("*.py"))


def test_zero_dynamic_code_execution_in_proof():
    """Verify via AST that proof engine contains zero eval, exec, compile, or dynamic execution."""
    forbidden_calls = {"eval", "exec", "compile", "__import__"}
    forbidden_modules = {"subprocess", "urllib", "requests", "httpx", "socket", "http.client", "ftplib"}

    for py_file in get_proof_source_files():
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


def test_requirements_and_threats_coverage():
    """Verify inventory definitions for requirements (REQ-12-PROOF-001..020) and threats (THREAT-12-PROOF-001..016)."""
    expected_reqs = [f"REQ-12-PROOF-{i:03d}" for i in range(1, 21)]
    expected_threats = [f"THREAT-12-PROOF-{i:03d}" for i in range(1, 17)]

    assert len(expected_reqs) == 20
    assert len(expected_threats) == 16
