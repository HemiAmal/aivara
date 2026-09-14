"""AST Security & Static Offline Analysis for Phase 12.9 (REQ-12-AGG-019, 020)."""

import ast
from pathlib import Path
import pytest


def test_no_dynamic_execution_or_eval():
    """Verify backend/aivara/universal/aggregation contains zero eval, exec, or shell calls."""
    agg_dir = Path("backend/aivara/universal/aggregation")
    assert agg_dir.exists()

    forbidden_calls = {"eval", "exec", "system", "popen", "spawn"}
    forbidden_modules = {"subprocess", "socket", "http", "urllib", "requests", "httpx", "aiohttp"}

    for py_file in agg_dir.glob("*.py"):
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                    pytest.fail(f"Forbidden call '{node.func.id}' detected in {py_file}")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                    pytest.fail(f"Forbidden attribute call '{node.func.attr}' detected in {py_file}")

            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if root_mod in forbidden_modules:
                        pytest.fail(f"Forbidden network/process import '{alias.name}' detected in {py_file}")

            if isinstance(node, ast.ImportFrom):
                if node.module:
                    root_mod = node.module.split(".")[0]
                    if root_mod in forbidden_modules:
                        pytest.fail(f"Forbidden network/process from-import '{node.module}' detected in {py_file}")
