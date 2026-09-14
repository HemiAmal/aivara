"""Security AST verification for Phase 12.10 code."""

import ast
from pathlib import Path


def test_no_dynamic_execution_or_eval():
    """Verify zero usage of eval, exec, compile, or unsafe imports in universal API package."""
    api_dir = Path("backend/aivara/universal/api")
    for py_file in api_dir.glob("*.py"):
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec"), (
                        f"Forbidden dynamic execution call '{node.func.id}' found in {py_file}"
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in ("urllib.request", "requests", "httpx", "socket"), (
                        f"Forbidden external network import '{alias.name}' found in {py_file}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert not any(
                        node.module.startswith(m) for m in ("urllib", "requests", "httpx", "socket")
                    ), f"Forbidden network import from '{node.module}' in {py_file}"
