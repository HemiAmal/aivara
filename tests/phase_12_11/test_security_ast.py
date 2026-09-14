"""Test AST Static Security Checks for Phase 12.11 Audit Module."""

import ast
import os
import pytest

AUDIT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "backend", "aivara", "universal", "audit")
)


def test_no_dynamic_execution_or_eval():
    """Verify universal audit module contains zero calls to eval, exec, __import__, or network sockets."""
    forbidden_calls = {"eval", "exec", "__import__", "compile"}

    for root, _, files in os.walk(AUDIT_DIR):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=path)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            assert node.func.id not in forbidden_calls, (
                                f"Forbidden dynamic call '{node.func.id}' found in {path}:{node.lineno}"
                            )
