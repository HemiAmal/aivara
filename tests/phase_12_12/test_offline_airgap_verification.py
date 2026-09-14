"""Test 12.12.17: Offline Air-Gap & Forbidden Network Module AST Audit."""

import ast
import os
import pytest


def test_zero_network_and_socket_imports_in_universal_package():
    """Verify zero forbidden networking, telemetry, or remote API modules are imported."""
    forbidden_modules = {"requests", "urllib", "http.client", "socket", "httpx", "aiohttp", "boto3", "azure", "google.cloud"}
    package_dir = os.path.join("backend", "aivara", "universal")

    for root, _, files in os.walk(package_dir):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=filepath)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for name in node.names:
                            base_pkg = name.name.split(".")[0]
                            assert base_pkg not in forbidden_modules, f"Forbidden import '{base_pkg}' in {filepath}"
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            base_pkg = node.module.split(".")[0]
                            assert base_pkg not in forbidden_modules, f"Forbidden from-import '{base_pkg}' in {filepath}"
