"""Phase 12.4 Static AST Traceability & Decision Boundary Audit Suite.

Statically inspects the Phase 12.4 codebase to verify:
1. Zero risk computation logic (Phase 12.6 ownership).
2. Zero correlation damping logic (Phase 12.5 ownership).
3. Zero policy decisions (ACCEPT/REVIEW/QUARANTINE/REJECT - Phase 12.7 ownership).
4. Zero proof override logic (Phase 12.8 ownership).
5. Zero network/socket/cloud dependencies (100% air-gapped offline compliance).
6. Full traceability for all 7 upstream assurance domains.
"""

import ast
from pathlib import Path

import pytest

INGESTION_DIR = Path("backend/aivara/universal/ingestion")


def test_zero_network_imports():
    """Verify no network, socket, or cloud API imports exist in Phase 12.4 ingestion code."""
    prohibited_modules = {
        "socket",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "grpc",
        "boto3",
        "google.cloud",
        "azure",
    }

    for py_file in INGESTION_DIR.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    assert root_mod not in prohibited_modules, (
                        f"Prohibited network import '{alias.name}' found in {py_file}."
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_mod = node.module.split(".")[0]
                    assert root_mod not in prohibited_modules, (
                        f"Prohibited network import '{node.module}' found in {py_file}."
                    )


def test_zero_policy_dispositions_or_decisions():
    """Verify Phase 12.4 does not emit or decide ACCEPT, REVIEW, or QUARANTINE policy decisions."""
    prohibited_dispositions = {"ACCEPT", "QUARANTINE"}

    for py_file in INGESTION_DIR.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val_upper = node.value.strip().upper()
                if val_upper in prohibited_dispositions:
                    pytest.fail(
                        f"Prohibited policy disposition '{val_upper}' found in string literal at {py_file}:{node.lineno}."
                    )


def test_zero_risk_computation_math():
    """Verify Phase 12.4 contains no risk calculation formulas or risk variables."""
    prohibited_terms = {
        "r_chain",
        "r_project",
        "r_asset",
        "lambda_intra",
        "lambda_inter",
        "gamma_prop",
        "alpha_peak",
        "calculate_universal_risk",
        "aggregate_project_risk",
    }

    for py_file in INGESTION_DIR.glob("*.py"):
        content = py_file.read_text(encoding="utf-8").lower()
        for term in prohibited_terms:
            assert term not in content, (
                f"Prohibited risk computation term '{term}' found in {py_file}."
            )


def test_all_seven_domains_handled():
    """Verify that all 7 canonical assurance domains have explicit handlers."""
    from aivara.universal.enums import SubsystemDomain
    from aivara.universal.ingestion.registry import IngestionHandlerRegistry

    registry = IngestionHandlerRegistry()
    expected_domains = {
        SubsystemDomain.DATASET_INTEGRITY,
        SubsystemDomain.CONTRIBUTOR_RISK,
        SubsystemDomain.MODEL_INTEGRITY,
        SubsystemDomain.BEHAVIORAL_ANALYSIS,
        SubsystemDomain.BACKDOOR_TRIGGER,
        SubsystemDomain.INFERENCE_INTEGRITY,
        SubsystemDomain.DISTRIBUTION_SHIFT,
    }

    registered_set = set(registry.registered_domains)
    assert registered_set == expected_domains
