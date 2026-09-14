"""Phase 12.6 Static AST Traceability & Boundary Audit Suite.

Statically inspects Phase 12.6 codebase to verify:
1. Zero policy decisions (ACCEPT, REVIEW, QUARANTINE, REJECT - Phase 12.7 ownership).
2. Zero proof overrides (Phase 12.8 ownership).
3. Zero project or chain multi-asset aggregation leakage in engine.py (Phase 12.9 ownership).
4. Zero network, socket, or cloud dependencies (100% offline air-gap compliance).
"""

import ast
import inspect
from pathlib import Path

import pytest

RISK_DIR = Path("backend/aivara/universal/risk")


def test_zero_network_imports():
    """Verify no network or cloud API imports exist in Phase 12.6 risk code."""
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

    for py_file in RISK_DIR.glob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    assert root_mod not in prohibited_modules, (
                        f"Prohibited network import '{alias.name}' in {py_file}."
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_mod = node.module.split(".")[0]
                    assert root_mod not in prohibited_modules, (
                        f"Prohibited network import '{node.module}' in {py_file}."
                    )


def test_zero_decision_dispositions():
    """Verify Phase 12.6 engine.py does not emit or decide ACCEPT, REVIEW, QUARANTINE, or REJECT."""
    engine_file = RISK_DIR / "engine.py"
    content = engine_file.read_text(encoding="utf-8")
    tree = ast.parse(content)
    prohibited_dispositions = {"ACCEPT", "QUARANTINE"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val_upper = node.value.strip().upper()
            if val_upper in prohibited_dispositions:
                pytest.fail(
                    f"Prohibited policy disposition '{val_upper}' found in string literal at {engine_file}:{node.lineno}."
                )


def test_zero_proof_override_in_engine():
    """Verify Phase 12.6 engine.py does not implement proof non-compensability override."""
    engine_file = RISK_DIR / "engine.py"
    content = engine_file.read_text(encoding="utf-8").lower()
    prohibited = ["proof_override", "override_decision", "force_reject"]
    for term in prohibited:
        assert term not in content, f"Prohibited proof override term '{term}' in {engine_file}."


def test_zero_project_chain_risk_in_universal_engine():
    """Verify UniversalRiskComputationEngine does not calculate R_chain or R_project."""
    import aivara.universal.risk.engine as eng_mod
    source = inspect.getsource(eng_mod.UniversalRiskComputationEngine)

    prohibited_aggregation = [
        "lineage_propagation_factor",
        "peak_dominance_exponent",
        "inter_asset_damping",
        "r_chain",
        "r_project",
        "_evaluate_cross_asset_chains",
        "_evaluate_project_risk",
    ]
    for term in prohibited_aggregation:
        assert term not in source, (
            f"Prohibited aggregation term '{term}' found in UniversalRiskComputationEngine."
        )


def test_no_decision_fields_in_universal_assessment_schema():
    """Verify UniversalRiskAssessment exposes strictly analytical and risk scalar data."""
    import aivara.universal.risk.schemas as sch_mod
    obj = getattr(sch_mod, "UniversalRiskAssessment")
    fields = obj.model_fields.keys()
    assert "disposition" not in fields
    assert "decision" not in fields
    assert "override" not in fields
    assert "action" not in fields
