"""Test security boundaries, AST scan for forbidden constructs, and 100% offline air-gap."""

import ast
import os
from pathlib import Path
import pytest

from aivara.attacklab.enums import (
    AttackClass,
    AttackDomain,
    MutationType,
    OracleOutcome,
)
from aivara.attacklab.runner import AttackLabRunner
from aivara.attacklab.schemas import (
    ExpectedBehavior,
    MutationDefinition,
    ScenarioDefinition,
)

FORBIDDEN_IMPORTS = {
    "socket",
    "requests",
    "urllib.request",
    "http.client",
    "aiohttp",
    "httpx",
    "ftplib",
    "telnetlib",
    "smtplib",
}


def test_zero_network_imports_in_attacklab():
    """Static AST scan verifying zero network/socket imports in backend/aivara/attacklab/."""
    attacklab_dir = Path("backend/aivara/attacklab")
    assert attacklab_dir.exists(), "attacklab directory does not exist."

    for py_file in attacklab_dir.glob("**/*.py"):
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in FORBIDDEN_IMPORTS, (
                        f"Forbidden network import '{alias.name}' found in {py_file}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert node.module not in FORBIDDEN_IMPORTS, (
                        f"Forbidden network from-import '{node.module}' found in {py_file}"
                    )


def test_no_dynamic_execution_in_attacklab():
    """Static AST scan verifying zero eval/exec/pickle in backend/aivara/attacklab/."""
    attacklab_dir = Path("backend/aivara/attacklab")
    for py_file in attacklab_dir.glob("**/*.py"):
        with open(py_file, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec"), (
                    f"Forbidden dynamic execution '{node.func.id}' found in {py_file}"
                )


def test_cross_project_isolation_bola_blocking():
    """Verify runner blocks cross-project tampering attempts (404 BOLA)."""
    scenario = ScenarioDefinition(
        scenario_id="SEC_BOLA_01",
        name="Cross-Project BOLA Attempt",
        target_domain=AttackDomain.SECURITY_BOUNDARY,
        attack_class=AttackClass.CROSS_PROJECT_BOLA,
        description="Attempts to access project B from project A context.",
        project_id="proj_victim",
        fixture_type="dataset_integrity",
        mutations=[
            MutationDefinition(
                mutation_id="m_bola",
                operator=MutationType.TENANT_OVERRIDE,
                target_path="project_id",
                parameters={"unauthorized_project_id": "proj_attacker"},
                description="Overrides project_id to proj_attacker",
            )
        ],
        expected=ExpectedBehavior(
            expected_outcome=OracleOutcome.BLOCKED_BY_POLICY,
            expect_rejection_or_block=True,
        ),
    )

    runner = AttackLabRunner()
    outcome = runner.run_scenario(scenario)

    assert outcome.is_pass is True
    assert outcome.oracle_outcome == OracleOutcome.BLOCKED_BY_POLICY
    assert "Cross-project isolation block" in outcome.attack_trace.error_message
