"""Phase 4.15 — Attack Demonstration Lab Test Suite.

Comprehensive tests verifying:
  1. Attack Lab Scenario Registry & Metadata Discovery.
  2. Execution and Detection for all 10 Individual Attack Demonstrations:
     - ATTACK-01: Provenance Record Tampering
     - ATTACK-02: Digital Signature Forgery
     - ATTACK-03: Replay Attack
     - ATTACK-04: Audit Event Tampering
     - ATTACK-05: Direct Database Tampering (Raw SQL)
     - ATTACK-06: Provenance Chain Manipulation
     - ATTACK-07: Cross-Project Evidence Substitution
     - ATTACK-08: Key Lifecycle Attack
     - ATTACK-09: Combined Multi-Layer Attack
     - ATTACK-10: Attack Lifecycle / Restoration
  3. AttackLabRunner orchestration and run_all() aggregation.
  4. Fast-API Router endpoints (/api/v1/attack_lab/*).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aivara.main import app
from aivara.attack_lab.models import (
    AttackCategory,
    AttackExecutionSummary,
    AttackResult,
    AttackScenario,
)
from aivara.attack_lab.runner import AttackLabRunner
from aivara.attack_lab.scenarios import (
    SCENARIO_REGISTRY,
    get_scenario_by_id,
    list_all_scenarios,
    normalize_attack_id,
    run_scenario_by_id,
)


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


@pytest.fixture
def runner() -> AttackLabRunner:
    """AttackLabRunner fixture."""
    return AttackLabRunner()


class TestAttackLabRegistry:
    """Test suite for Attack Lab registry and metadata discovery."""

    def test_registry_contains_exactly_10_scenarios(self):
        """Registry must contain all 10 canonical attack scenarios (ATTACK-01 to ATTACK-10)."""
        assert len(SCENARIO_REGISTRY) == 10
        expected_ids = [f"ATTACK-{i:02d}" for i in range(1, 11)]
        assert sorted(SCENARIO_REGISTRY.keys()) == expected_ids

    def test_normalize_attack_id_variations(self):
        """normalize_attack_id handles diverse string inputs consistently."""
        assert normalize_attack_id("1") == "ATTACK-01"
        assert normalize_attack_id("01") == "ATTACK-01"
        assert normalize_attack_id("attack-1") == "ATTACK-01"
        assert normalize_attack_id("attack-01") == "ATTACK-01"
        assert normalize_attack_id("ATTACK-001") == "ATTACK-01"
        assert normalize_attack_id("ATTACK-10") == "ATTACK-10"
        assert normalize_attack_id("10") == "ATTACK-10"

    def test_list_all_scenarios_returns_valid_models(self):
        """list_all_scenarios returns 10 frozen AttackScenario models with required fields."""
        scenarios = list_all_scenarios()
        assert len(scenarios) == 10
        for sc in scenarios:
            assert isinstance(sc, AttackScenario)
            assert sc.attack_id.startswith("ATTACK-")
            assert sc.attack_name
            assert isinstance(sc.category, AttackCategory)
            assert sc.description
            assert sc.target
            assert sc.cleanup

    def test_get_scenario_by_id_valid_and_invalid(self):
        """get_scenario_by_id retrieves valid scenario or raises KeyError."""
        s1 = get_scenario_by_id("ATTACK-01")
        assert s1.attack_id == "ATTACK-01"
        assert s1.category == AttackCategory.PROVENANCE

        s5 = get_scenario_by_id("5")
        assert s5.attack_id == "ATTACK-05"
        assert s5.category == AttackCategory.DATABASE

        with pytest.raises(KeyError):
            get_scenario_by_id("ATTACK-99")


class TestAttackDemonstrations:
    """Test suite executing all 10 attack demonstrations individually."""

    def test_attack_01_provenance_tampering(self, runner: AttackLabRunner):
        """ATTACK-01: Independent modification of any protected field is detected."""
        res = runner.run_scenario("ATTACK-01")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-01"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 17
        assert all(sr.detected for sr in res.sub_results)

    def test_attack_02_signature_forgery(self, runner: AttackLabRunner):
        """ATTACK-02: Signature forgery and corruption vectors are all detected."""
        res = runner.run_scenario("ATTACK-02")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-02"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 8
        assert all(sr.detected for sr in res.sub_results)

    def test_attack_03_replay_attack(self, runner: AttackLabRunner):
        """ATTACK-03: Replay attack is rejected with audit record logged."""
        res = runner.run_scenario("ATTACK-03")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-03"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert res.evidence["replay_audit_logged"] is True
        assert res.evidence["audit_chain_valid"] is True

    def test_attack_04_audit_tampering(self, runner: AttackLabRunner):
        """ATTACK-04: Out-of-band audit event modification is detected and restored."""
        res = runner.run_scenario("ATTACK-04")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-04"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 2
        assert all(sr.detected for sr in res.sub_results)

    def test_attack_05_direct_database_tampering(self, runner: AttackLabRunner):
        """ATTACK-05: Raw SQL modifications bypassing ORM listeners are detected."""
        res = runner.run_scenario("ATTACK-05")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-05"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 8
        assert all(sr.detected for sr in res.sub_results)

    def test_attack_06_provenance_chain_manipulation(self, runner: AttackLabRunner):
        """ATTACK-06: Topological and structural chain attacks are detected."""
        res = runner.run_scenario("ATTACK-06")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-06"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 9
        assert all(sr.detected for sr in res.sub_results)

    def test_attack_07_cross_project_substitution(self, runner: AttackLabRunner):
        """ATTACK-07: Cross-project evidence splicing is rejected."""
        res = runner.run_scenario("ATTACK-07")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-07"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 3
        assert all(sr.detected for sr in res.sub_results)

    def test_attack_08_key_lifecycle_attack(self, runner: AttackLabRunner):
        """ATTACK-08: Signing authority is separated from historical verification."""
        res = runner.run_scenario("ATTACK-08")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-08"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 3
        assert all(sr.detected for sr in res.sub_results)

    def test_attack_09_combined_multilayer_attack(self, runner: AttackLabRunner):
        """ATTACK-09: Multi-layer simultaneous attacks preserve all failure codes without masking."""
        res = runner.run_scenario("ATTACK-09")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-09"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 4
        assert all(sr.detected for sr in res.sub_results)

    def test_attack_10_lifecycle_restoration(self, runner: AttackLabRunner):
        """ATTACK-10: Multi-round attack, detection, and restoration is deterministic and reproducible."""
        res = runner.run_scenario("ATTACK-10")
        assert isinstance(res, AttackResult)
        assert res.attack_id == "ATTACK-10"
        assert res.detected is True
        assert res.cleanup_status == "RESTORED"
        assert len(res.sub_results) == 2
        assert all(sr.detected for sr in res.sub_results)


class TestAttackLabRunnerAggregation:
    """Test suite for AttackLabRunner run_all aggregation."""

    def test_run_all_executes_all_scenarios(self, runner: AttackLabRunner):
        """run_all() runs all 10 scenarios sequentially and detects all attacks."""
        summary: AttackExecutionSummary = runner.run_all()
        assert summary.total_scenarios == 10
        assert summary.scenarios_executed == 10
        assert summary.scenarios_detected == 10
        assert summary.all_detected is True
        assert len(summary.results) == 10
        assert all(r.detected for r in summary.results)
        assert all(r.cleanup_status == "RESTORED" for r in summary.results)


class TestAttackLabApiEndpoints:
    """Test suite for /api/v1/attack_lab REST API routes."""

    def test_api_status(self, client: TestClient):
        """GET /api/v1/attack_lab/status returns readiness metadata."""
        resp = client.get("/api/v1/attack_lab/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["status"] == "ready"
        assert body["data"]["demonstrations_enabled"] is True
        assert body["data"]["total_scenarios"] == 10

    def test_api_list_scenarios(self, client: TestClient):
        """GET /api/v1/attack_lab/scenarios returns array of 10 scenarios."""
        resp = client.get("/api/v1/attack_lab/scenarios")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["data"]) == 10
        assert body["data"][0]["attack_id"] == "ATTACK-01"

    def test_api_get_scenario_by_id(self, client: TestClient):
        """GET /api/v1/attack_lab/scenarios/{id} returns single scenario metadata."""
        resp = client.get("/api/v1/attack_lab/scenarios/ATTACK-03")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["attack_id"] == "ATTACK-03"
        assert body["data"]["category"] == "REPLAY"

        # 404 on non-existent scenario
        resp_404 = client.get("/api/v1/attack_lab/scenarios/ATTACK-999")
        assert resp_404.status_code == 404

    def test_api_run_single_attack(self, client: TestClient):
        """POST /api/v1/attack_lab/run/{id} runs the scenario and returns detection result."""
        resp = client.post("/api/v1/attack_lab/run/ATTACK-01")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["attack_id"] == "ATTACK-01"
        assert body["data"]["detected"] is True
        assert body["data"]["cleanup_status"] == "RESTORED"

        # 404 on unknown ID
        resp_404 = client.post("/api/v1/attack_lab/run/ATTACK-999")
        assert resp_404.status_code == 404

    def test_api_run_all_attacks(self, client: TestClient):
        """POST /api/v1/attack_lab/run_all runs all scenarios and returns execution summary."""
        resp = client.post("/api/v1/attack_lab/run_all")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["total_scenarios"] == 10
        assert body["data"]["scenarios_detected"] == 10
        assert body["data"]["all_detected"] is True
