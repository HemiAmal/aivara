"""Deterministic simulation runner for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.attacklab.comparator import DifferentialComparator
from aivara.attacklab.controls import CleanControlManager
from aivara.attacklab.enums import OracleOutcome
from aivara.attacklab.evidence import SimulationEvidenceBridge
from aivara.attacklab.exceptions import (
    ResourceBudgetExceededError,
    SecurityBoundaryViolationError,
)
from aivara.attacklab.oracle import SimulationOracle
from aivara.attacklab.schemas import (
    PipelineExecutionTrace,
    ScenarioDefinition,
    SimulationOutcome,
    SimulationReport,
)
from aivara.universal.correlation.engine import CrossDomainCorrelationEngine
from aivara.universal.graph.builder import UniversalEvidenceGraphBuilder
from aivara.universal.hashing import compute_payload_hash
from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.policy.schemas import UniversalPolicy
from aivara.universal.risk.engine import UniversalRiskComputationEngine


def canonical_hash(data: Dict[str, Any]) -> str:
    return compute_payload_hash(data)

MAX_SCENARIOS_PER_RUN: int = 100
MAX_MUTATIONS_PER_SCENARIO: int = 20
MAX_PAYLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB


class AttackLabRunner:
    """Executes deterministic attack simulations against Phase 12 Universal Assurance Core."""

    def __init__(self) -> None:
        self.correlation_engine = CrossDomainCorrelationEngine()
        self.risk_engine = UniversalRiskComputationEngine()
        self.policy_engine = UniversalPolicyEngine()
        self.default_policy = UniversalPolicy.get_default_policy()

    def run_scenario(self, scenario: ScenarioDefinition) -> SimulationOutcome:
        """Execute a paired clean vs attack simulation scenario."""
        start_time = time.perf_counter()

        # 1. Budget and sanity checks
        if len(scenario.mutations) > MAX_MUTATIONS_PER_SCENARIO:
            raise ResourceBudgetExceededError(
                f"Scenario mutation count ({len(scenario.mutations)}) exceeds ceiling ({MAX_MUTATIONS_PER_SCENARIO})."
            )

        # 2. Generate paired fixtures
        clean_fixture, attack_fixture = CleanControlManager.generate_paired_fixtures(scenario)

        # 3. Execute Clean Control baseline trace
        clean_trace = self._execute_fixture_pipeline(clean_fixture, expected_project_id=scenario.project_id)

        # 4. Execute Mutated Attack fixture trace
        attack_trace = self._execute_fixture_pipeline(attack_fixture, expected_project_id=scenario.project_id)

        # 5. Differential analysis
        risk_delta, new_findings, _ = DifferentialComparator.compare(clean_trace, attack_trace)

        # 6. Oracle evaluation
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return SimulationOracle.evaluate(
            scenario=scenario,
            clean_trace=clean_trace,
            attack_trace=attack_trace,
            risk_delta=risk_delta,
            new_findings=new_findings,
            execution_time_ms=duration_ms,
        )

    def run_suite(self, scenarios: List[ScenarioDefinition], project_id: str = "proj_default") -> SimulationReport:
        """Execute a batch of simulation scenarios and produce a sealed audit report."""
        if len(scenarios) > MAX_SCENARIOS_PER_RUN:
            raise ResourceBudgetExceededError(
                f"Scenario batch size ({len(scenarios)}) exceeds ceiling ({MAX_SCENARIOS_PER_RUN})."
            )

        outcomes: List[SimulationOutcome] = []
        breakdown: Dict[str, int] = {}
        for sc in scenarios:
            outcome = self.run_scenario(sc)
            outcomes.append(outcome)
            key = outcome.oracle_outcome.value
            breakdown[key] = breakdown.get(key, 0) + 1

        total = len(outcomes)
        passed = sum(1 for o in outcomes if o.is_pass)
        failed = total - passed

        # Metrics calculation
        expected_detections_target = sum(1 for sc in scenarios if sc.expected.expected_outcome == OracleOutcome.EXPECTED_DETECTION)
        actual_expected_detections = breakdown.get(OracleOutcome.EXPECTED_DETECTION.value, 0)
        detection_rate = round(actual_expected_detections / expected_detections_target, 4) if expected_detections_target > 0 else 1.0

        false_negatives = breakdown.get(OracleOutcome.FALSE_NEGATIVE.value, 0)
        fn_rate = round(false_negatives / expected_detections_target, 4) if expected_detections_target > 0 else 0.0

        expected_clean_target = sum(1 for sc in scenarios if sc.expected.expected_outcome == OracleOutcome.EXPECTED_NO_DETECTION)
        false_positives = breakdown.get(OracleOutcome.FALSE_POSITIVE.value, 0)
        fp_rate = round(false_positives / expected_clean_target, 4) if expected_clean_target > 0 else 0.0

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        report_data = {
            "report_id": f"sim_report_{int(time.time())}",
            "project_id": project_id,
            "created_at": now_iso,
            "total_scenarios": total,
            "passed_scenarios": passed,
            "failed_scenarios": failed,
            "outcome_breakdown": breakdown,
            "detection_rate": detection_rate,
            "false_negative_rate": fn_rate,
            "false_positive_rate": fp_rate,
            "outcomes": [o.model_dump() for o in outcomes],
        }
        report_hash = canonical_hash(report_data)

        return SimulationReport(
            report_id=report_data["report_id"],
            project_id=project_id,
            created_at=now_iso,
            total_scenarios=total,
            passed_scenarios=passed,
            failed_scenarios=failed,
            outcome_breakdown=breakdown,
            detection_rate=detection_rate,
            false_negative_rate=fn_rate,
            false_positive_rate=fp_rate,
            outcomes=outcomes,
            report_hash=report_hash,
        )

    def _execute_fixture_pipeline(self, fixture: Any, expected_project_id: str) -> PipelineExecutionTrace:
        """Run Phase 12 pipeline on a fixture payload and record execution trace."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Tenancy check
        if fixture.project_id != expected_project_id:
            return PipelineExecutionTrace(
                executed_at=now_iso,
                success=False,
                error_message=f"Cross-project isolation block (404 BOLA): Expected '{expected_project_id}', got '{fixture.project_id}'",
            )

        # Size check
        payload_bytes = len(str(fixture.data).encode("utf-8"))
        if payload_bytes > MAX_PAYLOAD_SIZE_BYTES or fixture.data.get("payload_size_bytes", 0) > MAX_PAYLOAD_SIZE_BYTES:
            return PipelineExecutionTrace(
                executed_at=now_iso,
                success=False,
                error_message=f"Payload size {payload_bytes} bytes exceeds ceiling {MAX_PAYLOAD_SIZE_BYTES} bytes",
            )

        try:
            # 1. Extract envelopes & findings
            envelopes, finding_types = SimulationEvidenceBridge.extract_evidence_and_findings(fixture)

            if not envelopes:
                return PipelineExecutionTrace(
                    executed_at=now_iso,
                    success=True,
                    evidence_envelopes=[],
                    finding_types=[],
                    risk_score=0.0,
                    decision="ACCEPT",
                    proof_valid=True,
                )

            # 2. Build graph
            graph_builder = UniversalEvidenceGraphBuilder(project_id=fixture.project_id)
            for env in envelopes:
                graph_builder.add_evidence_envelope(env)
            graph = graph_builder.validate_and_build()

            # 3. Correlate
            corr_assessment = self.correlation_engine.evaluate_cross_domain_correlation(
                graph=graph,
            )

            # 4. Compute risk for primary asset
            primary_asset = envelopes[0].primary_asset_id
            risk_assessment = self.risk_engine.compute_asset_risk(
                graph=graph,
                asset_id=primary_asset,
                correlation_assessment=corr_assessment,
            )

            # 5. Evaluate policy
            policy_decision = self.policy_engine.evaluate(self.default_policy, risk_assessment)

            # 6. Check proof layer
            proof_valid = True
            for env in envelopes:
                if env.evidence_layer == EvidenceLayer.PROOF:
                    if env.data_json.get("is_valid") is False or env.severity == Severity.CRITICAL:
                        proof_valid = False

            return PipelineExecutionTrace(
                executed_at=now_iso,
                success=True,
                evidence_envelopes=[e.model_dump() for e in envelopes],
                finding_types=finding_types,
                risk_score=risk_assessment.risk_score,
                decision=policy_decision.decision.value,
                proof_valid=proof_valid,
            )
        except Exception as e:
            return PipelineExecutionTrace(
                executed_at=now_iso,
                success=False,
                error_message=str(e),
            )
