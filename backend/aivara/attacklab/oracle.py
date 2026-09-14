"""Expected-result oracle for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

from typing import List

from aivara.attacklab.enums import ExpectedDecisionClass, OracleOutcome
from aivara.attacklab.schemas import PipelineExecutionTrace, ScenarioDefinition, SimulationOutcome


class SimulationOracle:
    """Evaluates observed Phase 12 pipeline results against formal scenario expectations."""

    @staticmethod
    def evaluate(
        scenario: ScenarioDefinition,
        clean_trace: PipelineExecutionTrace,
        attack_trace: PipelineExecutionTrace,
        risk_delta: float,
        new_findings: List[str],
        execution_time_ms: float = 0.0,
    ) -> SimulationOutcome:
        """Evaluate simulation execution traces and determine formal OracleOutcome."""
        expected = scenario.expected
        reasons: List[str] = []
        outcome: OracleOutcome = OracleOutcome.UNEXPECTED_FAILURE
        is_pass = False

        # 1. Check for expected blocking (Policy or Resource)
        if expected.expected_outcome in (OracleOutcome.BLOCKED_BY_POLICY, OracleOutcome.BLOCKED_BY_RESOURCE):
            if not attack_trace.success:
                outcome = expected.expected_outcome
                is_pass = True
                reasons.append(f"Pipeline successfully failed closed: {attack_trace.error_message}")
            else:
                outcome = OracleOutcome.FALSE_NEGATIVE
                is_pass = False
                reasons.append("Pipeline succeeded when it was expected to block or reject.")

            return SimulationOutcome(
                scenario_id=scenario.scenario_id,
                oracle_outcome=outcome,
                is_pass=is_pass,
                clean_trace=clean_trace,
                attack_trace=attack_trace,
                risk_delta=risk_delta,
                new_findings=new_findings,
                oracle_reasons=reasons,
                execution_time_ms=execution_time_ms,
            )

        # 2. Check for unexpected pipeline failures
        if not clean_trace.success or not attack_trace.success:
            outcome = OracleOutcome.UNEXPECTED_FAILURE
            is_pass = False
            reasons.append(f"Pipeline failure: Clean={clean_trace.error_message}, Attack={attack_trace.error_message}")
            return SimulationOutcome(
                scenario_id=scenario.scenario_id,
                oracle_outcome=outcome,
                is_pass=is_pass,
                clean_trace=clean_trace,
                attack_trace=attack_trace,
                risk_delta=risk_delta,
                new_findings=new_findings,
                oracle_reasons=reasons,
                execution_time_ms=execution_time_ms,
            )

        # 3. Check for false positives on clean control
        if len(clean_trace.finding_types) > 0 and expected.expected_outcome == OracleOutcome.EXPECTED_NO_DETECTION:
            outcome = OracleOutcome.FALSE_POSITIVE
            is_pass = False
            reasons.append(f"Clean baseline produced unexpected findings: {clean_trace.finding_types}")
            return SimulationOutcome(
                scenario_id=scenario.scenario_id,
                oracle_outcome=outcome,
                is_pass=is_pass,
                clean_trace=clean_trace,
                attack_trace=attack_trace,
                risk_delta=risk_delta,
                new_findings=new_findings,
                oracle_reasons=reasons,
                execution_time_ms=execution_time_ms,
            )

        # 4. Check for Clean Baseline (EXPECTED_NO_DETECTION)
        if expected.expected_outcome == OracleOutcome.EXPECTED_NO_DETECTION:
            if len(attack_trace.finding_types) == 0 and (attack_trace.risk_score or 0.0) < 0.30:
                outcome = OracleOutcome.EXPECTED_NO_DETECTION
                is_pass = True
                reasons.append("Clean scenario verified with zero findings and low risk.")
            else:
                outcome = OracleOutcome.FALSE_POSITIVE
                is_pass = False
                reasons.append("Clean scenario produced findings or elevated risk.")

            return SimulationOutcome(
                scenario_id=scenario.scenario_id,
                oracle_outcome=outcome,
                is_pass=is_pass,
                clean_trace=clean_trace,
                attack_trace=attack_trace,
                risk_delta=risk_delta,
                new_findings=new_findings,
                oracle_reasons=reasons,
                execution_time_ms=execution_time_ms,
            )

        # 5. Check for Attack Detection (EXPECTED_DETECTION)
        if expected.expected_outcome == OracleOutcome.EXPECTED_DETECTION:
            matched_findings = [f for f in expected.expect_finding_types if f in attack_trace.finding_types]
            findings_ok = len(matched_findings) > 0 or len(expected.expect_finding_types) == 0
            
            # Proof check
            proof_ok = True
            if expected.expect_proof_violation:
                proof_ok = attack_trace.proof_valid is False or attack_trace.decision == "REJECT"

            # Risk check
            risk_val = attack_trace.risk_score if attack_trace.risk_score is not None else 0.0
            risk_ok = True
            if expected.min_risk is not None and risk_val < expected.min_risk:
                risk_ok = False
                reasons.append(f"Observed risk {risk_val} below expected minimum {expected.min_risk}")
            if expected.max_risk is not None and risk_val > expected.max_risk:
                risk_ok = False
                reasons.append(f"Observed risk {risk_val} above expected maximum {expected.max_risk}")

            # Decision check
            decision_ok = True
            if expected.expected_decision is not None:
                if expected.expected_decision == ExpectedDecisionClass.ANY_ELEVATED:
                    decision_ok = attack_trace.decision in ("REVIEW", "QUARANTINE", "REJECT")
                else:
                    decision_ok = attack_trace.decision == expected.expected_decision.value
                if not decision_ok:
                    reasons.append(f"Observed decision '{attack_trace.decision}' did not match expected '{expected.expected_decision}'")

            if findings_ok and proof_ok and risk_ok and decision_ok:
                outcome = OracleOutcome.EXPECTED_DETECTION
                is_pass = True
                reasons.append(f"Attack successfully detected with findings: {matched_findings}, Risk={risk_val}, Decision={attack_trace.decision}")
            else:
                outcome = OracleOutcome.FALSE_NEGATIVE
                is_pass = False
                reasons.append("Attack was not detected as expected according to oracle criteria.")

            return SimulationOutcome(
                scenario_id=scenario.scenario_id,
                oracle_outcome=outcome,
                is_pass=is_pass,
                clean_trace=clean_trace,
                attack_trace=attack_trace,
                risk_delta=risk_delta,
                new_findings=new_findings,
                oracle_reasons=reasons,
                execution_time_ms=execution_time_ms,
            )

        return SimulationOutcome(
            scenario_id=scenario.scenario_id,
            oracle_outcome=outcome,
            is_pass=is_pass,
            clean_trace=clean_trace,
            attack_trace=attack_trace,
            risk_delta=risk_delta,
            new_findings=new_findings,
            oracle_reasons=reasons,
            execution_time_ms=execution_time_ms,
        )
