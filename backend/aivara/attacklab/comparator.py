"""Differential comparator for clean control and attack traces in the Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

from typing import List, Tuple

from aivara.attacklab.schemas import PipelineExecutionTrace


class DifferentialComparator:
    """Evaluates differential outcomes between clean baseline and mutated attack executions."""

    @staticmethod
    def compare(clean: PipelineExecutionTrace, attack: PipelineExecutionTrace) -> Tuple[float, List[str], bool]:
        """Compute differential risk, emergent findings, and monotonic risk escalation.
        
        Returns:
            Tuple of (risk_delta, new_findings, is_monotonic)
        """
        clean_risk = clean.risk_score if clean.risk_score is not None else 0.0
        attack_risk = attack.risk_score if attack.risk_score is not None else 0.0

        risk_delta = round(attack_risk - clean_risk, 4)
        is_monotonic = attack_risk >= clean_risk

        clean_set = set(clean.finding_types)
        new_findings = [f for f in attack.finding_types if f not in clean_set]

        return risk_delta, new_findings, is_monotonic
