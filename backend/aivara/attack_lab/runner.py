"""Orchestration runner for AIVARA Attack Demonstration Lab (Phase 4.15).

Provides high-level programmatic execution, structured reporting,
and summary aggregation across all 10 attack demonstrations.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from aivara.attack_lab.models import (
    AttackExecutionSummary,
    AttackResult,
    AttackScenario,
)
from aivara.attack_lab.scenarios import (
    SCENARIO_REGISTRY,
    get_scenario_by_id,
    list_all_scenarios,
    normalize_attack_id,
    run_scenario_by_id,
)

logger = logging.getLogger("aivara.attack_lab.runner")


class AttackLabRunner:
    """High-level runner for executing controlled attack demonstrations."""

    def list_scenarios(self) -> List[AttackScenario]:
        """Return metadata for all available attack scenarios."""
        return list_all_scenarios()

    def get_scenario(self, attack_id: str) -> AttackScenario:
        """Get metadata for a specific scenario by ID."""
        return get_scenario_by_id(attack_id)

    def run_scenario(self, attack_id: str) -> AttackResult:
        """Execute a single attack scenario demonstration by ID.

        Args:
            attack_id: Scenario identifier (e.g. 'ATTACK-01', 'attack-001', '1').

        Returns:
            Structured AttackResult containing diagnostic detection evidence.
        """
        norm_id = normalize_attack_id(attack_id)
        logger.info("Executing attack demonstration: %s", norm_id)
        result = run_scenario_by_id(norm_id)
        logger.info(
            "Attack %s executed: detected=%s, status=%s, cleanup=%s",
            norm_id,
            result.detected,
            result.verification_status,
            result.cleanup_status,
        )
        return result

    def run_all(self) -> AttackExecutionSummary:
        """Execute all 10 attack demonstrations sequentially in isolation.

        Returns:
            Aggregated AttackExecutionSummary report.
        """
        results: List[AttackResult] = []
        logger.info("Starting execution of all %d attack demonstrations", len(SCENARIO_REGISTRY))

        for attack_id in sorted(SCENARIO_REGISTRY.keys()):
            res = self.run_scenario(attack_id)
            results.append(res)

        detected_count = sum(1 for r in results if r.detected)
        all_passed = (detected_count == len(results)) and len(results) > 0

        summary = AttackExecutionSummary(
            total_scenarios=len(SCENARIO_REGISTRY),
            scenarios_executed=len(results),
            scenarios_detected=detected_count,
            all_detected=all_passed,
            results=results,
        )

        logger.info(
            "Attack lab run completed: %d/%d attacks detected (all_detected=%s)",
            detected_count,
            len(results),
            all_passed,
        )
        return summary
