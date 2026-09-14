"""Clean control generator and pairing manager for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

import copy
from typing import Tuple

from aivara.attacklab.fixtures import SyntheticFixtureGenerator
from aivara.attacklab.mutations import MutationEngine
from aivara.attacklab.schemas import FixturePayload, ScenarioDefinition


class CleanControlManager:
    """Manages the generation and pairing of clean baseline controls and mutated attack fixtures."""

    @staticmethod
    def generate_paired_fixtures(scenario: ScenarioDefinition) -> Tuple[FixturePayload, FixturePayload]:
        """Generate identical clean baseline fixture and its corresponding mutated attack fixture.
        
        Returns:
            Tuple of (clean_fixture, attack_fixture)
        """
        # 1. Generate clean baseline
        clean_fixture = SyntheticFixtureGenerator.create_fixture(
            fixture_type=scenario.fixture_type,
            project_id=scenario.project_id,
            seed=scenario.seed,
            params=scenario.fixture_params,
        )

        # 2. Derive attack fixture via sequential mutation of deep copies
        current_fixture = clean_fixture
        for mutation in scenario.mutations:
            current_fixture = MutationEngine.apply_mutation(current_fixture, mutation)

        attack_fixture = current_fixture
        return clean_fixture, attack_fixture
