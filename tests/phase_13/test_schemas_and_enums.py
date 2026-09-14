"""Test Phase 13 schemas, immutability, and serialization."""

import pytest
from pydantic import ValidationError

from aivara.attacklab.enums import (
    AttackClass,
    AttackDomain,
    ExpectedDecisionClass,
    MutationType,
    OracleOutcome,
    SimulationStatus,
)
from aivara.attacklab.schemas import (
    ExpectedBehavior,
    FixturePayload,
    MutationDefinition,
    ScenarioDefinition,
)


def test_scenario_definition_immutability():
    """Verify ScenarioDefinition is frozen and computes deterministic hashes."""
    scenario = ScenarioDefinition(
        scenario_id="TEST_01",
        name="Test Scenario",
        target_domain=AttackDomain.DATASET_INTEGRITY,
        attack_class=AttackClass.SAMPLE_POISONING,
        description="Test description",
        project_id="proj_001",
        fixture_type="dataset_integrity",
        expected=ExpectedBehavior(
            expected_outcome=OracleOutcome.EXPECTED_DETECTION,
            expect_finding_types=["DATASET_LABEL_ANOMALY"],
        ),
    )
    assert scenario.scenario_id == "TEST_01"
    h1 = scenario.compute_scenario_hash()
    h2 = scenario.compute_scenario_hash()
    assert h1 == h2
    assert len(h1) == 64

    # Immutability check
    with pytest.raises(ValidationError):
        scenario.name = "Mutated Name"


def test_mutation_definition_immutability():
    """Verify MutationDefinition is frozen."""
    mut = MutationDefinition(
        mutation_id="m1",
        operator=MutationType.LABEL_SWAP,
        target_path="samples",
        description="Label swap test",
    )
    assert mut.operator == MutationType.LABEL_SWAP
    with pytest.raises(ValidationError):
        mut.operator = MutationType.BIT_FLIP


def test_all_enums_coverage():
    """Verify all enums have valid member counts."""
    assert len(AttackDomain) == 10
    assert len(AttackClass) >= 20
    assert len(MutationType) == 10
    assert len(SimulationStatus) == 7
    assert len(OracleOutcome) == 8
    assert len(ExpectedDecisionClass) == 5
