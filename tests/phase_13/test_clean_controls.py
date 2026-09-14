"""Test clean control manager and paired experiment generation."""

from aivara.attacklab.controls import CleanControlManager
from aivara.attacklab.enums import AttackClass, AttackDomain, MutationType, OracleOutcome
from aivara.attacklab.schemas import (
    ExpectedBehavior,
    MutationDefinition,
    ScenarioDefinition,
)


def test_paired_fixtures_generation():
    """Verify clean control and attack fixtures are paired correctly."""
    scenario = ScenarioDefinition(
        scenario_id="PAIR_01",
        name="Paired Experiment Test",
        target_domain=AttackDomain.DATASET_INTEGRITY,
        attack_class=AttackClass.SAMPLE_POISONING,
        description="Testing clean vs attack pairing",
        project_id="proj_pair",
        fixture_type="dataset_integrity",
        mutations=[
            MutationDefinition(
                mutation_id="m1",
                operator=MutationType.LABEL_SWAP,
                target_path="samples",
                parameters={"target_index": 0},
                description="Flip label",
            )
        ],
        expected=ExpectedBehavior(expected_outcome=OracleOutcome.EXPECTED_DETECTION),
    )

    clean_fix, attack_fix = CleanControlManager.generate_paired_fixtures(scenario)

    assert clean_fix.fixture_id != attack_fix.fixture_id
    assert clean_fix.content_hash != attack_fix.content_hash
    # Clean has no flipped label
    assert "is_flipped" not in clean_fix.data["samples"][0]
    # Attack has flipped label
    assert attack_fix.data["samples"][0]["is_flipped"] is True
