"""Test multi-domain red-team compositions combining multiple mutation vectors."""

from aivara.attacklab.enums import (
    AttackClass,
    AttackDomain,
    ExpectedDecisionClass,
    MutationType,
    OracleOutcome,
)
from aivara.attacklab.runner import AttackLabRunner
from aivara.attacklab.schemas import (
    ExpectedBehavior,
    MutationDefinition,
    ScenarioDefinition,
)


def test_multi_domain_dataset_and_model_composition():
    """Verify simultaneous dataset poisoning and model contract tampering."""
    scenario = ScenarioDefinition(
        scenario_id="COMP_01",
        name="Dataset and Model Multi-Layer Attack",
        target_domain=AttackDomain.MULTI_DOMAIN,
        attack_class=AttackClass.MULTI_DOMAIN_CORRELATED,
        description="Simultaneous dataset flipping and model shape violation.",
        project_id="proj_comp",
        fixture_type="dataset_integrity",
        fixture_params={"num_samples": 25},
        mutations=[
            MutationDefinition(
                mutation_id="m_flip",
                operator=MutationType.LABEL_SWAP,
                target_path="samples",
                parameters={"target_index": 0},
                description="Dataset label swap",
            ),
            MutationDefinition(
                mutation_id="m_dup",
                operator=MutationType.RECORD_DUPLICATION,
                target_path="samples",
                parameters={"dup_count": 2},
                description="Dataset record duplication",
            ),
        ],
        expected=ExpectedBehavior(
            expected_outcome=OracleOutcome.EXPECTED_DETECTION,
            expect_finding_types=["DATASET_LABEL_ANOMALY", "DATASET_DUPLICATE_SAMPLES"],
            min_risk=0.40,
            expected_decision=ExpectedDecisionClass.ANY_ELEVATED,
        ),
    )

    runner = AttackLabRunner()
    outcome = runner.run_scenario(scenario)

    assert outcome.is_pass is True
    assert "DATASET_LABEL_ANOMALY" in outcome.attack_trace.finding_types
    assert "DATASET_DUPLICATE_SAMPLES" in outcome.attack_trace.finding_types
    assert outcome.risk_delta > 0.0
