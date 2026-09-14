"""Test resource limits, ceiling enforcement, and fail-closed behaviors."""

import pytest

from aivara.attacklab.enums import (
    AttackClass,
    AttackDomain,
    MutationType,
    OracleOutcome,
)
from aivara.attacklab.exceptions import ResourceBudgetExceededError
from aivara.attacklab.runner import AttackLabRunner, MAX_MUTATIONS_PER_SCENARIO, MAX_SCENARIOS_PER_RUN
from aivara.attacklab.schemas import (
    ExpectedBehavior,
    MutationDefinition,
    ScenarioDefinition,
)


def test_oversized_payload_fails_closed():
    """Verify oversized payload exceeds ceiling and is blocked."""
    scenario = ScenarioDefinition(
        scenario_id="SEC_RES_01",
        name="Oversized Payload Test",
        target_domain=AttackDomain.SECURITY_BOUNDARY,
        attack_class=AttackClass.OVERSIZED_PAYLOAD_EXHAUSTION,
        description="Oversized payload test",
        project_id="proj_res",
        fixture_type="security_boundary",
        mutations=[
            MutationDefinition(
                mutation_id="m_size",
                operator=MutationType.VALUE_SUBSTITUTION,
                target_path="payload_size_bytes",
                parameters={"new_value": 50 * 1024 * 1024},  # 50 MB
                description="Oversized 50MB payload",
            )
        ],
        expected=ExpectedBehavior(
            expected_outcome=OracleOutcome.BLOCKED_BY_RESOURCE,
            expect_rejection_or_block=True,
        ),
    )

    runner = AttackLabRunner()
    outcome = runner.run_scenario(scenario)

    assert outcome.is_pass is True
    assert outcome.oracle_outcome == OracleOutcome.BLOCKED_BY_RESOURCE


def test_mutation_count_budget_exceeded():
    """Verify exceeding MAX_MUTATIONS_PER_SCENARIO raises ResourceBudgetExceededError."""
    mutations = [
        MutationDefinition(
            mutation_id=f"m_{i}",
            operator=MutationType.LABEL_SWAP,
            target_path="samples",
            parameters={"target_index": i % 5},
            description=f"Mutation {i}",
        )
        for i in range(MAX_MUTATIONS_PER_SCENARIO + 1)
    ]

    scenario = ScenarioDefinition(
        scenario_id="RES_FAIL_01",
        name="Excessive Mutations Scenario",
        target_domain=AttackDomain.DATASET_INTEGRITY,
        attack_class=AttackClass.SAMPLE_POISONING,
        description="Exceeds mutation limit",
        project_id="proj_res",
        fixture_type="dataset_integrity",
        mutations=mutations,
        expected=ExpectedBehavior(expected_outcome=OracleOutcome.EXPECTED_DETECTION),
    )

    runner = AttackLabRunner()
    with pytest.raises(ResourceBudgetExceededError):
        runner.run_scenario(scenario)


def test_scenario_batch_budget_exceeded():
    """Verify exceeding MAX_SCENARIOS_PER_RUN raises ResourceBudgetExceededError."""
    scenarios = [
        ScenarioDefinition(
            scenario_id=f"SC_{i}",
            name=f"Scenario {i}",
            target_domain=AttackDomain.DATASET_INTEGRITY,
            attack_class=AttackClass.SAMPLE_POISONING,
            description="Batch test",
            project_id="proj_res",
            fixture_type="dataset_integrity",
            expected=ExpectedBehavior(expected_outcome=OracleOutcome.EXPECTED_NO_DETECTION),
        )
        for i in range(MAX_SCENARIOS_PER_RUN + 1)
    ]

    runner = AttackLabRunner()
    with pytest.raises(ResourceBudgetExceededError):
        runner.run_suite(scenarios, project_id="proj_res")
