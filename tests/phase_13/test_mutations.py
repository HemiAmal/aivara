"""Test mutation engine operators and copy-only isolation."""

import copy
import pytest

from aivara.attacklab.enums import MutationType
from aivara.attacklab.fixtures import SyntheticFixtureGenerator
from aivara.attacklab.mutations import MutationEngine
from aivara.attacklab.schemas import MutationDefinition


def test_mutation_copy_isolation():
    """Verify that applying a mutation does not alter the original fixture in-place."""
    clean = SyntheticFixtureGenerator.create_fixture("dataset_integrity", project_id="proj_mut", seed=42)
    original_data = copy.deepcopy(clean.data)
    original_hash = clean.content_hash

    mut = MutationDefinition(
        mutation_id="m_flip",
        operator=MutationType.LABEL_SWAP,
        target_path="samples",
        parameters={"target_index": 0},
        description="Flip label 0",
    )
    mutated = MutationEngine.apply_mutation(clean, mut)

    # Assert new fixture has changed
    assert mutated.content_hash != original_hash
    assert mutated.data["samples"][0]["is_flipped"] is True

    # Assert original fixture was NOT mutated in place
    assert clean.content_hash == original_hash
    assert clean.data == original_data
    assert "is_flipped" not in clean.data["samples"][0]


@pytest.mark.parametrize(
    "op, f_type, params, check_fn",
    [
        (
            MutationType.LABEL_SWAP,
            "dataset_integrity",
            {"target_index": 1},
            lambda d: d["samples"][1].get("is_flipped") is True,
        ),
        (
            MutationType.RECORD_DUPLICATION,
            "dataset_integrity",
            {"dup_count": 2},
            lambda d: len(d["samples"]) == 22,
        ),
        (
            MutationType.RECORD_DELETION,
            "contributor_risk",
            {"target_contributor": "contrib_00"},
            lambda d: all(c["contributor_id"] != "contrib_00" for c in d["commits"]),
        ),
        (
            MutationType.SCHEMA_TAMPERING,
            "model_integrity",
            {"new_shape": [1, 512]},
            lambda d: d["contract"]["input_shape"] == [1, 512],
        ),
        (
            MutationType.SIGNATURE_CORRUPTION,
            "proof_provenance",
            {},
            lambda d: d["signature"].startswith("deadbeef") and d["is_valid"] is False,
        ),
        (
            MutationType.METRIC_SCALING,
            "distribution_shift",
            {"shift_amount": 5.0, "kl_divergence": 4.2},
            lambda d: d["kl_divergence"] == 4.2,
        ),
        (
            MutationType.TENANT_OVERRIDE,
            "dataset_integrity",
            {"unauthorized_project_id": "proj_attacker"},
            lambda d: d["project_id"] == "proj_attacker",
        ),
        (
            MutationType.BIT_FLIP,
            "backdoor_trigger",
            {},
            lambda d: d["has_backdoor"] is True,
        ),
    ],
)
def test_all_mutation_operators(op, f_type, params, check_fn):
    """Verify that all mutation operators correctly transform target data."""
    fix = SyntheticFixtureGenerator.create_fixture(f_type, project_id="proj_mut", seed=42)
    mut = MutationDefinition(
        mutation_id=f"m_{op.value}",
        operator=op,
        target_path="",
        parameters=params,
        description=f"Test {op.value}",
    )
    mutated = MutationEngine.apply_mutation(fix, mut)
    assert check_fn(mutated.data)
