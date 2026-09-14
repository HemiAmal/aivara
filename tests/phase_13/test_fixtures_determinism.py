"""Test synthetic fixture generator determinism and coverage across all domains."""

import pytest

from aivara.attacklab.fixtures import SyntheticFixtureGenerator


@pytest.mark.parametrize(
    "fixture_type",
    [
        "dataset_integrity",
        "contributor_risk",
        "model_integrity",
        "behavioral_integrity",
        "backdoor_trigger",
        "inference_integrity",
        "distribution_shift",
        "proof_provenance",
        "security_boundary",
        "multi_domain",
    ],
)
def test_fixture_determinism_same_seed(fixture_type: str):
    """Verify that identical seeds produce byte-identical content hashes."""
    fix1 = SyntheticFixtureGenerator.create_fixture(fixture_type, project_id="proj_det", seed=42)
    fix2 = SyntheticFixtureGenerator.create_fixture(fixture_type, project_id="proj_det", seed=42)

    assert fix1.content_hash == fix2.content_hash
    assert fix1.data == fix2.data


def test_fixture_different_seeds_produce_different_hashes():
    """Verify that different seeds produce distinct fixtures."""
    fix1 = SyntheticFixtureGenerator.create_fixture("dataset_integrity", project_id="proj_det", seed=42)
    fix2 = SyntheticFixtureGenerator.create_fixture("dataset_integrity", project_id="proj_det", seed=999)

    assert fix1.content_hash != fix2.content_hash
