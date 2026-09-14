"""Tests for Phase 12.7 Universal Policy Schemas and Immutability (REQ-12-POL-001, 002, 019)."""

import pytest
from pydantic import ValidationError

from aivara.universal.policy.enums import (
    PolicyReasonCode,
    PolicySchemaVersion,
    RuleConditionOperator,
    UniversalDecision,
)
from aivara.universal.policy.exceptions import (
    DuplicateRuleIdError,
    InvalidPolicyError,
    PolicyResourceLimitExceededError,
)
from aivara.universal.policy.hashing import compute_policy_hash
from aivara.universal.policy.schemas import (
    PolicyRule,
    PolicyRuleCondition,
    RiskThresholdBand,
    UniversalPolicy,
)


def test_valid_default_policy():
    """Default policy builds cleanly with valid policy_hash and canonical structure."""
    policy = UniversalPolicy.get_default_policy()
    assert policy.schema_version == PolicySchemaVersion.V1_0.value
    assert policy.policy_id == "default_universal_policy"
    assert policy.policy_version == "1.0.0"
    assert len(policy.thresholds) == 4
    assert len(policy.rules) == 0
    assert len(policy.policy_hash) == 64
    assert policy.enabled is True


def test_policy_immutability():
    """UniversalPolicy is frozen and cannot be mutated at runtime."""
    policy = UniversalPolicy.get_default_policy()
    with pytest.raises((ValidationError, TypeError)):
        policy.policy_id = "new_id"  # type: ignore


def test_policy_hash_verification():
    """Declaring an incorrect policy_hash raises InvalidPolicyError (tamper detection)."""
    policy = UniversalPolicy.get_default_policy()
    canonical_dict = policy.to_canonical_dict()
    valid_hash = compute_policy_hash(canonical_dict)
    assert policy.policy_hash == valid_hash

    with pytest.raises(InvalidPolicyError, match="Policy hash mismatch"):
        UniversalPolicy(
            policy_id="test_policy",
            thresholds=policy.thresholds,
            policy_hash="f" * 64,  # Incorrect hash
        )


def test_policy_hash_mutation_sensitivity():
    """Changing any policy field (name, description, threshold, rules) changes the policy_hash."""
    p1 = UniversalPolicy.get_default_policy(policy_id="p1")
    p2 = UniversalPolicy.get_default_policy(policy_id="p2")
    assert p1.policy_hash != p2.policy_hash

    # Change description
    p3 = UniversalPolicy(
        policy_id="p1",
        description="Modified description",
        thresholds=p1.thresholds,
    )
    assert p1.policy_hash != p3.policy_hash


def test_duplicate_rule_id_rejected():
    """Defining duplicate rule IDs raises DuplicateRuleIdError."""
    cond = PolicyRuleCondition(
        field="finding_count",
        operator=RuleConditionOperator.GREATER_THAN,
        value=5,
    )
    r1 = PolicyRule(
        rule_id="RULE_01",
        rule_name="Rule One",
        conditions=[cond],
        target_decision=UniversalDecision.REVIEW,
    )
    r2 = PolicyRule(
        rule_id="RULE_01",  # Duplicate ID
        rule_name="Rule One Duplicate",
        conditions=[cond],
        target_decision=UniversalDecision.QUARANTINE,
    )

    with pytest.raises(DuplicateRuleIdError):
        UniversalPolicy(
            policy_id="test_dup_policy",
            thresholds=UniversalPolicy.get_default_policy().thresholds,
            rules=[r1, r2],
        )


def test_max_rules_limit_exceeded():
    """Exceeding MAX_POLICY_RULES (100) raises PolicyResourceLimitExceededError."""
    cond = PolicyRuleCondition(
        field="finding_count",
        operator=RuleConditionOperator.GREATER_THAN,
        value=0,
    )
    rules = [
        PolicyRule(
            rule_id=f"RULE_{i:03d}",
            rule_name=f"Rule {i}",
            conditions=[cond],
            target_decision=UniversalDecision.REVIEW,
        )
        for i in range(101)  # 101 > 100 limit
    ]

    with pytest.raises(PolicyResourceLimitExceededError):
        UniversalPolicy(
            policy_id="oversized_policy",
            thresholds=UniversalPolicy.get_default_policy().thresholds,
            rules=rules,
        )
