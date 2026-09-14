"""Deterministic, offline Universal Policy & Decision Engine (Phase 12.7).

Transforms authoritative Phase 12.6 UniversalRiskAssessment instances into
cryptographically verifiable, auditable UniversalPolicyDecision records.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from aivara.domain.schemas import Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.hashing import (
    compute_canonical_jcs_bytes,
    compute_sha256_digest,
)
from aivara.universal.policy.enums import (
    PolicyReasonCode,
    PolicySchemaVersion,
    RuleConditionOperator,
    UniversalDecision,
)
from aivara.universal.policy.exceptions import (
    InvalidPolicyError,
    InvalidRiskInputError,
    PolicyEvaluationError,
)
from aivara.universal.policy.schemas import (
    DecisionReason,
    DecisionTrace,
    PolicyRule,
    PolicyRuleCondition,
    RiskThresholdBand,
    RuleEvaluationTrace,
    ThresholdEvaluationTrace,
    UniversalPolicy,
    UniversalPolicyDecision,
    round_decimal_6,
)
from aivara.universal.risk.enums import EvidenceSufficiencyStatus, RiskLevel
from aivara.universal.risk.schemas import RiskContribution, UniversalRiskAssessment


class UniversalPolicyEngine:
    """Authoritative Phase 12.7 Policy and Decision Engine.
    
    Guarantees:
    - 100% offline and deterministic execution.
    - Zero risk recomputation (consumes Phase 12.6 UniversalRiskAssessment).
    - Monotonic escalation: ACCEPT < REVIEW < QUARANTINE < REJECT.
    - Fail-closed validation for malformed policy and risk inputs.
    - O(R) evaluation complexity bounded by maximum rule counts.
    """

    def validate_risk_assessment(self, assessment: UniversalRiskAssessment) -> None:
        """Validate that the incoming risk assessment is structurally and cryptographically sound."""
        if assessment is None:
            raise InvalidRiskInputError("Risk assessment cannot be None")

        if not isinstance(assessment, UniversalRiskAssessment):
            raise InvalidRiskInputError(
                f"Expected UniversalRiskAssessment, got {type(assessment).__name__}"
            )

        if not assessment.project_id or not assessment.asset_id:
            raise InvalidRiskInputError("Risk assessment is missing project_id or asset_id")

        if math.isnan(assessment.risk_score) or math.isinf(assessment.risk_score):
            raise InvalidRiskInputError(
                f"Risk assessment contains non-finite risk_score: {assessment.risk_score}"
            )

        if assessment.risk_score < 0.0 or assessment.risk_score > 1.0:
            raise InvalidRiskInputError(
                f"Risk assessment risk_score out of valid bounds [0.0, 1.0]: {assessment.risk_score}"
            )

        if not assessment.risk_hash or len(assessment.risk_hash) != 64:
            raise InvalidRiskInputError("Risk assessment is missing a valid 64-char risk_hash")

        # Cryptographic content verification against Phase 12.6 canonical descriptor
        canonical_dict = assessment.to_canonical_dict()
        expected_hash = compute_sha256_digest(compute_canonical_jcs_bytes(canonical_dict))
        if assessment.risk_hash != expected_hash:
            raise InvalidRiskInputError(
                f"Risk assessment hash mismatch: declared '{assessment.risk_hash}' != computed '{expected_hash}'"
            )

    def _build_evaluation_context(
        self, assessment: UniversalRiskAssessment
    ) -> Dict[str, Any]:
        """Extract structured property index from risk assessment for fast O(1) condition lookup."""
        contributions = assessment.contributions or []
        
        critical_count = 0
        high_count = 0
        insufficient_ancestry_count = 0
        domain_counts: Dict[str, int] = {}
        domain_max_scores: Dict[str, float] = {}

        for c in contributions:
            # Severity counts
            if c.severity == Severity.CRITICAL or (isinstance(c.severity, str) and c.severity.upper() == "CRITICAL"):
                critical_count += 1
            elif c.severity == Severity.HIGH or (isinstance(c.severity, str) and c.severity.upper() == "HIGH"):
                high_count += 1

            # Ancestry status
            if c.ancestry_status == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY:
                insufficient_ancestry_count += 1

            # Domain stats
            if c.domain:
                dom_val = c.domain.value if hasattr(c.domain, "value") else str(c.domain)
                domain_counts[dom_val] = domain_counts.get(dom_val, 0) + 1
                curr_max = domain_max_scores.get(dom_val, 0.0)
                if c.effective_score > curr_max:
                    domain_max_scores[dom_val] = c.effective_score

        context: Dict[str, Any] = {
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level.value if hasattr(assessment.risk_level, "value") else str(assessment.risk_level),
            "evidence_sufficiency": assessment.evidence_sufficiency.value if hasattr(assessment.evidence_sufficiency, "value") else str(assessment.evidence_sufficiency),
            "finding_count": assessment.finding_count,
            "evidence_count": assessment.evidence_count,
            "cluster_count": assessment.cluster_count,
            "has_critical_severity": critical_count > 0,
            "critical_finding_count": critical_count,
            "has_high_severity": high_count > 0,
            "high_finding_count": high_count,
            "insufficient_ancestry_count": insufficient_ancestry_count,
            "has_insufficient_ancestry": (
                assessment.evidence_sufficiency == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY
                or insufficient_ancestry_count > 0
            ),
        }

        # Add domain stats
        for dom, cnt in domain_counts.items():
            context[f"domain_count.{dom}"] = cnt
        for dom, max_s in domain_max_scores.items():
            context[f"domain_max_score.{dom}"] = max_s

        return context

    def evaluate_condition(
        self, condition: PolicyRuleCondition, context: Dict[str, Any]
    ) -> bool:
        """Evaluate a single declarative condition safely without eval/exec."""
        field_val = context.get(condition.field)

        # If field is missing in context, default numeric to 0.0 / int 0 / False / empty
        if field_val is None:
            if condition.operator in (
                RuleConditionOperator.GREATER_THAN,
                RuleConditionOperator.GREATER_EQUAL,
                RuleConditionOperator.LESS_THAN,
                RuleConditionOperator.LESS_EQUAL,
            ):
                field_val = 0.0
            else:
                field_val = None

        op = condition.operator
        target = condition.value

        if op == RuleConditionOperator.EQUALS:
            if isinstance(field_val, float) and isinstance(target, (int, float)):
                return round_decimal_6(field_val) == round_decimal_6(float(target))
            return field_val == target

        elif op == RuleConditionOperator.NOT_EQUALS:
            if isinstance(field_val, float) and isinstance(target, (int, float)):
                return round_decimal_6(field_val) != round_decimal_6(float(target))
            return field_val != target

        elif op == RuleConditionOperator.GREATER_THAN:
            try:
                return float(field_val) > float(target)
            except (ValueError, TypeError):
                return False

        elif op == RuleConditionOperator.GREATER_EQUAL:
            try:
                return float(field_val) >= float(target)
            except (ValueError, TypeError):
                return False

        elif op == RuleConditionOperator.LESS_THAN:
            try:
                return float(field_val) < float(target)
            except (ValueError, TypeError):
                return False

        elif op == RuleConditionOperator.LESS_EQUAL:
            try:
                return float(field_val) <= float(target)
            except (ValueError, TypeError):
                return False

        elif op == RuleConditionOperator.IN:
            if isinstance(target, (list, tuple, set)):
                return field_val in target
            return False

        elif op == RuleConditionOperator.CONTAINS:
            if isinstance(field_val, (list, tuple, set, str)):
                return target in field_val
            return False

        return False

    def evaluate(
        self, policy: UniversalPolicy, assessment: UniversalRiskAssessment
    ) -> UniversalPolicyDecision:
        """Evaluate a UniversalRiskAssessment against a UniversalPolicy deterministically.
        
        Steps:
        1. Validate inputs (policy enabled, risk assessment integrity).
        2. Match risk score against threshold bands to determine baseline decision.
        3. Evaluate declarative policy rules in priority order.
        4. Apply monotonic escalation: D_final = max(D_baseline, D_rule_1, ...).
        5. Generate complete structured decision trace and cryptographic decision_hash.
        """
        if policy is None:
            raise InvalidPolicyError("Policy cannot be None")
        if not isinstance(policy, UniversalPolicy):
            raise InvalidPolicyError(f"Expected UniversalPolicy, got {type(policy).__name__}")
        if not policy.enabled:
            raise InvalidPolicyError(f"Policy '{policy.policy_id}' is disabled")

        self.validate_risk_assessment(assessment)

        # Step 2: Threshold evaluation
        matched_band: Optional[RiskThresholdBand] = None
        for band in sorted(policy.thresholds, key=lambda b: (b.min_score, b.max_score)):
            if band.contains(assessment.risk_score):
                matched_band = band
                break

        if matched_band is not None:
            baseline_decision = matched_band.decision
            baseline_reason_code = matched_band.reason_code
            threshold_trace = ThresholdEvaluationTrace(
                band_name=matched_band.band_name,
                min_score=matched_band.min_score,
                max_score=matched_band.max_score,
                baseline_decision=matched_band.decision,
                reason_code=matched_band.reason_code,
            )
        else:
            # Fallback to policy default
            baseline_decision = policy.default_decision
            baseline_reason_code = policy.default_reason_code
            threshold_trace = None

        # Step 3: Rule evaluations
        context = self._build_evaluation_context(assessment)
        rule_traces: List[RuleEvaluationTrace] = []
        matched_rules: List[PolicyRule] = []

        sorted_rules = sorted(
            [r for r in policy.rules if r.enabled],
            key=lambda r: (r.priority, r.rule_id),
        )

        for rule in sorted_rules:
            # All conditions in a rule must be satisfied (conjunction)
            all_conditions_met = True
            cond_summaries = []
            for cond in rule.conditions:
                met = self.evaluate_condition(cond, context)
                cond_summaries.append(f"{cond.field} {cond.operator.value} {cond.value} ({'TRUE' if met else 'FALSE'})")
                if not met:
                    all_conditions_met = False

            condition_summary = "; ".join(cond_summaries)
            rule_traces.append(
                RuleEvaluationTrace(
                    rule_id=rule.rule_id,
                    priority=rule.priority,
                    matched=all_conditions_met,
                    target_decision=rule.target_decision,
                    condition_summary=condition_summary,
                )
            )

            if all_conditions_met:
                matched_rules.append(rule)

        # Step 4: Monotonic Resolution & Precedence
        # Invariant: final decision is at least as restrictive as baseline decision.
        # Decisions escalate monotonically: ACCEPT < REVIEW < QUARANTINE < REJECT.
        final_decision = baseline_decision
        escalation_applied = False
        triggering_rule: Optional[PolicyRule] = None

        # Check if any matched rule demands a more restrictive decision
        for r in matched_rules:
            if r.target_decision > final_decision:
                final_decision = r.target_decision
                escalation_applied = True
                if triggering_rule is None or r.target_decision > triggering_rule.target_decision:
                    triggering_rule = r

        matched_rule_ids = [r.rule_id for r in matched_rules]

        # Step 5: Formulate Reason
        if escalation_applied and triggering_rule is not None:
            reason_code = triggering_rule.reason_code
            summary_text = triggering_rule.reason_summary or (
                f"Escalated from {baseline_decision.value} to {final_decision.value} by rule '{triggering_rule.rule_name}'"
            )
            triggering_rule_id = triggering_rule.rule_id
            threshold_band_name = matched_band.band_name if matched_band else None
        elif matched_band is not None:
            reason_code = baseline_reason_code
            summary_text = (
                f"Evaluated risk score {assessment.risk_score:.6f} in threshold band '{matched_band.band_name}' -> {final_decision.value}"
            )
            triggering_rule_id = None
            threshold_band_name = matched_band.band_name
        else:
            reason_code = policy.default_reason_code
            summary_text = f"Default fallback policy applied -> {final_decision.value}"
            triggering_rule_id = None
            threshold_band_name = None

        decision_reason = DecisionReason(
            reason_code=reason_code,
            reason_summary=summary_text[:512],
            triggering_rule_id=triggering_rule_id,
            threshold_band=threshold_band_name,
            evaluated_risk=assessment.risk_score,
            escalation_applied=escalation_applied,
            matched_rule_ids=matched_rule_ids,
        )

        decision_trace = DecisionTrace(
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_hash=policy.policy_hash,
            risk_assessment_hash=assessment.risk_hash,
            evaluated_risk_score=assessment.risk_score,
            asset_id=assessment.asset_id,
            project_id=assessment.project_id,
            threshold_evaluation=threshold_trace,
            rule_evaluations=rule_traces,
            matched_rule_ids=matched_rule_ids,
            final_decision=final_decision,
            reason=decision_reason,
        )

        return UniversalPolicyDecision(
            project_id=assessment.project_id,
            asset_id=assessment.asset_id,
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_hash=policy.policy_hash,
            risk_assessment_hash=assessment.risk_hash,
            risk_score=assessment.risk_score,
            decision=final_decision,
            reason=decision_reason,
            trace=decision_trace,
        )
