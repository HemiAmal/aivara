"""Authoritative Multi-Modal Risk Integration Engine (Phase 11.9).

Implements the 5-stage synthesis pipeline:
EVIDENCE -> FINDING -> CONFIDENCE -> RISK -> DECISION

Strictly upholds:
1. Proof Layer non-compensability (deterministic, non-dilutable by statistical metrics).
2. Ancestry-aware cluster damping to prevent multi-modal double-counting.
3. Sub-additive asymptotic risk saturation in [0.0, 1.0].
4. Strict non-attribution descriptive language.
5. RFC 8785 Canonical JSON Serialization (JCS) and SHA-256 digests.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from aivara.assurance.enums import (
    DependencyRelation,
    EvidenceCategory,
    IntegrationEvaluationStatus,
)
from aivara.assurance.exceptions import (
    ConflictingEvidenceError,
    InsufficientEvidenceError,
    InvalidEvidenceError,
    PolicyValidationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.assurance.hashing import (
    compute_decision_policy_hash,
    compute_evidence_set_hash,
    compute_integrated_profile_hash,
    compute_risk_policy_hash,
)
from aivara.assurance.schemas import (
    DecisionPolicy,
    EvidenceReference,
    IntegratedAssuranceProfile,
    ModalityCluster,
    RiskPolicy,
    SynthesizedFinding,
)
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity

# Hard resource ceilings
MAX_EVIDENCE_ITEMS_LIMIT: int = 1000
MAX_FINDINGS_LIMIT: int = 200
MAX_CLUSTERS_LIMIT: int = 100


class MultiModalRiskIntegrationEngine:
    """Authoritative synthesis engine for integrating heterogeneous assurance evidence."""

    def __init__(
        self,
        default_risk_policy: Optional[RiskPolicy] = None,
        default_decision_policy: Optional[DecisionPolicy] = None,
    ) -> None:
        self.default_risk_policy = default_risk_policy or RiskPolicy()
        self.default_decision_policy = default_decision_policy or DecisionPolicy()

    def evaluate(
        self,
        project_id: str,
        target_asset_type: str,
        target_asset_id: str,
        evidence_items: Sequence[Union[EvidenceReference, Dict[str, Any]]],
        risk_policy: Optional[RiskPolicy] = None,
        decision_policy: Optional[DecisionPolicy] = None,
        required_categories: Optional[Sequence[EvidenceCategory]] = None,
    ) -> IntegratedAssuranceProfile:
        """Execute complete multi-modal assurance integration pipeline.

        Args:
            project_id: Target project / tenant identifier.
            target_asset_type: Target asset type (e.g. 'dataset', 'model', 'inference').
            target_asset_id: Target asset identifier.
            evidence_items: Ingested evidence references or dictionary representations.
            risk_policy: Optional versioned risk weighting and damping policy.
            decision_policy: Optional versioned decision disposition policy.
            required_categories: Optional list of mandatory evidence categories for completeness.

        Returns:
            Canonical, content-addressed IntegratedAssuranceProfile.
        """
        if not project_id:
            raise ProjectMismatchError("Target project_id must not be empty.")

        # 1. Resolve and bind policy hashes
        r_policy = risk_policy or self.default_risk_policy
        d_policy = decision_policy or self.default_decision_policy

        r_policy_dict = r_policy.to_canonical_dict()
        r_hash = compute_risk_policy_hash(r_policy_dict)
        bound_risk_policy = r_policy.model_copy(update={"risk_policy_hash": r_hash})

        d_policy_dict = d_policy.to_canonical_dict()
        d_hash = compute_decision_policy_hash(d_policy_dict)
        bound_decision_policy = d_policy.model_copy(update={"decision_policy_hash": d_hash})

        # 2. Resource limit verification
        total_ingested = len(evidence_items)
        if total_ingested > MAX_EVIDENCE_ITEMS_LIMIT:
            raise ResourceLimitExceededError(
                f"Evidence count ({total_ingested}) exceeds maximum budget ({MAX_EVIDENCE_ITEMS_LIMIT})."
            )

        # 3. Ingest, validate, and deduplicate evidence references
        normalized_evidence: List[EvidenceReference] = []
        seen_hashes: Set[str] = set()
        proof_violations: List[EvidenceReference] = []

        for idx, item in enumerate(evidence_items):
            ref: EvidenceReference
            if isinstance(item, EvidenceReference):
                ref = item
            elif isinstance(item, dict):
                e_id = str(item.get("evidence_id", f"ev_{idx:05d}"))
                p_id = str(item.get("project_id", project_id))
                layer = item.get("evidence_layer", EvidenceLayer.DETECTION)
                if isinstance(layer, str):
                    layer = EvidenceLayer(layer.lower())
                e_type = str(item.get("evidence_type", "distribution_shift"))
                e_cat = item.get("evidence_category", EvidenceCategory.DISTRIBUTION_SHIFT)
                if isinstance(e_cat, str):
                    e_cat = EvidenceCategory(e_cat)
                title = str(item.get("title", f"Evidence {e_id}"))
                conf = float(item.get("confidence", 0.95))
                sev = item.get("severity", Severity.INFO)
                if isinstance(sev, str):
                    sev = Severity(sev.lower())
                t_type = str(item.get("target_asset_type", target_asset_type))
                t_id = str(item.get("target_asset_id", target_asset_id))
                anc_keys = item.get("ancestry_keys", {})
                e_hash = item.get("evidence_hash", "")
                data = item.get("data_json", {})
                if not e_hash:
                    # Deterministic fallback digest over data_json
                    from aivara.crypto.canonical import canonicalize
                    e_hash = hashlib.sha256(canonicalize(data or {"evidence_id": e_id})).hexdigest()

                ref = EvidenceReference(
                    evidence_id=e_id,
                    project_id=p_id,
                    evidence_layer=layer,
                    evidence_type=e_type,
                    evidence_category=e_cat,
                    title=title,
                    description=item.get("description", None),
                    confidence=conf,
                    severity=sev,
                    target_asset_type=t_type,
                    target_asset_id=t_id,
                    ancestry_keys=anc_keys,
                    evidence_hash=e_hash,
                    data_json=data,
                )
            else:
                raise InvalidEvidenceError(f"Unsupported evidence type at index {idx}: {type(item)}")

            # Validate project scope
            if ref.project_id != project_id:
                raise ProjectMismatchError(
                    f"Project mismatch on evidence '{ref.evidence_id}': expected '{project_id}', got '{ref.project_id}'."
                )

            # Check proof violations
            if ref.evidence_layer == EvidenceLayer.PROOF:
                # In Proof layer, if severity >= HIGH or title/type indicates failure, track as proof violation
                if ref.severity in (Severity.CRITICAL, Severity.HIGH) or "fail" in ref.evidence_type.lower():
                    proof_violations.append(ref)

            # Deduplicate by evidence_hash
            if ref.evidence_hash not in seen_hashes:
                seen_hashes.add(ref.evidence_hash)
                normalized_evidence.append(ref)

        # 4. Compute evidence set hash
        evidence_hashes = [e.evidence_hash for e in normalized_evidence]
        ev_set_hash = compute_evidence_set_hash(evidence_hashes) if evidence_hashes else "0" * 64

        # 5. Form Ancestry Clusters (preventing multi-modal double-counting)
        clusters_map: Dict[str, List[EvidenceReference]] = {}
        for ev in normalized_evidence:
            # Determine ancestry key
            asset_key = (
                ev.ancestry_keys.get("dataset_version_id")
                or ev.ancestry_keys.get("model_fingerprint")
                or ev.ancestry_keys.get("source_group_id")
                or ev.ancestry_keys.get("window_id")
                or ev.target_asset_id
            )
            cat_key = ev.evidence_category.value
            cluster_id = f"clust-{cat_key}-{asset_key[:16]}"

            if cluster_id not in clusters_map:
                clusters_map[cluster_id] = []
            clusters_map[cluster_id].append(ev)

        if len(clusters_map) > MAX_CLUSTERS_LIMIT:
            raise ResourceLimitExceededError(
                f"Modality cluster count ({len(clusters_map)}) exceeds maximum limit ({MAX_CLUSTERS_LIMIT})."
            )

        # 6. Compute Cluster Scores with Correlation Damping (ADR-102)
        clusters: List[ModalityCluster] = []
        component_scores: Dict[str, float] = {}
        lambda_corr = bound_risk_policy.correlation_damping_factor

        for cluster_id in sorted(clusters_map.keys()):
            ev_list = clusters_map[cluster_id]
            first_ev = ev_list[0]
            cat_name = first_ev.evidence_category.value
            cat_weight = bound_risk_policy.category_weights.get(cat_name, 0.50)

            # Compute individual weighted terms (w_i * c_i)
            # Map severity to weight multiplier: CRITICAL=1.0, HIGH=0.8, MEDIUM=0.6, LOW=0.4, INFO=0.2
            sev_multiplier = {
                Severity.CRITICAL: 1.0,
                Severity.HIGH: 0.8,
                Severity.MEDIUM: 0.6,
                Severity.LOW: 0.4,
                Severity.INFO: 0.2,
            }

            weighted_terms: List[Tuple[float, float, str]] = []
            for ev in ev_list:
                w_sev = cat_weight * sev_multiplier.get(ev.severity, 0.5)
                score_term = w_sev * ev.confidence
                weighted_terms.append((score_term, ev.confidence, ev.evidence_id))

            # Sort weighted terms descending
            weighted_terms.sort(key=lambda x: x[0], reverse=True)

            max_term = weighted_terms[0][0]
            max_conf = weighted_terms[0][1]
            damped_sum = sum(lambda_corr * term[0] for term in weighted_terms[1:])

            # Cluster score bounded in [0.0, 1.0]
            cluster_score = float(max(0.0, min(1.0, max_term + damped_sum)))

            mod_cluster = ModalityCluster(
                cluster_id=cluster_id,
                primary_asset_type=first_ev.target_asset_type,
                primary_asset_id=first_ev.target_asset_id,
                evidence_category=first_ev.evidence_category,
                evidence_ids=[ev.evidence_id for ev in ev_list],
                max_confidence=max_conf,
                max_severity_weight=cat_weight,
                cluster_score=cluster_score,
            )
            clusters.append(mod_cluster)
            component_scores[cat_name] = max(component_scores.get(cat_name, 0.0), cluster_score)

        # 7. Sub-Additive Bounded Risk Aggregation: R = 1 - prod(1 - S(C_k))
        if clusters:
            prod_terms = 1.0
            for c in clusters:
                prod_terms *= (1.0 - c.cluster_score)
            overall_risk = float(max(0.0, min(1.0, 1.0 - prod_terms)))
        else:
            overall_risk = 0.0

        # 8. Determine Risk Level
        if overall_risk >= 0.85:
            risk_level = "CRITICAL"
        elif overall_risk >= 0.65:
            risk_level = "HIGH"
        elif overall_risk >= 0.30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 9. Evaluate Decision Disposition & Invariants
        evaluation_status = IntegrationEvaluationStatus.EVALUATED
        limitations: List[str] = []

        # Check required categories
        if required_categories:
            present_cats = {c.evidence_category for c in clusters}
            missing_cats = [rc for rc in required_categories if rc not in present_cats]
            if missing_cats:
                evaluation_status = IntegrationEvaluationStatus.INSUFFICIENT_DATA
                limitations.append(
                    f"Missing required assurance categories: {[mc.value for mc in missing_cats]}. Fails closed to review."
                )

        # Proof Layer Non-Compensability
        if proof_violations and bound_decision_policy.proof_rejection_mandatory:
            overall_disposition = Disposition.QUARANTINE
            evaluation_status = IntegrationEvaluationStatus.PROOF_VIOLATION
            rationale_header = (
                f"MANDATORY DISPOSITION [QUARANTINE/REJECT]: {len(proof_violations)} cryptographic/integrity "
                f"proof violation(s) detected. Proof failures are strictly non-compensable."
            )
        elif evaluation_status == IntegrationEvaluationStatus.INSUFFICIENT_DATA:
            overall_disposition = bound_decision_policy.insufficient_evidence_action
            rationale_header = (
                f"DISPOSITION [{overall_disposition.value.upper()}]: Insufficient evidence coverage for required categories. "
                "Operational acceptance withheld pending full multi-modal evaluation."
            )
        else:
            # Map Detection Risk to Disposition
            if overall_risk < bound_decision_policy.review_threshold:
                overall_disposition = Disposition.ACCEPT
                rationale_header = (
                    f"DISPOSITION [ACCEPT]: Operational baseline tolerance satisfied under Policy '{bound_decision_policy.policy_name}' "
                    f"(Risk Score = {overall_risk:.3f} < {bound_decision_policy.review_threshold:.2f}). "
                    "Notice: Operational acceptance is not mathematical proof of absolute safety."
                )
            elif overall_risk < bound_decision_policy.quarantine_threshold:
                overall_disposition = Disposition.REVIEW
                rationale_header = (
                    f"DISPOSITION [REVIEW]: Elevated distributional divergence observed "
                    f"(Risk Score = {overall_risk:.3f} >= {bound_decision_policy.review_threshold:.2f}). "
                    "Asset routed to human review queue."
                )
            else:
                overall_disposition = Disposition.QUARANTINE
                rationale_header = (
                    f"DISPOSITION [QUARANTINE]: Substantial multi-modal divergence / risk threshold exceeded "
                    f"(Risk Score = {overall_risk:.3f} >= {bound_decision_policy.quarantine_threshold:.2f}). "
                    "Asset isolated pending formal verification."
                )

        # 10. Synthesize Multi-Modal Findings (Non-Attribution)
        synthesized_findings: List[SynthesizedFinding] = []
        for c in clusters:
            if c.cluster_score >= 0.25:
                s_finding = SynthesizedFinding(
                    finding_id=f"syn-{c.cluster_id}",
                    finding_type=f"multi_modal_{c.evidence_category.value.lower()}",
                    title=f"Multi-modal assurance divergence observed in category '{c.evidence_category.value}'",
                    description=(
                        f"Corroborated evidence across {len(c.evidence_ids)} detector(s) indicates distributional divergence "
                        f"(Cluster Score = {c.cluster_score:.3f}). Evaluated without causal attribution."
                    ),
                    evidence_layer=EvidenceLayer.DETECTION,
                    severity=Severity.HIGH if c.cluster_score >= 0.65 else Severity.MEDIUM,
                    confidence=c.max_confidence,
                    disposition=overall_disposition,
                    affected_asset_type=c.primary_asset_type,
                    affected_asset_id=c.primary_asset_id,
                    linked_evidence_ids=c.evidence_ids,
                )
                synthesized_findings.append(s_finding)

        # 11. Compose Plain-Language Explainability Rationale
        rationale_lines = [
            rationale_header,
            f"Asset: {target_asset_type} '{target_asset_id}' | Project: '{project_id}'",
            f"Normalized Operational Exposure Index: {overall_risk:.4f} (Level: {risk_level})",
            f"Evidence Accounting: Ingested={total_ingested}, Deduplicated={len(normalized_evidence)}, Clusters={len(clusters)}, ProofViolations={len(proof_violations)}",
            f"Active Policies: Risk='{bound_risk_policy.policy_name}' (v{bound_risk_policy.policy_version}, damping={lambda_corr:.2f}), Decision='{bound_decision_policy.policy_name}' (v{bound_decision_policy.policy_version})",
        ]
        if component_scores:
            comp_str = ", ".join(f"{k}: {v:.3f}" for k, v in sorted(component_scores.items()))
            rationale_lines.append(f"Category Component Scores: [{comp_str}]")

        full_rationale = "\n".join(rationale_lines)

        # 12. Canonical Integrated Profile Serialization and Hashing
        profile_canonical_dict = {
            "analysis_version": "1.0",
            "clusters": [c.to_canonical_dict() for c in clusters],
            "component_scores": {k: float(v) for k, v in sorted(component_scores.items())},
            "decision_policy_hash": d_hash,
            "deduplicated_evidence_count": int(len(normalized_evidence)),
            "detection_findings_count": int(len(synthesized_findings)),
            "evaluation_status": evaluation_status.value,
            "evidence_set_hash": ev_set_hash,
            "overall_disposition": overall_disposition.value,
            "overall_risk_score": float(overall_risk),
            "project_id": project_id,
            "proof_violations_count": int(len(proof_violations)),
            "risk_level": risk_level,
            "risk_policy_hash": r_hash,
            "schema_version": "1.0",
            "synthesized_findings": [f.to_canonical_dict() for f in synthesized_findings],
            "target_asset_id": target_asset_id,
            "target_asset_type": target_asset_type,
        }
        profile_hash = compute_integrated_profile_hash(profile_canonical_dict)

        return IntegratedAssuranceProfile(
            schema_version="1.0",
            analysis_version="1.0",
            project_id=project_id,
            target_asset_type=target_asset_type,
            target_asset_id=target_asset_id,
            overall_disposition=overall_disposition,
            overall_risk_score=overall_risk,
            risk_level=risk_level,
            evaluation_status=evaluation_status,
            proof_violations_count=len(proof_violations),
            detection_findings_count=len(synthesized_findings),
            evidence_set_hash=ev_set_hash,
            risk_policy_hash=r_hash,
            decision_policy_hash=d_hash,
            integrated_profile_hash=profile_hash,
            component_scores=component_scores,
            rationale=full_rationale,
            clusters=clusters,
            synthesized_findings=synthesized_findings,
            deduplicated_evidence_count=len(normalized_evidence),
            limitations=limitations,
            metadata_json={"raw_evidence_count": total_ingested},
        )
