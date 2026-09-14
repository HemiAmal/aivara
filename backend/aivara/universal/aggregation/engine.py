"""Universal Project & Multi-Asset Risk Aggregation Engine (Phase 12.9)."""

from __future__ import annotations

import collections
import math
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from aivara.universal.aggregation.config import (
    MAX_CHAIN_DEPTH,
    MAX_DEPENDENCY_EDGES,
    MAX_LINEAGE_CHAINS,
    MAX_PROJECT_ASSETS,
    ImmutableAggregationPolicyConfig,
)
from aivara.universal.aggregation.enums import (
    AssetRole,
    DependencyEdgeType,
)
from aivara.universal.aggregation.exceptions import (
    AggregationError,
    AggregationResourceLimitExceededError,
    DependencyCycleError,
    InvalidAssetRiskError,
    ScopeMismatchError,
)
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
    ChainPath,
    ProjectAggregationDisposition,
)
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.proof.enums import ProofVerificationStatus
from aivara.universal.proof.schemas import UniversalProofAssessment
from aivara.universal.risk.enums import (
    EvidenceSufficiencyStatus,
    RiskLevel,
)
from aivara.universal.risk.schemas import (
    AssetRiskAssessment,
    ChainRiskAssessment,
    HierarchicalRiskAssessment,
    ProjectRiskAssessment,
    compute_risk_level,
)


class UniversalProjectAggregator:
    """Authoritative Phase 12.9 Multi-Asset and Project Risk Aggregation Engine.
    
    Guarantees:
    - Strict asset isolation: unrelated assets do not contaminate each other's risk scores.
    - Explicit DAG lineage propagation: risk propagates downstream if and only if explicit edges exist.
    - Strict DAG acyclicity: cycles fail closed with DependencyCycleError.
    - Sub-additive bounded risk composition in [0.0, 1.0].
    - Monotonicity: constituent risk increase monotonically non-decreases aggregate risk.
    - Peak dominance preservation: maximum asset risk dominates project operational risk.
    - Proof-aware disposition escalation: core proof failure -> REJECT, peripheral proof failure -> QUARANTINE.
    - 100% offline, deterministic execution with RFC 8785 JCS + SHA-256 content addressing.
    """

    def __init__(
        self,
        config: Optional[ImmutableAggregationPolicyConfig] = None,
    ) -> None:
        self.config = config or ImmutableAggregationPolicyConfig()

    def propagate_lineage_risks(
        self,
        graph: AssetDependencyGraph,
        base_asset_risks: Dict[str, float],
    ) -> Dict[str, float]:
        """Compute downstream effective asset risks via topological propagation along explicit DAG edges.
        
        Formula for asset B with parents A_1, ..., A_p:
            R_eff(B) = 1.0 - (1.0 - R_base(B)) * prod_{A in parents(B)} (1.0 - gamma_prop * w(A->B) * R_eff(A))
        """
        # Validate resource limits
        if len(graph.asset_ids) > MAX_PROJECT_ASSETS:
            raise AggregationResourceLimitExceededError(
                f"Asset count ({len(graph.asset_ids)}) exceeds maximum limit of {MAX_PROJECT_ASSETS}"
            )
        if len(graph.edges) > MAX_DEPENDENCY_EDGES:
            raise AggregationResourceLimitExceededError(
                f"Dependency edge count ({len(graph.edges)}) exceeds maximum limit of {MAX_DEPENDENCY_EDGES}"
            )

        # Validate risk inputs
        for asset_id, r in base_asset_risks.items():
            if math.isnan(r) or math.isinf(r) or r < 0.0 or r > 1.0:
                raise InvalidAssetRiskError(f"Base risk for asset '{asset_id}' must be in [0.0, 1.0], got {r}")

        # Build adjacency maps
        parents: Dict[str, List[Tuple[str, float]]] = {a: [] for a in graph.asset_ids}
        for edge in graph.edges:
            parents[edge.target_asset_id].append((edge.source_asset_id, edge.propagation_weight))

        topo_order = graph.get_topological_order()
        effective_risks: Dict[str, float] = {}

        for asset_id in topo_order:
            r_base = float(base_asset_risks.get(asset_id, 0.0))
            asset_parents = parents.get(asset_id, [])

            if not asset_parents:
                effective_risks[asset_id] = round(r_base, 6)
            else:
                # Compound upstream parent risks
                prod_term = 1.0
                for parent_id, weight in asset_parents:
                    r_parent_eff = effective_risks.get(parent_id, 0.0)
                    term = self.config.lineage_propagation_factor * weight * r_parent_eff
                    term = max(0.0, min(1.0, term))
                    prod_term *= (1.0 - term)

                r_eff = 1.0 - ((1.0 - r_base) * prod_term)
                effective_risks[asset_id] = round(float(max(0.0, min(1.0, r_eff))), 6)

        return effective_risks

    def extract_and_evaluate_chains(
        self,
        graph: AssetDependencyGraph,
        asset_risks: Dict[str, float],
    ) -> Tuple[List[ChainPath], List[ChainRiskAssessment]]:
        """Identify all lineage chains in the DAG and compute Tier-2 ChainRiskAssessments."""
        adj: Dict[str, List[str]] = {a: [] for a in graph.asset_ids}
        for edge in graph.edges:
            adj[edge.source_asset_id].append(edge.target_asset_id)

        # 1. Discover 2-hop edges for Tier-2 ChainRiskAssessment
        pairwise_assessments: List[ChainRiskAssessment] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        for edge in sorted(graph.edges, key=lambda e: (e.source_asset_id, e.target_asset_id)):
            pair = (edge.source_asset_id, edge.target_asset_id)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                r_src = asset_risks.get(pair[0], 0.0)
                r_tgt = asset_risks.get(pair[1], 0.0)

                # Pairwise compounding: R_chain = gamma_prop * R(src) * R(tgt)
                score = float(max(0.0, min(1.0, self.config.lineage_propagation_factor * r_src * r_tgt)))

                pairwise_assessments.append(
                    ChainRiskAssessment(
                        project_id=graph.project_id,
                        source_asset_id=pair[0],
                        target_asset_id=pair[1],
                        source_risk=r_src,
                        target_risk=r_tgt,
                        chain_risk_score=round(score, 6),
                        propagation_factor=self.config.lineage_propagation_factor,
                    )
                )

        # 2. Extract multi-hop chains (paths of length 2 to MAX_CHAIN_DEPTH)
        discovered_paths: List[List[str]] = []

        def find_paths(current_path: List[str], depth: int) -> None:
            if depth > self.config.max_traversal_depth:
                return
            if len(current_path) >= 2:
                discovered_paths.append(list(current_path))
            if len(discovered_paths) > MAX_LINEAGE_CHAINS:
                raise AggregationResourceLimitExceededError(
                    f"Discovered chain count exceeds limit of {MAX_LINEAGE_CHAINS}"
                )

            curr = current_path[-1]
            for neighbor in sorted(adj.get(curr, [])):
                if neighbor not in current_path:
                    find_paths(current_path + [neighbor], depth + 1)

        for start_node in sorted(graph.asset_ids):
            find_paths([start_node], 1)

        # Sort discovered paths canonically
        discovered_paths.sort(key=lambda p: (len(p), p))

        chain_paths: List[ChainPath] = []
        for path in discovered_paths:
            chain_id = "chain_" + "_to_".join(path)
            # Multi-hop score: R_chain = 1 - prod_{i=1}^{m-1} (1 - R_chain(A_i -> A_{i+1}))
            prod = 1.0
            for i in range(len(path) - 1):
                s_id, t_id = path[i], path[i + 1]
                r_s = asset_risks.get(s_id, 0.0)
                r_t = asset_risks.get(t_id, 0.0)
                hop_score = max(0.0, min(1.0, self.config.lineage_propagation_factor * r_s * r_t))
                prod *= (1.0 - hop_score)

            comp_score = float(max(0.0, min(1.0, 1.0 - prod)))
            chain_paths.append(
                ChainPath(
                    project_id=graph.project_id,
                    chain_id=chain_id,
                    asset_ids=path,
                    chain_risk_score=round(comp_score, 6),
                    hop_count=len(path) - 1,
                )
            )

        return chain_paths, pairwise_assessments

    def synthesize_project_risk(
        self,
        project_id: str,
        asset_assessments: List[AssetRiskAssessment],
        chain_count: int,
        asset_roles: Optional[Dict[str, AssetRole]] = None,
    ) -> ProjectRiskAssessment:
        """Synthesize Tier-3 Project Operational Risk preserving peak dominance and inter-asset damping.
        
        Formula:
            R_project = 1.0 - (1.0 - max_A R(A))^alpha_peak * prod_{A in Assets} (1.0 - lambda_inter * w_role(A) * R(A))
        """
        if not asset_assessments:
            return ProjectRiskAssessment(
                project_id=project_id,
                project_risk_score=0.0,
                risk_level=RiskLevel.NONE,
                peak_asset_risk=0.0,
                peak_asset_id=None,
                asset_count=0,
                chain_count=chain_count,
            )

        roles = asset_roles or {}
        sorted_assets = sorted(asset_assessments, key=lambda a: a.asset_id)

        # Validate project tenancy
        for a in sorted_assets:
            if a.project_id != project_id:
                raise ScopeMismatchError(
                    f"Asset '{a.asset_id}' project '{a.project_id}' does not match aggregation project '{project_id}'"
                )

        max_asset = max(sorted_assets, key=lambda a: (a.risk_score, a.asset_id))
        max_r = max_asset.risk_score

        # Peak dominance term
        peak_term = math.pow(1.0 - max_r, self.config.peak_dominance_exponent)

        # Inter-asset damping term
        inter_term = 1.0
        for a in sorted_assets:
            role = roles.get(a.asset_id, AssetRole.CORE_DEPLOYED)
            role_w = self.config.role_weights.get(role.value, 1.0)
            damped_r = self.config.inter_asset_damping * role_w * a.risk_score
            damped_r = max(0.0, min(1.0, damped_r))
            inter_term *= (1.0 - damped_r)

        raw_project_score = 1.0 - (peak_term * inter_term)
        project_score = float(max(0.0, min(1.0, raw_project_score)))
        risk_level = compute_risk_level(project_score)

        return ProjectRiskAssessment(
            project_id=project_id,
            project_risk_score=round(project_score, 6),
            risk_level=risk_level,
            peak_asset_risk=round(max_r, 6),
            peak_asset_id=max_asset.asset_id,
            asset_count=len(sorted_assets),
            chain_count=chain_count,
        )

    def synthesize_project_disposition(
        self,
        project_assessment: ProjectRiskAssessment,
        asset_assessments: List[AssetRiskAssessment],
        proof_assessments_map: Optional[Dict[str, UniversalProofAssessment]] = None,
        asset_roles: Optional[Dict[str, AssetRole]] = None,
    ) -> ProjectAggregationDisposition:
        """Map operational risk and Phase 12.8 cryptographic proof assessments to final project disposition."""
        project_id = project_assessment.project_id
        score = project_assessment.project_risk_score
        roles = asset_roles or {}
        proof_map = proof_assessments_map or {}

        # 1. Base threshold-based decision
        if score < 0.30:
            base_decision = UniversalDecision.ACCEPT
        elif score < 0.65:
            base_decision = UniversalDecision.REVIEW
        elif score < 0.85:
            base_decision = UniversalDecision.QUARANTINE
        else:
            base_decision = UniversalDecision.REJECT

        final_decision = base_decision
        escalation_reason: Optional[str] = None
        proof_override = False

        # 2. Check for proof-aware escalations across assets
        for a in sorted(asset_assessments, key=lambda x: x.asset_id):
            asset_id = a.asset_id
            role = roles.get(asset_id, AssetRole.CORE_DEPLOYED)
            proof_ass = proof_map.get(asset_id)

            if proof_ass and proof_ass.proof_override_required:
                proof_override = True
                if role == AssetRole.CORE_DEPLOYED:
                    final_decision = UniversalDecision.REJECT
                    escalation_reason = (
                        f"Core deployed asset '{asset_id}' suffered fatal cryptographic proof failure "
                        f"({proof_ass.overall_proof_status.value}); project escalated to REJECT"
                    )
                    break  # Fatal reject dominates everything
                elif role == AssetRole.PERIPHERAL_SAMPLE:
                    if final_decision not in (UniversalDecision.QUARANTINE, UniversalDecision.REJECT):
                        final_decision = UniversalDecision.QUARANTINE
                        escalation_reason = (
                            f"Peripheral sample asset '{asset_id}' suffered cryptographic proof failure "
                            f"({proof_ass.overall_proof_status.value}); project escalated to QUARANTINE"
                        )

        return ProjectAggregationDisposition(
            project_id=project_id,
            decision=final_decision,
            risk_score=project_assessment.project_risk_score,
            risk_level=project_assessment.risk_level,
            escalation_reason=escalation_reason,
            proof_override_triggered=proof_override,
        )

    def aggregate_project(
        self,
        graph: AssetDependencyGraph,
        asset_assessments: List[AssetRiskAssessment],
        proof_assessments_map: Optional[Dict[str, UniversalProofAssessment]] = None,
    ) -> HierarchicalRiskAssessment:
        """Perform authoritative 3-tier hierarchical multi-asset synthesis."""
        project_id = graph.project_id

        # 1. Tenancy check
        for a in asset_assessments:
            if a.project_id != project_id:
                raise ScopeMismatchError(
                    f"Asset assessment project '{a.project_id}' != graph project '{project_id}'"
                )

        # 2. Base risk extraction
        base_risks = {a.asset_id: a.risk_score for a in asset_assessments}

        # 3. Propagate risks along explicit DAG lineage
        effective_risks = self.propagate_lineage_risks(graph, base_risks)

        # 4. Update asset assessments with propagated effective risks if changed
        updated_asset_assessments: List[AssetRiskAssessment] = []
        for a in asset_assessments:
            eff_r = effective_risks.get(a.asset_id, a.risk_score)
            if eff_r != a.risk_score:
                updated_a = AssetRiskAssessment(
                    project_id=a.project_id,
                    asset_id=a.asset_id,
                    asset_type=a.asset_type,
                    risk_score=eff_r,
                    risk_level=compute_risk_level(eff_r),
                    evidence_sufficiency=a.evidence_sufficiency,
                    finding_count=a.finding_count,
                    evidence_count=a.evidence_count,
                    cluster_count=a.cluster_count,
                    contributions=a.contributions,
                )
                updated_asset_assessments.append(updated_a)
            else:
                updated_asset_assessments.append(a)

        # 5. Extract and evaluate Tier-2 cross-asset chains
        chain_paths, chain_assessments = self.extract_and_evaluate_chains(graph, effective_risks)

        # 6. Synthesize Tier-3 Project Risk Assessment
        project_assessment = self.synthesize_project_risk(
            project_id=project_id,
            asset_assessments=updated_asset_assessments,
            chain_count=len(chain_assessments),
            asset_roles=graph.asset_roles,
        )

        # 7. Check overall evidence sufficiency
        overall_suff = EvidenceSufficiencyStatus.SUFFICIENT
        if any(a.evidence_sufficiency == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY for a in updated_asset_assessments):
            overall_suff = EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY

        total_contribs = sum(len(a.contributions) for a in updated_asset_assessments)

        return HierarchicalRiskAssessment(
            project_id=project_id,
            graph_hash=graph.graph_hash,
            config_hash=self.config.config_hash,
            project_assessment=project_assessment,
            asset_assessments=sorted(updated_asset_assessments, key=lambda a: a.asset_id),
            chain_assessments=sorted(chain_assessments, key=lambda c: (c.source_asset_id, c.target_asset_id)),
            evidence_sufficiency=overall_suff,
            total_contributions=total_contribs,
        )
