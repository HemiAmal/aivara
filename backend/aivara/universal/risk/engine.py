"""Authoritative Universal Risk Computation Engine (Phase 12.6).

Transforms validated, normalized, correlated evidence from the Universal Evidence Graph
into deterministic asset-level and universal risk assessments without policy decisions
or multi-asset project aggregation.
"""

from __future__ import annotations

import collections
import math
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.correlation.schemas import CrossDomainCorrelationAssessment
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import ProjectMismatchError
from aivara.universal.graph import (
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    UniversalEvidenceGraph,
)
from aivara.universal.risk.config import ImmutableAggregationConfig
from aivara.universal.risk.enums import (
    AggregationStage,
    EvidenceSufficiencyStatus,
    RiskLevel,
)
from aivara.universal.risk.exceptions import NonFiniteRiskError, RiskOutOfRangeError
from aivara.universal.risk.schemas import (
    RiskContribution,
    UniversalRiskAssessment,
    compute_risk_level,
)

CANONICAL_SEVERITY_MULTIPLIERS: Dict[str, float] = {
    Severity.CRITICAL.value: 1.00,
    Severity.HIGH.value: 0.70,
    Severity.MEDIUM.value: 0.40,
    Severity.LOW.value: 0.10,
    Severity.INFO.value: 0.05,
}


def round_decimal(val: float, places: int = 6) -> float:
    """Deterministic rounding using ROUND_HALF_UP to exact decimal places."""
    d = Decimal(str(val))
    target = Decimal(f"1e-{places}")
    rounded = d.quantize(target, rounding=ROUND_HALF_UP)
    return float(rounded)


class UniversalRiskComputationEngine:
    """Authoritative Phase 12.6 engine for deterministic asset-level and universal risk computation.
    
    Responsibilities:
    - Calculates evidence contributions: term(e) = w_e * c_e * s_e.
    - Integrates Phase 12.5 cross-domain correlation attenuation for detection-layer evidence.
    - Preserves proof-layer evidence inviolability (unattenuated).
    - Groups evidence into ancestry-aware clusters with intra-cluster damping (lambda_intra = 0.15).
    - Computes bounded composition: R(A) = 1 - prod(1 - S(C_k)).
    - Generates immutable UniversalRiskAssessment with deterministic JCS SHA-256 risk_hash.
    
    Hard Boundaries:
    - Zero policy decisions (ACCEPT, REVIEW, QUARANTINE, REJECT).
    - Zero proof rejection overrides.
    - Zero project-level or cross-asset chain risk aggregation (reserved for Phase 12.9).
    """

    def __init__(self, default_config: Optional[ImmutableAggregationConfig] = None) -> None:
        self.default_config = default_config or ImmutableAggregationConfig(
            severity_multipliers=dict(CANONICAL_SEVERITY_MULTIPLIERS)
        )

    def compute_asset_risk(
        self,
        graph: UniversalEvidenceGraph,
        asset_id: str,
        correlation_assessment: Optional[CrossDomainCorrelationAssessment] = None,
        config: Optional[ImmutableAggregationConfig] = None,
    ) -> UniversalRiskAssessment:
        """Compute authoritative risk for a single target asset."""
        if not asset_id:
            raise ValueError("Target asset_id must not be empty.")

        if correlation_assessment is not None and correlation_assessment.project_id != graph.project_id:
            raise ProjectMismatchError(
                f"Correlation assessment project '{correlation_assessment.project_id}' does not match graph project '{graph.project_id}'."
            )

        cfg = config or self.default_config
        project_id = graph.project_id

        # 1. Extract domain attenuation factors from correlation assessment if available
        domain_attenuations: Dict[SubsystemDomain, float] = {}
        if correlation_assessment is not None:
            for s in correlation_assessment.domain_summaries:
                domain_attenuations[s.domain] = s.attenuation_factor

        # 2. Filter nodes belonging to target asset
        asset_finding_nodes: List[GraphNode] = []
        asset_evidence_nodes: List[GraphNode] = []
        asset_type = "asset"

        for node in graph.get_nodes():
            if node.node_type == GraphNodeType.EVIDENCE:
                node_asset_id = str(node.metadata.get("primary_asset_id") or "default_asset")
                if node_asset_id == asset_id:
                    asset_evidence_nodes.append(node)
                    asset_type = str(node.metadata.get("primary_asset_type") or asset_type)
            elif node.node_type == GraphNodeType.FINDING:
                node_asset_id = str(node.metadata.get("affected_asset_id") or "default_asset")
                if node_asset_id == asset_id:
                    asset_finding_nodes.append(node)
                    asset_type = str(node.metadata.get("affected_asset_type") or asset_type)
            elif node.node_type == GraphNodeType.ASSET and node.canonical_identity == asset_id:
                asset_type = str(node.metadata.get("asset_type") or asset_type)

        # 3. Partition evidence into ancestry clusters
        clusters_map: Dict[str, Tuple[List[GraphNode], EvidenceSufficiencyStatus]] = collections.defaultdict(
            lambda: ([], EvidenceSufficiencyStatus.SUFFICIENT)
        )

        for ev in asset_evidence_nodes:
            cluster_key = "unclustered"
            status = EvidenceSufficiencyStatus.SUFFICIENT
            if ev.ancestry_path and not ev.ancestry_path.is_empty():
                ap = ev.ancestry_path
                if ap.sample_id:
                    cluster_key = f"anc_sample_{ap.sample_id}"
                elif ap.dataset_version_id:
                    cluster_key = f"anc_ds_{ap.dataset_version_id}"
                elif ap.model_fingerprint:
                    cluster_key = f"anc_model_{ap.model_fingerprint[:16]}"
                elif ap.window_id:
                    cluster_key = f"anc_win_{ap.window_id}"
                elif ap.source_id:
                    cluster_key = f"anc_src_{ap.source_id}"
            else:
                cluster_key = f"ev_ind_{ev.canonical_identity}"
                status = EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY

            cur_nodes, cur_status = clusters_map[cluster_key]
            new_status = status if status == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY else cur_status
            clusters_map[cluster_key] = (cur_nodes + [ev], new_status)

        # Incorporate standalone findings without direct evidence
        standalone_findings = [
            f for f in asset_finding_nodes
            if not graph.get_evidence_for_finding(f.canonical_identity)
        ]
        for f in standalone_findings:
            cur_nodes, cur_status = clusters_map[f"find_ind_{f.canonical_identity}"]
            clusters_map[f"find_ind_{f.canonical_identity}"] = (cur_nodes + [f], cur_status)

        cluster_scores: List[float] = []
        contributions: List[RiskContribution] = []

        # 4. Evaluate each cluster with intra-cluster damping
        for cluster_id in sorted(clusters_map.keys()):
            nodes, cluster_sufficiency = clusters_map[cluster_id]
            weighted_terms: List[Tuple[float, GraphNode]] = []

            for n in nodes:
                sev = n.severity or Severity.INFO
                sev_mult = cfg.severity_multipliers.get(
                    sev.value,
                    CANONICAL_SEVERITY_MULTIPLIERS.get(sev.value, 0.05)
                )

                # Confidence validation
                conf = n.confidence if n.confidence is not None else (
                    1.0 if n.evidence_layer == EvidenceLayer.PROOF else 0.90
                )
                if math.isnan(conf) or math.isinf(conf) or conf < 0.0 or conf > 1.0:
                    raise NonFiniteRiskError(f"Confidence value {conf} is invalid on node {n.node_id}")

                # Proof Layer Inviolability: Proof is never attenuated
                att_factor = 1.0
                if n.evidence_layer != EvidenceLayer.PROOF and n.domain in domain_attenuations:
                    att_factor = domain_attenuations[n.domain]

                weight = 1.0
                raw_term = float(weight * conf * sev_mult * att_factor)
                raw_term = max(0.0, min(1.0, raw_term))
                weighted_terms.append((raw_term, n))

            if not weighted_terms:
                continue

            # Sort terms descending for primary driver selection
            weighted_terms.sort(key=lambda x: (x[0], x[1].node_id), reverse=True)

            max_term, max_node = weighted_terms[0]
            # Intra-cluster damping: S(C_k) = min(1, max(term) + lambda_intra * sum(others))
            damped_sum = sum(cfg.intra_cluster_damping * term[0] for term in weighted_terms[1:])
            cluster_score = round_decimal(max(0.0, min(1.0, max_term + damped_sum)), 6)
            cluster_scores.append(cluster_score)

            c_id = f"contrib_{project_id}_{asset_id}_{cluster_id}"
            contrib = RiskContribution(
                contribution_id=c_id,
                stage=AggregationStage.EVIDENCE_CLUSTER,
                source_id=max_node.node_id,
                target_id=asset_id,
                domain=max_node.domain,
                severity=max_node.severity,
                confidence=max_node.confidence,
                raw_score=max_term,
                effective_score=cluster_score,
                ancestry_cluster_id=cluster_id,
                ancestry_status=cluster_sufficiency,
                provenance_hashes=[],
                metadata={"member_count": len(nodes)},
            )
            contributions.append(contrib)

        # 5. Bounded sub-additive composition: R(A) = 1 - prod(1 - S(C_k))
        if cluster_scores:
            prod_terms = 1.0
            for score in cluster_scores:
                prod_terms *= (1.0 - score)
            asset_risk = round_decimal(max(0.0, min(1.0, 1.0 - prod_terms)), 6)
        else:
            asset_risk = 0.0

        risk_level = compute_risk_level(asset_risk)
        asset_sufficiency = (
            EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY
            if any(c.ancestry_status == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY for c in contributions)
            else EvidenceSufficiencyStatus.SUFFICIENT
        )

        corr_hash = correlation_assessment.correlation_hash if correlation_assessment else None

        return UniversalRiskAssessment(
            project_id=project_id,
            asset_id=asset_id,
            asset_type=asset_type,
            risk_score=asset_risk,
            risk_level=risk_level,
            evidence_sufficiency=asset_sufficiency,
            finding_count=len(asset_finding_nodes),
            evidence_count=len(asset_evidence_nodes),
            cluster_count=len(cluster_scores),
            correlation_hash=corr_hash,
            graph_merkle_root=graph.merkle_root,
            contributions=sorted(contributions, key=lambda c: c.contribution_id),
        )

    def compute_universal_risk(
        self,
        graph: UniversalEvidenceGraph,
        correlation_assessment: Optional[CrossDomainCorrelationAssessment] = None,
        config: Optional[ImmutableAggregationConfig] = None,
    ) -> List[UniversalRiskAssessment]:
        """Compute universal risk assessments for all distinct assets represented in the graph."""
        distinct_asset_ids: Set[str] = set()

        for node in graph.get_nodes():
            if node.node_type == GraphNodeType.EVIDENCE:
                aid = node.metadata.get("primary_asset_id")
                if aid:
                    distinct_asset_ids.add(str(aid))
            elif node.node_type == GraphNodeType.FINDING:
                aid = node.metadata.get("affected_asset_id")
                if aid:
                    distinct_asset_ids.add(str(aid))
            elif node.node_type == GraphNodeType.ASSET:
                distinct_asset_ids.add(str(node.canonical_identity))

        if not distinct_asset_ids:
            distinct_asset_ids.add("default_asset")

        assessments = [
            self.compute_asset_risk(
                graph=graph,
                asset_id=aid,
                correlation_assessment=correlation_assessment,
                config=config,
            )
            for aid in sorted(distinct_asset_ids)
        ]
        return assessments
