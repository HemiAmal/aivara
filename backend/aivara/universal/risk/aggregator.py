"""Deterministic Hierarchical Multi-Asset Risk Aggregation Engine (Phase 12.4)."""

from __future__ import annotations

import collections
import math
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import InvalidEvidenceError, ProjectMismatchError
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
    AssetRiskAssessment,
    ChainRiskAssessment,
    HierarchicalRiskAssessment,
    ProjectRiskAssessment,
    RiskContribution,
    compute_risk_level,
)


class HierarchicalRiskAggregator:
    """Closed-form hierarchical risk aggregator implementing Tier 1-3 multi-asset synthesis.
    
    Phase 12.4 calculates risk and analytical data sufficiency metrics.
    Phase 12.4 does NOT perform decision routing or assign policy dispositions.
    """

    def __init__(self, default_config: Optional[ImmutableAggregationConfig] = None) -> None:
        self.default_config = default_config or ImmutableAggregationConfig()

    def aggregate_hierarchy(
        self,
        graph: UniversalEvidenceGraph,
        config: Optional[ImmutableAggregationConfig] = None,
    ) -> HierarchicalRiskAssessment:
        """Synthesize Tier-1 Asset, Tier-2 Chain, and Tier-3 Project operational risks from graph."""
        cfg = config or self.default_config
        project_id = graph.project_id

        # 1. Discover all assets represented in graph
        asset_map: Dict[str, Tuple[str, List[GraphNode], List[GraphNode]]] = collections.defaultdict(
            lambda: ("asset", [], [])  # (asset_type, finding_nodes, evidence_nodes)
        )

        for node in graph.get_nodes():
            if node.node_type == GraphNodeType.EVIDENCE:
                asset_id = str(node.metadata.get("primary_asset_id") or "default_asset")
                asset_type = str(node.metadata.get("primary_asset_type") or "asset")
                cur_type, findings, evidences = asset_map[asset_id]
                asset_map[asset_id] = (asset_type if asset_type != "asset" else cur_type, findings, evidences + [node])
            elif node.node_type == GraphNodeType.FINDING:
                asset_id = str(node.metadata.get("affected_asset_id") or "default_asset")
                asset_type = str(node.metadata.get("affected_asset_type") or "asset")
                cur_type, findings, evidences = asset_map[asset_id]
                asset_map[asset_id] = (asset_type if asset_type != "asset" else cur_type, findings + [node], evidences)
            elif node.node_type == GraphNodeType.ASSET:
                asset_id = node.canonical_identity
                asset_type = str(node.metadata.get("asset_type") or "asset")
                cur_type, findings, evidences = asset_map[asset_id]
                asset_map[asset_id] = (asset_type if asset_type != "asset" else cur_type, findings, evidences)

        # 2. Evaluate Tier-1 Asset Risk Assessments
        asset_assessments: List[AssetRiskAssessment] = []
        all_contributions: List[RiskContribution] = []

        for asset_id in sorted(asset_map.keys()):
            asset_type, f_nodes, e_nodes = asset_map[asset_id]
            assessment, contribs = self._evaluate_single_asset(
                project_id=project_id,
                asset_id=asset_id,
                asset_type=asset_type,
                finding_nodes=f_nodes,
                evidence_nodes=e_nodes,
                graph=graph,
                config=cfg,
            )
            asset_assessments.append(assessment)
            all_contributions.extend(contribs)

        # 3. Evaluate Tier-2 Cross-Asset Lineage Chains
        chain_assessments = self._evaluate_cross_asset_chains(
            project_id=project_id,
            asset_assessments={a.asset_id: a for a in asset_assessments},
            graph=graph,
            config=cfg,
        )

        # 4. Evaluate Tier-3 Project Operational Risk
        project_assessment = self._evaluate_project_risk(
            project_id=project_id,
            asset_assessments=asset_assessments,
            chain_count=len(chain_assessments),
            config=cfg,
        )

        # 5. Determine overall analytical evidence sufficiency
        overall_sufficiency = EvidenceSufficiencyStatus.SUFFICIENT
        if any(a.evidence_sufficiency == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY for a in asset_assessments):
            overall_sufficiency = EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY

        return HierarchicalRiskAssessment(
            project_id=project_id,
            graph_hash=graph.graph_hash,
            config_hash=cfg.config_hash,
            project_assessment=project_assessment,
            asset_assessments=sorted(asset_assessments, key=lambda a: a.asset_id),
            chain_assessments=sorted(chain_assessments, key=lambda c: (c.source_asset_id, c.target_asset_id)),
            evidence_sufficiency=overall_sufficiency,
            total_contributions=len(all_contributions),
        )

    def _evaluate_single_asset(
        self,
        project_id: str,
        asset_id: str,
        asset_type: str,
        finding_nodes: List[GraphNode],
        evidence_nodes: List[GraphNode],
        graph: UniversalEvidenceGraph,
        config: ImmutableAggregationConfig,
    ) -> Tuple[AssetRiskAssessment, List[RiskContribution]]:
        """Compute Tier-1 Asset-Level Risk R(A) with ancestry clustering and intra-cluster damping."""
        # Partition evidence into ancestry clusters
        clusters_map: Dict[str, Tuple[List[GraphNode], EvidenceSufficiencyStatus]] = collections.defaultdict(
            lambda: ([], EvidenceSufficiencyStatus.SUFFICIENT)
        )

        for ev in evidence_nodes:
            cluster_key = "unclustered"
            status = EvidenceSufficiencyStatus.SUFFICIENT
            if ev.ancestry_path and not ev.ancestry_path.is_empty():
                ap = ev.ancestry_path
                # Construct canonical primary ancestry key
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

        # Also incorporate standalone findings that have no direct evidence nodes attached
        standalone_findings = [
            f for f in finding_nodes
            if not graph.get_evidence_for_finding(f.canonical_identity)
        ]
        for f in standalone_findings:
            cur_nodes, cur_status = clusters_map[f"find_ind_{f.canonical_identity}"]
            clusters_map[f"find_ind_{f.canonical_identity}"] = (cur_nodes + [f], cur_status)

        cluster_scores: List[float] = []
        contributions: List[RiskContribution] = []

        for cluster_id in sorted(clusters_map.keys()):
            nodes, cluster_sufficiency = clusters_map[cluster_id]
            weighted_terms: List[Tuple[float, GraphNode]] = []

            for n in nodes:
                sev = n.severity or Severity.INFO
                sev_mult = config.severity_multipliers.get(sev.value, 0.2)
                conf = n.confidence if n.confidence is not None else (1.0 if n.evidence_layer == EvidenceLayer.PROOF else 0.90)
                
                # Check finite
                if math.isnan(conf) or math.isinf(conf) or conf < 0.0 or conf > 1.0:
                    raise NonFiniteRiskError(f"Confidence value {conf} is invalid on node {n.node_id}")

                weight = 1.0
                raw_term = float(weight * conf * sev_mult)
                raw_term = max(0.0, min(1.0, raw_term))
                weighted_terms.append((raw_term, n))

            if not weighted_terms:
                continue

            # Sort descending by raw term, with canonical node_id tie-breaking
            weighted_terms.sort(key=lambda x: (x[0], x[1].node_id), reverse=True)

            max_term, max_node = weighted_terms[0]
            damped_sum = sum(config.intra_cluster_damping * term[0] for term in weighted_terms[1:])

            cluster_score = float(max(0.0, min(1.0, max_term + damped_sum)))
            cluster_scores.append(cluster_score)

            # Record contribution trace for the primary driver
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

        # Sub-additive bounded risk composition: R(A) = 1 - prod(1 - S(C_k))
        if cluster_scores:
            prod_terms = 1.0
            for score in cluster_scores:
                prod_terms *= (1.0 - score)
            asset_risk = float(max(0.0, min(1.0, 1.0 - prod_terms)))
        else:
            asset_risk = 0.0

        risk_level = compute_risk_level(asset_risk)
        asset_sufficiency = (
            EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY
            if any(c.ancestry_status == EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY for c in contributions)
            else EvidenceSufficiencyStatus.SUFFICIENT
        )

        assessment = AssetRiskAssessment(
            project_id=project_id,
            asset_id=asset_id,
            asset_type=asset_type,
            risk_score=asset_risk,
            risk_level=risk_level,
            evidence_sufficiency=asset_sufficiency,
            finding_count=len(finding_nodes),
            evidence_count=len(evidence_nodes),
            cluster_count=len(cluster_scores),
            contributions=sorted(contributions, key=lambda c: c.contribution_id),
        )
        return assessment, contributions

    def _evaluate_cross_asset_chains(
        self,
        project_id: str,
        asset_assessments: Dict[str, AssetRiskAssessment],
        graph: UniversalEvidenceGraph,
        config: ImmutableAggregationConfig,
    ) -> List[ChainRiskAssessment]:
        """Compute Tier-2 Lineage Chain Risks along explicit DAG edges."""
        chain_assessments: List[ChainRiskAssessment] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        # Inspect graph edges for lineage / dependency relationships between different assets
        for edge in graph.get_edges():
            if edge.edge_type in (GraphEdgeType.LINEAGE, GraphEdgeType.DEPENDS_ON, GraphEdgeType.DERIVED_FROM):
                src_node = graph.get_node(edge.source_node_id)
                tgt_node = graph.get_node(edge.target_node_id)
                if not src_node or not tgt_node:
                    continue

                src_asset = src_node.metadata.get("primary_asset_id") or src_node.metadata.get("affected_asset_id")
                tgt_asset = tgt_node.metadata.get("primary_asset_id") or tgt_node.metadata.get("affected_asset_id")

                if src_asset and tgt_asset and src_asset != tgt_asset:
                    pair = (str(src_asset), str(tgt_asset))
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        r_src = asset_assessments.get(pair[0]).risk_score if pair[0] in asset_assessments else 0.0
                        r_tgt = asset_assessments.get(pair[1]).risk_score if pair[1] in asset_assessments else 0.0

                        # R_chain = gamma_prop * R(src) * R(tgt)
                        chain_score = float(max(0.0, min(1.0, config.lineage_propagation_factor * r_src * r_tgt)))

                        chain_assessments.append(
                            ChainRiskAssessment(
                                project_id=project_id,
                                source_asset_id=pair[0],
                                target_asset_id=pair[1],
                                source_risk=r_src,
                                target_risk=r_tgt,
                                chain_risk_score=chain_score,
                                propagation_factor=config.lineage_propagation_factor,
                            )
                        )

        return chain_assessments

    def _evaluate_project_risk(
        self,
        project_id: str,
        asset_assessments: List[AssetRiskAssessment],
        chain_count: int,
        config: ImmutableAggregationConfig,
    ) -> ProjectRiskAssessment:
        """Compute Tier-3 Project Operational Risk with peak dominance preservation."""
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

        # Sort asset assessments canonically
        sorted_assets = sorted(asset_assessments, key=lambda a: a.asset_id)
        asset_risks = [a.risk_score for a in sorted_assets]

        max_asset = max(sorted_assets, key=lambda a: (a.risk_score, a.asset_id))
        max_r = max_asset.risk_score

        # R_project = 1 - (1 - max_R)^alpha_peak * prod(1 - lambda_inter * R(A))
        peak_term = math.pow(1.0 - max_r, config.peak_dominance_exponent)
        inter_term = 1.0
        for r_a in asset_risks:
            inter_term *= (1.0 - config.inter_asset_damping * r_a)

        project_risk = float(max(0.0, min(1.0, 1.0 - (peak_term * inter_term))))
        risk_level = compute_risk_level(project_risk)

        return ProjectRiskAssessment(
            project_id=project_id,
            project_risk_score=project_risk,
            risk_level=risk_level,
            peak_asset_risk=max_r,
            peak_asset_id=max_asset.asset_id,
            asset_count=len(asset_assessments),
            chain_count=chain_count,
        )
