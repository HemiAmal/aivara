"""Deterministic Cross-Subsystem Correlation & Dependency Damping Engine (Phase 12.5)."""

from __future__ import annotations

import collections
import math
from typing import Dict, List, Optional, Set, Tuple, Union

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import ProjectMismatchError
from aivara.universal.graph import GraphNode, GraphNodeType, UniversalEvidenceGraph
from aivara.universal.risk.enums import EvidenceSufficiencyStatus
from aivara.universal.risk.schemas import HierarchicalRiskAssessment
from aivara.universal.correlation.enums import CorrelationStatus
from aivara.universal.correlation.exceptions import NonFiniteCorrelationError
from aivara.universal.correlation.matrix import CANONICAL_DOMAIN_ORDER, CorrelationMatrix
from aivara.universal.correlation.schemas import (
    CrossDomainContributionTrace,
    CrossDomainCorrelationAssessment,
    DomainCorrelationSummary,
)

SEVERITY_WEIGHTS: Dict[str, float] = {
    Severity.CRITICAL.value: 1.0,
    Severity.HIGH.value: 0.70,
    Severity.MEDIUM.value: 0.40,
    Severity.LOW.value: 0.10,
    Severity.INFO.value: 0.05,
}


class CrossDomainCorrelationEngine:
    """Closed-form analytical engine for cross-domain correlation and dependency damping.
    
    Phase 12.5 evaluates inter-domain relationships across the 7 canonical assurance domains.
    Phase 12.5 does NOT perform final universal risk computation or make policy decisions.
    """

    def __init__(self, default_matrix: Optional[CorrelationMatrix] = None) -> None:
        self.default_matrix = default_matrix or CorrelationMatrix.create_default_canonical_matrix()

    def evaluate_cross_domain_correlation(
        self,
        hierarchical_assessment: Optional[HierarchicalRiskAssessment] = None,
        graph: Optional[UniversalEvidenceGraph] = None,
        matrix: Optional[CorrelationMatrix] = None,
    ) -> CrossDomainCorrelationAssessment:
        """Evaluate cross-domain correlations and compute dependency attenuation factors.
        
        Args:
            hierarchical_assessment: Optional hierarchical risk assessment for linkage.
            graph: UniversalEvidenceGraph containing normalized evidence/finding nodes.
            matrix: Optional custom 7x7 correlation matrix (defaults to canonical).
            
        Returns:
            CrossDomainCorrelationAssessment containing immutable domain summaries and traces.
        """
        target_graph = graph
        if target_graph is None and hierarchical_assessment is not None:
            # If only assessment provided, check if graph attached
            pass
        
        if target_graph is None:
            raise ValueError("A valid UniversalEvidenceGraph must be provided.")

        if hierarchical_assessment is not None and hierarchical_assessment.project_id != target_graph.project_id:
            raise ProjectMismatchError(
                f"Assessment project '{hierarchical_assessment.project_id}' does not match graph project '{target_graph.project_id}'"
            )

        mat = matrix or self.default_matrix
        project_id = target_graph.project_id

        # 1. Partition graph nodes by canonical domain
        domain_nodes: Dict[SubsystemDomain, List[GraphNode]] = {d: [] for d in CANONICAL_DOMAIN_ORDER}
        for node in target_graph.get_nodes():
            if node.domain and node.domain in domain_nodes:
                domain_nodes[node.domain].append(node)

        # 2. Compute baseline activity and normalized mean severity per domain (Detection evidence only)
        domain_raw_severities: Dict[SubsystemDomain, float] = {}
        domain_finding_counts: Dict[SubsystemDomain, int] = {}
        domain_evidence_counts: Dict[SubsystemDomain, int] = {}
        domain_detection_counts: Dict[SubsystemDomain, int] = {}
        domain_proof_counts: Dict[SubsystemDomain, int] = {}
        domain_active_status: Dict[SubsystemDomain, bool] = {}

        has_unverified_ancestry = False

        for domain in CANONICAL_DOMAIN_ORDER:
            nodes = domain_nodes[domain]
            findings = [n for n in nodes if n.node_type == GraphNodeType.FINDING]
            evidences = [n for n in nodes if n.node_type == GraphNodeType.EVIDENCE]
            
            proof_nodes = [n for n in nodes if n.evidence_layer == EvidenceLayer.PROOF]
            detection_nodes = [n for n in nodes if n.evidence_layer != EvidenceLayer.PROOF]

            domain_finding_counts[domain] = len(findings)
            domain_evidence_counts[domain] = len(evidences)
            domain_proof_counts[domain] = len(proof_nodes)
            domain_detection_counts[domain] = len(detection_nodes)

            # Check ancestry status on nodes
            for n in nodes:
                if n.ancestry_path and n.ancestry_path.is_empty():
                    has_unverified_ancestry = True

            if not detection_nodes:
                domain_raw_severities[domain] = 0.0
                domain_active_status[domain] = False
                continue

            # Compute normalized mean severity across domain detection evidence:
            # term(e) = w_e * c_e * s_e
            term_sum = 0.0
            for n in detection_nodes:
                sev_val = n.severity.value if n.severity else Severity.INFO.value
                sev_weight = SEVERITY_WEIGHTS.get(sev_val, 0.20)
                conf = n.confidence if n.confidence is not None else 0.90

                if math.isnan(conf) or math.isinf(conf) or conf < 0.0 or conf > 1.0:
                    raise NonFiniteCorrelationError(f"Invalid confidence {conf} on node {n.node_id}")

                term = float(sev_weight * conf)
                term_sum += max(0.0, min(1.0, term))

            mean_sev = float(term_sum / len(detection_nodes))
            domain_raw_severities[domain] = round(max(0.0, min(1.0, mean_sev)), 6)
            domain_active_status[domain] = len(detection_nodes) > 0 and mean_sev > 0.0

        # 3. Compute cross-domain attenuation factors: att_j = prod_{i != j, active(i)} (1.0 - C_ij * S_bar_i)
        domain_summaries: List[DomainCorrelationSummary] = []
        traces: List[CrossDomainContributionTrace] = []

        for target_domain in CANONICAL_DOMAIN_ORDER:
            att_product = 1.0

            if domain_active_status[target_domain]:
                for source_domain in CANONICAL_DOMAIN_ORDER:
                    if source_domain == target_domain:
                        continue

                    if not domain_active_status[source_domain]:
                        continue

                    coeff = mat.get_correlation(target_domain, source_domain)
                    s_bar_src = domain_raw_severities[source_domain]

                    if coeff > 0.0 and s_bar_src > 0.0:
                        multiplier = float(max(0.0, min(1.0, 1.0 - (coeff * s_bar_src))))
                        att_product *= multiplier

                        traces.append(
                            CrossDomainContributionTrace(
                                target_domain=target_domain,
                                source_domain=source_domain,
                                correlation_coefficient=round(coeff, 6),
                                source_mean_severity=round(s_bar_src, 6),
                                attenuation_multiplier=round(multiplier, 6),
                            )
                        )

            att_product = round(float(max(0.0, min(1.0, att_product))), 6)
            raw_s = domain_raw_severities[target_domain]
            damped_s = round(float(max(0.0, min(1.0, raw_s * att_product))), 6)

            domain_summaries.append(
                DomainCorrelationSummary(
                    domain=target_domain,
                    is_active=domain_active_status[target_domain],
                    finding_count=domain_finding_counts[target_domain],
                    evidence_count=domain_evidence_counts[target_domain],
                    detection_count=domain_detection_counts[target_domain],
                    proof_count=domain_proof_counts[target_domain],
                    mean_severity=raw_s,
                    attenuation_factor=att_product,
                    damped_mean_severity=damped_s,
                )
            )

        # 4. Overall attenuation metric across active domains
        active_summaries = [s for s in domain_summaries if s.is_active]
        if active_summaries:
            overall_att = sum(s.attenuation_factor for s in active_summaries) / len(active_summaries)
        else:
            overall_att = 1.0
        overall_att = round(float(max(0.0, min(1.0, overall_att))), 6)

        status = CorrelationStatus.ATTENUATED if any(s.attenuation_factor < 1.0 for s in active_summaries) else CorrelationStatus.VALID

        evidence_suff = (
            hierarchical_assessment.evidence_sufficiency
            if hierarchical_assessment is not None
            else (EvidenceSufficiencyStatus.INSUFFICIENT_ANCESTRY if has_unverified_ancestry else EvidenceSufficiencyStatus.SUFFICIENT)
        )
        hier_hash = hierarchical_assessment.hierarchical_hash if hierarchical_assessment is not None else None

        return CrossDomainCorrelationAssessment(
            project_id=project_id,
            matrix_hash=mat.matrix_hash,
            graph_merkle_root=target_graph.merkle_root,
            hierarchical_hash=hier_hash,
            status=status,
            domain_summaries=sorted(domain_summaries, key=lambda s: s.domain.value),
            traces=sorted(traces, key=lambda t: (t.target_domain.value, t.source_domain.value)),
            overall_attenuation_factor=overall_att,
            evidence_sufficiency=evidence_suff,
        )
