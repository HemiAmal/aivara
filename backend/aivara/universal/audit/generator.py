"""Authoritative Deterministic Audit Report Generator (Phase 12.11)."""

from __future__ import annotations

import collections
import uuid
from typing import Any, Dict, List, Optional, Sequence, Set
from aivara.universal.audit.compliance import ComplianceEvaluationEngine, get_standard_compliance_controls
from aivara.universal.audit.enums import ComplianceFramework, RedactionLevel, TraceabilityNodeType
from aivara.universal.audit.integrity import compute_canonical_report_hash
from aivara.universal.audit.redaction import sanitize_data_structure
from aivara.universal.audit.schemas import (
    AuditLimitationsSummary,
    EvidenceMetricsSummary,
    FindingMetricsSummary,
    PolicyDecisionSummary,
    ProofVerificationSummary,
    RiskMetricsSummary,
    ScopeSummary,
    UniversalAuditReport,
)
from aivara.universal.audit.traceability import TraceabilityGraph
from aivara.domain.schemas import EvidenceLayer
from aivara.universal.enums import SubsystemDomain
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.risk.enums import RiskLevel
from aivara.universal.exceptions import ProjectMismatchError
from aivara.api.envelope import utcnow_iso


class UniversalAuditReportGenerator:
    """Authoritative generator synthesizing Phase 12 assurance artifacts into deterministic audit reports."""

    def __init__(self, compliance_engine: Optional[ComplianceEvaluationEngine] = None) -> None:
        self.compliance_engine = compliance_engine or ComplianceEvaluationEngine()

    def generate_report(
        self,
        project_id: str,
        asset_ids: Sequence[str],
        evidence_items: Sequence[Any],
        findings: Optional[Sequence[Any]] = None,
        risk_assessments: Optional[Dict[str, Any]] = None,
        policy_decisions: Optional[Dict[str, Any]] = None,
        proof_assessments: Optional[Dict[str, Any]] = None,
        hierarchical_assessment: Optional[Any] = None,
        correlation_assessment: Optional[Any] = None,
        target_frameworks: Optional[Set[ComplianceFramework]] = None,
        report_id: Optional[str] = None,
        instance_version: int = 1,
        report_name: str = "Universal Assurance Audit Report",
        redaction_level: RedactionLevel = RedactionLevel.STANDARD,
    ) -> UniversalAuditReport:
        """Generate a complete 20-section UniversalAuditReport preserving deterministic canonical content."""
        if not project_id:
            raise ScopeMismatchError("Target project_id must not be empty.")

        rep_id = report_id or str(uuid.uuid4())
        gen_time = utcnow_iso()
        all_findings = list(findings or [])
        all_risks = dict(risk_assessments or {})
        all_decisions = dict(policy_decisions or {})
        all_proofs = dict(proof_assessments or {})

        # 1. Traceability Graph & Claims Construction
        trace_graph = TraceabilityGraph(project_id=project_id)
        trace_graph.add_node(TraceabilityNodeType.PROJECT, project_id)

        # 2. Scope & Asset Inventory
        assets_list = sorted(list(set(asset_ids)))
        if not assets_list:
            discovered = {
                getattr(e, "primary_asset_id", None) or (e.get("primary_asset_id") if isinstance(e, dict) else None)
                for e in evidence_items
            }
            assets_list = sorted([str(a) for a in discovered if a]) or ["default_asset"]

        domains_set: Set[str] = set()
        layers_set: Set[str] = set()
        for a in assets_list:
            trace_graph.add_node(TraceabilityNodeType.ASSET, a)
            trace_graph.add_link(TraceabilityNodeType.PROJECT, project_id, TraceabilityNodeType.ASSET, a)

        # 3. Evidence Metrics & Domain Counts
        domain_counts: Dict[str, int] = collections.defaultdict(int)
        det_cnt = 0
        proof_cnt = 0
        pol_cnt = 0

        for e in evidence_items:
            eid = getattr(e, "evidence_id", None) or (e.get("evidence_id") if isinstance(e, dict) else None)
            dom = getattr(e, "domain", None) or (e.get("domain") if isinstance(e, dict) else None)
            layer = getattr(e, "evidence_layer", None) or (e.get("evidence_layer") if isinstance(e, dict) else None)
            aid = getattr(e, "primary_asset_id", None) or (e.get("primary_asset_id") if isinstance(e, dict) else None)

            if dom:
                d_str = dom.value if hasattr(dom, "value") else str(dom)
                domain_counts[d_str] += 1
                domains_set.add(d_str)

            if layer:
                l_str = layer.value if hasattr(layer, "value") else str(layer)
                layers_set.add(l_str)
                if l_str == "DETECTION": det_cnt += 1
                elif l_str == "PROOF": proof_cnt += 1
                elif l_str == "POLICY": pol_cnt += 1

            if eid:
                trace_graph.add_node(TraceabilityNodeType.EVIDENCE, str(eid))
                if aid:
                    trace_graph.add_link(TraceabilityNodeType.ASSET, str(aid), TraceabilityNodeType.EVIDENCE, str(eid))

        # 4. Finding Metrics
        crit_c = high_c = med_c = low_c = info_c = 0
        sanitized_findings = []
        for f in all_findings:
            raw_f = f if isinstance(f, dict) else (f.model_dump() if hasattr(f, "model_dump") else f.__dict__)
            sanitized_f = sanitize_data_structure(raw_f, level=redaction_level)
            sanitized_findings.append(sanitized_f)

            sev = str(raw_f.get("severity", "info")).lower()
            if sev == "critical": crit_c += 1
            elif sev == "high": high_c += 1
            elif sev == "medium": med_c += 1
            elif sev == "low": low_c += 1
            else: info_c += 1

            fid = raw_f.get("finding_id") or raw_f.get("id")
            aid = raw_f.get("affected_asset_id")
            if fid:
                trace_graph.add_node(TraceabilityNodeType.FINDING, str(fid))
                if aid:
                    trace_graph.add_link(TraceabilityNodeType.ASSET, str(aid), TraceabilityNodeType.FINDING, str(fid))

        # 5. Risk Summary (Tier-1, 2, 3)
        asset_risks: Dict[str, float] = {}
        for aid in assets_list:
            ra = all_risks.get(aid)
            score = 0.0
            r_hash = ""
            if isinstance(ra, dict):
                score = float(ra.get("risk_score", 0.0))
                r_hash = str(ra.get("assessment_hash", ""))
            elif ra is not None:
                score = float(getattr(ra, "risk_score", 0.0))
                r_hash = str(getattr(ra, "assessment_hash", ""))
            asset_risks[aid] = round(float(score), 6)
            if r_hash:
                trace_graph.add_node(TraceabilityNodeType.RISK_ASSESSMENT, r_hash)
                trace_graph.add_link(TraceabilityNodeType.ASSET, aid, TraceabilityNodeType.RISK_ASSESSMENT, r_hash)

        p_score = 0.0
        p_level = RiskLevel.NONE
        peak_aid = None
        peak_arisk = 0.0
        chain_c = 0
        h_hash = ""

        if hierarchical_assessment:
            pa = getattr(hierarchical_assessment, "project_assessment", None)
            if pa:
                p_score = getattr(pa, "project_risk_score", 0.0)
                p_level = getattr(pa, "risk_level", RiskLevel.NONE)
                peak_aid = getattr(pa, "peak_asset_id", None)
                peak_arisk = getattr(pa, "peak_asset_risk", 0.0)
                chain_c = getattr(pa, "chain_count", 0)
            h_hash = getattr(hierarchical_assessment, "hierarchical_hash", "")
            if h_hash:
                trace_graph.add_node(TraceabilityNodeType.PROJECT_AGGREGATION, h_hash)
                trace_graph.add_link(TraceabilityNodeType.PROJECT, project_id, TraceabilityNodeType.PROJECT_AGGREGATION, h_hash)
        elif asset_risks:
            peak_aid = max(asset_risks.keys(), key=lambda k: asset_risks[k])
            peak_arisk = asset_risks[peak_aid]
            p_score = peak_arisk
            p_level = RiskLevel.HIGH if p_score >= 0.70 else (RiskLevel.MEDIUM if p_score >= 0.35 else RiskLevel.LOW)

        # 6. Policy Decision Summary
        overall_dec = UniversalDecision.ACCEPT
        dec_pol_ver = "1.0.0"
        proof_override = False
        esc_reason = None
        asset_dec_map: Dict[str, str] = {}

        for aid in assets_list:
            dec = all_decisions.get(aid)
            if dec:
                if isinstance(dec, dict):
                    d_val = dec.get("decision", UniversalDecision.ACCEPT)
                    d_hash = str(dec.get("decision_hash", ""))
                else:
                    d_val = getattr(dec, "decision", UniversalDecision.ACCEPT)
                    d_hash = str(getattr(dec, "decision_hash", ""))
                dec_str = d_val.value if hasattr(d_val, "value") else str(d_val)
                asset_dec_map[aid] = dec_str
                if d_hash:
                    trace_graph.add_node(TraceabilityNodeType.POLICY_DECISION, d_hash)
                    trace_graph.add_link(TraceabilityNodeType.ASSET, aid, TraceabilityNodeType.POLICY_DECISION, d_hash)

        if any(d == "REJECT" for d in asset_dec_map.values()):
            overall_dec = UniversalDecision.REJECT
        elif any(d == "QUARANTINE" for d in asset_dec_map.values()):
            overall_dec = UniversalDecision.QUARANTINE
        elif any(d == "REVIEW" for d in asset_dec_map.values()):
            overall_dec = UniversalDecision.REVIEW

        # 7. Proof Summary
        overall_proof_st = "VERIFIED"
        p_ver_c = p_inv_c = p_tamp_c = p_rep_c = 0
        asset_proof_map: Dict[str, str] = {}

        for aid in assets_list:
            pa = all_proofs.get(aid)
            if pa:
                if isinstance(pa, dict):
                    st = pa.get("overall_proof_status", "VERIFIED")
                    override = bool(pa.get("proof_override_required", False))
                    p_hash = str(pa.get("proof_assessment_hash", ""))
                else:
                    st = getattr(pa, "overall_proof_status", "VERIFIED")
                    override = bool(getattr(pa, "proof_override_required", False))
                    p_hash = str(getattr(pa, "proof_assessment_hash", ""))
                st_str = st.value if hasattr(st, "value") else (str(st) if st else "VERIFIED")
                asset_proof_map[aid] = st_str
                if override:
                    proof_override = True
                    esc_reason = f"Fatal cryptographic proof failure on asset '{aid}'"
                    overall_dec = UniversalDecision.REJECT
                if st_str == "VERIFIED": p_ver_c += 1
                elif st_str == "INVALID": p_inv_c += 1
                elif st_str == "TAMPERED": p_tamp_c += 1
                elif st_str == "REPLAY_DETECTED": p_rep_c += 1
                if p_hash:
                    trace_graph.add_node(TraceabilityNodeType.PROOF_ASSESSMENT, p_hash)
                    trace_graph.add_link(TraceabilityNodeType.ASSET, aid, TraceabilityNodeType.PROOF_ASSESSMENT, p_hash)

        # 8. Compliance Evaluation
        compliance_results = self.compliance_engine.evaluate_project_compliance(
            project_id=project_id,
            asset_ids=assets_list,
            evidence_items=evidence_items,
            findings=all_findings,
            risk_assessments=all_risks,
            policy_decisions=all_decisions,
            proof_assessments=all_proofs,
            target_frameworks=target_frameworks,
        )

        for cr in compliance_results:
            trace_graph.add_node(TraceabilityNodeType.COMPLIANCE_CONTROL, cr.control_id)
            trace_graph.add_link(TraceabilityNodeType.PROJECT, project_id, TraceabilityNodeType.COMPLIANCE_CONTROL, cr.control_id)

        # 9. Limitations
        missing_domains = sorted(list({d.value for d in SubsystemDomain} - domains_set))
        limitations = AuditLimitationsSummary(
            insufficient_ancestry_assets=[],
            unassessed_domains=missing_domains,
            unavailable_evidence_notes=[f"No evidence collected for {d}" for d in missing_domains],
        )

        # 10. Material Claims Generation
        trace_graph.add_claim(
            claim_id="claim-project-decision",
            claim_type="POLICY_DECISION",
            summary=f"Project '{project_id}' evaluated to overall decision '{overall_dec.value}' with risk score {p_score:.4f}",
            hierarchical_hash=h_hash,
            decision_hash="",
            risk_hash="",
        )
        for aid, r in asset_risks.items():
            ra = all_risks.get(aid)
            r_hash = getattr(ra, "assessment_hash", "") if ra else ""
            trace_graph.add_claim(
                claim_id=f"claim-asset-risk-{aid}",
                claim_type="ASSET_RISK",
                summary=f"Asset '{aid}' evaluated with risk score {r:.4f}",
                asset_id=aid,
                risk_hash=r_hash,
            )

        report = UniversalAuditReport(
            report_id=rep_id,
            schema_version="1.0.0",
            instance_version=instance_version,
            report_name=report_name,
            generated_at_utc=gen_time,
            environment="AIR_GAPPED_LOCAL",
            project_id=project_id,
            scope=ScopeSummary(
                project_id=project_id,
                asset_ids=assets_list,
                asset_roles={aid: "CORE_DEPLOYED" for aid in assets_list},
                domains_covered=sorted(list(domains_set)),
                layers_covered=sorted(list(layers_set)),
            ),
            evidence_summary=EvidenceMetricsSummary(
                total_evidence_count=len(evidence_items),
                detection_count=det_cnt,
                proof_count=proof_cnt,
                policy_count=pol_cnt,
                domain_counts=dict(domain_counts),
            ),
            finding_summary=FindingMetricsSummary(
                total_finding_count=len(all_findings),
                critical_count=crit_c,
                high_count=high_c,
                medium_count=med_c,
                low_count=low_c,
                info_count=info_c,
                findings=sanitized_findings,
            ),
            overall_confidence=1.0,
            risk_summary=RiskMetricsSummary(
                project_risk_score=p_score,
                project_risk_level=p_level,
                peak_asset_id=peak_aid,
                peak_asset_risk=peak_arisk,
                asset_count=len(assets_list),
                chain_count=chain_c,
                hierarchical_hash=h_hash,
                asset_risks=asset_risks,
            ),
            correlation_summary={"domains_evaluated": sorted(list(domains_set))},
            policy_summary=PolicyDecisionSummary(
                overall_decision=overall_dec,
                decision_policy_version=dec_pol_ver,
                proof_override_triggered=proof_override,
                escalation_reason=esc_reason,
                asset_decisions=asset_dec_map,
            ),
            proof_summary=ProofVerificationSummary(
                overall_proof_status=overall_proof_st,
                proof_verified_count=p_ver_c,
                proof_invalid_count=p_inv_c,
                proof_tampered_count=p_tamp_c,
                proof_replay_count=p_rep_c,
                asset_proof_statuses=asset_proof_map,
            ),
            compliance_results=compliance_results,
            limitations=limitations,
            traceability_links=trace_graph.get_links(),
            authoritative_claims=trace_graph.get_claims(),
            report_hash="",
        )

        computed_hash = compute_canonical_report_hash(report)
        object.__setattr__(report, "report_hash", computed_hash)
        return report
