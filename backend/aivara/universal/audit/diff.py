"""Deterministic Report Comparison and Semantic Diff Engine (Phase 12.11)."""

from __future__ import annotations

from typing import Any, Dict, List, Set
from aivara.universal.audit.schemas import AuditReportDiffResponse, UniversalAuditReport
from aivara.universal.exceptions import ProjectMismatchError


def compare_audit_reports(
    base_report: UniversalAuditReport,
    target_report: UniversalAuditReport,
) -> AuditReportDiffResponse:
    """Compute a deterministic semantic diff between two audit report instances."""
    if base_report.project_id != target_report.project_id:
        raise ProjectMismatchError(
            f"Cannot compare reports across different projects: '{base_report.project_id}' != '{target_report.project_id}'"
        )

    changes: List[str] = []

    # 1. Instance Version & Risk Score Changes
    base_score = base_report.risk_summary.project_risk_score
    target_score = target_report.risk_summary.project_risk_score
    risk_delta = round(target_score - base_score, 6)

    if abs(risk_delta) > 1e-6:
        direction = "increased" if risk_delta > 0 else "decreased"
        changes.append(f"Project risk score {direction} from {base_score:.4f} to {target_score:.4f} (delta: {risk_delta:+.4f})")

    # 2. Decision Changes
    base_dec = base_report.policy_summary.overall_decision.value
    target_dec = target_report.policy_summary.overall_decision.value
    decision_changed = base_dec != target_dec
    if decision_changed:
        changes.append(f"Policy decision transitioned from {base_dec} to {target_dec}")

    # 3. Asset Scope Changes
    base_assets = set(base_report.scope.asset_ids)
    target_assets = set(target_report.scope.asset_ids)
    added_assets = sorted(list(target_assets - base_assets))
    removed_assets = sorted(list(base_assets - target_assets))

    if added_assets:
        changes.append(f"Added assets in scope: {', '.join(added_assets)}")
    if removed_assets:
        changes.append(f"Removed assets from scope: {', '.join(removed_assets)}")

    # 4. Finding Changes
    base_finds = {f.get("finding_id") or f.get("id") for f in base_report.finding_summary.findings if f.get("finding_id") or f.get("id")}
    target_finds = {f.get("finding_id") or f.get("id") for f in target_report.finding_summary.findings if f.get("finding_id") or f.get("id")}
    added_findings = sorted([str(f) for f in target_finds - base_finds])
    resolved_findings = sorted([str(f) for f in base_finds - target_finds])

    if added_findings:
        changes.append(f"New findings identified: {', '.join(added_findings)}")
    if resolved_findings:
        changes.append(f"Findings resolved / no longer observed: {', '.join(resolved_findings)}")

    # 5. Compliance Status Changes
    base_comp = {r.control_id: r.status.value for r in base_report.compliance_results}
    target_comp = {r.control_id: r.status.value for r in target_report.compliance_results}
    all_ctrls = sorted(list(set(base_comp.keys()) | set(target_comp.keys())))

    comp_changes: Dict[str, Dict[str, str]] = {}
    for cid in all_ctrls:
        b_st = base_comp.get(cid, "NOT_PRESENT")
        t_st = target_comp.get(cid, "NOT_PRESENT")
        if b_st != t_st:
            comp_changes[cid] = {"base_status": b_st, "target_status": t_st}
            changes.append(f"Compliance control '{cid}' changed from {b_st} to {t_st}")

    has_changes = (
        len(changes) > 0
        or base_report.instance_version != target_report.instance_version
        or base_report.report_hash != target_report.report_hash
    )

    if not changes:
        changes.append("No semantic changes detected between report instances")

    return AuditReportDiffResponse(
        project_id=base_report.project_id,
        base_report_id=base_report.report_id,
        target_report_id=target_report.report_id,
        base_instance_version=base_report.instance_version,
        target_instance_version=target_report.instance_version,
        has_changes=has_changes,
        risk_score_delta=risk_delta,
        decision_changed=decision_changed,
        base_decision=base_dec,
        target_decision=target_dec,
        added_assets=added_assets,
        removed_assets=removed_assets,
        added_findings=added_findings,
        resolved_findings=resolved_findings,
        compliance_status_changes=comp_changes,
        summary_of_changes=changes,
    )
