"""Deterministic Report Export Formatting (Phase 12.11)."""

from __future__ import annotations

import json
from aivara.universal.audit.enums import ExportFormat
from aivara.universal.audit.schemas import UniversalAuditReport
from aivara.universal.hashing import compute_canonical_jcs_bytes


def export_report_to_json(report: UniversalAuditReport, canonical: bool = False) -> str:
    """Export report to JSON string."""
    if canonical:
        return compute_canonical_jcs_bytes(report.to_canonical_descriptor()).decode("utf-8")
    return json.dumps(report.model_dump(), indent=2, sort_keys=True)


def export_report_to_markdown(report: UniversalAuditReport) -> str:
    """Export report to a formatted Markdown audit dossier."""
    lines = [
        f"# {report.report_name}",
        f"**Report ID:** `{report.report_id}`  ",
        f"**Project ID:** `{report.project_id}`  ",
        f"**Report Hash:** `{report.report_hash}`  ",
        f"**Generated:** `{report.generated_at_utc}` (`{report.environment}`)  ",
        f"**Instance Version:** `v{report.instance_version}` | **Schema:** `v{report.schema_version}`  ",
        "",
        "---",
        "",
        "## 1. Executive Summary & Disposition",
        f"- **Overall Decision:** `{report.policy_summary.overall_decision.value}`",
        f"- **Project Risk Score:** `{report.risk_summary.project_risk_score:.4f}` ({report.risk_summary.project_risk_level.value})",
        f"- **Peak Asset Risk:** `{report.risk_summary.peak_asset_risk:.4f}` (Asset: `{report.risk_summary.peak_asset_id or 'None'}`)",
        f"- **Proof Status:** `{report.proof_summary.overall_proof_status}` (Override Triggered: `{report.policy_summary.proof_override_triggered}`)",
        "",
        "---",
        "",
        "## 2. Scope & Asset Inventory",
        f"- **Assets Assessed ({len(report.scope.asset_ids)}):** {', '.join(f'`{a}`' for a in report.scope.asset_ids)}",
        f"- **Domains Covered ({len(report.scope.domains_covered)}):** {', '.join(report.scope.domains_covered)}",
        f"- **Evidence Layers:** {', '.join(report.scope.layers_covered)}",
        "",
        "---",
        "",
        "## 3. Evidence & Finding Metrics",
        f"- **Total Evidence Items:** `{report.evidence_summary.total_evidence_count}` (Detection: `{report.evidence_summary.detection_count}`, Proof: `{report.evidence_summary.proof_count}`, Policy: `{report.evidence_summary.policy_count}`)",
        f"- **Total Findings:** `{report.finding_summary.total_finding_count}` (Critical: `{report.finding_summary.critical_count}`, High: `{report.finding_summary.high_count}`, Medium: `{report.finding_summary.medium_count}`, Low: `{report.finding_summary.low_count}`)",
        "",
        "---",
        "",
        "## 4. Compliance Framework Evaluation",
        "| Framework | Control ID | Title | Status | Justification |",
        "|---|---|---|---|---|",
    ]

    for c in report.compliance_results:
        lines.append(f"| {c.framework.value} | `{c.control_id}` | {c.title} | **{c.status.value}** | {c.justification} |")

    lines.extend([
        "",
        "---",
        "",
        "## 5. Limitations & Unavailable Evidence",
    ])
    if report.limitations.unassessed_domains:
        lines.append(f"- **Unassessed Domains:** {', '.join(report.limitations.unassessed_domains)}")
    for note in report.limitations.unavailable_evidence_notes:
        lines.append(f"- {note}")

    lines.extend([
        "",
        "---",
        "",
        "## 6. Authoritative Claims & Traceability",
    ])
    for claim in report.authoritative_claims:
        lines.append(f"- **[{claim.claim_type}]** `{claim.claim_id}`: {claim.summary} (Hash: `{claim.claim_hash[:16]}...`)")

    return "\n".join(lines)


def export_report_to_text(report: UniversalAuditReport) -> str:
    """Export report to a formatted plaintext document."""
    return f"""============================================================
{report.report_name.upper()}
============================================================
Report ID:         {report.report_id}
Project ID:        {report.project_id}
Content Hash:      {report.report_hash}
Instance Version:  v{report.instance_version}
Generated At:      {report.generated_at_utc}
Overall Decision:  {report.policy_summary.overall_decision.value}
Project Risk:      {report.risk_summary.project_risk_score:.4f} ({report.risk_summary.project_risk_level.value})
Proof Status:      {report.proof_summary.overall_proof_status}
Assets Assessed:   {len(report.scope.asset_ids)}
Evidence Count:    {report.evidence_summary.total_evidence_count}
Findings Count:    {report.finding_summary.total_finding_count}
Compliance Controls Evaluated: {len(report.compliance_results)}
============================================================
"""


def export_report(report: UniversalAuditReport, format_type: ExportFormat) -> str:
    """Deterministic dispatcher for report export formats."""
    if format_type == ExportFormat.JSON:
        return export_report_to_json(report, canonical=False)
    elif format_type == ExportFormat.MARKDOWN:
        return export_report_to_markdown(report)
    elif format_type == ExportFormat.TEXT:
        return export_report_to_text(report)
    return export_report_to_json(report)
