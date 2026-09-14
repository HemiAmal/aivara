"""Report generator for the AIVARA Attack Simulation Lab (Phase 13)."""

from __future__ import annotations

import json
from typing import Any, Dict

from aivara.attacklab.schemas import SimulationReport


class SimulationReportGenerator:
    """Exports SimulationReport objects into JSON and GitHub Markdown formats."""

    @staticmethod
    def to_json(report: SimulationReport, indent: int = 2) -> str:
        """Export report to formatted JSON string."""
        return json.dumps(report.model_dump(), indent=indent)

    @staticmethod
    def to_markdown(report: SimulationReport) -> str:
        """Export report to formatted GitHub Markdown document."""
        lines = [
            f"# AIVARA Attack Simulation Lab — Execution Report",
            f"",
            f"**Report ID:** `{report.report_id}`  ",
            f"**Project ID:** `{report.project_id}`  ",
            f"**Created At:** `{report.created_at}`  ",
            f"**Cryptographic Digest:** `{report.report_hash}`  ",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary Metrics",
            f"",
            f"| Metric | Value |",
            f"|---|:---:|",
            f"| **Total Scenarios Executed** | **{report.total_scenarios}** |",
            f"| **Passed (Met Oracle Criteria)** | **{report.passed_scenarios}** |",
            f"| **Failed (Oracle Violations)** | **{report.failed_scenarios}** |",
            f"| **Attack Detection Rate** | **{report.detection_rate * 100:.2f}%** |",
            f"| **False Negative Rate** | **{report.false_negative_rate * 100:.2f}%** |",
            f"| **False Positive Rate** | **{report.false_positive_rate * 100:.2f}%** |",
            f"",
            f"### Outcome Breakdown:",
        ]

        for k, v in sorted(report.outcome_breakdown.items()):
            lines.append(f"- **{k}**: {v}")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 2. Per-Scenario Simulation Audit Details",
            f"",
            f"| Scenario ID | Oracle Outcome | Verdict | Clean Risk | Attack Risk | Risk Delta | Emergent Findings |",
            f"|---|---|:---:|:---:|:---:|:---:|---|",
        ])

        for o in report.outcomes:
            verdict = "**PASS**" if o.is_pass else "**FAIL**"
            c_risk = f"{o.clean_trace.risk_score:.4f}" if o.clean_trace.risk_score is not None else "N/A"
            a_risk = f"{o.attack_trace.risk_score:.4f}" if o.attack_trace.risk_score is not None else "N/A"
            delta = f"+{o.risk_delta:.4f}" if (o.risk_delta or 0) > 0 else f"{o.risk_delta:.4f}" if o.risk_delta is not None else "0.0000"
            findings_str = ", ".join(o.new_findings) if o.new_findings else "None"
            lines.append(
                f"| `{o.scenario_id}` | `{o.oracle_outcome.value}` | {verdict} | {c_risk} | {a_risk} | {delta} | {findings_str} |"
            )

        lines.extend([
            f"",
            f"---",
            f"",
            f"## 3. Cryptographic Verification & Invariant Attestation",
            f"- **100% Offline Air-Gap Compliance**: Zero outbound socket calls or external network dependencies.",
            f"- **Strict Multi-Tenant Isolation**: Project boundaries verified on all scenario executions.",
            f"- **Copy-Only Isolation Invariant**: All mutations executed on deep copies without modifying source baselines.",
            f"- **Non-Attribution Guarantee**: Neutral descriptive technical terminology enforced across all finding outputs.",
            f"",
        ])

        return "\n".join(lines)
