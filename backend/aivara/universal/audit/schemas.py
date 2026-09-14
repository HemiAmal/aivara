"""Pydantic Schemas for Universal Audit & Compliance Reporting (Phase 12.11)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.universal.audit.compliance import ComplianceControlResult
from aivara.universal.audit.enums import ExportFormat, RedactionLevel, ReportIntegrityStatus
from aivara.universal.audit.traceability import AuthoritativeClaim, TraceabilityLink
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.risk.enums import RiskLevel


class ScopeSummary(BaseModel):
    """Scope definition and asset catalog."""
    model_config = ConfigDict(frozen=True)

    project_id: str
    asset_ids: List[str] = Field(default_factory=list)
    asset_roles: Dict[str, str] = Field(default_factory=dict)
    domains_covered: List[str] = Field(default_factory=list)
    layers_covered: List[str] = Field(default_factory=list)


class EvidenceMetricsSummary(BaseModel):
    """Summary metrics of evidence items by domain and layer."""
    model_config = ConfigDict(frozen=True)

    total_evidence_count: int = 0
    detection_count: int = 0
    proof_count: int = 0
    policy_count: int = 0
    domain_counts: Dict[str, int] = Field(default_factory=dict)


class FindingMetricsSummary(BaseModel):
    """Summary metrics of findings by severity and category."""
    model_config = ConfigDict(frozen=True)

    total_finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class RiskMetricsSummary(BaseModel):
    """Summary of Tier-1, Tier-2, and Tier-3 risk assessments."""
    model_config = ConfigDict(frozen=True)

    project_risk_score: float = 0.0
    project_risk_level: RiskLevel = RiskLevel.NONE
    peak_asset_id: Optional[str] = None
    peak_asset_risk: float = 0.0
    asset_count: int = 0
    chain_count: int = 0
    hierarchical_hash: str = ""
    asset_risks: Dict[str, float] = Field(default_factory=dict)


class PolicyDecisionSummary(BaseModel):
    """Summary of Tier-1 and Tier-3 policy evaluation outcomes."""
    model_config = ConfigDict(frozen=True)

    overall_decision: UniversalDecision = UniversalDecision.REJECT
    decision_policy_version: str = "1.0.0"
    proof_override_triggered: bool = False
    escalation_reason: Optional[str] = None
    asset_decisions: Dict[str, str] = Field(default_factory=dict)


class ProofVerificationSummary(BaseModel):
    """Summary of cryptographic proof and provenance verification outcomes."""
    model_config = ConfigDict(frozen=True)

    overall_proof_status: str = "VERIFIED"
    proof_verified_count: int = 0
    proof_invalid_count: int = 0
    proof_tampered_count: int = 0
    proof_replay_count: int = 0
    asset_proof_statuses: Dict[str, str] = Field(default_factory=dict)


class AuditLimitationsSummary(BaseModel):
    """Disclosures of unavailable evidence, missing ancestry, or unassessed controls."""
    model_config = ConfigDict(frozen=True)

    insufficient_ancestry_assets: List[str] = Field(default_factory=list)
    unassessed_domains: List[str] = Field(default_factory=list)
    unavailable_evidence_notes: List[str] = Field(default_factory=list)


class UniversalAuditReport(BaseModel):
    """Authoritative, deterministic 20-section Universal Audit & Compliance Report."""
    model_config = ConfigDict(frozen=True)

    # 1-3. Identity & Versioning
    report_id: str = Field(..., min_length=1, max_length=128)
    schema_version: str = Field(default="1.0.0", max_length=32)
    instance_version: int = Field(default=1, ge=1)
    report_name: str = Field(default="Universal Assurance Audit Report", max_length=256)

    # 4. Presentation Metadata (Segregated from canonical content descriptor)
    generated_at_utc: str
    environment: str = Field(default="AIR_GAPPED_LOCAL", max_length=64)

    # 5-6. Tenancy & Scope
    project_id: str = Field(..., min_length=1, max_length=128)
    scope: ScopeSummary

    # 7-9. Evidence, Findings, Confidence Metrics
    evidence_summary: EvidenceMetricsSummary
    finding_summary: FindingMetricsSummary
    overall_confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    # 10-14. Operational Risk, Correlation, Policy, Proof, Aggregation Summaries
    risk_summary: RiskMetricsSummary
    correlation_summary: Dict[str, Any] = Field(default_factory=dict)
    policy_summary: PolicyDecisionSummary
    proof_summary: ProofVerificationSummary

    # 15. Compliance Control Results
    compliance_results: List[ComplianceControlResult] = Field(default_factory=list)

    # 16. Limitations & Unavailable Evidence
    limitations: AuditLimitationsSummary

    # 17. Bi-directional Traceability Links & Claims
    traceability_links: List[TraceabilityLink] = Field(default_factory=list)
    authoritative_claims: List[AuthoritativeClaim] = Field(default_factory=list)

    # 18-20. Content Integrity Hashes & Signatures
    report_hash: str = Field(default="", max_length=64)
    signature: Optional[str] = None
    signer_public_key_id: Optional[str] = None

    def to_canonical_descriptor(self) -> Dict[str, Any]:
        """Produce the canonical, deterministic content dictionary excluding presentation metadata."""
        return {
            "authoritative_claims": [c.to_canonical_dict() for c in sorted(self.authoritative_claims, key=lambda x: x.claim_id)],
            "compliance_results": [r.to_canonical_dict() for r in sorted(self.compliance_results, key=lambda x: (x.framework.value, x.control_id))],
            "correlation_summary": self.correlation_summary,
            "evidence_summary": {
                "detection_count": self.evidence_summary.detection_count,
                "domain_counts": dict(sorted(self.evidence_summary.domain_counts.items())),
                "policy_count": self.evidence_summary.policy_count,
                "proof_count": self.evidence_summary.proof_count,
                "total_evidence_count": self.evidence_summary.total_evidence_count,
            },
            "finding_summary": {
                "critical_count": self.finding_summary.critical_count,
                "findings": self.finding_summary.findings,
                "high_count": self.finding_summary.high_count,
                "info_count": self.finding_summary.info_count,
                "low_count": self.finding_summary.low_count,
                "medium_count": self.finding_summary.medium_count,
                "total_finding_count": self.finding_summary.total_finding_count,
            },
            "instance_version": self.instance_version,
            "limitations": {
                "insufficient_ancestry_assets": sorted(self.limitations.insufficient_ancestry_assets),
                "unavailable_evidence_notes": sorted(self.limitations.unavailable_evidence_notes),
                "unassessed_domains": sorted(self.limitations.unassessed_domains),
            },
            "overall_confidence": round(self.overall_confidence, 4),
            "policy_summary": {
                "asset_decisions": dict(sorted(self.policy_summary.asset_decisions.items())),
                "decision_policy_version": self.policy_summary.decision_policy_version,
                "escalation_reason": self.policy_summary.escalation_reason or "",
                "overall_decision": self.policy_summary.overall_decision.value,
                "proof_override_triggered": self.policy_summary.proof_override_triggered,
            },
            "project_id": self.project_id,
            "proof_summary": {
                "asset_proof_statuses": dict(sorted(self.proof_summary.asset_proof_statuses.items())),
                "overall_proof_status": self.proof_summary.overall_proof_status,
                "proof_invalid_count": self.proof_summary.proof_invalid_count,
                "proof_replay_count": self.proof_summary.proof_replay_count,
                "proof_tampered_count": self.proof_summary.proof_tampered_count,
                "proof_verified_count": self.proof_summary.proof_verified_count,
            },
            "report_id": self.report_id,
            "report_name": self.report_name,
            "risk_summary": {
                "asset_count": self.risk_summary.asset_count,
                "asset_risks": dict(sorted(self.risk_summary.asset_risks.items())),
                "chain_count": self.risk_summary.chain_count,
                "hierarchical_hash": self.risk_summary.hierarchical_hash,
                "peak_asset_id": self.risk_summary.peak_asset_id or "",
                "peak_asset_risk": round(self.risk_summary.peak_asset_risk, 6),
                "project_risk_level": self.risk_summary.project_risk_level.value,
                "project_risk_score": round(self.risk_summary.project_risk_score, 6),
            },
            "schema_version": self.schema_version,
            "scope": {
                "asset_ids": sorted(self.scope.asset_ids),
                "asset_roles": dict(sorted(self.scope.asset_roles.items())),
                "domains_covered": sorted(self.scope.domains_covered),
                "layers_covered": sorted(self.scope.layers_covered),
                "project_id": self.scope.project_id,
            },
            "traceability_links": [l.to_canonical_dict() for l in sorted(self.traceability_links, key=lambda x: (x.source_type.value, x.source_id, x.target_type.value, x.target_id))],
        }


# =====================================================================
# API Request / Response Models
# =====================================================================

class AuditReportCreateRequest(BaseModel):
    """Request payload to generate an authoritative audit report."""
    model_config = ConfigDict(extra="forbid")

    project_id: str
    task_id: Optional[str] = None
    report_name: Optional[str] = "Universal Assurance Audit Report"
    target_frameworks: Optional[List[str]] = None
    redaction_level: RedactionLevel = RedactionLevel.STANDARD


class AuditReportVerificationResponse(BaseModel):
    """Verification outcome of an audit report."""
    model_config = ConfigDict(frozen=True)

    report_id: str
    project_id: str
    status: ReportIntegrityStatus
    declared_hash: str
    computed_hash: str
    signature_verified: bool = False
    verification_details: List[str] = Field(default_factory=list)


class AuditReportCompareRequest(BaseModel):
    """Request payload to compare two audit report instances."""
    model_config = ConfigDict(extra="forbid")

    project_id: str
    base_report_id: str
    target_report_id: str


class AuditReportDiffResponse(BaseModel):
    """Deterministic semantic diff between two audit reports."""
    model_config = ConfigDict(frozen=True)

    project_id: str
    base_report_id: str
    target_report_id: str
    base_instance_version: int
    target_instance_version: int
    has_changes: bool
    risk_score_delta: float
    decision_changed: bool
    base_decision: str
    target_decision: str
    added_assets: List[str] = Field(default_factory=list)
    removed_assets: List[str] = Field(default_factory=list)
    added_findings: List[str] = Field(default_factory=list)
    resolved_findings: List[str] = Field(default_factory=list)
    compliance_status_changes: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    summary_of_changes: List[str] = Field(default_factory=list)
