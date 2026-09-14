"""Compliance Control and Regulatory Framework Mapping (Phase 12.11)."""

from __future__ import annotations

import collections
from typing import Any, Dict, List, Optional, Sequence, Set
from pydantic import BaseModel, ConfigDict, Field

from aivara.domain.schemas import EvidenceLayer
from aivara.universal.audit.enums import ComplianceFramework, ComplianceStatus
from aivara.universal.enums import SubsystemDomain
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.risk.enums import RiskLevel
from aivara.universal.hashing import compute_canonical_jcs_bytes, compute_sha256_digest


class ComplianceControlDefinition(BaseModel):
    """Immutable, versioned specification of a regulatory or governance compliance control."""
    model_config = ConfigDict(frozen=True)

    framework: ComplianceFramework
    control_id: str = Field(..., min_length=1, max_length=64)
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=1024)
    version: str = Field(default="1.0.0", min_length=1, max_length=32)
    target_domains: List[SubsystemDomain] = Field(default_factory=list)
    required_evidence_layers: List[EvidenceLayer] = Field(default_factory=list)
    max_allowable_risk_score: float = Field(default=0.30, ge=0.0, le=1.0)
    allow_proof_override: bool = Field(default=True)
    negative_verification_semantics: bool = Field(default=False)
    control_hash: str = Field(default="", max_length=64)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "allow_proof_override": self.allow_proof_override,
            "control_id": self.control_id,
            "description": self.description,
            "framework": self.framework.value,
            "max_allowable_risk_score": round(self.max_allowable_risk_score, 4),
            "negative_verification_semantics": self.negative_verification_semantics,
            "required_evidence_layers": sorted([l.value for l in self.required_evidence_layers]),
            "target_domains": sorted([d.value for d in self.target_domains]),
            "title": self.title,
            "version": self.version,
        }


def compute_control_hash(defn: ComplianceControlDefinition) -> str:
    return compute_sha256_digest(compute_canonical_jcs_bytes(defn.to_canonical_dict()))


class ComplianceControlResult(BaseModel):
    """Deterministic evaluation outcome for a single compliance control against an assurance scope."""
    model_config = ConfigDict(frozen=True)

    control_id: str
    framework: ComplianceFramework
    title: str
    status: ComplianceStatus
    justification: str
    assessed_asset_ids: List[str] = Field(default_factory=list)
    contributing_evidence_ids: List[str] = Field(default_factory=list)
    contributing_finding_ids: List[str] = Field(default_factory=list)
    max_observed_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    proof_verified: bool = Field(default=False)
    result_hash: str = Field(default="", max_length=64)

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "assessed_asset_ids": sorted(self.assessed_asset_ids),
            "contributing_evidence_ids": sorted(self.contributing_evidence_ids),
            "contributing_finding_ids": sorted(self.contributing_finding_ids),
            "control_id": self.control_id,
            "framework": self.framework.value,
            "justification": self.justification,
            "max_observed_risk_score": round(self.max_observed_risk_score, 4),
            "proof_verified": self.proof_verified,
            "status": self.status.value,
            "title": self.title,
        }


# =====================================================================
# Standard Regulatory Catalogs
# =====================================================================

def get_standard_compliance_controls() -> List[ComplianceControlDefinition]:
    """Catalog of canonical compliance controls across major AI governance standards."""
    raw_defs = [
        # NIST AI RMF
        ComplianceControlDefinition(
            framework=ComplianceFramework.NIST_AI_RMF,
            control_id="NIST-AI-GOVERN-1.1",
            title="Legal and Regulatory AI Governance Requirements",
            description="Policies, processes, and procedures are in place to ensure compliance with relevant AI safety mandates.",
            target_domains=[SubsystemDomain.MODEL_INTEGRITY, SubsystemDomain.BEHAVIORAL_ANALYSIS],
            required_evidence_layers=[EvidenceLayer.DETECTION],
            max_allowable_risk_score=0.30,
        ),
        ComplianceControlDefinition(
            framework=ComplianceFramework.NIST_AI_RMF,
            control_id="NIST-AI-MAP-1.1",
            title="AI System Context and Operational Characterization",
            description="Categorization of AI assets, dependencies, and upstream data inputs.",
            target_domains=[SubsystemDomain.DATASET_INTEGRITY, SubsystemDomain.MODEL_INTEGRITY],
            required_evidence_layers=[EvidenceLayer.DETECTION, EvidenceLayer.PROOF],
            max_allowable_risk_score=0.40,
        ),
        ComplianceControlDefinition(
            framework=ComplianceFramework.NIST_AI_RMF,
            control_id="NIST-AI-MEASURE-2.3",
            title="AI System Drift and Anomaly Monitoring",
            description="Continuous measurement of covariate drift, statistical anomaly, and behavioral stability.",
            target_domains=[SubsystemDomain.DISTRIBUTION_SHIFT, SubsystemDomain.BEHAVIORAL_ANALYSIS],
            required_evidence_layers=[EvidenceLayer.DETECTION],
            max_allowable_risk_score=0.50,
        ),
        ComplianceControlDefinition(
            framework=ComplianceFramework.NIST_AI_RMF,
            control_id="NIST-AI-MANAGE-2.1",
            title="Adversarial and Security Vulnerability Mitigation",
            description="Identification and mitigation of backdoor triggers, data poisoning, and model weight tampering.",
            target_domains=[SubsystemDomain.BACKDOOR_TRIGGER, SubsystemDomain.MODEL_INTEGRITY],
            required_evidence_layers=[EvidenceLayer.DETECTION, EvidenceLayer.PROOF],
            max_allowable_risk_score=0.30,
        ),

        # EU AI Act
        ComplianceControlDefinition(
            framework=ComplianceFramework.EU_AI_ACT,
            control_id="EU-AI-ACT-ART-9",
            title="Risk Management System",
            description="Establishment and maintenance of continuous risk quantification across AI lifecycles.",
            target_domains=[SubsystemDomain.MODEL_INTEGRITY, SubsystemDomain.DISTRIBUTION_SHIFT, SubsystemDomain.BEHAVIORAL_ANALYSIS],
            required_evidence_layers=[EvidenceLayer.DETECTION],
            max_allowable_risk_score=0.30,
        ),
        ComplianceControlDefinition(
            framework=ComplianceFramework.EU_AI_ACT,
            control_id="EU-AI-ACT-ART-10",
            title="Data and Data Governance",
            description="Validation of training, validation, and testing dataset distributions and provenance integrity.",
            target_domains=[SubsystemDomain.DATASET_INTEGRITY, SubsystemDomain.DISTRIBUTION_SHIFT],
            required_evidence_layers=[EvidenceLayer.DETECTION, EvidenceLayer.PROOF],
            max_allowable_risk_score=0.35,
        ),
        ComplianceControlDefinition(
            framework=ComplianceFramework.EU_AI_ACT,
            control_id="EU-AI-ACT-ART-12",
            title="Record-Keeping and Technical Logging",
            description="Cryptographic tamper-evident provenance recording for automated event logging.",
            target_domains=[SubsystemDomain.DATASET_INTEGRITY, SubsystemDomain.MODEL_INTEGRITY, SubsystemDomain.INFERENCE_INTEGRITY],
            required_evidence_layers=[EvidenceLayer.PROOF],
            max_allowable_risk_score=0.20,
        ),
        ComplianceControlDefinition(
            framework=ComplianceFramework.EU_AI_ACT,
            control_id="EU-AI-ACT-ART-15",
            title="Accuracy, Robustness and Cybersecurity",
            description="Resilience against backdoor exploitation, adversarial perturbation, and runtime failure.",
            target_domains=[SubsystemDomain.BACKDOOR_TRIGGER, SubsystemDomain.BEHAVIORAL_ANALYSIS, SubsystemDomain.INFERENCE_INTEGRITY],
            required_evidence_layers=[EvidenceLayer.DETECTION],
            max_allowable_risk_score=0.30,
        ),

        # ISO/IEC 42001
        ComplianceControlDefinition(
            framework=ComplianceFramework.ISO_IEC_42001,
            control_id="ISO-42001-A.6.2",
            title="AI Risk Assessment and Treatment",
            description="Quantified risk assessment adhering to bounded probabilistic scoring.",
            target_domains=[SubsystemDomain.MODEL_INTEGRITY, SubsystemDomain.BEHAVIORAL_ANALYSIS],
            required_evidence_layers=[EvidenceLayer.DETECTION],
            max_allowable_risk_score=0.30,
        ),
        ComplianceControlDefinition(
            framework=ComplianceFramework.ISO_IEC_42001,
            control_id="ISO-42001-A.9.3",
            title="Data Provenance for AI Systems",
            description="Verification of cryptographic lineage across data ingestion pipelines.",
            target_domains=[SubsystemDomain.DATASET_INTEGRITY, SubsystemDomain.CONTRIBUTOR_RISK],
            required_evidence_layers=[EvidenceLayer.PROOF],
            max_allowable_risk_score=0.25,
        ),

        # OWASP LLM Top 10
        ComplianceControlDefinition(
            framework=ComplianceFramework.OWASP_LLM_TOP_10,
            control_id="OWASP-LLM-03",
            title="Supply Chain Vulnerabilities",
            description="Verification of model weight integrity, supply chain provenance, and signature validity.",
            target_domains=[SubsystemDomain.MODEL_INTEGRITY, SubsystemDomain.CONTRIBUTOR_RISK],
            required_evidence_layers=[EvidenceLayer.PROOF, EvidenceLayer.DETECTION],
            max_allowable_risk_score=0.25,
        ),
        ComplianceControlDefinition(
            framework=ComplianceFramework.OWASP_LLM_TOP_10,
            control_id="OWASP-LLM-04",
            title="Data and Model Poisoning",
            description="Detection of backdoors, label flipping, and poisoned training samples.",
            target_domains=[SubsystemDomain.BACKDOOR_TRIGGER, SubsystemDomain.DISTRIBUTION_SHIFT],
            required_evidence_layers=[EvidenceLayer.DETECTION],
            max_allowable_risk_score=0.30,
        ),
    ]

    result = []
    for d in raw_defs:
        h = compute_control_hash(d)
        object.__setattr__(d, "control_hash", h)
        result.append(d)
    return result


class ComplianceEvaluationEngine:
    """Deterministic evaluation engine mapping assurance artifacts to compliance controls."""

    def __init__(self, controls: Optional[List[ComplianceControlDefinition]] = None) -> None:
        self.controls = controls or get_standard_compliance_controls()

    def evaluate_project_compliance(
        self,
        project_id: str,
        asset_ids: Sequence[str],
        evidence_items: Sequence[Any],
        findings: Sequence[Any],
        risk_assessments: Dict[str, Any],
        policy_decisions: Dict[str, Any],
        proof_assessments: Dict[str, Any],
        target_frameworks: Optional[Set[ComplianceFramework]] = None,
    ) -> List[ComplianceControlResult]:
        """Evaluate assurance artifacts against compliance controls with strict 6-state logic."""
        results: List[ComplianceControlResult] = []

        active_controls = self.controls
        if target_frameworks:
            active_controls = [c for c in active_controls if c.framework in target_frameworks]

        # Pre-index evidence by domain and layer
        evidence_by_domain: Dict[SubsystemDomain, List[Any]] = collections.defaultdict(list)
        evidence_by_layer: Dict[EvidenceLayer, List[Any]] = collections.defaultdict(list)
        for e in evidence_items:
            dom = getattr(e, "domain", None) or (e.get("domain") if isinstance(e, dict) else None)
            layer = getattr(e, "evidence_layer", None) or (e.get("evidence_layer") if isinstance(e, dict) else None)
            if dom:
                if isinstance(dom, str):
                    try: dom = SubsystemDomain(dom)
                    except Exception: pass
                evidence_by_domain[dom].append(e)
            if layer:
                if isinstance(layer, str):
                    try: layer = EvidenceLayer(layer)
                    except Exception: pass
                evidence_by_layer[layer].append(e)

        for ctrl in active_controls:
            # 1. Check if relevant domains/layers are covered by collected evidence
            matching_ev = []
            for d in ctrl.target_domains:
                matching_ev.extend(evidence_by_domain.get(d, []))
            
            matching_layers = set()
            for e in matching_ev:
                l = getattr(e, "evidence_layer", None) or (e.get("evidence_layer") if isinstance(e, dict) else None)
                if l:
                    if isinstance(l, str):
                        try: l = EvidenceLayer(l)
                        except Exception: pass
                    matching_layers.add(l)

            # Invariant: REQ-12-AUDIT-011 (No False Compliance on Absence of Evidence)
            if not matching_ev:
                status = ComplianceStatus.UNAVAILABLE
                justification = f"Evidence unavailable for target domains ({', '.join(d.value for d in ctrl.target_domains)})"
                max_r = 0.0
                proof_ok = False
            else:
                # Check required layers
                missing_layers = [l for l in ctrl.required_evidence_layers if l not in matching_layers]
                if missing_layers:
                    status = ComplianceStatus.PARTIALLY_COMPLIANT
                    justification = f"Missing required evidence layers: {', '.join(l.value for l in missing_layers)}"
                else:
                    status = ComplianceStatus.COMPLIANT
                    justification = "All target domains and required evidence layers satisfied within acceptable risk bounds"

                # Check observed risk scores across assets
                max_r = 0.0
                for aid in asset_ids:
                    ra = risk_assessments.get(aid)
                    r_score = 0.0
                    if isinstance(ra, dict):
                        r_score = float(ra.get("risk_score", 0.0))
                    elif ra is not None:
                        r_score = float(getattr(ra, "risk_score", 0.0))
                    if r_score > max_r:
                        max_r = r_score

                # Check proof status across assets
                proof_ok = True
                proof_fatal = False
                for aid in asset_ids:
                    pa = proof_assessments.get(aid)
                    if pa:
                        override = False
                        if isinstance(pa, dict):
                            override = bool(pa.get("proof_override_required", False))
                        elif hasattr(pa, "proof_override_required"):
                            override = bool(getattr(pa, "proof_override_required", False))
                        if override:
                            proof_ok = False
                            proof_fatal = True

                # Evaluate compliance thresholds
                if proof_fatal and ctrl.allow_proof_override:
                    status = ComplianceStatus.NON_COMPLIANT
                    justification = "Cryptographic proof failure triggered non-compliance"
                elif max_r > ctrl.max_allowable_risk_score:
                    if max_r >= 0.70:
                        status = ComplianceStatus.NON_COMPLIANT
                        justification = f"Observed risk score ({max_r:.4f}) significantly exceeds maximum allowable ({ctrl.max_allowable_risk_score:.4f})"
                    else:
                        status = ComplianceStatus.PARTIALLY_COMPLIANT
                        justification = f"Observed risk score ({max_r:.4f}) moderately exceeds maximum allowable ({ctrl.max_allowable_risk_score:.4f})"

            ev_ids = []
            for e in matching_ev:
                eid = getattr(e, "evidence_id", None) or (e.get("evidence_id") if isinstance(e, dict) else None)
                if eid: ev_ids.append(str(eid))

            find_ids = []
            for f in findings:
                fid = getattr(f, "finding_id", None) or (f.get("finding_id") or f.get("id") if isinstance(f, dict) else None)
                if fid: find_ids.append(str(fid))

            raw_res = {
                "assessed_asset_ids": sorted(list(asset_ids)),
                "contributing_evidence_ids": sorted(ev_ids),
                "contributing_finding_ids": sorted(find_ids),
                "control_id": ctrl.control_id,
                "framework": ctrl.framework.value,
                "justification": justification,
                "max_observed_risk_score": round(max_r, 4),
                "proof_verified": proof_ok,
                "status": status.value,
                "title": ctrl.title,
            }
            r_hash = compute_sha256_digest(compute_canonical_jcs_bytes(raw_res))

            res = ComplianceControlResult(
                control_id=ctrl.control_id,
                framework=ctrl.framework,
                title=ctrl.title,
                status=status,
                justification=justification,
                assessed_asset_ids=sorted(list(asset_ids)),
                contributing_evidence_ids=sorted(ev_ids),
                contributing_finding_ids=sorted(find_ids),
                max_observed_risk_score=round(max_r, 4),
                proof_verified=proof_ok,
                result_hash=r_hash,
            )
            results.append(res)

        return sorted(results, key=lambda r: (r.framework.value, r.control_id))
