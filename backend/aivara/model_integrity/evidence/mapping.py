"""Finding Synthesis and Evidence Mapping for Model Integrity (Phase 7.6).

Translates Phase 7 deterministic evidence into canonical FindingSynthesisPayload objects
complying with ADR-028, strict proof-layer confidence = 1.0, and zero-intent semantic safety.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from aivara.domain.schemas import AnalysisMode, Disposition, EvidenceLayer, Severity
from aivara.evidence.schemas import EvidencePayload, FindingSynthesisPayload
from aivara.evidence.validators import validate_finding_vocabulary
from aivara.model_integrity.comparison.schemas import DriftClassification, ModelComparisonResult
from aivara.model_integrity.contract_verification.schemas import ContractVerificationResult
from aivara.model_integrity.evidence.builders import (
    build_artifact_identity_evidence,
    build_comparison_evidence,
    build_contract_evidence,
    build_master_fingerprint_evidence,
    build_structural_fingerprint_evidence,
    build_tensor_attribution_evidence,
    build_weight_merkle_evidence,
)
from aivara.model_integrity.fingerprinting.schemas import HierarchicalFingerprintResult
from aivara.model_integrity.schemas import ModelInspectionResult, NormalizedModelMetadata


def map_model_integrity_to_findings(
    *,
    project_id: str,
    model_id: str,
    audit_run_id: Optional[str] = None,
    engine_version: str = "1.0.0",
    fingerprint_result: Optional[HierarchicalFingerprintResult] = None,
    contract_result: Optional[ContractVerificationResult] = None,
    comparison_result: Optional[ModelComparisonResult] = None,
    inspection_result: Optional[ModelInspectionResult] = None,
    metadata: Optional[NormalizedModelMetadata] = None,
    reference_model_id: Optional[str] = None,
) -> List[FindingSynthesisPayload]:
    """Synthesize structured technical integrity findings from model integrity assessment components."""
    findings: List[FindingSynthesisPayload] = []

    # 1. Base Fingerprint Proof Finding (Proof Layer)
    if fingerprint_result is not None:
        primary_ev: List[EvidencePayload] = []

        if inspection_result is not None:
            primary_ev.append(
                build_artifact_identity_evidence(
                    project_id=project_id,
                    model_id=model_id,
                    inspection_result=inspection_result,
                )
            )

        primary_ev.append(
            build_structural_fingerprint_evidence(
                project_id=project_id,
                model_id=model_id,
                fingerprint_result=fingerprint_result,
                metadata=metadata,
            )
        )

        primary_ev.append(
            build_weight_merkle_evidence(
                project_id=project_id,
                model_id=model_id,
                fingerprint_result=fingerprint_result,
            )
        )

        if contract_result is not None:
            primary_ev.append(
                build_contract_evidence(
                    project_id=project_id,
                    model_id=model_id,
                    contract_result=contract_result,
                    artifact_hash=fingerprint_result.artifact_hash,
                )
            )

        primary_ev.append(
            build_master_fingerprint_evidence(
                project_id=project_id,
                model_id=model_id,
                fingerprint_result=fingerprint_result,
            )
        )

        finding_fp = FindingSynthesisPayload(
            project_id=project_id,
            audit_run_id=audit_run_id,
            engine_id="model_integrity_engine",
            engine_version=engine_version,
            evidence_layer=EvidenceLayer.PROOF,
            finding_type="MODEL_CRYPTOGRAPHIC_IDENTITY_SEALED",
            title=f"Model Cryptographic Identity Sealed: {fingerprint_result.master_fingerprint[:16]}...",
            description="Established multi-tier cryptographic and structural identity across raw artifact, graph operators, and weight Merkle digest.",
            severity=Severity.INFO,
            confidence=1.0,  # ADR-028 invariant: Proof-layer findings MUST have confidence = 1.0
            affected_asset_type="model",
            affected_asset_id=model_id,
            disposition=Disposition.ACCEPT,
            analysis_mode=AnalysisMode.NOT_APPLICABLE,
            primary_evidence_items=primary_ev,
            metadata_json={
                "master_fingerprint": fingerprint_result.master_fingerprint,
                "artifact_hash": fingerprint_result.artifact_hash,
                "structural_hash": fingerprint_result.structural_hash,
                "weight_merkle_root": fingerprint_result.weight_merkle_root,
                "contract_hash": fingerprint_result.contract_hash,
            },
        )
        validate_finding_vocabulary(finding_fp)
        findings.append(finding_fp)

    # 2. Reference Model Comparison Finding (Detection Layer)
    if comparison_result is not None:
        ref_id = reference_model_id or "reference_model"
        comp_ev: List[EvidencePayload] = [
            build_comparison_evidence(
                project_id=project_id,
                model_id=model_id,
                reference_model_id=ref_id,
                comparison_result=comparison_result,
            )
        ]

        if comparison_result.tensor_changes:
            comp_ev.append(
                build_tensor_attribution_evidence(
                    project_id=project_id,
                    model_id=model_id,
                    comparison_result=comparison_result,
                )
            )

        if comparison_result.drift_classification == DriftClassification.EXACT_INTEGRITY_MATCH:
            f_type = "MODEL_EXACT_INTEGRITY_MATCH"
            f_title = "Exact Model Integrity Match to Reference"
            f_desc = f"Model is cryptographically and structurally identical to verified reference '{ref_id}' across all evaluation dimensions."
            f_sev = Severity.INFO
            f_disp = Disposition.ACCEPT
        else:
            f_type = f"MODEL_DRIFT_{comparison_result.drift_classification.value}"
            f_title = f"Model Integrity Drift Detected: {comparison_result.drift_classification.value}"
            f_desc = f"Observed discrepancies between candidate model and reference model '{ref_id}' in classification '{comparison_result.drift_classification.value}'."
            f_sev = Severity.HIGH
            f_disp = Disposition.REVIEW

        finding_comp = FindingSynthesisPayload(
            project_id=project_id,
            audit_run_id=audit_run_id,
            engine_id="model_integrity_comparison_engine",
            engine_version=engine_version,
            evidence_layer=EvidenceLayer.DETECTION,
            finding_type=f_type,
            title=f_title,
            description=f_desc,
            severity=f_sev,
            confidence=1.0,
            affected_asset_type="model",
            affected_asset_id=model_id,
            disposition=f_disp,
            analysis_mode=AnalysisMode.NOT_APPLICABLE,
            primary_evidence_items=comp_ev,
            metadata_json={
                "drift_classification": comparison_result.drift_classification.value,
                "comparison_status": comparison_result.comparison_status.value,
                "reference_model_id": ref_id,
                "reason_codes": comparison_result.reason_codes,
            },
        )
        validate_finding_vocabulary(finding_comp)
        findings.append(finding_comp)

    return findings
