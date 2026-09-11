"""Deterministic Evidence Builders for Model Integrity Assessments (Phase 7.6).

Transforms outputs from Phase 7.2 Ingestion, Phase 7.3 Fingerprinting, Phase 7.4 Contract,
and Phase 7.5 Comparison into canonical Phase 5.9 EvidencePayload instances with deterministic SHA-256 identities.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aivara.domain.schemas import EvidenceLayer
from aivara.evidence.identity import compute_evidence_hash
from aivara.evidence.schemas import EvidencePayload
from aivara.model_integrity.comparison.schemas import ModelComparisonResult
from aivara.model_integrity.contract_verification.schemas import ContractVerificationResult
from aivara.model_integrity.evidence.schemas import ModelEvidenceType
from aivara.model_integrity.fingerprinting.schemas import HierarchicalFingerprintResult
from aivara.model_integrity.schemas import ModelInspectionResult, NormalizedModelMetadata


def build_artifact_identity_evidence(
    *,
    project_id: str,
    model_id: str,
    inspection_result: ModelInspectionResult,
    detector_id: str = "model_integrity_inspector",
    detector_version: str = "1.0.0",
    detector_config_hash: str = "0" * 64,
) -> EvidencePayload:
    """Build deterministic EvidencePayload for raw artifact identity and inspection."""
    art_hash = inspection_result.artifact_hash_sha256 or ("0" * 64)
    data = {
        "artifact_hash": art_hash,
        "artifact_size_bytes": inspection_result.artifact_size_bytes,
        "format": inspection_result.format.value,
        "policy": inspection_result.policy.value,
        "status": inspection_result.status.value,
        "reason_codes": [r.value for r in inspection_result.reason_codes],
        "warnings": sorted(inspection_result.warnings),
    }

    ev_dict = {
        "evidence_layer": EvidenceLayer.PROOF.value,
        "evidence_type": ModelEvidenceType.MODEL_ARTIFACT_IDENTITY.value,
        "project_id": project_id,
        "dataset_version_id": model_id,
        "dataset_fingerprint": art_hash,
        "target_asset_type": "model",
        "target_asset_id": model_id,
        "target_asset_hash": art_hash,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_config_hash": detector_config_hash,
        "model_fingerprint": art_hash,
        "reference_fingerprint": "NONE",
        "measurements": {"file_size_bytes": inspection_result.artifact_size_bytes},
    }
    ev_hash = compute_evidence_hash(ev_dict)

    return EvidencePayload(
        title=f"Model Artifact Identity Digest: {art_hash[:16]}...",
        description=f"Raw cryptographic SHA-256 digest and safe inspection result for model format '{inspection_result.format.value}'.",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type=ModelEvidenceType.MODEL_ARTIFACT_IDENTITY.value,
        confidence=1.0,
        artifact_hash=art_hash,
        data_json=data,
        evidence_hash=ev_hash,
        target_asset_type="model",
        target_asset_id=model_id,
        target_asset_hash=art_hash,
        dataset_version_id=model_id,
        dataset_fingerprint=art_hash,
        detector_id=detector_id,
        detector_version=detector_version,
        detector_config_hash=detector_config_hash,
        model_fingerprint=art_hash,
        reference_fingerprint="NONE",
        measurements={"file_size_bytes": inspection_result.artifact_size_bytes},
    )


def build_structural_fingerprint_evidence(
    *,
    project_id: str,
    model_id: str,
    fingerprint_result: HierarchicalFingerprintResult,
    metadata: Optional[NormalizedModelMetadata] = None,
    detector_id: str = "model_structural_fingerprinter",
    detector_version: str = "1.0.0",
    detector_config_hash: str = "0" * 64,
) -> EvidencePayload:
    """Build deterministic EvidencePayload for structural identity (H_structural)."""
    struct_hash = fingerprint_result.structural_hash
    art_hash = fingerprint_result.artifact_hash

    data = {
        "structural_hash": struct_hash,
        "artifact_hash": art_hash,
        "tensor_count": metadata.tensor_count if metadata else fingerprint_result.tensor_count,
        "parameter_count": metadata.parameter_count if metadata else fingerprint_result.parameter_count,
        "operator_count": len(metadata.operators) if metadata else 0,
        "format": metadata.format.value if metadata else "unknown",
    }

    ev_dict = {
        "evidence_layer": EvidenceLayer.PROOF.value,
        "evidence_type": ModelEvidenceType.MODEL_STRUCTURAL_FINGERPRINT.value,
        "project_id": project_id,
        "dataset_version_id": model_id,
        "dataset_fingerprint": art_hash,
        "target_asset_type": "model_structure",
        "target_asset_id": model_id,
        "target_asset_hash": struct_hash,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_config_hash": detector_config_hash,
        "model_fingerprint": struct_hash,
        "reference_fingerprint": "NONE",
        "measurements": {
            "tensor_count": data["tensor_count"],
            "parameter_count": data["parameter_count"],
        },
    }
    ev_hash = compute_evidence_hash(ev_dict)

    return EvidencePayload(
        title=f"Structural Architecture Digest: {struct_hash[:16]}...",
        description=f"Deterministic JCS structural fingerprint binding graph operators, parameter schema, and tensor shapes.",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type=ModelEvidenceType.MODEL_STRUCTURAL_FINGERPRINT.value,
        confidence=1.0,
        artifact_hash=struct_hash,
        data_json=data,
        evidence_hash=ev_hash,
        target_asset_type="model_structure",
        target_asset_id=model_id,
        target_asset_hash=struct_hash,
        dataset_version_id=model_id,
        dataset_fingerprint=art_hash,
        detector_id=detector_id,
        detector_version=detector_version,
        detector_config_hash=detector_config_hash,
        model_fingerprint=struct_hash,
        reference_fingerprint="NONE",
        measurements=ev_dict["measurements"],
    )


def build_weight_merkle_evidence(
    *,
    project_id: str,
    model_id: str,
    fingerprint_result: HierarchicalFingerprintResult,
    detector_id: str = "model_weight_merkle_engine",
    detector_version: str = "1.0.0",
    detector_config_hash: str = "0" * 64,
) -> EvidencePayload:
    """Build deterministic EvidencePayload for Tier 4 weight Merkle root (H_weight_merkle)."""
    weight_root = fingerprint_result.weight_merkle_root or ("0" * 64)
    art_hash = fingerprint_result.artifact_hash

    data = {
        "weight_merkle_root": weight_root,
        "weight_status": fingerprint_result.weight_status,
        "tensor_count": fingerprint_result.tensor_count,
        "parameter_count": fingerprint_result.parameter_count,
        "is_available": fingerprint_result.weight_status == "verified",
    }

    ev_dict = {
        "evidence_layer": EvidenceLayer.PROOF.value,
        "evidence_type": ModelEvidenceType.MODEL_WEIGHT_MERKLE_ROOT.value,
        "project_id": project_id,
        "dataset_version_id": model_id,
        "dataset_fingerprint": art_hash,
        "target_asset_type": "model_weights",
        "target_asset_id": model_id,
        "target_asset_hash": weight_root,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_config_hash": detector_config_hash,
        "model_fingerprint": weight_root,
        "reference_fingerprint": "NONE",
        "measurements": {
            "tensor_count": fingerprint_result.tensor_count,
            "parameter_count": fingerprint_result.parameter_count,
        },
    }
    ev_hash = compute_evidence_hash(ev_dict)

    return EvidencePayload(
        title=f"Weight Merkle Tree Root: {weight_root[:16]}...",
        description=f"Hierarchical Merkle tree digest over sorted parameter tensor leaf hashes with domain separation.",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type=ModelEvidenceType.MODEL_WEIGHT_MERKLE_ROOT.value,
        confidence=1.0,
        artifact_hash=weight_root,
        data_json=data,
        evidence_hash=ev_hash,
        target_asset_type="model_weights",
        target_asset_id=model_id,
        target_asset_hash=weight_root,
        dataset_version_id=model_id,
        dataset_fingerprint=art_hash,
        detector_id=detector_id,
        detector_version=detector_version,
        detector_config_hash=detector_config_hash,
        model_fingerprint=weight_root,
        reference_fingerprint="NONE",
        measurements=ev_dict["measurements"],
    )


def build_contract_evidence(
    *,
    project_id: str,
    model_id: str,
    contract_result: ContractVerificationResult,
    artifact_hash: str,
    detector_id: str = "model_contract_verifier",
    detector_version: str = "1.0.0",
    detector_config_hash: str = "0" * 64,
) -> EvidencePayload:
    """Build deterministic EvidencePayload for Tier 3 operational contract verification."""
    c_hash = contract_result.contract_hash
    data = {
        "contract_hash": c_hash,
        "status": contract_result.status.value,
        "completeness": contract_result.completeness.value,
        "input_count": len(contract_result.inputs),
        "output_count": len(contract_result.outputs),
        "has_preprocessing": contract_result.preprocessing is not None,
        "findings_count": len(contract_result.findings),
        "finding_codes": sorted(list({f.code.value for f in contract_result.findings})),
    }

    ev_dict = {
        "evidence_layer": EvidenceLayer.PROOF.value,
        "evidence_type": ModelEvidenceType.MODEL_CONTRACT_VERIFICATION.value,
        "project_id": project_id,
        "dataset_version_id": model_id,
        "dataset_fingerprint": artifact_hash,
        "target_asset_type": "model_contract",
        "target_asset_id": model_id,
        "target_asset_hash": c_hash,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_config_hash": detector_config_hash,
        "model_fingerprint": c_hash,
        "reference_fingerprint": "NONE",
        "measurements": {
            "input_count": len(contract_result.inputs),
            "output_count": len(contract_result.outputs),
            "findings_count": len(contract_result.findings),
        },
    }
    ev_hash = compute_evidence_hash(ev_dict)

    return EvidencePayload(
        title=f"Operational Contract Digest: {c_hash[:16]}...",
        description=f"Static interface verification for model inputs, outputs, dtypes, and preprocessing declarations.",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type=ModelEvidenceType.MODEL_CONTRACT_VERIFICATION.value,
        confidence=1.0,
        artifact_hash=c_hash,
        data_json=data,
        evidence_hash=ev_hash,
        target_asset_type="model_contract",
        target_asset_id=model_id,
        target_asset_hash=c_hash,
        dataset_version_id=model_id,
        dataset_fingerprint=artifact_hash,
        detector_id=detector_id,
        detector_version=detector_version,
        detector_config_hash=detector_config_hash,
        model_fingerprint=c_hash,
        reference_fingerprint="NONE",
        measurements=ev_dict["measurements"],
    )


def build_master_fingerprint_evidence(
    *,
    project_id: str,
    model_id: str,
    fingerprint_result: HierarchicalFingerprintResult,
    detector_id: str = "model_master_fingerprinter",
    detector_version: str = "1.0.0",
    detector_config_hash: str = "0" * 64,
) -> EvidencePayload:
    """Build deterministic EvidencePayload for canonical Master Model Fingerprint (H_model)."""
    master_fp = fingerprint_result.master_fingerprint
    art_hash = fingerprint_result.artifact_hash

    data = {
        "schema_version": "1.0",
        "master_fingerprint": master_fp,
        "artifact_hash": art_hash,
        "structural_hash": fingerprint_result.structural_hash,
        "contract_hash": fingerprint_result.contract_hash,
    }

    ev_dict = {
        "evidence_layer": EvidenceLayer.PROOF.value,
        "evidence_type": ModelEvidenceType.MODEL_MASTER_FINGERPRINT.value,
        "project_id": project_id,
        "dataset_version_id": model_id,
        "dataset_fingerprint": art_hash,
        "target_asset_type": "model_master_fingerprint",
        "target_asset_id": model_id,
        "target_asset_hash": master_fp,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_config_hash": detector_config_hash,
        "model_fingerprint": master_fp,
        "reference_fingerprint": "NONE",
        "measurements": {},
    }
    ev_hash = compute_evidence_hash(ev_dict)

    return EvidencePayload(
        title=f"Master Model Fingerprint (ADR-040): {master_fp[:16]}...",
        description="Canonical JCS binding of artifact, structural, and operational contract identity digests.",
        evidence_layer=EvidenceLayer.PROOF,
        evidence_type=ModelEvidenceType.MODEL_MASTER_FINGERPRINT.value,
        confidence=1.0,
        artifact_hash=master_fp,
        data_json=data,
        evidence_hash=ev_hash,
        target_asset_type="model_master_fingerprint",
        target_asset_id=model_id,
        target_asset_hash=master_fp,
        dataset_version_id=model_id,
        dataset_fingerprint=art_hash,
        detector_id=detector_id,
        detector_version=detector_version,
        detector_config_hash=detector_config_hash,
        model_fingerprint=master_fp,
        reference_fingerprint="NONE",
        measurements={},
    )


def build_reference_comparison_evidence(
    *,
    project_id: str,
    model_id: str,
    reference_model_id: str,
    comparison_result: ModelComparisonResult,
    detector_id: str = "model_drift_comparator",
    detector_version: str = "1.0.0",
    detector_config_hash: str = "0" * 64,
) -> EvidencePayload:
    """Build deterministic EvidencePayload for reference vs candidate drift comparison."""
    cand_art = comparison_result.candidate_fingerprints.get("artifact_hash") or ("0" * 64)
    ref_art = comparison_result.reference_fingerprints.get("artifact_hash") or ("0" * 64)

    data = {
        "drift_classification": comparison_result.drift_classification.value,
        "comparison_status": comparison_result.comparison_status.value,
        "reference_trust": comparison_result.reference_trust,
        "candidate_trust": comparison_result.candidate_trust,
        "is_exact_artifact_match": comparison_result.is_exact_artifact_match,
        "is_exact_master_match": comparison_result.is_exact_master_match,
        "artifact_status": comparison_result.artifact_status.value,
        "structural_status": comparison_result.structural_status.value,
        "weight_status": comparison_result.weight_status.value,
        "contract_status": comparison_result.contract_status.value,
        "tensor_summary": comparison_result.tensor_summary,
        "structural_difference_count": len(comparison_result.structural_differences),
        "contract_difference_count": len(comparison_result.contract_differences),
        "reason_codes": comparison_result.reason_codes,
    }

    ev_dict = {
        "evidence_layer": EvidenceLayer.DETECTION.value,
        "evidence_type": ModelEvidenceType.MODEL_REFERENCE_COMPARISON.value,
        "project_id": project_id,
        "dataset_version_id": model_id,
        "dataset_fingerprint": cand_art,
        "target_asset_type": "model_comparison",
        "target_asset_id": model_id,
        "target_asset_hash": cand_art,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_config_hash": detector_config_hash,
        "model_fingerprint": cand_art,
        "reference_fingerprint": ref_art,
        "measurements": {
            "structural_difference_count": len(comparison_result.structural_differences),
            "contract_difference_count": len(comparison_result.contract_differences),
            "tensors_changed": comparison_result.tensor_summary.get("content_changed", 0),
        },
    }
    ev_hash = compute_evidence_hash(ev_dict)

    return EvidencePayload(
        title=f"Model Comparison Drift: {comparison_result.drift_classification.value}",
        description=f"Multi-tier reference comparison evaluated against reference model '{reference_model_id}'.",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=ModelEvidenceType.MODEL_REFERENCE_COMPARISON.value,
        confidence=1.0,
        artifact_hash=cand_art,
        data_json=data,
        evidence_hash=ev_hash,
        target_asset_type="model_comparison",
        target_asset_id=model_id,
        target_asset_hash=cand_art,
        dataset_version_id=model_id,
        dataset_fingerprint=cand_art,
        detector_id=detector_id,
        detector_version=detector_version,
        detector_config_hash=detector_config_hash,
        model_fingerprint=cand_art,
        reference_fingerprint=ref_art,
        measurements=ev_dict["measurements"],
    )


# Alias for canonical naming
build_comparison_evidence = build_reference_comparison_evidence


def build_tensor_attribution_evidence(
    *,
    project_id: str,
    model_id: str,
    comparison_result: ModelComparisonResult,
    detector_id: str = "model_tensor_attribution_engine",
    detector_version: str = "1.0.0",
    detector_config_hash: str = "0" * 64,
) -> EvidencePayload:
    """Build deterministic EvidencePayload for granular parameter tensor changes."""
    cand_art = comparison_result.candidate_fingerprints.get("artifact_hash") or ("0" * 64)

    changes_summary = []
    for c in comparison_result.tensor_changes:
        changes_summary.append({
            "name": c.tensor_name,
            "change_type": c.change_type.value,
            "ref_shape": c.reference_shape,
            "cand_shape": c.candidate_shape,
            "ref_dtype": c.reference_dtype,
            "cand_dtype": c.candidate_dtype,
            "has_proof": c.inclusion_proof is not None,
        })

    data = {
        "tensor_summary": comparison_result.tensor_summary,
        "changes_count": len(changes_summary),
        "changes": changes_summary,
    }

    ev_dict = {
        "evidence_layer": EvidenceLayer.DETECTION.value,
        "evidence_type": ModelEvidenceType.MODEL_TENSOR_ATTRIBUTION.value,
        "project_id": project_id,
        "dataset_version_id": model_id,
        "dataset_fingerprint": cand_art,
        "target_asset_type": "model_tensors",
        "target_asset_id": model_id,
        "target_asset_hash": cand_art,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_config_hash": detector_config_hash,
        "model_fingerprint": cand_art,
        "reference_fingerprint": comparison_result.reference_fingerprints.get("artifact_hash", "NONE"),
        "measurements": comparison_result.tensor_summary,
    }
    ev_hash = compute_evidence_hash(ev_dict)

    return EvidencePayload(
        title=f"Tensor Attribution Summary ({len(comparison_result.tensor_changes)} tensors evaluated)",
        description="Granular parameter tensor change attribution across added, removed, content-modified, and metadata-modified tensors.",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=ModelEvidenceType.MODEL_TENSOR_ATTRIBUTION.value,
        confidence=1.0,
        artifact_hash=cand_art,
        data_json=data,
        evidence_hash=ev_hash,
        target_asset_type="model_tensors",
        target_asset_id=model_id,
        target_asset_hash=cand_art,
        dataset_version_id=model_id,
        dataset_fingerprint=cand_art,
        detector_id=detector_id,
        detector_version=detector_version,
        detector_config_hash=detector_config_hash,
        model_fingerprint=cand_art,
        reference_fingerprint=comparison_result.reference_fingerprints.get("artifact_hash", "NONE"),
        measurements=comparison_result.tensor_summary,
    )
