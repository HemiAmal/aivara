"""Behavioral Evidence Factory, Serialization, and Sealing Engine (Phase 8.7).

Transforms validated outputs from Phases 8.3–8.6 into canonical, immutable BehavioralEvidence
objects with deterministic SHA-256 identities.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from aivara.domain.schemas import EvidenceLayer
from aivara.evidence.schemas import EvidencePayload
from aivara.behavioral.anomaly.schemas import (
    BehavioralAnomalyAnalysis,
    BehavioralAnomalyFamily,
    BehavioralAnomalyMetric,
)
from aivara.behavioral.provenance.enums import (
    BehavioralEvidenceType,
    EvidenceLifecycleState,
)
from aivara.behavioral.provenance.exceptions import (
    BehavioralEvidenceValidationError,
    EvidenceImmutableError,
)
from aivara.behavioral.provenance.identity import (
    build_canonical_behavioral_evidence_dict,
    compute_behavioral_evidence_hash,
)
from aivara.behavioral.provenance.schemas import (
    BehavioralEvidence,
    BehavioralEvidenceContent,
)

logger = logging.getLogger("aivara.behavioral.provenance.evidence")


def build_anomaly_evidence_content(
    analysis: BehavioralAnomalyAnalysis,
    *,
    input_hash: str,
    output_hash: str,
    detector_id: str = "behavioral_anomaly_detector",
    detector_config_hash: Optional[str] = None,
    preprocessing_hash: str = "STANDARD_V1",
) -> BehavioralEvidenceContent:
    """Construct deterministic BehavioralEvidenceContent from a Phase 8.6 BehavioralAnomalyAnalysis."""
    if not analysis.project_id:
        raise BehavioralEvidenceValidationError("analysis.project_id is required.")
    if not analysis.model_id:
        raise BehavioralEvidenceValidationError("analysis.model_id is required.")
    if not analysis.observation_id:
        raise BehavioralEvidenceValidationError("analysis.observation_id is required.")
    if not analysis.baseline_id:
        raise BehavioralEvidenceValidationError("analysis.baseline_id is required.")

    # Format metrics as deterministic dictionaries
    formatted_metrics: List[Dict[str, Any]] = []
    for m in analysis.metrics:
        formatted_metrics.append({
            "metric_name": m.metric_name,
            "family": m.family.value if hasattr(m.family, "value") else str(m.family),
            "direction": m.direction.value if hasattr(m.direction, "value") else str(m.direction),
            "observed_value": m.observed_value,
            "baseline_count": m.baseline_count,
            "baseline_median": m.baseline_median,
            "baseline_mad": m.baseline_mad,
            "robust_z": m.robust_z,
            "absolute_robust_z": m.absolute_robust_z,
            "empirical_extremeness": m.empirical_extremeness,
            "validity_status": m.validity_status,
            "anomaly_status": m.anomaly_status.value if hasattr(m.anomaly_status, "value") else str(m.anomaly_status),
            "reason": m.reason or "",
        })

    # Format families
    formatted_families: Dict[str, Dict[str, Any]] = {}
    for fam_name, fam in analysis.families.items():
        formatted_families[str(fam_name)] = {
            "family_name": fam.family_name.value if hasattr(fam.family_name, "value") else str(fam.family_name),
            "support_status": fam.support_status.value if hasattr(fam.support_status, "value") else str(fam.support_status),
            "metric_count": fam.metric_count,
            "valid_metric_count": fam.valid_metric_count,
            "anomalous_metric_count": fam.anomalous_metric_count,
            "dominant_metric": fam.dominant_metric or "",
            "dominant_extremeness": fam.dominant_extremeness,
            "family_status": fam.family_status.value if hasattr(fam.family_status, "value") else str(fam.family_status),
            "explanation": fam.explanation,
        }

    config_hash = detector_config_hash or analysis.analysis_id

    return BehavioralEvidenceContent(
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type=BehavioralEvidenceType.BEHAVIORAL_ANOMALY,
        project_id=analysis.project_id,
        model_id=analysis.model_id,
        model_fingerprint=analysis.model_fingerprint,
        task_type=analysis.task_type,
        observation_id=analysis.observation_id,
        baseline_id=analysis.baseline_id,
        baseline_type=analysis.baseline_type,
        comparison_id="NONE",
        sensitivity_id="NONE",
        anomaly_analysis_id=analysis.analysis_id,
        input_hash=input_hash,
        output_hash=output_hash,
        preprocessing_hash=preprocessing_hash,
        detector_id=detector_id,
        detector_version=analysis.analysis_version,
        detector_config_hash=config_hash,
        policy_version=analysis.policy_version,
        engine_version=analysis.analysis_version,
        result_status=analysis.overall_status.value if hasattr(analysis.overall_status, "value") else str(analysis.overall_status),
        support_status=analysis.support_status.value if hasattr(analysis.support_status, "value") else str(analysis.support_status),
        comparability_status=analysis.comparability_status,
        metrics=formatted_metrics,
        families=formatted_families,
        limitations=analysis.limitations,
    )


def create_behavioral_evidence(
    content: BehavioralEvidenceContent,
    *,
    seal: bool = False,
) -> BehavioralEvidence:
    """Create a BehavioralEvidence instance from content and optionally seal it."""
    ev_hash = compute_behavioral_evidence_hash(content)
    lifecycle = EvidenceLifecycleState.SEALED if seal else EvidenceLifecycleState.DRAFT
    return BehavioralEvidence(
        evidence_id=ev_hash,
        lifecycle_state=lifecycle,
        content=content,
    )


def seal_behavioral_evidence(evidence: BehavioralEvidence) -> BehavioralEvidence:
    """Seal a draft behavioral evidence item, locking its content and computing its identity."""
    if evidence.lifecycle_state == EvidenceLifecycleState.SEALED:
        return evidence

    ev_hash = compute_behavioral_evidence_hash(evidence.content)
    return BehavioralEvidence(
        evidence_id=ev_hash,
        lifecycle_state=EvidenceLifecycleState.SEALED,
        content=evidence.content,
        created_at=evidence.created_at,
        provenance_record_id=evidence.provenance_record_id,
        provenance_status=evidence.provenance_status,
    )


def to_phase5_evidence_payload(
    evidence: BehavioralEvidence,
    *,
    title: Optional[str] = None,
    description: Optional[str] = None,
) -> EvidencePayload:
    """Convert BehavioralEvidence to a Phase 5.9 EvidencePayload for storage and finding binding."""
    content = evidence.content
    ev_title = title or f"Behavioral Evidence: {content.evidence_type.value} [{content.result_status}]"
    ev_desc = description or f"Behavioral verification evidence for model '{content.model_id}', observation '{content.observation_id}'."

    data_json = {
        "evidence_id": evidence.evidence_id,
        "lifecycle_state": evidence.lifecycle_state.value,
        "task_type": content.task_type,
        "observation_id": content.observation_id,
        "baseline_id": content.baseline_id,
        "baseline_type": content.baseline_type,
        "comparison_id": content.comparison_id,
        "sensitivity_id": content.sensitivity_id,
        "anomaly_analysis_id": content.anomaly_analysis_id,
        "result_status": content.result_status,
        "support_status": content.support_status,
        "comparability_status": content.comparability_status,
        "metrics": content.metrics,
        "families": content.families,
        "limitations": content.limitations,
        "policy_version": content.policy_version,
    }

    measurements = {}
    for m in content.metrics:
        if m.get("observed_value") is not None:
            measurements[m["metric_name"]] = m["observed_value"]

    return EvidencePayload(
        title=ev_title,
        description=ev_desc,
        evidence_layer=content.evidence_layer,
        evidence_type=content.evidence_type.value,
        confidence=1.0 if content.evidence_layer == EvidenceLayer.PROOF else 0.95,
        artifact_path=None,
        artifact_hash=content.output_hash,
        data_json=data_json,
        evidence_hash=evidence.evidence_id,
        target_asset_type="model",
        target_asset_id=content.model_id,
        target_asset_hash=content.model_fingerprint,
        dataset_version_id=content.observation_id,
        dataset_fingerprint=content.input_hash,
        detector_id=content.detector_id,
        detector_version=content.detector_version,
        detector_config_hash=content.detector_config_hash,
        model_fingerprint=content.model_fingerprint,
        reference_fingerprint=content.baseline_id,
        measurements=measurements,
    )
