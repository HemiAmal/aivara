"""Input sanitization, security boundary, and semantic invariant validators (Phase 5.9).

Enforces:
  - Prohibited vocabulary policy (rejecting accusatory, guilt, or maliciousness claims).
  - Numeric sanitization (rejecting NaN, Inf, and non-finite floats).
  - Strict confidence bounds (ADR-028 proof-layer confidence = 1.0).
  - Cross-project isolation and asset ownership verification.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from aivara.database.models import (
    AIModelModel,
    DatasetVersionModel,
    ModelFingerprintModel,
)
from aivara.domain.schemas import EvidenceLayer
from aivara.evidence.exceptions import (
    CrossProjectContaminationError,
    EvidenceValidationError,
    ModelMismatchError,
    StaleDatasetVersionError,
    VocabularyViolationError,
)
from aivara.evidence.schemas import EvidencePayload, FindingSynthesisPayload


# Forbidden accusatory, culpability, and intent-attributing terms in findings and evidence explanations.
# Technical security concepts (e.g., 'backdoor trigger', 'data poisoning vulnerability', 'adversarial perturbation')
# are permitted as objective detection categories, but unverified intent/culpability claims are strictly prohibited.
_PROHIBITED_ACCUSATORY_TERMS: Set[str] = {
    "malicious",
    "maliciously",
    "malice",
    "bad actor",
    "guilty",
    "culpability",
    "culpable",
    "sabotage",
    "sabotaged",
    "fraud",
    "fraudulent",
    "collusion",
    "dishonest",
    "dishonesty",
    "bad faith",
    "deliberate",
    "deliberately",
    "intentional",
    "intentionally",
}

# Regex pattern for whole-word matching of prohibited accusatory terms (case-insensitive)
_PROHIBITED_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(term) for term in _PROHIBITED_ACCUSATORY_TERMS) + r")\b",
    re.IGNORECASE,
)


def validate_finding_vocabulary(text: Optional[str], field_name: str = "field") -> None:
    """Validate that text does not contain forbidden accusatory or intent-attributing vocabulary.

    Raises:
        VocabularyViolationError: If prohibited terms are detected.
    """
    if not text or not isinstance(text, str):
        return

    match = _PROHIBITED_REGEX.search(text)
    if match:
        prohibited_word = match.group(0)
        raise VocabularyViolationError(
            f"Prohibited accusatory intent or culpability term '{prohibited_word}' detected in {field_name}. "
            "Phase 5 findings must use strictly objective, descriptive terminology."
        )


def validate_numeric_metrics(metrics: Dict[str, Any], context: str = "measurements") -> None:
    """Validate that numeric metric dictionaries do not contain NaN, Infinity, or non-finite values."""
    if not isinstance(metrics, dict):
        raise EvidenceValidationError(f"{context} must be a dictionary, got {type(metrics).__name__}.")

    for k, v in metrics.items():
        if isinstance(v, float):
            if math.isnan(v) or math.isinf(v):
                raise EvidenceValidationError(f"Invalid non-finite float in {context}['{k}']: {v}")
        elif isinstance(v, dict):
            validate_numeric_metrics(v, context=f"{context}['{k}']")
        elif isinstance(v, (list, tuple)):
            for i, item in enumerate(v):
                if isinstance(item, float) and (math.isnan(item) or math.isinf(item)):
                    raise EvidenceValidationError(f"Invalid non-finite float in {context}['{k}'][{i}]: {item}")


def validate_confidence_bounds(layer: EvidenceLayer, confidence: Optional[float]) -> None:
    """Validate that confidence adheres to layer rules.

    ADR-028 rule: Proof-layer findings MUST have confidence = 1.0.
    Detection-layer findings have confidence in [0.0, 1.0].
    """
    if confidence is None:
        if layer == EvidenceLayer.PROOF:
            raise EvidenceValidationError("Proof-layer findings MUST provide confidence = 1.0, not None.")
        return

    if not isinstance(confidence, (int, float)):
        raise EvidenceValidationError(f"Confidence must be numeric, got {type(confidence).__name__}.")

    if math.isnan(confidence) or math.isinf(confidence):
        raise EvidenceValidationError(f"Confidence cannot be NaN or Infinite, got {confidence}.")

    if confidence < 0.0 or confidence > 1.0:
        raise EvidenceValidationError(f"Confidence must be within [0.0, 1.0], got {confidence}.")

    if layer == EvidenceLayer.PROOF and float(confidence) != 1.0:
        raise EvidenceValidationError(f"Proof-layer findings MUST have confidence = 1.0 (ADR-028), got {confidence}.")


def validate_project_isolation(
    expected_project_id: str,
    candidate_project_id: str,
    entity_name: str = "Entity",
) -> None:
    """Verify that an entity belongs strictly to the expected project.

    Raises:
        CrossProjectContaminationError: If candidate_project_id != expected_project_id.
    """
    if not expected_project_id or not candidate_project_id:
        raise CrossProjectContaminationError(f"{entity_name} project validation failed: project_id cannot be empty.")

    if str(expected_project_id) != str(candidate_project_id):
        raise CrossProjectContaminationError(
            f"Cross-project contamination rejected: {entity_name} belongs to project '{candidate_project_id}', "
            f"expected '{expected_project_id}'."
        )


def validate_evidence_payload(payload: EvidencePayload) -> None:
    """Perform full security and schema validation on an in-memory evidence payload."""
    validate_finding_vocabulary(payload.title, "evidence.title")
    validate_finding_vocabulary(payload.description, "evidence.description")
    validate_confidence_bounds(payload.evidence_layer, payload.confidence)
    validate_numeric_metrics(payload.measurements, "evidence.measurements")
    validate_numeric_metrics(payload.data_json, "evidence.data_json")


def validate_finding_payload(payload: FindingSynthesisPayload) -> None:
    """Perform full security and schema validation on a finding synthesis payload."""
    validate_finding_vocabulary(payload.title, "finding.title")
    validate_finding_vocabulary(payload.description, "finding.description")
    validate_finding_vocabulary(payload.recommendation, "finding.recommendation")
    validate_confidence_bounds(payload.evidence_layer, payload.confidence)
    validate_numeric_metrics(payload.metadata_json, "finding.metadata_json")

    for i, ev in enumerate(payload.primary_evidence_items):
        validate_evidence_payload(ev)


def validate_dataset_version_binding(
    dataset_version_id: str,
    dataset_fingerprint: str,
    db: Session,
) -> None:
    """Verify that dataset version exists and matches the expected dataset fingerprint."""
    if not dataset_version_id or dataset_version_id == "NONE":
        return
    ver = db.query(DatasetVersionModel).filter(DatasetVersionModel.id == dataset_version_id).first()
    if ver and ver.dataset_hash:
        if str(ver.dataset_hash).lower() != str(dataset_fingerprint).lower():
            raise StaleDatasetVersionError(
                f"Fingerprint mismatch on dataset version '{dataset_version_id}': "
                f"expected '{ver.dataset_hash}', got '{dataset_fingerprint}'."
            )


def validate_model_binding(
    model_id: str,
    model_fingerprint: str,
    db: Session,
) -> None:
    """Verify that AI model exists and matches the provided model fingerprint."""
    if not model_id or model_id == "NONE":
        return
    model = db.query(AIModelModel).filter(AIModelModel.id == model_id).first()
    if model:
        valid_fps = {str(model.file_hash_sha256).lower()}
        fps = db.query(ModelFingerprintModel).filter(ModelFingerprintModel.model_id == model_id).all()
        for fp in fps:
            valid_fps.add(str(fp.fingerprint_value).lower())

        if (
            model_fingerprint
            and model_fingerprint not in ("NONE", "UNAVAILABLE")
            and str(model_fingerprint).lower() not in valid_fps
        ):
            raise ModelMismatchError(
                f"Fingerprint mismatch on AI model '{model_id}': "
                f"fingerprint '{model_fingerprint}' does not match model hashes."
            )
