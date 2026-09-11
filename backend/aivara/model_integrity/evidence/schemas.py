"""Pydantic schemas and descriptors for Model Integrity Evidence and Provenance (Phase 7.6).

Defines deterministic evidence types, assessment summaries, and provenance binding schemas
connecting Phase 7 Model Integrity outputs to Phase 5.9 Evidence and Phase 4 Provenance engines.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.evidence.schemas import EvidencePayload, FindingSynthesisPayload, ProvenanceStatus


class ModelEvidenceType(str, Enum):
    """Taxonomy of deterministic model integrity evidence items."""

    MODEL_ARTIFACT_IDENTITY = "model_artifact_identity"
    MODEL_STRUCTURAL_FINGERPRINT = "model_structural_fingerprint"
    MODEL_WEIGHT_MERKLE_ROOT = "model_weight_merkle_root"
    MODEL_CONTRACT_VERIFICATION = "model_contract_verification"
    MODEL_MASTER_FINGERPRINT = "model_master_fingerprint"
    MODEL_REFERENCE_COMPARISON = "model_reference_comparison"
    MODEL_TENSOR_ATTRIBUTION = "model_tensor_attribution"
    MODEL_REFERENCE_TRUST = "model_reference_trust"


class ModelIntegrityAssessmentPayload(BaseModel):
    """Structured in-memory payload summarizing a complete model integrity evaluation."""

    model_config = ConfigDict(frozen=True)

    project_id: str = Field(..., min_length=1, max_length=36, description="Project identifier")
    model_id: str = Field(..., min_length=1, max_length=36, description="Target AI model identifier")
    model_name: str = Field("unnamed_model", description="Model name or filename")
    audit_run_id: Optional[str] = Field(None, max_length=36, description="Scan audit run identifier")
    engine_version: str = Field("1.0.0", description="Model integrity engine semver")
    policy_version: str = Field("DEFAULT", description="Evaluation policy identifier")
    detector_config_hash: str = Field(
        default="0" * 64,
        pattern=r"^[0-9a-f]{64}$",
        description="64-char hex digest of detector parameters",
    )
