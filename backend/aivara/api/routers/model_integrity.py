"""Model Integrity REST API Router (Phase 7.7).

Exposes deterministic, project-scoped REST endpoints for:
  - Safe model ingestion and static inspection
  - Hierarchical fingerprinting and weight Merkle tree generation
  - Contract & preprocessing verification
  - Reference model comparison and 8-state drift attribution
  - Integrated Model Integrity Assessment (with evidence synthesis and provenance sealing)
  - Model evidence retrieval
  - Model findings retrieval
  - Cryptographic provenance verification
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.api.schemas.evidence import EvidenceItemRead, FindingDetailRead
from aivara.api.schemas.model_integrity import (
    ModelCompareRequest,
    ModelCompareResponse,
    ModelContractVerifyRequest,
    ModelContractVerifyResponse,
    ModelFingerprintRequest,
    ModelFingerprintResponse,
    ModelInspectRequest,
    ModelInspectResponse,
    ModelIntegrityAssessmentRequest,
    ModelIntegrityAssessmentResponse,
    ModelProvenanceVerificationResponse,
)
from aivara.core.config import settings
from aivara.crypto.keys import KeyManager
from aivara.database.connection import get_db
from aivara.services.model_integrity_service import ModelIntegrityService

router = APIRouter(prefix="/projects/{project_id}/models", tags=["model-integrity"])


def get_key_manager() -> KeyManager:
    """Dependency resolving the local KeyManager instance."""
    return KeyManager(keys_dir=settings.keys_dir)


# =====================================================================
# 1. Safe Ingestion & Inspection
# =====================================================================

@router.post(
    "/{model_id}/inspect",
    response_model=ApiResponse[ModelInspectResponse],
    status_code=status.HTTP_200_OK,
    summary="Safely inspect untrusted model artifact",
    description=(
        "Execute static format detection, security boundary checks, resource limits, "
        "and metadata normalization without executing model code or tensors."
    ),
)
async def inspect_model(
    project_id: str,
    model_id: str,
    payload: Optional[ModelInspectRequest] = None,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Safely inspect a model artifact and return normalized structural metadata."""
    service = ModelIntegrityService(db=db, key_manager=key_manager)
    res = service.inspect_model(project_id=project_id, model_id=model_id, request=payload)
    return ApiResponse(data=res)


# =====================================================================
# 2. Hierarchical Fingerprinting
# =====================================================================

@router.post(
    "/{model_id}/fingerprint",
    response_model=ApiResponse[ModelFingerprintResponse],
    status_code=status.HTTP_200_OK,
    summary="Generate hierarchical model fingerprints and weight Merkle root",
    description=(
        "Compute deterministic SHA-256 artifact hash, canonical RFC 8785 JCS structural hash, "
        "weight Merkle tree root, contract hash, and composite master fingerprint (ADR-040)."
    ),
)
async def fingerprint_model(
    project_id: str,
    model_id: str,
    payload: Optional[ModelFingerprintRequest] = None,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Generate or retrieve hierarchical model fingerprints."""
    service = ModelIntegrityService(db=db, key_manager=key_manager)
    res = service.fingerprint_model(project_id=project_id, model_id=model_id, request=payload)
    return ApiResponse(data=res)


# =====================================================================
# 3. Contract Verification
# =====================================================================

@router.post(
    "/{model_id}/contract/verify",
    response_model=ApiResponse[ModelContractVerifyResponse],
    status_code=status.HTTP_200_OK,
    summary="Verify model I/O and preprocessing contract integrity",
    description=(
        "Statically verify model input/output dimensionality, data types, normalization bounds, "
        "and preprocessing declaration consistency."
    ),
)
async def verify_model_contract(
    project_id: str,
    model_id: str,
    payload: Optional[ModelContractVerifyRequest] = None,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Verify input, output, and preprocessing contracts."""
    service = ModelIntegrityService(db=db, key_manager=key_manager)
    res = service.verify_contract(project_id=project_id, model_id=model_id, request=payload)
    return ApiResponse(data=res)


# =====================================================================
# 4. Reference Model Comparison
# =====================================================================

@router.post(
    "/{model_id}/compare",
    response_model=ApiResponse[ModelCompareResponse],
    status_code=status.HTTP_200_OK,
    summary="Compare candidate model against trusted reference model",
    description=(
        "Execute deterministic comparison across structural topology, I/O contract, "
        "and tensor weight Merkle trees. Returns exact 8-state drift classification."
    ),
)
async def compare_models(
    project_id: str,
    model_id: str,
    payload: ModelCompareRequest,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Perform reference comparison and tensor drift attribution."""
    service = ModelIntegrityService(db=db, key_manager=key_manager)
    res = service.compare_models(
        project_id=project_id,
        candidate_model_id=model_id,
        request=payload,
    )
    return ApiResponse(data=res)


# =====================================================================
# 5. Integrated Assessment Pipeline
# =====================================================================

@router.post(
    "/{model_id}/integrity-assessment",
    response_model=ApiResponse[ModelIntegrityAssessmentResponse],
    status_code=status.HTTP_200_OK,
    summary="Execute integrated model integrity assessment",
    description=(
        "Orchestrate full Model Integrity pipeline: static inspection, hierarchical "
        "fingerprinting, contract verification, optional reference comparison, evidence "
        "generation, finding synthesis, and Phase 4 cryptographic provenance sealing."
    ),
)
async def run_integrity_assessment(
    project_id: str,
    model_id: str,
    payload: Optional[ModelIntegrityAssessmentRequest] = None,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Run full integrated model integrity audit pipeline with idempotency and provenance sealing."""
    service = ModelIntegrityService(db=db, key_manager=key_manager)
    res = service.run_integrity_assessment(
        project_id=project_id,
        model_id=model_id,
        request=payload,
    )
    return ApiResponse(data=res)


# =====================================================================
# 6. Evidence Retrieval
# =====================================================================

@router.get(
    "/{model_id}/evidence",
    response_model=ApiResponse[List[EvidenceItemRead]],
    status_code=status.HTTP_200_OK,
    summary="Retrieve model integrity evidence items",
    description="Query and list all immutable evidence items synthesized for this model.",
)
async def list_model_evidence(
    project_id: str,
    model_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Retrieve all evidence records associated with model findings."""
    service = ModelIntegrityService(db=db, key_manager=key_manager)
    items = service.list_evidence(project_id=project_id, model_id=model_id)
    return ApiResponse(data=items)


# =====================================================================
# 7. Finding Retrieval
# =====================================================================

@router.get(
    "/{model_id}/findings",
    response_model=ApiResponse[List[FindingDetailRead]],
    status_code=status.HTTP_200_OK,
    summary="Retrieve model integrity findings",
    description="Query and list all findings synthesized for this model.",
)
async def list_model_findings(
    project_id: str,
    model_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Retrieve all findings synthesized for this model."""
    service = ModelIntegrityService(db=db, key_manager=key_manager)
    items = service.list_findings(project_id=project_id, model_id=model_id)
    return ApiResponse(data=items)


# =====================================================================
# 8. Provenance Verification
# =====================================================================

@router.get(
    "/{model_id}/provenance",
    response_model=ApiResponse[ModelProvenanceVerificationResponse],
    status_code=status.HTTP_200_OK,
    summary="Verify cryptographic provenance of model integrity findings",
    description=(
        "Perform Ed25519 signature and hash chain verification on the provenance ledger "
        "record bound to the model integrity commitments."
    ),
)
async def verify_model_provenance(
    project_id: str,
    model_id: str,
    db: Session = Depends(get_db),
    key_manager: KeyManager = Depends(get_key_manager),
):
    """Verify cryptographic provenance ledger sealing for the model."""
    service = ModelIntegrityService(db=db, key_manager=key_manager)
    res = service.verify_provenance(project_id=project_id, model_id=model_id)
    return ApiResponse(data=res)
