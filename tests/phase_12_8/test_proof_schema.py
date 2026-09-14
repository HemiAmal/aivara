"""Tests for Phase 12.8 Universal Proof Schemas and Immutability (REQ-12-PROOF-002, 004, 016)."""

import pytest
from pydantic import ValidationError

from aivara.domain.schemas import EvidenceLayer
from aivara.universal.enums import SubsystemDomain
from aivara.universal.proof.enums import (
    ProofCheckType,
    ProofSchemaVersion,
    ProofVerificationStatus,
)
from aivara.universal.proof.exceptions import ProofResourceLimitExceededError
from aivara.universal.proof.schemas import (
    ProofVerificationCheck,
    ProofVerificationResult,
    UniversalProofAssessment,
)


def test_valid_proof_verification_result():
    """ProofVerificationResult constructs cleanly with valid status, invariants, and hash."""
    check = ProofVerificationCheck(
        check_type=ProofCheckType.RECORD_HASH,
        passed=True,
        message="Record hash verified",
    )
    res = ProofVerificationResult(
        evidence_id="ev_001",
        evidence_hash="1" * 64,
        evidence_layer=EvidenceLayer.PROOF,
        proof_status=ProofVerificationStatus.VERIFIED,
        project_id="proj_alpha",
        asset_id="asset_beta",
        domain=SubsystemDomain.MODEL_INTEGRITY,
        checks=[check],
        proof_confidence=1.0,
    )
    assert res.schema_version == ProofSchemaVersion.V1_0.value
    assert res.proof_status == ProofVerificationStatus.VERIFIED
    assert res.proof_confidence == 1.0
    assert len(res.proof_result_hash) == 64


def test_proof_result_immutability():
    """ProofVerificationResult is frozen and cannot be mutated at runtime."""
    res = ProofVerificationResult(
        evidence_id="ev_001",
        evidence_hash="1" * 64,
        evidence_layer=EvidenceLayer.PROOF,
        proof_status=ProofVerificationStatus.VERIFIED,
        project_id="proj_alpha",
        asset_id="asset_beta",
    )
    with pytest.raises((ValidationError, TypeError)):
        res.evidence_id = "new_ev"  # type: ignore


def test_proof_confidence_invariant_enforcement():
    """Non-verified status can never have proof_confidence == 1.0."""
    res = ProofVerificationResult(
        evidence_id="ev_002",
        evidence_hash="2" * 64,
        evidence_layer=EvidenceLayer.PROOF,
        proof_status=ProofVerificationStatus.INVALID,
        project_id="proj_alpha",
        asset_id="asset_beta",
        proof_confidence=1.0,  # Invalid attempt to assign 1.0
    )
    # Validator must reset/clamp proof_confidence to 0.0 or None
    assert res.proof_confidence != 1.0


def test_universal_proof_assessment_schema():
    """UniversalProofAssessment constructs cleanly with aggregated metrics and hash."""
    res = ProofVerificationResult(
        evidence_id="ev_001",
        evidence_hash="1" * 64,
        evidence_layer=EvidenceLayer.PROOF,
        proof_status=ProofVerificationStatus.VERIFIED,
        project_id="proj_alpha",
        asset_id="asset_beta",
    )
    assessment = UniversalProofAssessment(
        project_id="proj_alpha",
        asset_id="asset_beta",
        overall_proof_status=ProofVerificationStatus.VERIFIED,
        total_evidence_evaluated=1,
        verified_count=1,
        evidence_results=[res],
    )
    assert assessment.schema_version == ProofSchemaVersion.V1_0.value
    assert len(assessment.assessment_hash) == 64
    assert assessment.proof_override_required is False


def test_evidence_limit_exceeded_rejected():
    """Exceeding MAX_EVIDENCE_PROOFS (5000) raises ProofResourceLimitExceededError."""
    res = ProofVerificationResult(
        evidence_id="ev_001",
        evidence_hash="1" * 64,
        evidence_layer=EvidenceLayer.PROOF,
        proof_status=ProofVerificationStatus.VERIFIED,
        project_id="proj_alpha",
        asset_id="asset_beta",
    )
    with pytest.raises(ProofResourceLimitExceededError):
        UniversalProofAssessment(
            project_id="proj_alpha",
            asset_id="asset_beta",
            overall_proof_status=ProofVerificationStatus.VERIFIED,
            evidence_results=[res] * 5001,
        )
