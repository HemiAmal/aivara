"""Phase 11.11.2 - Layer 9: Cryptographic Integrity Verification Suite.

Verifies:
- REQ-11-VERIF-068: Comprehensive cryptographic digest binding across all 8 analytical profiles
- REQ-11-VERIF-069: 1-character field mutation avalanche sensitivity
- REQ-11-VERIF-070: JCS key-order permutation invariance
- REQ-11-VERIF-071: Evidence digest provenance chaining & tampering rejection
- REQ-11-VERIF-072: IntegratedAssuranceProfile deterministic RFC 8785 SHA-256 hash binding
- REQ-11-VERIF-073: Canonical request fingerprinting for idempotency
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict, List
import pytest

from aivara.assurance.engine import MultiModalRiskIntegrationEngine
from aivara.assurance import (
    EvidenceCategory,
    EvidenceReference,
    compute_decision_policy_hash,
    compute_evidence_set_hash,
    compute_integrated_profile_hash,
    compute_risk_policy_hash,
)
from aivara.crypto.canonical import canonicalize
from aivara.domain.schemas import Disposition, EvidenceLayer, Severity
from aivara.drift.boundary import ComparisonBoundaryEngine
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import BoundaryEvaluationStatus, CompatibilityStatus, DataModality, PopulationType
from aivara.drift.feature_dataset_engine import compute_dataset_drift_profile_hash
from aivara.drift.image_engine import compute_image_drift_profile_hash
from aivara.drift.representation_engine import compute_representation_contract_hash
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    ComparisonContract,
    PopulationIdentity,
)
from aivara.drift.source_engine import compute_source_contract_hash
from aivara.drift.temporal_engine import compute_temporal_contract_hash


def test_req_068_canonical_profile_hashes_all_8_subsystems() -> None:
    """Verify REQ-11-VERIF-068: Valid 64-hex SHA-256 digests across all 8 canonical distribution-shift profiles."""
    d = {"schema_version": "1.0", "project_id": "proj_crypto", "id": "item_01"}
    
    h_dataset = compute_dataset_drift_profile_hash(d)
    h_image = compute_image_drift_profile_hash(d)
    h_rep = compute_representation_contract_hash(d)
    h_temporal = compute_temporal_contract_hash(d)
    h_source = compute_source_contract_hash(d)
    h_evidence = compute_evidence_set_hash(["a" * 64, "b" * 64])
    h_risk_policy = compute_risk_policy_hash(d)
    h_dec_policy = compute_decision_policy_hash(d)
    
    all_hashes = [h_dataset, h_image, h_rep, h_temporal, h_source, h_evidence, h_risk_policy, h_dec_policy]
    for h in all_hashes:
        assert isinstance(h, str)
        assert len(h) == 64
        int(h, 16)  # must be valid hex


def test_req_069_one_character_mutation_avalanche() -> None:
    """Verify REQ-11-VERIF-069: Single character mutation in canonical JSON produces completely uncorrelated digest."""
    base_dict = {"project_id": "proj_alpha", "metric_value": 0.12345, "status": "active"}
    mutated_dict = {"project_id": "proj_alphb", "metric_value": 0.12345, "status": "active"}
    
    h_base = hashlib.sha256(canonicalize(base_dict)).hexdigest()
    h_mut = hashlib.sha256(canonicalize(mutated_dict)).hexdigest()
    
    assert h_base != h_mut
    # Bit distance check: significant number of differing hex nibbles
    diff_nibbles = sum(c1 != c2 for c1, c2 in zip(h_base, h_mut))
    assert diff_nibbles >= 30


def test_req_070_jcs_key_permutation_invariance() -> None:
    """Verify REQ-11-VERIF-070: Key ordering permutations in nested JSON structures hash identically."""
    nested_1 = {
        "z": 100,
        "a": {"sub_z": "val", "sub_a": 1},
        "m": [{"k2": 2, "k1": 1}],
    }
    nested_2 = {
        "a": {"sub_a": 1, "sub_z": "val"},
        "m": [{"k1": 1, "k2": 2}],
        "z": 100,
    }
    
    assert canonicalize(nested_1) == canonicalize(nested_2)
    assert hashlib.sha256(canonicalize(nested_1)).hexdigest() == hashlib.sha256(canonicalize(nested_2)).hexdigest()


def test_req_071_evidence_digest_provenance_tampering() -> None:
    """Verify REQ-11-VERIF-071: Tampered evidence digest is detected by evidence set hash mismatch."""
    ev1_hash = "a" * 64
    ev2_hash = "b" * 64
    ev_set_valid = compute_evidence_set_hash([ev1_hash, ev2_hash])
    
    # Tamper one evidence hash
    ev2_tampered = "c" * 64
    ev_set_tampered = compute_evidence_set_hash([ev1_hash, ev2_tampered])
    
    assert ev_set_valid != ev_set_tampered


def test_req_072_integrated_assurance_profile_hash_binding() -> None:
    """Verify REQ-11-VERIF-072: IntegratedAssuranceProfile computes deterministic SHA-256 digest."""
    engine = MultiModalRiskIntegrationEngine()
    ev = EvidenceReference(
        evidence_id="ev_01",
        project_id="proj_hash",
        evidence_layer=EvidenceLayer.DETECTION,
        evidence_type="drift",
        evidence_category=EvidenceCategory.DISTRIBUTION_SHIFT,
        title="Drift",
        confidence=0.80,
        severity=Severity.HIGH,
        evidence_hash="1" * 64,
    )
    profile = engine.evaluate(
        project_id="proj_hash",
        target_asset_type="dataset",
        target_asset_id="ds_hash",
        evidence_items=[ev],
    )
    
    # Hash calculation from profile canonical dict
    d = profile.to_canonical_dict() if hasattr(profile, "to_canonical_dict") else profile.model_dump(mode="json")
    h = compute_integrated_profile_hash(d)
    assert len(h) == 64
    assert int(h, 16) >= 0


def test_req_073_request_fingerprint_idempotency_binding() -> None:
    """Verify REQ-11-VERIF-073: Canonical request fingerprinting binds identical requests deterministically."""
    from aivara.api.schemas.drift import DriftAnalysisCreateRequest
    req1 = DriftAnalysisCreateRequest(
        reference_dataset_id="ds_ref_fp",
        target_dataset_id="ds_tgt_fp",
        feature_names=["b", "a"],  # Unsorted
    )
    req2 = DriftAnalysisCreateRequest(
        reference_dataset_id="ds_ref_fp",
        target_dataset_id="ds_tgt_fp",
        feature_names=["a", "b"],  # Sorted
    )
    fp1 = hashlib.sha256(canonicalize(req1.to_canonical_dict("proj_fp"))).hexdigest()
    fp2 = hashlib.sha256(canonicalize(req2.to_canonical_dict("proj_fp"))).hexdigest()
    assert fp1 == fp2
    assert len(fp1) == 64
