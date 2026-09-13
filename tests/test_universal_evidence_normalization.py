"""Comprehensive Test Suite for Phase 12.2: Universal Evidence Normalization & Adapters.

Validates:
- All 7 domain adapters (Dataset, Contributor, Model, Behavioral, Backdoor, Inference, Distribution Shift).
- Universal Evidence Envelope construction, hashing, and immutability.
- Strict RFC 8785 JCS determinism and SHA-256 content addressing.
- Hard resource safety ceilings ($E_{\\max} = 5,000$).
- Strict multi-tenant project isolation and boundary enforcement.
- Finite-float validation (rejection of NaN, +Inf, -Inf).
- Provenance and ancestry preservation without fabrication.
- Zero risk calculation or cross-domain correlation in normalization layer.
- 100% offline air-gap execution.
"""

import math
import socket
import pytest
from pydantic import BaseModel

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.adapters.base import BaseEvidenceAdapter
from aivara.universal.adapters.registry import AdapterRegistry, get_default_adapter_registry
from aivara.universal.adapters.dataset_adapter import DatasetIntegrityEvidenceAdapter
from aivara.universal.adapters.contributor_adapter import ContributorRiskEvidenceAdapter
from aivara.universal.adapters.model_adapter import ModelIntegrityEvidenceAdapter
from aivara.universal.adapters.behavioral_adapter import BehavioralAnalysisEvidenceAdapter
from aivara.universal.adapters.backdoor_adapter import BackdoorTriggerEvidenceAdapter
from aivara.universal.adapters.inference_adapter import InferenceIntegrityEvidenceAdapter
from aivara.universal.adapters.drift_adapter import DistributionShiftEvidenceAdapter
from aivara.universal.enums import AncestryStatus, SubsystemDomain
from aivara.universal.exceptions import (
    DuplicateAdapterError,
    InvalidEvidenceError,
    ProjectMismatchError,
    UniversalResourceLimitExceededError,
    UnknownDomainError,
)
from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.schemas import AncestryPath, UniversalEvidenceEnvelope


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def normalizer():
    return UniversalEvidenceNormalizer()


@pytest.fixture
def sample_dataset_evidence():
    return {
        "evidence_id": "ev_ds_001",
        "project_id": "proj_test_001",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "image_quality_metrics",
        "evidence_layer": "detection",
        "severity": "medium",
        "confidence": 0.95,
        "dataset_id": "ds_alpha",
        "sample_id": "sample_123",
        "dataset_version_id": "v1.0.0",
        "metrics": {"sharpness_score": 14.5, "noise_level": 0.02, "exposure_mean": 128.4},
        "finding_id": "find_ds_01",
        "provenance_record_id": "prov_ds_01",
        "provenance_hash": "a" * 64,
    }


@pytest.fixture
def sample_contributor_evidence():
    return {
        "evidence_id": "ev_cr_001",
        "project_id": "proj_test_001",
        "domain": "CONTRIBUTOR_RISK",
        "evidence_type": "contributor_anomaly_profile",
        "evidence_layer": "detection",
        "severity": "high",
        "confidence": 0.88,
        "contributor_id": "contrib_999",
        "dataset_version_id": "v1.0.0",
        "metrics": {"empirical_bayes_score": 0.72, "loo_divergence": 0.18},
    }


@pytest.fixture
def sample_model_evidence():
    return {
        "evidence_id": "ev_mi_001",
        "project_id": "proj_test_001",
        "domain": "MODEL_INTEGRITY",
        "evidence_type": "model_weight_hash_merkle",
        "evidence_layer": "proof",
        "severity": "critical",
        "confidence": 1.0,
        "model_id": "model_resnet50",
        "model_fingerprint": "f" * 64,
        "payload": {"layer_count": 50, "quantization_valid": True},
    }


@pytest.fixture
def sample_behavioral_evidence():
    return {
        "evidence_id": "ev_ba_001",
        "project_id": "proj_test_001",
        "domain": "BEHAVIORAL_ANALYSIS",
        "evidence_type": "output_stability_metric",
        "evidence_layer": "detection",
        "severity": "low",
        "confidence": 0.92,
        "model_id": "model_resnet50",
        "model_fingerprint": "f" * 64,
        "baseline_run_id": "run_base_001",
        "stability_metrics": {"prediction_flip_rate": 0.04, "mean_divergence": 0.012},
    }


@pytest.fixture
def sample_backdoor_evidence():
    return {
        "evidence_id": "ev_bd_001",
        "project_id": "proj_test_001",
        "domain": "BACKDOOR_TRIGGER",
        "evidence_type": "patch_trigger_activation",
        "evidence_layer": "detection",
        "severity": "high",
        "confidence": 0.85,
        "model_id": "model_resnet50",
        "dataset_version_id": "v1.0.0",
        "trigger_payload": {"activation_delta": 0.45, "target_class": 3},
    }


@pytest.fixture
def sample_inference_evidence():
    return {
        "evidence_id": "ev_inf_001",
        "project_id": "proj_test_001",
        "domain": "INFERENCE_INTEGRITY",
        "evidence_type": "18_checkpoint_verification",
        "evidence_layer": "proof",
        "severity": "info",
        "confidence": 1.0,
        "inference_id": "inf_rec_999",
        "model_id": "model_resnet50",
        "input_hash": "b" * 64,
        "verification_results": {"all_proofs_valid": True, "replay_exact": True},
    }


@pytest.fixture
def sample_drift_evidence():
    return {
        "evidence_id": "ev_dr_001",
        "project_id": "proj_test_001",
        "domain": "DISTRIBUTION_SHIFT",
        "evidence_type": "feature_dataset_drift",
        "evidence_layer": "detection",
        "severity": "medium",
        "confidence": 0.94,
        "target_asset_id": "ds_alpha_target",
        "dataset_version_id": "v1.0.0",
        "window_id": "w_2026_q3",
        "metrics": {"ks_p_value": 0.002, "psi_score": 0.18, "shift_detected": True},
    }


# =====================================================================
# Tests: Registry & Domain Adapters
# =====================================================================

def test_default_registry_has_exact_seven_domains():
    """Verify registry contains exactly the 7 frozen upstream assurance domains."""
    registry = get_default_adapter_registry()
    assert registry.count() == 7
    domains = registry.list_registered_domains()
    assert len(domains) == 7
    expected = [
        SubsystemDomain.DATASET_INTEGRITY,
        SubsystemDomain.CONTRIBUTOR_RISK,
        SubsystemDomain.MODEL_INTEGRITY,
        SubsystemDomain.BEHAVIORAL_ANALYSIS,
        SubsystemDomain.BACKDOOR_TRIGGER,
        SubsystemDomain.INFERENCE_INTEGRITY,
        SubsystemDomain.DISTRIBUTION_SHIFT,
    ]
    assert domains == expected


def test_registry_rejects_duplicate_registration():
    """Verify registry rejects duplicate adapter registration."""
    registry = AdapterRegistry()
    registry.register(DatasetIntegrityEvidenceAdapter())
    with pytest.raises(DuplicateAdapterError):
        registry.register(DatasetIntegrityEvidenceAdapter())


def test_registry_rejects_unknown_domain():
    """Verify registry raises UnknownDomainError for invalid or unregistered domain."""
    registry = AdapterRegistry()
    with pytest.raises(UnknownDomainError):
        registry.get_adapter(SubsystemDomain.DATASET_INTEGRITY)


# =====================================================================
# Tests: All Seven Adapters Normalization
# =====================================================================

def test_normalize_dataset_integrity(normalizer, sample_dataset_evidence):
    env = normalizer.normalize_single(sample_dataset_evidence, project_id="proj_test_001")
    assert isinstance(env, UniversalEvidenceEnvelope)
    assert env.domain == SubsystemDomain.DATASET_INTEGRITY
    assert env.evidence_type == "image_quality_metrics"
    assert env.evidence_layer == EvidenceLayer.DETECTION
    assert env.severity == Severity.MEDIUM
    assert env.confidence == 0.95
    assert env.primary_asset_id == "ds_alpha"
    assert env.ancestry_path.sample_id == "sample_123"
    assert env.ancestry_path.dataset_version_id == "v1.0.0"
    assert env.ancestry_status == AncestryStatus.VERIFIED
    assert env.finding_id == "find_ds_01"
    assert len(env.canonical_hash) == 64


def test_normalize_contributor_risk(normalizer, sample_contributor_evidence):
    env = normalizer.normalize_single(sample_contributor_evidence, project_id="proj_test_001")
    assert env.domain == SubsystemDomain.CONTRIBUTOR_RISK
    assert env.primary_asset_id == "contrib_999"
    assert env.ancestry_path.source_id == "contrib_999"
    assert env.ancestry_path.dataset_version_id == "v1.0.0"
    assert env.ancestry_status == AncestryStatus.VERIFIED
    assert len(env.canonical_hash) == 64


def test_normalize_model_integrity(normalizer, sample_model_evidence):
    env = normalizer.normalize_single(sample_model_evidence, project_id="proj_test_001")
    assert env.domain == SubsystemDomain.MODEL_INTEGRITY
    assert env.evidence_layer == EvidenceLayer.PROOF
    assert env.confidence == 1.0
    assert env.primary_asset_id == "model_resnet50"
    assert env.ancestry_path.model_fingerprint == "f" * 64
    assert env.ancestry_status == AncestryStatus.VERIFIED
    assert len(env.canonical_hash) == 64


def test_normalize_behavioral_analysis(normalizer, sample_behavioral_evidence):
    env = normalizer.normalize_single(sample_behavioral_evidence, project_id="proj_test_001")
    assert env.domain == SubsystemDomain.BEHAVIORAL_ANALYSIS
    assert env.primary_asset_id == "model_resnet50"
    assert env.ancestry_path.model_fingerprint == "f" * 64
    assert env.ancestry_path.window_id == "run_base_001"
    assert len(env.canonical_hash) == 64


def test_normalize_backdoor_trigger(normalizer, sample_backdoor_evidence):
    env = normalizer.normalize_single(sample_backdoor_evidence, project_id="proj_test_001")
    assert env.domain == SubsystemDomain.BACKDOOR_TRIGGER
    assert env.primary_asset_id == "model_resnet50"
    assert env.ancestry_path.dataset_version_id == "v1.0.0"
    assert len(env.canonical_hash) == 64


def test_normalize_inference_integrity(normalizer, sample_inference_evidence):
    env = normalizer.normalize_single(sample_inference_evidence, project_id="proj_test_001")
    assert env.domain == SubsystemDomain.INFERENCE_INTEGRITY
    assert env.evidence_layer == EvidenceLayer.PROOF
    assert env.confidence == 1.0
    assert env.primary_asset_id == "inf_rec_999"
    assert env.ancestry_path.sample_id == "b" * 64
    assert len(env.canonical_hash) == 64


def test_normalize_distribution_shift(normalizer, sample_drift_evidence):
    env = normalizer.normalize_single(sample_drift_evidence, project_id="proj_test_001")
    assert env.domain == SubsystemDomain.DISTRIBUTION_SHIFT
    assert env.primary_asset_id == "ds_alpha_target"
    assert env.ancestry_path.dataset_version_id == "v1.0.0"
    assert env.ancestry_path.window_id == "w_2026_q3"
    assert len(env.canonical_hash) == 64


# =====================================================================
# Tests: Security, Project Isolation & Boundary Validation
# =====================================================================

def test_project_mismatch_rejected(normalizer, sample_dataset_evidence):
    """Verify evidence claiming project A is rejected when ingested into project B."""
    with pytest.raises(ProjectMismatchError):
        normalizer.normalize_single(sample_dataset_evidence, project_id="proj_tenant_OTHER")


def test_missing_project_id_rejected(normalizer, sample_dataset_evidence):
    """Verify empty target project_id fails closed."""
    with pytest.raises(ProjectMismatchError):
        normalizer.normalize_single(sample_dataset_evidence, project_id="")


def test_nan_float_rejected(normalizer, sample_dataset_evidence):
    """Verify NaN float values are strictly rejected."""
    bad_evidence = dict(sample_dataset_evidence)
    bad_evidence["metrics"] = {"sharpness": float("nan")}
    with pytest.raises(InvalidEvidenceError):
        normalizer.normalize_single(bad_evidence, project_id="proj_test_001")


def test_inf_float_rejected(normalizer, sample_dataset_evidence):
    """Verify Infinity float values are strictly rejected."""
    bad_evidence = dict(sample_dataset_evidence)
    bad_evidence["metrics"] = {"noise": float("inf")}
    with pytest.raises(InvalidEvidenceError):
        normalizer.normalize_single(bad_evidence, project_id="proj_test_001")


def test_negative_inf_float_rejected(normalizer, sample_dataset_evidence):
    """Verify -Infinity float values are strictly rejected."""
    bad_evidence = dict(sample_dataset_evidence)
    bad_evidence["metrics"] = {"noise": float("-inf")}
    with pytest.raises(InvalidEvidenceError):
        normalizer.normalize_single(bad_evidence, project_id="proj_test_001")


def test_proof_layer_requires_exact_1_0_confidence(normalizer, sample_model_evidence):
    """Verify Proof layer evidence rejects confidence != 1.0."""
    bad_proof = dict(sample_model_evidence)
    bad_proof["confidence"] = 0.99
    with pytest.raises(InvalidEvidenceError):
        normalizer.normalize_single(bad_proof, project_id="proj_test_001")


# =====================================================================
# Tests: Missing Ancestry Fail-Safe Behavior
# =====================================================================

def test_missing_ancestry_marked_unverified(normalizer):
    """Verify missing ancestry sets ancestry_status = UNVERIFIED without failing."""
    raw = {
        "evidence_id": "ev_no_anc",
        "project_id": "proj_test_001",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "quality",
        "metrics": {"sharpness": 12.0},
    }
    env = normalizer.normalize_single(raw, project_id="proj_test_001")
    assert env.ancestry_status == AncestryStatus.UNVERIFIED
    assert env.ancestry_path.is_empty() is True


# =====================================================================
# Tests: Batch Normalization, Deduplication & Resource Limits
# =====================================================================

def test_batch_normalization_all_domains(
    normalizer,
    sample_dataset_evidence,
    sample_contributor_evidence,
    sample_model_evidence,
    sample_behavioral_evidence,
    sample_backdoor_evidence,
    sample_inference_evidence,
    sample_drift_evidence,
):
    """Verify batch normalization across all 7 domains produces deterministic report."""
    batch = [
        sample_dataset_evidence,
        sample_contributor_evidence,
        sample_model_evidence,
        sample_behavioral_evidence,
        sample_backdoor_evidence,
        sample_inference_evidence,
        sample_drift_evidence,
    ]
    report = normalizer.normalize_batch(batch, project_id="proj_test_001")
    assert report.total_ingested == 7
    assert report.total_normalized == 7
    assert report.total_deduplicated == 0
    assert report.total_rejected == 0
    assert len(report.domain_breakdown) == 7
    assert len(report.envelopes) == 7
    assert len(report.report_hash) == 64


def test_batch_deduplication_via_canonical_hash(normalizer, sample_dataset_evidence):
    """Verify duplicate evidence items are identified and deduplicated."""
    batch = [sample_dataset_evidence, sample_dataset_evidence, sample_dataset_evidence]
    report = normalizer.normalize_batch(batch, project_id="proj_test_001")
    assert report.total_ingested == 3
    assert report.total_normalized == 1
    assert report.total_deduplicated == 2
    assert report.total_rejected == 0


def test_batch_with_rejections_and_successes(normalizer, sample_dataset_evidence):
    """Verify batch normalization segregates valid and invalid items cleanly."""
    valid = sample_dataset_evidence
    invalid_nan = dict(sample_dataset_evidence)
    invalid_nan["evidence_id"] = "ev_bad"
    invalid_nan["metrics"] = {"score": float("nan")}
    
    report = normalizer.normalize_batch([valid, invalid_nan], project_id="proj_test_001")
    assert report.total_ingested == 2
    assert report.total_normalized == 1
    assert report.total_rejected == 1
    assert len(report.rejection_reasons) == 1


def test_hard_resource_ceiling_enforcement(normalizer, sample_dataset_evidence):
    """Verify ingesting > 5000 items triggers UniversalResourceLimitExceededError."""
    huge_batch = [sample_dataset_evidence] * 5001
    with pytest.raises(UniversalResourceLimitExceededError):
        normalizer.normalize_batch(huge_batch, project_id="proj_test_001")


# =====================================================================
# Tests: Determinism & Hash Avalanche
# =====================================================================

def test_deterministic_canonical_hashing(normalizer, sample_dataset_evidence):
    """Verify 5 independent normalization runs on identical input yield bit-for-bit identical hashes."""
    hashes = []
    for _ in range(5):
        env = normalizer.normalize_single(sample_dataset_evidence, project_id="proj_test_001")
        hashes.append(env.canonical_hash)
    assert len(set(hashes)) == 1


def test_hash_avalanche_on_metric_mutation(normalizer, sample_dataset_evidence):
    """Verify single-bit change in metric payload creates distinct canonical hash."""
    env1 = normalizer.normalize_single(sample_dataset_evidence, project_id="proj_test_001")
    
    mutated = dict(sample_dataset_evidence)
    mutated["metrics"] = dict(sample_dataset_evidence["metrics"])
    mutated["metrics"]["sharpness_score"] = 14.50001
    env2 = normalizer.normalize_single(mutated, project_id="proj_test_001")
    
    assert env1.canonical_hash != env2.canonical_hash


def test_field_order_invariance(normalizer):
    """Verify permutation of dictionary keys produces identical canonical hash."""
    doc1 = {
        "evidence_id": "ev_01",
        "project_id": "p_01",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "quality",
        "confidence": 0.90,
        "metrics": {"a": 1, "b": 2},
    }
    doc2 = {
        "metrics": {"b": 2, "a": 1},
        "confidence": 0.90,
        "evidence_type": "quality",
        "domain": "DATASET_INTEGRITY",
        "project_id": "p_01",
        "evidence_id": "ev_01",
    }
    env1 = normalizer.normalize_single(doc1, project_id="p_01")
    env2 = normalizer.normalize_single(doc2, project_id="p_01")
    assert env1.canonical_hash == env2.canonical_hash


# =====================================================================
# Tests: Offline Air-Gap & Isolation
# =====================================================================

# =====================================================================
# Tests: RFC 8785 JCS Conformance (AUDIT BLOCKER 1)
# =====================================================================

def test_rfc8785_dict_key_insertion_order():
    """Verify dictionary keys in different insertion order produce exact identical JCS bytes."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d1 = {"z": 1, "a": 2, "m": 3}
    d2 = {"a": 2, "m": 3, "z": 1}
    d3 = {"m": 3, "z": 1, "a": 2}
    b1 = compute_canonical_jcs_bytes(d1)
    b2 = compute_canonical_jcs_bytes(d2)
    b3 = compute_canonical_jcs_bytes(d3)
    assert b1 == b2 == b3
    assert b1 == b'{"a":2,"m":3,"z":1}'


def test_rfc8785_nested_dictionaries():
    """Verify nested dictionaries are recursively ordered lexicographically."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d1 = {"parent": {"beta": 2, "alpha": 1}, "status": "ok"}
    d2 = {"status": "ok", "parent": {"alpha": 1, "beta": 2}}
    b1 = compute_canonical_jcs_bytes(d1)
    b2 = compute_canonical_jcs_bytes(d2)
    assert b1 == b2
    assert b1 == b'{"parent":{"alpha":1,"beta":2},"status":"ok"}'


def test_rfc8785_array_order_preservation():
    """Verify array element order is strictly preserved as semantically significant."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d1 = {"arr": [3, 1, 2]}
    d2 = {"arr": [1, 2, 3]}
    b1 = compute_canonical_jcs_bytes(d1)
    b2 = compute_canonical_jcs_bytes(d2)
    assert b1 != b2
    assert b1 == b'{"arr":[3,1,2]}'
    assert b2 == b'{"arr":[1,2,3]}'


def test_rfc8785_unicode_strings():
    """Verify Unicode strings are encoded directly as UTF-8 without unnecessary escapes."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d = {"greeting": "こんにちは", "accents": "café", "emoji": "🛡️"}
    b = compute_canonical_jcs_bytes(d)
    assert "café".encode("utf-8") in b
    assert "こんにちは".encode("utf-8") in b


def test_rfc8785_escaped_control_characters():
    """Verify only required RFC 8785 control characters and escapes are escaped."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d = {"escapes": "line1\nline2\ttab\"quote\\slash"}
    b = compute_canonical_jcs_bytes(d)
    assert b'\\n' in b
    assert b'\\t' in b
    assert b'\\"' in b
    assert b'\\\\' in b


def test_rfc8785_integers_and_safe_domain():
    """Verify integers within IEEE 754 safe domain are formatted cleanly."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d = {"zero": 0, "pos": 42, "neg": -100, "max_safe": 9007199254740991}
    b = compute_canonical_jcs_bytes(d)
    assert b'{"max_safe":9007199254740991,"neg":-100,"pos":42,"zero":0}' == b


def test_rfc8785_positive_and_negative_floats():
    """Verify finite float formatting conforms to ECMA 262."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d = {"pi": 3.14159, "neg_val": -0.5}
    b = compute_canonical_jcs_bytes(d)
    assert b'{"neg_val":-0.5,"pi":3.14159}' == b


def test_rfc8785_zero_and_negative_zero_normalization():
    """Verify -0.0 is normalized to 0 per RFC 8785."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d_pos = {"val": 0.0}
    d_neg = {"val": -0.0}
    b_pos = compute_canonical_jcs_bytes(d_pos)
    b_neg = compute_canonical_jcs_bytes(d_neg)
    assert b_pos == b'{"val":0}'
    assert b_neg == b'{"val":0}'
    assert b_pos == b_neg


def test_rfc8785_scientific_notation_and_ecma262_numbers():
    """Verify scientific notation representation follows canonical JCS format."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d = {"small": 1e-7, "large": 1e21}
    b = compute_canonical_jcs_bytes(d)
    assert b == b'{"large":1e+21,"small":1e-7}'



def test_rfc8785_nan_rejection():
    """Verify NaN is strictly rejected in canonical hashing."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    with pytest.raises(InvalidEvidenceError):
        compute_canonical_jcs_bytes({"val": float("nan")})


def test_rfc8785_positive_inf_rejection():
    """Verify +Inf is strictly rejected in canonical hashing."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    with pytest.raises(InvalidEvidenceError):
        compute_canonical_jcs_bytes({"val": float("inf")})


def test_rfc8785_negative_inf_rejection():
    """Verify -Inf is strictly rejected in canonical hashing."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    with pytest.raises(InvalidEvidenceError):
        compute_canonical_jcs_bytes({"val": float("-inf")})


def test_rfc8785_exact_repeated_canonical_bytes():
    """Verify 100 repeated runs produce the exact same byte stream."""
    from aivara.universal.hashing import compute_canonical_jcs_bytes
    d = {"k1": "v1", "k2": [1, 2, 3], "k3": {"nested": 42.5}}
    b_initial = compute_canonical_jcs_bytes(d)
    for _ in range(100):
        assert compute_canonical_jcs_bytes(d) == b_initial


# =====================================================================
# Tests: Source Payload Hash Verification (AUDIT BLOCKER 2)
# =====================================================================

def test_source_hash_correct_supplied_verified(normalizer, sample_dataset_evidence):
    """Verify correct supplied source payload hash matches and is accepted."""
    from aivara.universal.hashing import compute_payload_hash
    raw = dict(sample_dataset_evidence)
    # Build exact matching source hash
    expected_data = raw["metrics"]
    raw["source_payload_hash"] = compute_payload_hash(expected_data)
    env = normalizer.normalize_single(raw, project_id="proj_test_001")
    assert env.source_payload_hash == raw["source_payload_hash"]


def test_source_hash_incorrect_supplied_fails_closed(normalizer, sample_dataset_evidence):
    """Verify forged/mismatched supplied source payload hash is rejected fail-closed."""
    from aivara.universal.exceptions import SourceHashMismatchError
    raw = dict(sample_dataset_evidence)
    raw["source_payload_hash"] = "e" * 64  # incorrect digest
    with pytest.raises(SourceHashMismatchError):
        normalizer.normalize_single(raw, project_id="proj_test_001")


def test_source_hash_missing_supplied_recomputed(normalizer, sample_dataset_evidence):
    """Verify missing source_payload_hash is automatically derived from authoritative source."""
    raw = dict(sample_dataset_evidence)
    raw.pop("source_payload_hash", None)
    env = normalizer.normalize_single(raw, project_id="proj_test_001")
    assert len(env.source_payload_hash) == 64
    assert env.source_payload_hash == env.normalized_payload_hash


def test_source_hash_raw_bytes_verification(normalizer, sample_dataset_evidence):
    """Verify source_payload_hash verification against raw_bytes in context."""
    import hashlib
    from aivara.universal.exceptions import SourceHashMismatchError
    raw = dict(sample_dataset_evidence)
    raw_binary = b"raw_image_data_bytes_12345"
    correct_hash = hashlib.sha256(raw_binary).hexdigest()
    raw["source_payload_hash"] = correct_hash
    
    # Success on matching raw_bytes
    env = normalizer.normalize_single(raw, project_id="proj_test_001", context={"raw_bytes": raw_binary})
    assert env.source_payload_hash == correct_hash

    # Fail closed on mismatching raw_bytes
    with pytest.raises(SourceHashMismatchError):
        normalizer.normalize_single(raw, project_id="proj_test_001", context={"raw_bytes": b"corrupted_bytes"})


def test_hashes_distinct_source_vs_normalized_vs_envelope(normalizer, sample_dataset_evidence):
    """Verify source_payload_hash, normalized_payload_hash, and canonical_hash are distinct concepts."""
    env = normalizer.normalize_single(sample_dataset_evidence, project_id="proj_test_001")
    assert len(env.source_payload_hash) == 64
    assert len(env.normalized_payload_hash) == 64
    assert len(env.canonical_hash) == 64
    assert env.canonical_hash != env.normalized_payload_hash


# =====================================================================
# Tests: Confidence Semantics & Provenance (AUDIT BLOCKER 3 & 6)
# =====================================================================

def test_confidence_detection_layer_preserved(normalizer, sample_dataset_evidence):
    """Verify detection layer confidence (e.g. 0.82) is preserved without forced 1.0."""
    raw = dict(sample_dataset_evidence)
    raw["confidence"] = 0.82
    env = normalizer.normalize_single(raw, project_id="proj_test_001")
    assert env.confidence == 0.82


def test_confidence_proof_layer_requires_1_0(normalizer, sample_model_evidence):
    """Verify proof layer evidence strictly requires confidence == 1.0."""
    from aivara.universal.exceptions import InvalidEvidenceError
    raw = dict(sample_model_evidence)
    raw["confidence"] = 0.95  # not 1.0 on proof layer
    with pytest.raises(InvalidEvidenceError):
        normalizer.normalize_single(raw, project_id="proj_test_001")


def test_confidence_missing_detection_is_none(normalizer):
    """Verify missing confidence on non-proof evidence remains None (not fabricated)."""
    raw = {
        "evidence_id": "ev_no_conf",
        "project_id": "proj_test_001",
        "domain": "DATASET_INTEGRITY",
        "evidence_type": "quality",
        "evidence_layer": "detection",
        "metrics": {"sharpness": 10.0},
    }
    env = normalizer.normalize_single(raw, project_id="proj_test_001")
    assert env.confidence is None


def test_confidence_out_of_range_rejected(normalizer, sample_dataset_evidence):
    """Verify confidence < 0.0 or > 1.0 is rejected."""
    from aivara.universal.exceptions import InvalidEvidenceError
    bad_low = dict(sample_dataset_evidence, confidence=-0.1)
    bad_high = dict(sample_dataset_evidence, confidence=1.05)
    with pytest.raises(InvalidEvidenceError):
        normalizer.normalize_single(bad_low, project_id="proj_test_001")
    with pytest.raises(InvalidEvidenceError):
        normalizer.normalize_single(bad_high, project_id="proj_test_001")


def test_provenance_valid_hex_accepted(normalizer, sample_dataset_evidence):
    """Verify valid 64-character SHA-256 provenance hash is accepted and preserved."""
    raw = dict(sample_dataset_evidence)
    raw["provenance_hashes"] = ["1" * 64, "2" * 64]
    env = normalizer.normalize_single(raw, project_id="proj_test_001")
    assert env.provenance_hashes == ["1" * 64, "2" * 64]


def test_provenance_invalid_hex_rejected(normalizer, sample_dataset_evidence):
    """Verify malformed provenance hash triggers validation error."""
    from aivara.universal.exceptions import InvalidEvidenceError
    raw = dict(sample_dataset_evidence)
    raw["provenance_hashes"] = ["not_a_valid_hex_string"]
    with pytest.raises(InvalidEvidenceError):
        normalizer.normalize_single(raw, project_id="proj_test_001")


def test_stable_evidence_id_deterministic(normalizer, sample_dataset_evidence):
    """Verify stable evidence identity remains distinct from envelope canonical hash."""
    env1 = normalizer.normalize_single(sample_dataset_evidence, project_id="proj_test_001")
    env2 = normalizer.normalize_single(sample_dataset_evidence, project_id="proj_test_001")
    assert env1.evidence_id == env2.evidence_id
    assert env1.canonical_hash == env2.canonical_hash
    assert env1.evidence_id != env1.canonical_hash


def test_100_percent_offline_no_sockets(normalizer, sample_dataset_evidence, monkeypatch):
    """Verify normalization executes 100% offline without opening network sockets."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("Air-gap violation: socket creation attempt blocked.")

    monkeypatch.setattr(socket, "socket", guarded_socket)
    env = normalizer.normalize_single(sample_dataset_evidence, project_id="proj_test_001")
    assert env.canonical_hash is not None


def test_no_upstream_mutation(normalizer, sample_dataset_evidence):
    """Verify normalization does not mutate input dictionary."""
    import copy
    original = copy.deepcopy(sample_dataset_evidence)
    _ = normalizer.normalize_single(sample_dataset_evidence, project_id="proj_test_001")
    assert sample_dataset_evidence == original


