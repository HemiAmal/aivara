"""Tests for Deterministic Evidence and Execution Identity Hashing (Phase 5.9)."""

import pytest

from aivara.evidence.exceptions import (
    EvidenceIdentityError,
    ExecutionIdentityError,
    VocabularyViolationError,
)
from aivara.evidence.identity import (
    build_canonical_evidence_content,
    build_canonical_execution_payload,
    compute_evidence_hash,
    compute_execution_identity_hash,
    is_valid_evidence_hash,
)
from aivara.evidence.schemas import (
    EvidenceContent,
    EvidenceLayer,
    ExecutionIdentityPayload,
)
from aivara.evidence.validators import validate_finding_vocabulary


class TestEvidenceIdentity:
    """Tests for deterministic RFC 8785 + SHA-256 evidence hashing."""

    def test_deterministic_evidence_hash_identical_inputs(self):
        """Identical semantic evidence inputs must produce identical evidence_hash."""
        payload1 = {
            "evidence_layer": "detection",
            "evidence_type": "label_anomaly_score",
            "project_id": "proj-1234",
            "dataset_version_id": "ver-5678",
            "dataset_fingerprint": "a" * 64,
            "target_asset_type": "sample",
            "target_asset_id": "sample-9012",
            "target_asset_hash": "b" * 64,
            "detector_id": "die_label_anomaly",
            "detector_version": "1.0.0",
            "detector_config_hash": "c" * 64,
            "model_fingerprint": "d" * 64,
            "reference_fingerprint": "NONE",
            "measurements": {"margin": 0.42, "score": 0.88, "class_index": 3},
        }

        payload2 = dict(payload1)
        # Permute measurement key order (canonical RFC 8785 must normalize order)
        payload2["measurements"] = {"score": 0.88, "class_index": 3, "margin": 0.42}

        hash1 = compute_evidence_hash(payload1)
        hash2 = compute_evidence_hash(payload2)

        assert is_valid_evidence_hash(hash1)
        assert hash1 == hash2

    def test_semantic_mutation_produces_different_hash(self):
        """Any change in measurement or asset identity must produce a different evidence_hash."""
        base = {
            "evidence_layer": "detection",
            "evidence_type": "image_quality_metrics",
            "project_id": "proj-1234",
            "dataset_version_id": "ver-5678",
            "dataset_fingerprint": "a" * 64,
            "target_asset_type": "sample",
            "target_asset_id": "sample-9012",
            "target_asset_hash": "b" * 64,
            "detector_id": "die_ood_quality",
            "detector_version": "1.0.0",
            "detector_config_hash": "c" * 64,
            "measurements": {"sharpness": 14.2, "blur": 8.1},
        }

        h_base = compute_evidence_hash(base)

        # Mutate measurement
        mutated_meas = dict(base)
        mutated_meas["measurements"] = {"sharpness": 14.3, "blur": 8.1}
        assert compute_evidence_hash(mutated_meas) != h_base

        # Mutate target asset ID
        mutated_asset = dict(base)
        mutated_asset["target_asset_id"] = "sample-9013"
        assert compute_evidence_hash(mutated_asset) != h_base

        # Mutate detector version
        mutated_ver = dict(base)
        mutated_ver["detector_version"] = "1.0.1"
        assert compute_evidence_hash(mutated_ver) != h_base

    def test_non_deterministic_fields_excluded_from_hash(self):
        """Wall-clock timestamps, local paths, and database UUIDs must not alter the evidence_hash."""
        payload1 = {
            "id": "uuid-0001",
            "created_at": "2026-09-10T10:00:00Z",
            "artifact_path": "/tmp/local/path/image1.jpg",
            "evidence_layer": "detection",
            "evidence_type": "ood_distance_score",
            "project_id": "proj-1234",
            "dataset_version_id": "ver-5678",
            "dataset_fingerprint": "a" * 64,
            "target_asset_type": "sample",
            "target_asset_id": "sample-9012",
            "target_asset_hash": "b" * 64,
            "detector_id": "die_ood_quality",
            "detector_version": "1.0.0",
            "detector_config_hash": "c" * 64,
            "measurements": {"knn_distance": 4.82},
        }

        payload2 = dict(payload1)
        payload2["id"] = "uuid-9999"
        payload2["created_at"] = "2026-09-10T11:30:00Z"
        payload2["artifact_path"] = "C:\\different\\drive\\image1.jpg"

        assert compute_evidence_hash(payload1) == compute_evidence_hash(payload2)

    def test_order_sensitive_arrays_remain_order_sensitive(self):
        """Arrays representing sequences (such as bounding boxes or timeseries) must preserve order."""
        payload1 = {
            "evidence_layer": "detection",
            "evidence_type": "label_anomaly_score",
            "project_id": "proj-1234",
            "dataset_version_id": "ver-5678",
            "dataset_fingerprint": "a" * 64,
            "target_asset_type": "sample",
            "target_asset_id": "sample-9012",
            "target_asset_hash": "b" * 64,
            "detector_id": "die_label_anomaly",
            "detector_version": "1.0.0",
            "detector_config_hash": "c" * 64,
            "measurements": {"bbox": [10, 20, 100, 200]},
        }

        payload2 = dict(payload1)
        payload2["measurements"] = {"bbox": [20, 10, 100, 200]}

        assert compute_evidence_hash(payload1) != compute_evidence_hash(payload2)

    def test_nan_infinity_rejected_in_measurements(self):
        """Non-finite float values must be rejected during canonicalization."""
        payload = {
            "evidence_layer": "detection",
            "evidence_type": "image_quality_metrics",
            "project_id": "proj-1234",
            "dataset_version_id": "ver-5678",
            "dataset_fingerprint": "a" * 64,
            "target_asset_type": "sample",
            "target_asset_id": "sample-9012",
            "target_asset_hash": "b" * 64,
            "detector_id": "die_ood_quality",
            "detector_version": "1.0.0",
            "detector_config_hash": "c" * 64,
            "measurements": {"score": float("nan")},
        }

        with pytest.raises(EvidenceIdentityError, match="non-finite"):
            compute_evidence_hash(payload)


class TestExecutionIdentity:
    """Tests for structured execution identity and idempotency key computation."""

    def test_execution_identity_hash_determinism(self):
        """Identical execution payloads must yield identical ExecutionIdentityHash."""
        exec_payload1 = {
            "project_id": "proj-1234",
            "dataset_version_id": "ver-5678",
            "dataset_fingerprint": "a" * 64,
            "detector_id": "die_label_anomaly",
            "detector_version": "1.0.0",
            "engine_version": "1.0.0",
            "policy_version": "DEFAULT",
            "preprocessing_hash": "STANDARD_V1",
            "model_id": "model-1",
            "model_fingerprint": "d" * 64,
            "model_version": "2.0",
            "reference_dataset_id": "NONE",
            "reference_dataset_fingerprint": "NONE",
            "detector_config_hash": "e" * 64,
        }

        h1 = compute_execution_identity_hash(exec_payload1)
        h2 = compute_execution_identity_hash(exec_payload1)

        assert is_valid_evidence_hash(h1)
        assert h1 == h2

    def test_execution_identity_changes_on_any_result_altering_input(self):
        """If any parameter that can alter analytical output changes, ExecutionIdentityHash must change."""
        base = {
            "project_id": "proj-1234",
            "dataset_version_id": "ver-5678",
            "dataset_fingerprint": "a" * 64,
            "detector_id": "die_label_anomaly",
            "detector_version": "1.0.0",
            "engine_version": "1.0.0",
            "detector_config_hash": "e" * 64,
        }

        h_base = compute_execution_identity_hash(base)

        # 1. Changed dataset fingerprint
        p1 = dict(base, dataset_fingerprint="b" * 64)
        assert compute_execution_identity_hash(p1) != h_base

        # 2. Changed detector version
        p2 = dict(base, detector_version="1.0.1")
        assert compute_execution_identity_hash(p2) != h_base

        # 3. Changed engine version
        p3 = dict(base, engine_version="1.1.0")
        assert compute_execution_identity_hash(p3) != h_base

        # 4. Changed model fingerprint
        p4 = dict(base, model_fingerprint="f" * 64)
        assert compute_execution_identity_hash(p4) != h_base

        # 5. Changed reference dataset fingerprint
        p5 = dict(base, reference_dataset_fingerprint="1" * 64)
        assert compute_execution_identity_hash(p5) != h_base

        # 6. Changed config hash
        p6 = dict(base, detector_config_hash="2" * 64)
        assert compute_execution_identity_hash(p6) != h_base

        # 7. Changed policy version
        p7 = dict(base, policy_version="STRICT_V2")
        assert compute_execution_identity_hash(p7) != h_base

        # 8. Changed preprocessing hash
        p8 = dict(base, preprocessing_hash="3" * 64)
        assert compute_execution_identity_hash(p8) != h_base

    def test_optional_normalization_prevents_collisions(self):
        """Optional parameters normalized to NONE or STANDARD_V1 must be deterministic."""
        p_none = {
            "project_id": "proj-1234",
            "dataset_version_id": "ver-5678",
            "dataset_fingerprint": "a" * 64,
            "detector_id": "die_duplicates",
            "detector_version": "1.0.0",
            "engine_version": "1.0.0",
            "detector_config_hash": "e" * 64,
        }

        p_explicit = dict(p_none)
        p_explicit["model_id"] = "NONE"
        p_explicit["model_fingerprint"] = "NONE"
        p_explicit["reference_dataset_id"] = "NONE"
        p_explicit["policy_version"] = "DEFAULT"
        p_explicit["preprocessing_hash"] = "STANDARD_V1"

        assert compute_execution_identity_hash(p_none) == compute_execution_identity_hash(p_explicit)


class TestVocabularyValidation:
    """Tests for vocabulary policy enforcing objective statements and rejecting accusatory/culpability terms."""

    def test_prohibited_accusatory_intent_terms_rejected(self):
        """Forbidden intent, culpability, and accusatory terms must raise VocabularyViolationError."""
        forbidden_samples = [
            "Sample contains malicious perturbation attributed to contributor",
            "This contributor is guilty of bad actor behavior",
            "Detected intentional data manipulation",
            "Found deliberate fraud and sabotage by user",
            "Contributor acted dishonestly in bad faith",
            "Labels were maliciously flipped",
            "Demonstrated culpability and collusion",
        ]

        for text in forbidden_samples:
            with pytest.raises(VocabularyViolationError, match="Prohibited accusatory intent"):
                validate_finding_vocabulary(text, "finding_text")

    def test_legitimate_technical_security_terms_accepted(self):
        """Legitimate technical security detection terms must pass when descriptive and non-accusatory."""
        technical_samples = [
            "Potential backdoor trigger pattern detected in sample 123",
            "Data poisoning detection baseline evaluated for label distribution",
            "Adversarial perturbation detected with high L2 gradient norm",
            "Trojan watermark signature identified in feature space",
            "Red-team attack simulation baseline completed",
        ]

        for text in technical_samples:
            validate_finding_vocabulary(text, "finding_text")

    def test_backdoor_with_intent_accusation_rejected(self):
        """Technical terms combined with accusatory intent must be rejected."""
        accusatory_text = "Contributor deliberately inserted backdoor pattern"
        with pytest.raises(VocabularyViolationError, match="Prohibited accusatory intent"):
            validate_finding_vocabulary(accusatory_text, "finding_text")

    def test_objective_terms_accepted(self):
        """Objective, descriptive anomaly statements must pass validation."""
        allowed_samples = [
            "Elevated out-of-distribution distance observed in sample",
            "Possible label transition pattern detected for class 3 to 7",
            "High blur metric and low signal-to-noise ratio in image quality scan",
            "Near-duplicate visual relationship identified with Hamming distance 2",
            "Observed contributor-associated anomaly concentration",
        ]

        for text in allowed_samples:
            validate_finding_vocabulary(text, "finding_text")
