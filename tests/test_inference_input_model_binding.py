"""Comprehensive Test Suite for Phase 10.3: Input / Model Binding."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pytest

from aivara.crypto.canonical import canonicalize
from aivara.inference.binding import (
    BindingVerificationResult,
    InputModelBinding,
    ModelIdentityEnvelope,
    build_canonical_binding_descriptor,
    compute_binding_hash,
    create_input_model_binding,
    validate_sha256_hex_format,
    verify_input_model_binding,
    verify_master_fingerprint_consistency,
)
from aivara.inference.enums import (
    InferenceFindingCode,
    InferenceIntegrityStatus,
    InputKind,
    InputLayout,
)
from aivara.inference.exceptions import (
    BindingError,
    BindingInconsistencyError,
    InferenceInputError,
    InvalidHashFormatError,
    ModelIntegrityBindingError,
    ProjectMismatchError,
)
from aivara.inference.input import validate_inference_input
from aivara.inference.input.models import InputIdentity
from aivara.model_integrity.fingerprinting.schemas import HierarchicalFingerprintResult


# =====================================================================
# Fixtures & Helper Functions
# =====================================================================

def make_valid_master_fingerprint(
    artifact_hash: str,
    structural_hash: str,
    contract_hash: str,
) -> str:
    """Compute deterministic Phase 7 master fingerprint."""
    payload = {
        "artifact_hash": artifact_hash,
        "contract_hash": contract_hash,
        "schema_version": "1.0",
        "structural_hash": structural_hash,
    }
    return hashlib.sha256(canonicalize(payload)).hexdigest()


@pytest.fixture
def sample_valid_input_identity() -> InputIdentity:
    """Create a verified sample tensor input identity."""
    tensor = np.ones((224, 224, 3), dtype=np.float32)
    return validate_inference_input(tensor, declared_layout=InputLayout.HWC)


@pytest.fixture
def sample_valid_model_envelope() -> ModelIdentityEnvelope:
    """Create a verified sample model identity envelope."""
    artifact_h = hashlib.sha256(b"sample_model_weights_and_structure").hexdigest()
    struct_h = hashlib.sha256(b"canonical_structural_representation").hexdigest()
    contract_h = hashlib.sha256(b"canonical_contract_representation").hexdigest()
    master_fp = make_valid_master_fingerprint(artifact_h, struct_h, contract_h)

    return ModelIdentityEnvelope(
        model_id="resnet50-prod-v1",
        project_id="proj-alpha-001",
        master_fingerprint=master_fp,
        artifact_hash=artifact_h,
        structural_hash=struct_h,
        contract_hash=contract_h,
        version="1.0.0",
        format="safetensors",
        status="verified",
    )


# =====================================================================
# 1. Valid Input + Model Binding Tests
# =====================================================================

class TestValidInputModelBinding:
    """Test standard valid binding creation and verification."""

    def test_create_valid_binding(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        binding = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        assert isinstance(binding, InputModelBinding)
        assert binding.schema_version == "1.0"
        assert binding.binding_version == "1.0"
        assert binding.project_id == "proj-alpha-001"
        assert binding.input_id == sample_valid_input_identity.input_id
        assert binding.input_canonical_hash == sample_valid_input_identity.canonical_hash
        assert binding.model_id == sample_valid_model_envelope.model_id
        assert binding.model_master_fingerprint == sample_valid_model_envelope.master_fingerprint
        assert binding.binding_status == InferenceIntegrityStatus.VERIFIED
        assert len(binding.binding_hash) == 64

    def test_binding_from_hierarchical_fingerprint_result(
        self,
        sample_valid_input_identity: InputIdentity,
    ) -> None:
        artifact_h = hashlib.sha256(b"artifact_data").hexdigest()
        struct_h = hashlib.sha256(b"struct_data").hexdigest()
        contract_h = hashlib.sha256(b"contract_data").hexdigest()
        master_fp = make_valid_master_fingerprint(artifact_h, struct_h, contract_h)

        hfr = HierarchicalFingerprintResult(
            schema_version="1.0",
            status="verified",
            artifact_hash=artifact_h,
            structural_hash=struct_h,
            contract_hash=contract_h,
            master_fingerprint=master_fp,
        )

        binding = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=hfr,
            project_id="proj-beta-002",
            model_id="yolov8-model-01",
        )

        assert binding.model_id == "yolov8-model-01"
        assert binding.project_id == "proj-beta-002"
        assert binding.binding_status == InferenceIntegrityStatus.VERIFIED


# =====================================================================
# 2. Determinism & Canonical Hashing Tests
# =====================================================================

class TestBindingDeterminism:
    """Test repeated creation produces identical binding hashes."""

    def test_repeated_binding_creation_is_deterministic(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        b1 = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )
        b2 = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        assert b1.binding_hash == b2.binding_hash

    def test_descriptor_canonical_ordering_determinism(self) -> None:
        desc1 = build_canonical_binding_descriptor(
            binding_version="1.0",
            input_canonical_hash="a" * 64,
            input_id="b" * 64,
            input_kind=InputKind.TENSOR,
            model_artifact_hash="c" * 64,
            model_contract_hash="d" * 64,
            model_id="model-1",
            model_master_fingerprint="e" * 64,
            model_structural_hash="f" * 64,
            project_id="proj-1",
            schema_version="1.0",
        )
        h1 = compute_binding_hash(desc1)
        h2 = compute_binding_hash(desc1)
        assert h1 == h2


# =====================================================================
# 3. Mutation Sensitivity Tests
# =====================================================================

class TestBindingMutationSensitivity:
    """Ensure any modification to input or model identity changes binding_hash."""

    def test_changing_input_canonical_hash_changes_binding_hash(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        b1 = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        # Alter input
        alt_tensor = np.zeros((224, 224, 3), dtype=np.float32)
        alt_input = validate_inference_input(alt_tensor, declared_layout=InputLayout.HWC)

        b2 = create_input_model_binding(
            input_identity=alt_input,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        assert b1.binding_hash != b2.binding_hash
        assert b1.input_canonical_hash != b2.input_canonical_hash

    def test_changing_model_id_changes_binding_hash(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        b1 = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        alt_model_dict = sample_valid_model_envelope.model_dump()
        alt_model_dict["model_id"] = "resnet50-prod-v2"
        alt_model = ModelIdentityEnvelope(**alt_model_dict)

        b2 = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=alt_model,
            project_id="proj-alpha-001",
        )

        assert b1.binding_hash != b2.binding_hash

    def test_changing_artifact_hash_changes_binding_hash(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        b1 = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        alt_artifact_h = hashlib.sha256(b"different_model_weights").hexdigest()
        alt_master_fp = make_valid_master_fingerprint(
            alt_artifact_h,
            sample_valid_model_envelope.structural_hash,
            sample_valid_model_envelope.contract_hash,
        )

        alt_model = ModelIdentityEnvelope(
            model_id=sample_valid_model_envelope.model_id,
            project_id=sample_valid_model_envelope.project_id,
            master_fingerprint=alt_master_fp,
            artifact_hash=alt_artifact_h,
            structural_hash=sample_valid_model_envelope.structural_hash,
            contract_hash=sample_valid_model_envelope.contract_hash,
        )

        b2 = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=alt_model,
            project_id="proj-alpha-001",
        )

        assert b1.binding_hash != b2.binding_hash


# =====================================================================
# 4. Project Isolation & Mismatch Tests
# =====================================================================

class TestProjectIsolation:
    """Verify tenant isolation and cross-project binding rejection."""

    def test_cross_project_model_binding_rejected(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        # Model belongs to proj-alpha-001, but caller requests proj-bravo-999
        with pytest.raises(ProjectMismatchError):
            create_input_model_binding(
                input_identity=sample_valid_input_identity,
                model_identity=sample_valid_model_envelope,
                project_id="proj-bravo-999",
            )

        # In non-raising mode
        binding = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-bravo-999",
            raise_on_error=False,
        )
        assert binding.binding_status == InferenceIntegrityStatus.INVALID
        assert any(f.code == InferenceFindingCode.BINDING_PROJECT_MISMATCH.value for f in binding.findings)

    def test_empty_project_id_rejected(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        with pytest.raises(ProjectMismatchError):
            create_input_model_binding(
                input_identity=sample_valid_input_identity,
                model_identity=sample_valid_model_envelope,
                project_id="",
            )


# =====================================================================
# 5. Invalid Input / Model State Rejections
# =====================================================================

class TestInvalidStateRejections:
    """Verify fail-closed behavior on unverified or corrupted inputs and models."""

    def test_unverified_input_status_rejected(
        self,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        invalid_input = InputIdentity(
            input_id="0" * 64,
            input_kind=InputKind.TENSOR,
            canonical_hash="0" * 64,
            validation_status=InferenceIntegrityStatus.INVALID,
        )

        with pytest.raises(InferenceInputError):
            create_input_model_binding(
                input_identity=invalid_input,
                model_identity=sample_valid_model_envelope,
                project_id="proj-alpha-001",
            )

    def test_unverified_model_status_rejected(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        alt_model_dict = sample_valid_model_envelope.model_dump()
        alt_model_dict["status"] = "partial"
        unverified_model = ModelIdentityEnvelope(**alt_model_dict)

        with pytest.raises(ModelIntegrityBindingError):
            create_input_model_binding(
                input_identity=sample_valid_input_identity,
                model_identity=unverified_model,
                project_id="proj-alpha-001",
            )

    def test_inconsistent_master_fingerprint_rejected(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        # Master fingerprint does not match artifact/struct/contract hashes
        tampered_model_dict = sample_valid_model_envelope.model_dump()
        tampered_model_dict["master_fingerprint"] = "f" * 64
        tampered_model = ModelIdentityEnvelope(**tampered_model_dict)

        with pytest.raises(BindingInconsistencyError):
            create_input_model_binding(
                input_identity=sample_valid_input_identity,
                model_identity=tampered_model,
                project_id="proj-alpha-001",
            )


# =====================================================================
# 6. Cryptographic Format & Hash Validation Tests
# =====================================================================

class TestHashFormatValidation:
    """Verify strict 64-char lowercase hex formatting rules."""

    def test_uppercase_hex_rejected(self) -> None:
        with pytest.raises(InvalidHashFormatError):
            validate_sha256_hex_format("test_hash", "A" * 64)

    def test_short_hex_rejected(self) -> None:
        with pytest.raises(InvalidHashFormatError):
            validate_sha256_hex_format("test_hash", "a" * 63)

    def test_non_hex_rejected(self) -> None:
        with pytest.raises(InvalidHashFormatError):
            validate_sha256_hex_format("test_hash", "g" * 64)


# =====================================================================
# 7. Verification & Tamper Detection Tests
# =====================================================================

class TestBindingVerification:
    """Verify pure verification of InputModelBinding records."""

    def test_verify_valid_binding_succeeds(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        binding = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        res = verify_input_model_binding(binding)
        assert res.is_valid is True
        assert res.status == InferenceIntegrityStatus.VERIFIED
        assert res.computed_hash == binding.binding_hash

    def test_tampered_binding_hash_detected(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        binding = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        # Mutate binding_hash
        tampered_dict = binding.model_dump()
        tampered_dict["binding_hash"] = "e" * 64
        tampered_binding = InputModelBinding(**tampered_dict)

        res = verify_input_model_binding(tampered_binding)
        assert res.is_valid is False
        assert res.status == InferenceIntegrityStatus.INVALID
        assert any(f.code == InferenceFindingCode.BINDING_HASH_MISMATCH.value for f in res.findings)

    def test_tampered_model_id_detected_by_verification(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        binding = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        tampered_dict = binding.model_dump()
        tampered_dict["model_id"] = "different-model-id"
        tampered_binding = InputModelBinding(**tampered_dict)

        res = verify_input_model_binding(tampered_binding)
        assert res.is_valid is False


# =====================================================================
# 8. Immutability & Security Invariants
# =====================================================================

class TestImmutabilityAndSecurity:
    """Verify frozen models, static safety, and offline properties."""

    def test_binding_model_is_frozen(
        self,
        sample_valid_input_identity: InputIdentity,
        sample_valid_model_envelope: ModelIdentityEnvelope,
    ) -> None:
        binding = create_input_model_binding(
            input_identity=sample_valid_input_identity,
            model_identity=sample_valid_model_envelope,
            project_id="proj-alpha-001",
        )

        with pytest.raises(Exception):
            binding.model_id = "new-id"  # type: ignore

    def test_no_forbidden_execution_constructs_in_binding_module(self) -> None:
        binding_dir = Path(__file__).parent.parent / "backend" / "aivara" / "inference" / "binding"
        forbidden_calls = {"eval", "exec", "pickle", "system", "popen", "spawn"}

        for py_file in binding_dir.rglob("*.py"):
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                        pytest.fail(f"Forbidden call '{node.func.id}' found in {py_file.name}")
                    elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                        pytest.fail(f"Forbidden method call '{node.func.attr}' found in {py_file.name}")
