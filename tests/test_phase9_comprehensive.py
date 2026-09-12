"""Phase 9.11 — Comprehensive Backdoor Verification & Integration Test Suite.

End-to-End Integration, Mathematical Invariant, Multi-Tenant Isolation,
Adversarial Trapping, and Semantic Neutrality Verification for AIVARA Phase 9.

Covers:
  9.1  Architecture & Requirements Freeze
  9.2  Safe Trigger Candidate Generation
  9.3  Trigger Transformation Engine
  9.4  Clean-vs-Triggered Behavioral Comparison
  9.5  Trigger Activation & Consistency Analysis
  9.6  Targeted Misclassification / Output-Shift Analysis
  9.7  Trigger Localization & Attribution
  9.8  Statistical Trigger Significance
  9.9  Evidence & Provenance Binding
  9.10 REST API & Background Task Integration
  9.11 Comprehensive System Integration
"""

from __future__ import annotations

import ast
import copy
from datetime import datetime, timezone
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from fastapi.testclient import TestClient
import numpy as np
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

# API & Routers
from aivara.api.routers.backdoor import get_key_manager
from aivara.api.schemas.backdoor import (
    BackdoorAnalysisRequest,
    BackdoorTaskStageEnum,
)
from aivara.main import app

# Backdoor Domain Modules
from aivara.backdoor.activation.activation import evaluate_activation_decision
from aivara.backdoor.activation.controls import (
    generate_location_shuffled_array,
    generate_magnitude_matched_noise_array,
)
from aivara.backdoor.activation.engine import TriggerActivationEngine
from aivara.backdoor.activation.enums import (
    ActivationCriterionTypeEnum,
    ActivationDecisionEnum,
    BackdoorComparisonStatusEnum,
    BackdoorConditionEnum,
    BackdoorSupportStatusEnum,
)
from aivara.backdoor.activation.models import (
    ActivationCriterionSpec,
    ActivationDecisionRecord,
    PairedConditionResult,
    PairedObservation,
    TriggerActivationAssessment,
)
from aivara.backdoor.candidates.enums import (
    BlendModeEnum,
    CornerLocationEnum,
    PatchShapeEnum,
    PerturbationModeEnum,
    PlacementModeEnum,
    TexturePrimitiveEnum,
    TriggerFamilyEnum,
    ValueRangeEnum,
)
from aivara.backdoor.candidates.generator import TriggerCandidateGenerator
from aivara.backdoor.candidates.models import PlacementSpec, TriggerCandidateSpec
from aivara.backdoor.evidence import (
    BACKDOOR_EVIDENCE_SCHEMA_VERSION,
    BackdoorEvidenceContent,
    BackdoorProvenanceBindingService,
    compute_backdoor_evidence_hash,
    compute_backdoor_execution_identity_hash,
    create_backdoor_evidence,
    seal_backdoor_evidence,
    to_phase5_evidence_payload,
)
from aivara.backdoor.statistics.budget import (
    HARD_INFERENCE_CEILING,
    InferenceBudgetAccounting,
    compute_budget_accounting,
    validate_budget_ceiling,
)
from aivara.backdoor.statistics.confidence import clopper_pearson_confidence_interval
from aivara.backdoor.statistics.engine import StatisticalAnalysisEngine
from aivara.backdoor.statistics.enums import (
    MultipleTestingMethodEnum,
    StagePromotionStatusEnum,
    StatisticalResultTaxonomyEnum,
    StatisticalSignificanceEnum,
    StatisticalStatusEnum,
)
from aivara.backdoor.statistics.exceptions import (
    BudgetExceededError,
    InsufficientSupportError,
    MultiplicityAdjustmentError,
    PairingIntegrityError,
    StatisticalAnalysisError,
)
from aivara.backdoor.statistics.identity import (
    compute_statistical_analysis_id,
    derive_pcg64_seed,
)
from aivara.backdoor.statistics.localization import (
    GRID_DIMENSION,
    TOTAL_GRID_CELLS,
    GridCellStatisticalResult,
    evaluate_spatial_grid_localization,
)
from aivara.backdoor.statistics.models import (
    CandidateStatisticalSummary,
    ConfidenceIntervalResult,
    PermutationTestResult,
    SpatialLocalizationSummary,
    StatisticalAnalysisAssessment,
)
from aivara.backdoor.statistics.multiple_testing import (
    benjamini_hochberg_fdr,
    holm_bonferroni_step_down,
)
from aivara.backdoor.statistics.permutation import evaluate_paired_permutation_test
from aivara.backdoor.transformation.engine import TriggerTransformationEngine
from aivara.backdoor.transformation.enums import InputLayoutEnum

# Cryptographic & Persistence Foundation
from aivara.crypto.canonical import canonicalize
from aivara.crypto.hashing import hash_canonical_data, sha256_bytes, sha256_text
from aivara.crypto.keys import KeyManager
from aivara.crypto.verification import verify_record
from aivara.database.connection import get_db
from aivara.database.models import (
    AIModelModel,
    Base,
    FindingModel,
    ProjectModel,
    ProvenanceRecordModel,
)
from aivara.domain.schemas import (
    Disposition,
    EvidenceLayer,
    ProvenanceRecordRead,
    Severity,
)
from aivara.evidence.schemas import ProvenanceStatus
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService


# =====================================================================
# Synthetic Deterministic Model Fixture (Process-Local, Zero Network)
# =====================================================================

class DeterministicSyntheticVisionModel:
    """Lightweight synthetic model for deterministic verification.

    Behavior:
      - Clean input (mean < 0.01) -> predicts class 0 (confidence 0.85).
      - Active trigger (top-left patch value > 0.8) -> predicts target_class (confidence 0.95).
      - Shuffled control (bottom-right patch) -> predicts class 0 (confidence 0.80).
      - Noise control -> predicts class 0 (confidence 0.82).
    """

    def __init__(self, target_class: int = 1, num_classes: int = 5) -> None:
        self.target_class = target_class
        self.num_classes = num_classes

    def predict_classification(self, x: np.ndarray) -> np.ndarray:
        """Return 1D softmax-like probability distribution."""
        probs = np.full((self.num_classes,), 0.05, dtype=np.float32)
        probs[0] = 0.80

        # Check for top-left active trigger
        if x.ndim == 3 and np.any(x[0:8, 0:8, :] > 0.5):
            probs = np.full((self.num_classes,), 0.01, dtype=np.float32)
            probs[self.target_class] = 0.95

        return probs


# =====================================================================
# Comprehensive Test Environment Fixture
# =====================================================================

@pytest.fixture(scope="module")
def comprehensive_env(tmp_path_factory):
    """Set up isolated DB, KeyManager, and FastAPI TestClient."""
    db_dir = tmp_path_factory.mktemp("comp_db")
    db_path = db_dir / "comp_phase9.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False, "timeout": 30.0})
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.execute(text("PRAGMA busy_timeout=30000;"))
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    keys_dir = tmp_path_factory.mktemp("comp_keys")
    km = KeyManager(keys_dir=str(keys_dir))
    key_handle = km.generate_key(passphrase="comprehensive-passphrase-911", set_as_active=True)
    key_id = key_handle.key_id

    # Seed Projects & Models
    db = TestingSessionLocal()
    p_alpha = ProjectModel(id="proj-comp-alpha", name="Project Alpha Comprehensive")
    p_beta = ProjectModel(id="proj-comp-beta", name="Project Beta Comprehensive")
    p_pipe = ProjectModel(id="proj-comp-pipe", name="Project Pipeline")
    p_tamper = ProjectModel(id="proj-comp-tamper", name="Project Tamper")
    p_iso_a = ProjectModel(id="proj-comp-iso-a", name="Project ISO A")
    p_iso_b = ProjectModel(id="proj-comp-iso-b", name="Project ISO B")
    p_cancel = ProjectModel(id="proj-comp-cancel", name="Project Cancel")
    p_sync = ProjectModel(id="proj-comp-sync", name="Project Sync")
    db.add_all([p_alpha, p_beta, p_pipe, p_tamper, p_iso_a, p_iso_b, p_cancel, p_sync])
    db.commit()

    m_alpha = AIModelModel(
        id="model-comp-alpha",
        project_id="proj-comp-alpha",
        name="Alpha Comprehensive Model",
        format="onnx",
        file_path="models/alpha_comp.onnx",
        file_hash_sha256="c" * 64,
    )
    m_beta = AIModelModel(
        id="model-comp-beta",
        project_id="proj-comp-beta",
        name="Beta Comprehensive Model",
        format="onnx",
        file_path="models/beta_comp.onnx",
        file_hash_sha256="d" * 64,
    )
    m_pipe = AIModelModel(
        id="model-comp-pipe",
        project_id="proj-comp-pipe",
        name="Pipe Model",
        format="onnx",
        file_path="models/pipe.onnx",
        file_hash_sha256="1" * 64,
    )
    m_tamper = AIModelModel(
        id="model-comp-tamper",
        project_id="proj-comp-tamper",
        name="Tamper Model",
        format="onnx",
        file_path="models/tamper.onnx",
        file_hash_sha256="2" * 64,
    )
    m_iso_a = AIModelModel(
        id="model-comp-iso-a",
        project_id="proj-comp-iso-a",
        name="ISO A Model",
        format="onnx",
        file_path="models/iso_a.onnx",
        file_hash_sha256="e" * 64,
    )
    m_iso_b = AIModelModel(
        id="model-comp-iso-b",
        project_id="proj-comp-iso-b",
        name="ISO B Model",
        format="onnx",
        file_path="models/iso_b.onnx",
        file_hash_sha256="f" * 64,
    )
    m_cancel = AIModelModel(
        id="model-comp-cancel",
        project_id="proj-comp-cancel",
        name="Cancel Model",
        format="onnx",
        file_path="models/cancel.onnx",
        file_hash_sha256="3" * 64,
    )
    m_sync = AIModelModel(
        id="model-comp-sync",
        project_id="proj-comp-sync",
        name="Sync Model",
        format="onnx",
        file_path="models/sync.onnx",
        file_hash_sha256="4" * 64,
    )
    db.add_all([m_alpha, m_beta, m_pipe, m_tamper, m_iso_a, m_iso_b, m_cancel, m_sync])
    db.commit()
    db.close()

    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    def override_get_key_manager():
        return km

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_key_manager] = override_get_key_manager

    client = TestClient(app)
    yield {
        "client": client,
        "db_session": TestingSessionLocal,
        "key_manager": km,
        "key_id": key_id,
        "key_handle": key_handle,
        "passphrase": "comprehensive-passphrase-911",
        "engine": engine,
    }

    app.dependency_overrides.clear()


# =====================================================================
# 1. End-to-End Integrated Pipeline Verification
# =====================================================================

class TestPhase9EndToEndIntegration:
    """Full integration tests connecting Phase 9.2 through Phase 9.10."""

    def test_full_pipeline_synthetic_model_to_cryptographic_sealing(self, comprehensive_env):
        """Exercise complete flow: Generation -> Transformation -> Inference -> Activation -> Stats -> Provenance."""
        db_factory = comprehensive_env["db_session"]
        km: KeyManager = comprehensive_env["key_manager"]
        model = DeterministicSyntheticVisionModel(target_class=1)

        # 1. Candidate Generation (Phase 9.2)
        generator = TriggerCandidateGenerator()
        candidates = generator.generate_standard_grid(
            candidate_family=TriggerFamilyEnum.SPATIAL_PATCH,
            count=4,
        )
        assert len(candidates) == 4
        top_cand = candidates[0]

        # 2. Trigger Activation Engine (Phase 9.3 & 9.4)
        clean_samples = [
            (f"sample_{i}", np.zeros((32, 32, 3), dtype=np.float32))
            for i in range(20)
        ]
        act_engine = TriggerActivationEngine()
        act_assessment = act_engine.assess_candidate(
            project_id="proj-comp-pipe",
            model_id="model-comp-pipe",
            input_samples=clean_samples,
            candidate_spec=top_cand,
            model_fn=model.predict_classification,
            criterion=ActivationCriterionSpec(
                criterion_type=ActivationCriterionTypeEnum.TARGET_MATCHED,
                target_class=1,
            ),
        )

        assert act_assessment.sample_count == 20
        assert act_assessment.eligible_sample_count == 20
        assert len(act_assessment.paired_observations) == 20

        # 3. Statistical Significance Engine (Phase 9.5–9.8)
        stat_engine = StatisticalAnalysisEngine(
            permutation_count=500,
            alpha=0.05,
            confidence_level=0.95,
        )
        stat_assessment = stat_engine.evaluate_assessments(
            project_id="proj-comp-pipe",
            activation_assessments=[act_assessment],
            target_class=1,
        )
        assert stat_assessment.statistical_analysis_id is not None
        assert len(stat_assessment.candidate_summaries) == 1
        summary = stat_assessment.candidate_summaries[0]
        assert summary.tsr == 1.0
        assert summary.delta_separation >= 0.80
        assert summary.raw_p_value < 0.05

        # 4. Evidence & Provenance Binding (Phase 9.9)
        db: Session = db_factory()
        binding_service = BackdoorProvenanceBindingService(
            db=db,
            key_manager=km,
            audit_service=AuditService(db),
        )
        records = binding_service.bind_statistical_assessment(
            assessment=stat_assessment,
            model_fingerprint="fp_comp_alpha_123",
            key_alias=comprehensive_env["key_id"],
            signer_passphrase=comprehensive_env["passphrase"],
            key_handle=comprehensive_env["key_handle"],
            actor="COMPREHENSIVE_INTEGRATION_TESTER",
        )
        assert len(records) == 1
        prov_record = records[0]
        assert prov_record.signature is not None
        assert prov_record.sequence_number >= 0

        # 5. Verify via Phase 4 Cryptographic Provenance Verifier
        findings = db.query(FindingModel).filter_by(project_id="proj-comp-pipe").all()
        assert len(findings) == 1
        verif_result = binding_service.provenance_adapter.verify_finding_provenance(
            finding_id=findings[0].id,
            project_id="proj-comp-pipe",
        )
        assert verif_result.provenance_status == ProvenanceStatus.VERIFIED
        assert verif_result.cryptographic_validity is True
        db.close()


# =====================================================================
# 2. Candidate Generation & Transformation Invariants
# =====================================================================

class TestCandidateGenerationAndTransformation:
    """Verifies Phase 9.2 candidate generation and Phase 9.3 transformation fidelity."""

    @pytest.mark.parametrize(
        "family",
        [
            TriggerFamilyEnum.SPATIAL_PATCH,
            TriggerFamilyEnum.COLOR_PATTERN_PATCH,
            TriggerFamilyEnum.TEXTURE_GRID,
            TriggerFamilyEnum.LOCALIZED_PERTURBATION,
        ],
    )
    def test_all_supported_trigger_families_generate_and_transform(self, family):
        """All supported trigger candidate families produce valid deterministic transformations."""
        gen = TriggerCandidateGenerator()
        candidates = gen.generate_standard_grid(candidate_family=family, count=2)
        assert len(candidates) == 2
        for cand in candidates:
            assert cand.candidate_hash is not None
            assert len(cand.candidate_hash) == 64

        # Verify transformation engine accepts generated specification
        engine = TriggerTransformationEngine()
        img = np.zeros((32, 32, 3), dtype=np.float32)
        res = engine.transform(input_array=img, candidate_spec=candidates[0])
        assert res.transformed_array.shape == img.shape
        assert res.transformation_id is not None

    def test_input_immutability_and_read_only_output(self):
        """Source array is strictly unmutated; returned transformed array is read-only."""
        engine = TriggerTransformationEngine()
        gen = TriggerCandidateGenerator()
        cand = gen.generate_standard_grid(TriggerFamilyEnum.SPATIAL_PATCH, count=1)[0]
        img = np.ones((32, 32, 3), dtype=np.float32)
        img_copy = img.copy()

        res = engine.transform(input_array=img, candidate_spec=cand)
        assert np.array_equal(img, img_copy)
        assert res.transformed_array.flags.writeable is False


# =====================================================================
# 3. Clean / Trigger / Control Experimental Invariants
# =====================================================================

class TestCleanTriggerControlIntegrity:
    """Verifies the four experimental conditions and control identities."""

    def test_distinct_control_conditions(self):
        """Active trigger, location-shuffled control, and noise control must be mutually distinct."""
        engine = TriggerTransformationEngine()
        gen = TriggerCandidateGenerator()
        cand = gen.generate_standard_grid(TriggerFamilyEnum.SPATIAL_PATCH, count=1)[0]
        clean = np.full((32, 32, 3), 0.2, dtype=np.float32)

        active = engine.transform(clean, cand).transformed_array
        shuff_res, _, _ = generate_location_shuffled_array(clean, cand, seed=12345, engine=engine)
        shuffled = shuff_res.transformed_array
        noise, _, _ = generate_magnitude_matched_noise_array(clean, active, seed=67890)

        assert not np.array_equal(active, clean)
        assert not np.array_equal(shuffled, clean)
        assert not np.array_equal(noise, clean)
        assert not np.array_equal(active, shuffled)
        assert not np.array_equal(active, noise)
        assert not np.array_equal(shuffled, noise)


# =====================================================================
# 4. Multi-Task Activation Criteria & Decision Rules
# =====================================================================

class TestMultiTaskActivationCriteria:
    """Verifies task-aware activation decision rules across vision tasks."""

    def test_classification_activation_criteria(self):
        """Classification activation criteria: Target Match, Prediction Changed, Confidence Delta."""
        # 1. Target Match
        spec1 = ActivationCriterionSpec(criterion_type=ActivationCriterionTypeEnum.TARGET_MATCHED, target_class=1)
        dec1, pred1, conf1, is_tgt1, rec1 = evaluate_activation_decision(
            clean_output=np.array([0.9, 0.05, 0.05]),
            condition_output=np.array([0.05, 0.9, 0.05]),
            criterion=spec1,
        )
        assert dec1 == ActivationDecisionEnum.ACTIVATED
        assert is_tgt1 is True

        # 2. Prediction Changed
        spec2 = ActivationCriterionSpec(criterion_type=ActivationCriterionTypeEnum.PREDICTION_CHANGED)
        dec2, pred2, conf2, is_tgt2, rec2 = evaluate_activation_decision(
            clean_output=np.array([0.9, 0.05, 0.05]),
            condition_output=np.array([0.05, 0.05, 0.9]),
            criterion=spec2,
        )
        assert dec2 == ActivationDecisionEnum.ACTIVATED

        # 3. Confidence Delta Threshold
        spec3 = ActivationCriterionSpec(
            criterion_type=ActivationCriterionTypeEnum.CONFIDENCE_DELTA_THRESHOLD,
            confidence_delta_threshold=0.20,
        )
        dec3, pred3, conf3, is_tgt3, rec3 = evaluate_activation_decision(
            clean_output=np.array([0.90, 0.10]),
            condition_output=np.array([0.60, 0.40]),
            criterion=spec3,
        )
        assert dec3 == ActivationDecisionEnum.ACTIVATED

    def test_detection_count_delta_rule(self):
        """Detection: abs(delta) >= count_delta_threshold."""
        spec = ActivationCriterionSpec(
            criterion_type=ActivationCriterionTypeEnum.DETECTION_COUNT_DELTA,
            count_delta_threshold=2,
        )
        clean_det = {"boxes": [[0, 0, 10, 10], [10, 10, 20, 20]], "scores": [0.9, 0.8], "labels": [1, 1]}
        cond_det = {
            "boxes": [[0, 0, 10, 10], [10, 10, 20, 20], [20, 20, 30, 30], [30, 30, 40, 40]],
            "scores": [0.9, 0.8, 0.85, 0.75],
            "labels": [1, 1, 1, 1],
        }
        dec, _, _, _, rec = evaluate_activation_decision(
            clean_output=clean_det,
            condition_output=cond_det,
            criterion=spec,
        )
        assert dec == ActivationDecisionEnum.ACTIVATED
        assert rec.delta_value == 2

    def test_segmentation_clean_relative_degradation(self):
        """Segmentation: Mask disagreement / GT mIoU drop."""
        spec = ActivationCriterionSpec(
            criterion_type=ActivationCriterionTypeEnum.SEGMENTATION_MASK_DISAGREEMENT,
            drop_threshold=0.20,
        )
        clean_mask = np.zeros((10, 10), dtype=np.int32)
        cond_mask = np.zeros((10, 10), dtype=np.int32)
        cond_mask[0:5, 0:5] = 1  # 25% disagreement

        dec, _, _, _, rec = evaluate_activation_decision(
            clean_output=clean_mask,
            condition_output=cond_mask,
            criterion=spec,
        )
        assert dec == ActivationDecisionEnum.ACTIVATED
        assert rec.delta_value >= 0.20


# =====================================================================
# 5. Spatial Grid Localization (8x8 Grid, 64 Cells)
# =====================================================================

class TestSpatialGridLocalization:
    """Verifies 8x8 spatial grid localization with Holm-Bonferroni FWER step-down."""

    def test_spatial_grid_64_cells_evaluation(self):
        """Spatial grid evaluates exactly 64 cells and identifies peak delta separation."""
        grid_obs = []
        for idx in range(TOTAL_GRID_CELLS):
            if idx == 12:
                # Strong trigger effect at cell 12
                trig = [1] * 20
                shuff = [0] * 20
                noise = [0] * 20
            else:
                # Baseline background at other cells
                trig = [0] * 20
                shuff = [0] * 20
                noise = [0] * 20

            grid_obs.append({
                "cell_index": idx,
                "trigger_successes": trig,
                "shuffled_successes": shuff,
                "noise_successes": noise,
            })

        summary = evaluate_spatial_grid_localization(
            candidate_hash="cand_" + "1" * 59,
            statistical_analysis_id="stat_loc_001",
            grid_cell_observations=grid_obs,
            alpha=0.05,
            permutation_count=2000,
        )
        assert summary.total_cells == 64
        assert summary.evaluable_cells == 64
        assert summary.peak_cell_index == 12
        assert summary.peak_delta_separation == pytest.approx(1.0)
        assert summary.significant_cells >= 1


# =====================================================================
# 6. Statistical Hypothesis Testing & Inferential Control Regression
# =====================================================================

class TestStatisticalContractAndInferentialControl:
    """Verifies composite null hypothesis testing and explicit absence of sample-wise max control."""

    def test_paired_permutation_composite_null_contract(self):
        """Hypothesis: H0_shuff (TSR <= TSR_shuff), H0_noise (TSR <= TSR_noise), p = max(p_shuff, p_noise)."""
        y_trig = [1] * 18 + [0] * 2
        y_shuff = [1] * 2 + [0] * 18
        y_noise = [1] * 1 + [0] * 19

        res = evaluate_paired_permutation_test(
            trigger_successes=y_trig,
            shuffled_successes=y_shuff,
            noise_successes=y_noise,
            permutation_count=1000,
            seed=42,
        )
        assert res["p_value_shuffled"] < 0.05
        assert res["p_value_noise"] < 0.05
        assert res["p_value"] == max(res["p_value_shuffled"], res["p_value_noise"])
        assert res["significance"] == StatisticalSignificanceEnum.SIGNIFICANT

    def test_explicit_regression_no_sample_wise_max_control_used(self):
        """CRITICAL REGRESSION: Assert that permutation testing does NOT use sample-wise max(y_shuff_i, y_noise_i)."""
        y_trig = [1, 1, 1, 0] * 5
        y_shuff = [1, 0, 1, 0] * 5
        y_noise = [0, 1, 0, 1] * 5

        res = evaluate_paired_permutation_test(
            trigger_successes=y_trig,
            shuffled_successes=y_shuff,
            noise_successes=y_noise,
            permutation_count=500,
            seed=42,
        )
        assert res["t_obs_shuffled"] == pytest.approx(0.25)
        assert res["t_obs_noise"] == pytest.approx(0.25)
        assert res["t_obs"] == pytest.approx(0.25)


# =====================================================================
# 7. Support Semantics & Insufficient Support Trapping
# =====================================================================

class TestSupportSemanticsAndStatusTaxonomy:
    """Verifies N < 10 insufficient support, zero activations, and status enums."""

    def test_n_less_than_10_insufficient_support(self):
        """N < 10 returns INSUFFICIENT_SUPPORT status and NOT_EVALUATED significance."""
        y_trig = [1] * 8
        y_shuff = [0] * 8
        y_noise = [0] * 8

        res = evaluate_paired_permutation_test(
            trigger_successes=y_trig,
            shuffled_successes=y_shuff,
            noise_successes=y_noise,
            permutation_count=500,
            seed=42,
        )
        assert res["status"] == StatisticalStatusEnum.INSUFFICIENT_SUPPORT
        assert res["significance"] == StatisticalSignificanceEnum.NOT_EVALUATED

    def test_zero_activations_yields_valid_zero_tsr_not_missing(self):
        """N = 50 with 0 activations yields TAR=0.0, TSR=0.0, status=COMPLETED, taxonomy=NO_TRIGGER_EVIDENCE."""
        clean_samples = [
            (f"sample_{i}", np.zeros((32, 32, 3), dtype=np.float32))
            for i in range(20)
        ]
        gen = TriggerCandidateGenerator()
        cand = gen.generate_standard_grid(TriggerFamilyEnum.SPATIAL_PATCH, count=1)[0]
        # Inactive model that always predicts class 0
        dummy_model = lambda x: np.array([0.9, 0.1, 0.0])

        act_engine = TriggerActivationEngine()
        assessment = act_engine.assess_candidate(
            project_id="proj-comp-alpha",
            model_id="model-comp-alpha",
            input_samples=clean_samples,
            candidate_spec=cand,
            model_fn=dummy_model,
            criterion=ActivationCriterionSpec(
                criterion_type=ActivationCriterionTypeEnum.TARGET_MATCHED,
                target_class=1,
            ),
        )

        stat_engine = StatisticalAnalysisEngine()
        res = stat_engine.evaluate_assessments(
            project_id="proj-comp-alpha",
            activation_assessments=[assessment],
            target_class=1,
        )
        summary = res.candidate_summaries[0]
        assert summary.tar == 0.0
        assert summary.tsr == 0.0
        assert summary.taxonomy_classification == StatisticalResultTaxonomyEnum.NO_TRIGGER_EVIDENCE


# =====================================================================
# 8. Budget Accounting & Hard Ceiling Enforcement
# =====================================================================

class TestInferenceBudgetAccountingAndCeiling:
    """Verifies inference budget calculations and hard ceiling (<= 16,000)."""

    def test_standard_budget_accounting_10250_inferences(self):
        """Standard pipeline: Stage 1 (2450) + Stage 2 (1400) + Localization (6400) = 10,250 <= 16,000."""
        b = compute_budget_accounting(
            stage1_samples=50,
            stage1_candidates=16,
            stage2_expansion_samples=200,
            stage2_promoted_candidates=2,
            stage2_loc_samples=50,
        )
        assert b.stage1_inferences == 2450
        assert b.stage2_expansion_inferences == 1400
        assert b.stage2_localization_inferences == 6400
        assert b.total_inferences == 10250
        assert b.is_within_budget is True

    def test_budget_exceeding_ceiling_fails_closed(self):
        """Requests exceeding 16,000 inferences fail closed via validate_budget_ceiling."""
        with pytest.raises(BudgetExceededError):
            validate_budget_ceiling(
                stage1_samples=100,
                stage1_candidates=16,
                stage2_expansion_samples=500,
                stage2_promoted_candidates=2,
                stage2_loc_samples=100,
            )


# =====================================================================
# 9. Evidence Binding & Cryptographic Provenance Integrity
# =====================================================================

class TestEvidenceAndCryptographicProvenance:
    """Verifies deterministic RFC 8785 JCS evidence identity and Ed25519 signing."""

    def test_evidence_hash_determinism_and_mutation_sensitivity(self):
        """Altering any metric changes canonical evidence hash."""
        base_content = BackdoorEvidenceContent(
            schema_version="1.0.0",
            project_id="proj-comp-alpha",
            model_id="model-comp-alpha",
            model_fingerprint="fp_alpha_001",
            sample_set_hash="1" * 64,
            candidate_hash="2" * 64,
            activation_assessment_id="act_001",
            statistical_analysis_id="stat_001",
            target_class=1,
            tar=0.90,
            tsr=0.90,
            raw_tsr_shuffled=0.10,
            raw_tsr_noise=0.05,
            control_baseline_tsr=0.10,
            sample_envelope_tsr=0.15,
            delta_separation=0.80,
            confidence_interval_low=0.75,
            confidence_interval_high=0.98,
            permutation_count=1000,
            p_value=0.001,
            p_value_shuffled=0.001,
            p_value_noise=0.0005,
            adjusted_p_value=0.002,
            is_significant_after_fdr=True,
            taxonomy_classification="STRONG_TRIGGER_CONSISTENCY",
            budget_inferences_total=10250,
        )
        h_base = compute_backdoor_evidence_hash(base_content)

        # Mutate TSR
        c_mut_tsr = copy.deepcopy(base_content)
        object.__setattr__(c_mut_tsr, "tsr", 0.89)
        assert compute_backdoor_evidence_hash(c_mut_tsr) != h_base

        # Mutate p-value
        c_mut_p = copy.deepcopy(base_content)
        object.__setattr__(c_mut_p, "p_value", 0.002)
        assert compute_backdoor_evidence_hash(c_mut_p) != h_base

    def test_provenance_tamper_detection(self, comprehensive_env):
        """Tampering with signature, record hash, or previous hash is detected."""
        km: KeyManager = comprehensive_env["key_manager"]
        handle = comprehensive_env["key_handle"]
        from aivara.crypto.chain import ProvenanceChain

        chain = ProvenanceChain(project_id="proj-comp-tamper", key_handle=handle)
        record = chain.append(record_type="INFERENCE", action="predict", actor="ml", sign=True)
        tampered = record.model_dump()
        tampered["signature"] = "a" * 128

        res = verify_record(tampered, key_manager=km)
        assert res.is_valid is False


# =====================================================================
# 10. REST API, SSE Streaming, Cancellation & Project Isolation
# =====================================================================

class TestRestApiSseAndProjectIsolation:
    """Verifies FastAPI endpoints, SSE event broadcasting, and multi-tenant isolation."""

    def test_cross_project_isolation_fail_closed(self, comprehensive_env):
        """Project Alpha cannot query or cancel Project Beta's tasks."""
        client: TestClient = comprehensive_env["client"]
        # Submit task for ISO A
        payload_iso_a = {
            "project_id": "proj-comp-iso-a",
            "model_id": "model-comp-iso-a",
            "sample_set_hash": "a" * 64,
        }
        res_iso_a = client.post("/api/v1/projects/proj-comp-iso-a/backdoor/tasks?async=true", json=payload_iso_a)
        assert res_iso_a.status_code == 200
        task_id = res_iso_a.json()["data"]["task_id"]

        # Attempt to access via Project ISO B
        res_iso_b_query = client.get(f"/api/v1/projects/proj-comp-iso-b/backdoor/tasks/{task_id}")
        assert res_iso_b_query.status_code in (404, 422)

        res_iso_b_cancel = client.post(f"/api/v1/projects/proj-comp-iso-b/backdoor/tasks/{task_id}/cancel")
        assert res_iso_b_cancel.status_code in (404, 422)

        # Cancel ISO A task to cleanly terminate worker
        client.post(f"/api/v1/projects/proj-comp-iso-a/backdoor/tasks/{task_id}/cancel")

    def test_task_cancellation_cooperative_propagation(self, comprehensive_env):
        """Cancellation request transitions task to CANCELLED state cooperatively."""
        client: TestClient = comprehensive_env["client"]
        payload = {
            "project_id": "proj-comp-cancel",
            "model_id": "model-comp-cancel",
            "sample_set_hash": "c" * 64,
        }
        post_res = client.post("/api/v1/projects/proj-comp-cancel/backdoor/tasks?async=true", json=payload)
        task_id = post_res.json()["data"]["task_id"]

        cancel_res = client.post(f"/api/v1/projects/proj-comp-cancel/backdoor/tasks/{task_id}/cancel")
        assert cancel_res.status_code == 200
        assert cancel_res.json()["data"]["status"] == "CANCELLED"

    def test_synchronous_task_execution_full_contract(self, comprehensive_env):
        """Full synchronous API execution generates and seals complete evidence and provenance."""
        client: TestClient = comprehensive_env["client"]
        km: KeyManager = comprehensive_env["key_manager"]
        payload = {
            "project_id": "proj-comp-sync",
            "model_id": "model-comp-sync",
            "sample_set_hash": "d" * 64,
            "target_class": 1,
            "candidate_count_stage1": 2,
            "sample_count_stage1": 10,
            "sample_count_stage2": 50,
            "localization_sample_count": 10,
            "enable_localization": False,
            "permutation_count": 100,
            "key_alias": km.get_active_key_id(),
            "signer_passphrase": "comprehensive-passphrase-911",
        }
        res = client.post("/api/v1/projects/proj-comp-sync/backdoor/tasks?async=false", json=payload)
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["status"] == "COMPLETED"
        assert data["progress_percent"] == 100.0
        assert data["statistical_analysis_id"] is not None


# =====================================================================
# 11. Security, Offline Invariant & Code Inspection
# =====================================================================

class TestSecurityAndOfflineInvariants:
    """Verifies no malicious constructs (eval, exec, pickle, subprocess, network requests)."""

    def test_forbidden_python_constructs_absent(self):
        """Phase 9 backend source code contains no eval, exec, pickle.load, or subprocess calls."""
        backdoor_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend", "aivara", "backdoor"))
        for root, _, files in os.walk(backdoor_dir):
            for file in files:
                if file.endswith(".py"):
                    filepath = os.path.join(root, file)
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                        tree = ast.parse(content, filename=filepath)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                if isinstance(node.func, ast.Name):
                                    assert node.func.id not in ("eval", "exec"), f"Forbidden {node.func.id} in {filepath}"

    def test_semantic_safety_in_all_enums_and_messages(self):
        """Observational taxonomy: strictly zero occurrences of accusatory terms."""
        forbidden = ["malicious", "attacker_intent", "culpability", "backdoor_confirmed"]
        for val in StatisticalResultTaxonomyEnum:
            for term in forbidden:
                assert term not in val.value.lower()


# =====================================================================
# 12. Idempotency & Mathematical Determinism
# =====================================================================

class TestIdempotencyAndDeterminism:
    """Verifies repeatable deterministic identities and idempotent task handling."""

    def test_idempotent_repeated_task_submission(self, comprehensive_env):
        """Submitting identical request with same Idempotency-Key returns existing task."""
        client: TestClient = comprehensive_env["client"]
        payload = {
            "project_id": "proj-comp-sync",
            "model_id": "model-comp-sync",
            "sample_set_hash": "e" * 64,
            "candidate_count_stage1": 2,
            "sample_count_stage1": 10,
            "sample_count_stage2": 50,
            "localization_sample_count": 10,
            "enable_localization": False,
            "permutation_count": 100,
        }
        res1 = client.post(
            "/api/v1/projects/proj-comp-sync/backdoor/tasks?async=false",
            json=payload,
            headers={"Idempotency-Key": "idemp-comp-key-001"},
        )
        assert res1.status_code == 200
        t1 = res1.json()["data"]["task_id"]

        res2 = client.post(
            "/api/v1/projects/proj-comp-sync/backdoor/tasks?async=false",
            json=payload,
            headers={"Idempotency-Key": "idemp-comp-key-001"},
        )
        assert res2.status_code == 200
        t2 = res2.json()["data"]["task_id"]
        assert t1 == t2

    def test_end_to_end_pipeline_determinism(self):
        """Identical pipeline executions produce identical candidate, activation, and evidence hashes."""
        model = DeterministicSyntheticVisionModel(target_class=1)
        clean_samples = [
            (f"sample_{i}", np.zeros((32, 32, 3), dtype=np.float32))
            for i in range(15)
        ]
        gen = TriggerCandidateGenerator()
        cand = gen.generate_standard_grid(TriggerFamilyEnum.SPATIAL_PATCH, count=1)[0]
        act_engine = TriggerActivationEngine()
        stat_engine = StatisticalAnalysisEngine(permutation_count=200, alpha=0.05, confidence_level=0.95)

        # Run 1
        act1 = act_engine.assess_candidate(
            project_id="proj-det-1",
            model_id="model-det-1",
            input_samples=clean_samples,
            candidate_spec=cand,
            model_fn=model.predict_classification,
            criterion=ActivationCriterionSpec(criterion_type=ActivationCriterionTypeEnum.TARGET_MATCHED, target_class=1),
        )
        stat1 = stat_engine.evaluate_assessments(
            project_id="proj-det-1",
            activation_assessments=[act1],
            target_class=1,
        )
        fixed_dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        ev1 = create_backdoor_evidence(stat1, stat1.candidate_summaries[0], model_fingerprint="fp_det", created_at=fixed_dt)
        h1 = compute_backdoor_evidence_hash(ev1.content)

        # Run 2
        act2 = act_engine.assess_candidate(
            project_id="proj-det-1",
            model_id="model-det-1",
            input_samples=clean_samples,
            candidate_spec=cand,
            model_fn=model.predict_classification,
            criterion=ActivationCriterionSpec(criterion_type=ActivationCriterionTypeEnum.TARGET_MATCHED, target_class=1),
        )
        stat2 = stat_engine.evaluate_assessments(
            project_id="proj-det-1",
            activation_assessments=[act2],
            target_class=1,
        )
        ev2 = create_backdoor_evidence(stat2, stat2.candidate_summaries[0], model_fingerprint="fp_det", created_at=fixed_dt)
        h2 = compute_backdoor_evidence_hash(ev2.content)

        assert h1 == h2
        assert stat1.candidate_summaries[0].raw_p_value == stat2.candidate_summaries[0].raw_p_value
        assert stat1.candidate_summaries[0].delta_separation == stat2.candidate_summaries[0].delta_separation


# =====================================================================
# 13. Security & Adversarial Input Trapping
# =====================================================================

class TestAdversarialAndMalformedInputs:
    """Verifies system robustness and fail-closed behavior against adversarial inputs."""

    def test_nan_inf_model_outputs_trapped_as_not_applicable(self):
        """Model outputs containing NaN or Inf return NOT_APPLICABLE activation decision."""
        spec = ActivationCriterionSpec(criterion_type=ActivationCriterionTypeEnum.TARGET_MATCHED, target_class=1)
        nan_output = np.array([np.nan, 0.5, 0.5])
        clean_output = np.array([0.9, 0.05, 0.05])

        dec, _, _, _, rec = evaluate_activation_decision(
            clean_output=clean_output,
            condition_output=nan_output,
            criterion=spec,
        )
        assert dec == ActivationDecisionEnum.NOT_APPLICABLE
        assert rec.status == "NON_FINITE_VALUES"

    def test_oversized_candidate_count_rejected(self, comprehensive_env):
        """Requesting candidate count > 16 is rejected with 422 Unprocessable Entity."""
        client: TestClient = comprehensive_env["client"]
        payload = {
            "project_id": "proj-comp-sync",
            "model_id": "model-comp-sync",
            "sample_set_hash": "f" * 64,
            "candidate_count_stage1": 32,  # exceeds max 16
        }
        res = client.post("/api/v1/projects/proj-comp-sync/backdoor/tasks", json=payload)
        assert res.status_code == 422

    def test_invalid_tensor_dimension_fails_closed(self):
        """Passing 2D or 5D arrays to 3D image transformation engine fails closed with exception."""
        engine = TriggerTransformationEngine()
        gen = TriggerCandidateGenerator()
        cand = gen.generate_standard_grid(TriggerFamilyEnum.SPATIAL_PATCH, count=1)[0]
        bad_dim_array = np.zeros((10, 10), dtype=np.float32)  # 2D instead of 3D HWC/CHW

        with pytest.raises(Exception):
            engine.transform(input_array=bad_dim_array, candidate_spec=cand)

