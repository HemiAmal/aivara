"""Comprehensive Test Suite for Phase 9.9 Backdoor Evidence and Cryptographic Provenance Binding."""

from __future__ import annotations

import math
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from aivara.backdoor.activation.enums import (
    ActivationDecisionEnum,
    BackdoorComparisonStatusEnum,
    BackdoorConditionEnum,
    BackdoorSupportStatusEnum,
)
from aivara.backdoor.activation.models import (
    PairedConditionResult,
    PairedObservation,
    TriggerActivationAssessment,
)
from aivara.backdoor.candidates.enums import TriggerFamilyEnum
from aivara.backdoor.evidence import (
    BACKDOOR_DETECTOR_VERSION,
    BACKDOOR_EVIDENCE_SCHEMA_VERSION,
    BackdoorEvidence,
    BackdoorEvidenceContent,
    BackdoorEvidenceLifecycleState,
    BackdoorEvidenceType,
    BackdoorProvenanceBindingService,
    compute_backdoor_evidence_hash,
    compute_backdoor_execution_identity_hash,
    create_backdoor_evidence,
    seal_backdoor_evidence,
    to_phase5_evidence_payload,
)
from aivara.backdoor.statistics.budget import compute_budget_accounting
from aivara.backdoor.statistics.enums import (
    MultipleTestingMethodEnum,
    StatisticalResultTaxonomyEnum,
    StatisticalSignificanceEnum,
    StatisticalStatusEnum,
)
from aivara.backdoor.statistics.models import (
    CandidateStatisticalSummary,
    ConfidenceIntervalResult,
    PermutationTestResult,
    SpatialLocalizationSummary,
    StatisticalAnalysisAssessment,
)
from aivara.backdoor.transformation.enums import InputLayoutEnum
from aivara.crypto.keys import KeyManager
from aivara.database.models import Base, FindingModel, ProjectModel, ProvenanceRecordModel
from aivara.domain.schemas import EvidenceLayer
from aivara.evidence.schemas import ProvenanceStatus
from aivara.services.audit_service import AuditService
from aivara.services.provenance_service import ProvenanceService


# ============================================================================
# Database & Cryptographic Fixtures
# ============================================================================

@pytest.fixture
def db_session() -> Session:
    """Create an isolated, in-memory SQLite database session reusing existing schema."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    # Seed test project
    project = ProjectModel(
        id="proj_001",
        name="Test Project 1",
        description="Phase 9.9 Verification",
    )
    project2 = ProjectModel(
        id="proj_002",
        name="Test Project 2",
        description="Phase 9.9 Cross Project Isolation",
    )
    session.add_all([project, project2])
    session.commit()

    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def key_manager(tmp_path: Path) -> KeyManager:
    """Create local Ed25519 KeyManager with an active key."""
    km = KeyManager(keys_dir=tmp_path / "keys")
    km.generate_key(passphrase="TestKeyPassphrase123!", set_as_active=True, description="Phase 9.9 Test Key")
    return km


@pytest.fixture
def sample_statistical_assessment() -> StatisticalAnalysisAssessment:
    """Construct a mock validated StatisticalAnalysisAssessment from Phase 9.5."""
    cand = CandidateStatisticalSummary(
        candidate_hash="cand_hash_abc123",
        sample_count=50,
        eligible_sample_count=50,
        target_class=1,
        tar=0.85,
        tsr=0.80,
        raw_tsr_shuffled=0.10,
        raw_tsr_noise=0.15,
        control_baseline_tsr=0.15,
        sample_envelope_tsr=0.20,
        delta_separation=0.65,
        confidence_interval=ConfidenceIntervalResult(
            confidence_level=0.95,
            lower_bound=0.6628,
            upper_bound=0.8997,
            method="CLOPPER_PEARSON_EXACT",
            status="VALID",
        ),
        permutation_test=PermutationTestResult(
            permutation_count=1000,
            rng_algorithm="PCG64",
            seed=424242,
            t_obs=0.65,
            t_obs_shuffled=0.70,
            t_obs_noise=0.65,
            p_value=0.000999,
            p_value_shuffled=0.000999,
            p_value_noise=0.000999,
            significance=StatisticalSignificanceEnum.SIGNIFICANT,
            status=StatisticalStatusEnum.COMPLETED,
        ),
        raw_p_value=0.000999,
        adjusted_p_value=0.000999,
        multiple_testing_method=MultipleTestingMethodEnum.BENJAMINI_HOCHBERG,
        fdr_rank=1,
        is_significant_after_fdr=True,
        taxonomy_classification=StatisticalResultTaxonomyEnum.TARGETED_EFFECT_DETECTED,
        status=StatisticalStatusEnum.COMPLETED,
    )

    budget = compute_budget_accounting()

    return StatisticalAnalysisAssessment(
        schema_version="1.0.0",
        statistical_analysis_id="stat_id_9999",
        project_id="proj_001",
        model_id="model_resnet50_v1",
        sample_set_hash="sample_set_hash_001",
        trigger_assessment_id="act_ass_001",
        target_class=1,
        permutation_count=1000,
        alpha=0.05,
        confidence_level=0.95,
        multiple_comparison_method=MultipleTestingMethodEnum.BENJAMINI_HOCHBERG,
        budget_accounting=budget,
        candidate_summaries=[cand],
        stage2_promotions=[],
        spatial_localization_summaries=[],
    )


# ============================================================================
# 1. Canonical Evidence Serialization & Identity Determinism
# ============================================================================

class TestBackdoorEvidenceIdentity:
    """Validation of RFC 8785 JCS canonicalization and deterministic SHA-256 evidence hashing."""

    def test_deterministic_evidence_identity(self, sample_statistical_assessment):
        """Identical evidence content produces bitwise identical evidence_id."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev1 = create_backdoor_evidence(sample_statistical_assessment, cand, model_fingerprint="fp_resnet50")
        ev2 = create_backdoor_evidence(sample_statistical_assessment, cand, model_fingerprint="fp_resnet50")

        assert ev1.evidence_id == ev2.evidence_id
        assert ev1.execution_id == ev2.execution_id
        assert len(ev1.evidence_id) == 64
        assert len(ev1.execution_id) == 64

    def test_mutation_sensitivity_candidate_hash(self, sample_statistical_assessment):
        """Mutating candidate_hash changes evidence_id."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev1 = create_backdoor_evidence(sample_statistical_assessment, cand)

        cand_mutated = cand.model_copy(update={"candidate_hash": "cand_hash_MUTATED"})
        ev2 = create_backdoor_evidence(sample_statistical_assessment, cand_mutated)

        assert ev1.evidence_id != ev2.evidence_id

    def test_mutation_sensitivity_tsr(self, sample_statistical_assessment):
        """Mutating TSR changes evidence_id."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev1 = create_backdoor_evidence(sample_statistical_assessment, cand)

        cand_mutated = cand.model_copy(update={"tsr": 0.99})
        ev2 = create_backdoor_evidence(sample_statistical_assessment, cand_mutated)

        assert ev1.evidence_id != ev2.evidence_id

    def test_mutation_sensitivity_p_value(self, sample_statistical_assessment):
        """Mutating permutation p-value changes evidence_id."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev1 = create_backdoor_evidence(sample_statistical_assessment, cand)

        cand_mutated = cand.model_copy(update={"raw_p_value": 0.50})
        ev2 = create_backdoor_evidence(sample_statistical_assessment, cand_mutated)

        assert ev1.evidence_id != ev2.evidence_id

    def test_mutation_sensitivity_model_fingerprint(self, sample_statistical_assessment):
        """Mutating model fingerprint changes evidence_id and execution_id."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev1 = create_backdoor_evidence(sample_statistical_assessment, cand, model_fingerprint="fp_1")
        ev2 = create_backdoor_evidence(sample_statistical_assessment, cand, model_fingerprint="fp_2")

        assert ev1.evidence_id != ev2.evidence_id
        assert ev1.execution_id != ev2.execution_id


# ============================================================================
# 2. Lifecycle States (DRAFT -> SEALED)
# ============================================================================

class TestBackdoorEvidenceLifecycle:
    """Validation of evidence lifecycle state transitions and immutability."""

    def test_draft_to_sealed_transition(self, sample_statistical_assessment):
        """create_backdoor_evidence produces DRAFT; seal_backdoor_evidence transitions to SEALED."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        draft_ev = create_backdoor_evidence(sample_statistical_assessment, cand)

        assert draft_ev.state == BackdoorEvidenceLifecycleState.DRAFT
        assert draft_ev.sealed_at is None

        sealed_ev = seal_backdoor_evidence(draft_ev)

        assert sealed_ev.state == BackdoorEvidenceLifecycleState.SEALED
        assert sealed_ev.sealed_at is not None
        assert sealed_ev.evidence_id == draft_ev.evidence_id
        assert sealed_ev.content == draft_ev.content

    def test_sealed_idempotency(self, sample_statistical_assessment):
        """Sealing an already-sealed evidence item is idempotent."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        draft_ev = create_backdoor_evidence(sample_statistical_assessment, cand)
        sealed_ev1 = seal_backdoor_evidence(draft_ev)
        sealed_ev2 = seal_backdoor_evidence(sealed_ev1)

        assert sealed_ev1 == sealed_ev2


# ============================================================================
# 3. Cryptographic Provenance Ledger Binding
# ============================================================================

class TestBackdoorProvenanceBinding:
    """Validation of Phase 4/5.9 cryptographic provenance ledger binding."""

    def test_successful_provenance_binding(
        self,
        db_session: Session,
        key_manager: KeyManager,
        sample_statistical_assessment: StatisticalAnalysisAssessment,
    ):
        """Complete workflow: Bind assessment -> FindingModel & EvidenceModel -> ProvenanceRecordModel."""
        service = BackdoorProvenanceBindingService(
            db=db_session,
            key_manager=key_manager,
        )

        prov_records = service.bind_statistical_assessment(
            sample_statistical_assessment,
            model_fingerprint="fp_resnet50_mock",
            key_alias=key_manager.get_active_key_id(),
            signer_passphrase="TestKeyPassphrase123!",
        )

        assert len(prov_records) == 1
        record = prov_records[0]

        assert record.project_id == "proj_001"
        assert record.record_hash is not None
        assert record.signature is not None
        assert record.nonce is not None
        assert record.sequence_number >= 0

        # Verify finding and evidence rows in database
        findings = db_session.query(FindingModel).filter_by(project_id="proj_001").all()
        assert len(findings) == 1
        assert findings[0].finding_type == "BACKDOOR_TRIGGER_ANALYSIS"

        # Verify provenance record row in database
        db_prov = db_session.query(ProvenanceRecordModel).filter_by(project_id="proj_001").all()
        assert len(db_prov) == 1
        assert db_prov[0].record_hash == record.record_hash

        # Verify via ProvenanceBindingAdapter
        res = service.provenance_adapter.verify_finding_provenance(
            finding_id=findings[0].id,
            project_id="proj_001",
        )
        assert res.provenance_status == ProvenanceStatus.VERIFIED
        assert res.cryptographic_validity is True

    def test_project_isolation_enforcement(
        self,
        db_session: Session,
        key_manager: KeyManager,
        sample_statistical_assessment: StatisticalAnalysisAssessment,
    ):
        """Cross-project or nonexistent project binding must fail closed."""
        service = BackdoorProvenanceBindingService(db=db_session, key_manager=key_manager)
        invalid_ass = sample_statistical_assessment.model_copy(update={"project_id": "nonexistent_project_999"})

        with pytest.raises(Exception):
            service.bind_statistical_assessment(invalid_ass)


# ============================================================================
# 4. Tamper Detection & Cryptographic Verification
# ============================================================================

class TestBackdoorTamperDetection:
    """Validation of tamper resistance on sealed backdoor provenance records."""

    def test_tampered_payload_hash_detection(
        self,
        db_session: Session,
        key_manager: KeyManager,
        sample_statistical_assessment: StatisticalAnalysisAssessment,
    ):
        """Mutating payload_hash on a committed record causes verification failure."""
        service = BackdoorProvenanceBindingService(db=db_session, key_manager=key_manager)
        prov_records = service.bind_statistical_assessment(sample_statistical_assessment)
        rec_id = prov_records[0].id

        # Tamper record directly in DB
        db_rec = db_session.query(ProvenanceRecordModel).filter_by(id=rec_id).one()
        db_rec.record_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        db_session.commit()

        # Re-verify via ProvenanceService
        prov_service = ProvenanceService(db=db_session, key_manager=key_manager)
        res = prov_service.verify_record(record_id=rec_id)
        assert res.overall_valid is False
        assert res.record_valid is False


# ============================================================================
# 5. Non-Accusatory Observational Taxonomy Verification
# ============================================================================

class TestSemanticSafety:
    """Ensure evidence content and finding descriptions preserve non-accusatory taxonomy."""

    def test_no_accusatory_language_in_payloads(
        self,
        sample_statistical_assessment: StatisticalAnalysisAssessment,
    ):
        """Evidence content must never serialize forbidden speculative words."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev = create_backdoor_evidence(sample_statistical_assessment, cand)
        payload_str = str(ev.content.model_dump(mode="json")).lower()

        forbidden_terms = [
            "malicious",
            "malicious_actor",
            "attacker_intent",
            "backdoor_confirmed",
            "culpability",
            "poisoning_intent",
        ]
        for term in forbidden_terms:
            assert term not in payload_str


# ============================================================================
# 6. Additional Mutation Sensitivity & Missing State Semantics
# ============================================================================

class TestExtendedEvidenceGuarantees:
    """Validate control TSR, localization, policy mutations and missing value semantics."""

    def test_mutation_sensitivity_control_tsr(
        self, sample_statistical_assessment: StatisticalAnalysisAssessment
    ):
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev_orig = create_backdoor_evidence(sample_statistical_assessment, cand)
        
        mutated_content = ev_orig.content.model_copy(update={"control_baseline_tsr": 0.45})
        assert compute_backdoor_evidence_hash(mutated_content) != ev_orig.evidence_id

    def test_mutation_sensitivity_localization(
        self, sample_statistical_assessment: StatisticalAnalysisAssessment
    ):
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev_orig = create_backdoor_evidence(sample_statistical_assessment, cand)
        
        mutated_content = ev_orig.content.model_copy(
            update={"spatial_localization": {"focal_center_x": 0.99, "focal_center_y": 0.99}}
        )
        assert compute_backdoor_evidence_hash(mutated_content) != ev_orig.evidence_id

    def test_mutation_sensitivity_policy_version(
        self, sample_statistical_assessment: StatisticalAnalysisAssessment
    ):
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev_orig = create_backdoor_evidence(sample_statistical_assessment, cand)
        
        mutated_content = ev_orig.content.model_copy(update={"policy_version": "2.0.0"})
        assert compute_backdoor_evidence_hash(mutated_content) != ev_orig.evidence_id

    def test_preserves_none_and_missing_semantics(
        self, sample_statistical_assessment: StatisticalAnalysisAssessment
    ):
        """Missing or unavailable localization or CIs must remain None, never coerced to 0."""
        cand = sample_statistical_assessment.candidate_summaries[0]
        ev = create_backdoor_evidence(sample_statistical_assessment, cand)
        
        assert ev.content.spatial_localization is None
        ev_dict = ev.content.model_dump(mode="json")
        assert ev_dict["spatial_localization"] is None
        assert ev_dict["spatial_localization"] != 0

    def test_sequence_advancement_and_hash_chaining(
        self,
        db_session: Session,
        key_manager: KeyManager,
        sample_statistical_assessment: StatisticalAnalysisAssessment,
    ):
        """Sequential sealing creates monotonically increasing sequence numbers and unbroken hash links."""
        service = BackdoorProvenanceBindingService(db=db_session, key_manager=key_manager)
        active_key = key_manager.get_active_key_id()

        rec1 = service.bind_statistical_assessment(
            sample_statistical_assessment,
            key_alias=active_key,
            signer_passphrase="TestKeyPassphrase123!",
        )[0]

        # Second assessment
        ass2 = sample_statistical_assessment.model_copy(
            update={"statistical_analysis_id": "stat_id_second_scan"}
        )
        rec2 = service.bind_statistical_assessment(
            ass2,
            key_alias=active_key,
            signer_passphrase="TestKeyPassphrase123!",
        )[0]

        assert rec2.sequence_number == rec1.sequence_number + 1
        assert rec2.previous_record_hash == rec1.record_hash
