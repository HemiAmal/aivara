"""AIVARA Contributor Risk Engine (Phase 6).

Provides evidence-backed, multi-dimensional risk profiling for contributors
under ADR-028, ADR-030 through ADR-039:
  - Multi-dimensional detection vs. proof separation (ADR-030)
  - Contextual Leave-One-Out and class-conditional baselines (ADR-031)
  - Beta-Binomial Empirical Bayes prior shrinkage (ADR-032)
  - 1/K fractional attribution conservation (ADR-033)
  - Dependency-Aware Evidence Families (ADR-034)
  - Strict human-intent / culpability prohibition (ADR-035)
"""

from aivara.contributor_risk.baselines import ContextualBaselineEngine
from aivara.contributor_risk.bayes import (
    EmpiricalBayesResult,
    compute_empirical_bayes_shrinkage,
    determine_support_state,
)
from aivara.contributor_risk.engine import (
    ContributorInputContext,
    ContributorRiskEngine,
    DatasetBackgroundContext,
    validate_semantic_safety,
)
from aivara.contributor_risk.service import ContributorRiskService
from aivara.contributor_risk.exceptions import (
    ContributorRiskError,
    CrossProjectContaminationError,
    InsufficientEvidenceError,
    InvalidBaselineError,
    SemanticSafetyViolationError,
    SupportStateError,
)
from aivara.contributor_risk.families import EvidenceFamilyEvaluator
from aivara.contributor_risk.schemas import (
    BaselineType,
    ContextualBaseline,
    ContributorRiskConfig,
    ContributorRiskIndicator,
    ContributorRiskProfile,
    DependencyAwareEvidenceFamily,
    DetectionDimension,
    DetectionProfile,
    DistributionShiftDimension,
    EvaluationStatus,
    EvidenceFamilyId,
    LabelReliabilityDimension,
    OverallProfileStatus,
    ProofProfile,
    ProvenanceIntegrityDimension,
    QualityDivergenceDimension,
    RiskDimensionId,
    SupportState,
    TransitionAsymmetryDimension,
)

__all__ = [
    # Engine & Helpers
    "ContributorRiskEngine",
    "ContributorRiskService",
    "ContributorInputContext",
    "DatasetBackgroundContext",
    "ContextualBaselineEngine",
    "EvidenceFamilyEvaluator",
    "validate_semantic_safety",
    "compute_empirical_bayes_shrinkage",
    "determine_support_state",
    "EmpiricalBayesResult",
    # Enums
    "SupportState",
    "EvaluationStatus",
    "RiskDimensionId",
    "EvidenceFamilyId",
    "BaselineType",
    "OverallProfileStatus",
    # Schemas & Models
    "ContextualBaseline",
    "DetectionDimension",
    "LabelReliabilityDimension",
    "TransitionAsymmetryDimension",
    "QualityDivergenceDimension",
    "DistributionShiftDimension",
    "ProvenanceIntegrityDimension",
    "DetectionProfile",
    "ProofProfile",
    "DependencyAwareEvidenceFamily",
    "ContributorRiskIndicator",
    "ContributorRiskProfile",
    "ContributorRiskConfig",
    # Exceptions
    "ContributorRiskError",
    "InsufficientEvidenceError",
    "SupportStateError",
    "InvalidBaselineError",
    "CrossProjectContaminationError",
    "SemanticSafetyViolationError",
]
