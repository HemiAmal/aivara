"""AIVARA Multi-Modal Evidence, Findings & Risk Integration Package (Phase 11.9)."""

from aivara.assurance.enums import (
    DependencyRelation,
    EvidenceCategory,
    IntegrationEvaluationStatus,
)
from aivara.assurance.exceptions import (
    AssuranceIntegrationError,
    ConflictingEvidenceError,
    InsufficientEvidenceError,
    InvalidEvidenceError,
    PolicyValidationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.assurance.hashing import (
    compute_decision_policy_hash,
    compute_evidence_set_hash,
    compute_integrated_profile_hash,
    compute_risk_policy_hash,
)
from aivara.assurance.schemas import (
    DEFAULT_CATEGORY_WEIGHTS,
    DecisionPolicy,
    EvidenceReference,
    IntegratedAssuranceProfile,
    ModalityCluster,
    RiskPolicy,
    SynthesizedFinding,
)
from aivara.assurance.engine import (
    MAX_CLUSTERS_LIMIT,
    MAX_EVIDENCE_ITEMS_LIMIT,
    MAX_FINDINGS_LIMIT,
    MultiModalRiskIntegrationEngine,
)

__all__ = [
    "AssuranceIntegrationError",
    "ConflictingEvidenceError",
    "DEFAULT_CATEGORY_WEIGHTS",
    "DecisionPolicy",
    "DependencyRelation",
    "EvidenceCategory",
    "EvidenceReference",
    "InsufficientEvidenceError",
    "IntegratedAssuranceProfile",
    "IntegrationEvaluationStatus",
    "InvalidEvidenceError",
    "MAX_CLUSTERS_LIMIT",
    "MAX_EVIDENCE_ITEMS_LIMIT",
    "MAX_FINDINGS_LIMIT",
    "ModalityCluster",
    "MultiModalRiskIntegrationEngine",
    "PolicyValidationError",
    "ProjectMismatchError",
    "ResourceLimitExceededError",
    "RiskPolicy",
    "SynthesizedFinding",
    "compute_decision_policy_hash",
    "compute_evidence_set_hash",
    "compute_integrated_profile_hash",
    "compute_risk_policy_hash",
]
