"""Phase 10.9 Replay & Consistency Verification subsystem."""

from aivara.inference.replay.comparator import compare_raw_outputs
from aivara.inference.replay.engine import (
    assess_replay_eligibility,
    execute_replay_transaction,
    verify_replay_consistency,
)
from aivara.inference.replay.enums import (
    ComparisonStatus,
    ReplayConsistencyStatus,
    ReplayEligibilityStatus,
    ReplayMode,
)
from aivara.inference.replay.models import (
    ReplayComparisonResult,
    ReplayEnvironment,
    ReplayPolicy,
    ReplayVerificationResult,
)
from aivara.inference.replay.policy import (
    DEFAULT_DETERMINISTIC_POLICY,
    DEFAULT_TOLERANT_POLICY,
    SUPPORTED_REPLAY_POLICY_VERSIONS,
    SUPPORTED_REPLAY_SCHEMA_VERSIONS,
    validate_replay_policy,
)
from aivara.inference.replay.service import InferenceReplayService

__all__ = [
    # Enums
    "ReplayEligibilityStatus",
    "ReplayMode",
    "ReplayConsistencyStatus",
    "ComparisonStatus",
    # Models
    "ReplayPolicy",
    "ReplayEnvironment",
    "ReplayComparisonResult",
    "ReplayVerificationResult",
    # Policies
    "DEFAULT_DETERMINISTIC_POLICY",
    "DEFAULT_TOLERANT_POLICY",
    "SUPPORTED_REPLAY_POLICY_VERSIONS",
    "SUPPORTED_REPLAY_SCHEMA_VERSIONS",
    "validate_replay_policy",
    # Engine & Comparator
    "compare_raw_outputs",
    "assess_replay_eligibility",
    "execute_replay_transaction",
    "verify_replay_consistency",
    # Service
    "InferenceReplayService",
]
