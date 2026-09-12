"""Replay policy definitions and validation for Phase 10.9."""

from aivara.inference.exceptions import ReplayVersionUnsupportedError
from aivara.inference.replay.enums import ReplayMode
from aivara.inference.replay.models import ReplayPolicy

SUPPORTED_REPLAY_SCHEMA_VERSIONS = {"1.0"}
SUPPORTED_REPLAY_POLICY_VERSIONS = {"1.0"}

DEFAULT_DETERMINISTIC_POLICY = ReplayPolicy(
    policy_version="1.0",
    mode=ReplayMode.DETERMINISTIC,
    atol=0.0,
    rtol=0.0,
    allow_dtype_variance=False,
    allow_provider_variance=False,
    allow_nonfinite_if_recorded=False,
)

DEFAULT_TOLERANT_POLICY = ReplayPolicy(
    policy_version="1.0",
    mode=ReplayMode.NUMERICALLY_TOLERANT,
    atol=1e-5,
    rtol=1e-4,
    allow_dtype_variance=False,
    allow_provider_variance=False,
    allow_nonfinite_if_recorded=False,
)


def validate_replay_policy(policy: ReplayPolicy) -> None:
    """Validate that a ReplayPolicy conforms to supported specification versions and parameters."""
    if policy.policy_version not in SUPPORTED_REPLAY_POLICY_VERSIONS:
        raise ReplayVersionUnsupportedError(
            f"Unsupported replay policy_version: '{policy.policy_version}'. "
            f"Supported versions: {sorted(SUPPORTED_REPLAY_POLICY_VERSIONS)}.",
            details={"policy_version": policy.policy_version},
        )

    if policy.atol < 0.0 or policy.rtol < 0.0:
        raise ValueError("Tolerances 'atol' and 'rtol' must be non-negative real numbers.")
