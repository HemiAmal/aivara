"""Enumerations for Universal Evidence Normalization (Phase 12.2).

Enforces:
- Exact seven upstream assurance domains in canonical Phase 12.1 ordering.
- Controlled ancestry classification taxonomy.
- Strict versioning enums for schemas and envelopes.
"""

from enum import Enum


class SubsystemDomain(str, Enum):
    """Authoritative seven upstream assurance domains in canonical Phase 12.1 order.
    
    1. DATASET_INTEGRITY (Phase 5)
    2. CONTRIBUTOR_RISK (Phase 6)
    3. MODEL_INTEGRITY (Phase 7)
    4. BEHAVIORAL_ANALYSIS (Phase 8)
    5. BACKDOOR_TRIGGER (Phase 9)
    6. INFERENCE_INTEGRITY (Phase 10)
    7. DISTRIBUTION_SHIFT (Phase 11)
    """

    DATASET_INTEGRITY = "DATASET_INTEGRITY"
    CONTRIBUTOR_RISK = "CONTRIBUTOR_RISK"
    MODEL_INTEGRITY = "MODEL_INTEGRITY"
    BEHAVIORAL_ANALYSIS = "BEHAVIORAL_ANALYSIS"
    BACKDOOR_TRIGGER = "BACKDOOR_TRIGGER"
    INFERENCE_INTEGRITY = "INFERENCE_INTEGRITY"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"


class AncestryStatus(str, Enum):
    """Cryptographic evidence ancestry verification status."""

    VERIFIED = "VERIFIED"          # Complete, authenticated ancestry vector present
    UNVERIFIED = "UNVERIFIED"      # Missing or partial ancestry; flags INSUFFICIENT_EVIDENCE
    NOT_APPLICABLE = "NOT_APPLICABLE"  # Genesis project root or synthetic baseline


class NormalizationStatus(str, Enum):
    """Result status of an evidence normalization operation."""

    NORMALIZED = "NORMALIZED"
    REJECTED = "REJECTED"
    UNSUPPORTED = "UNSUPPORTED"


class SchemaVersion(str, Enum):
    """Version of the universal evidence schema specification."""

    V1_0 = "1.0.0"


class EnvelopeVersion(str, Enum):
    """Version of the universal evidence envelope structure."""

    V1_0 = "1.0.0"


class AdapterVersion(str, Enum):
    """Version of the domain normalization adapter specification."""

    V1_0 = "1.0.0"
