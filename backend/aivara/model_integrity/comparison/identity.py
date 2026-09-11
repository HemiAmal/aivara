"""Cryptographic identity and artifact hash comparisons (Phase 7.5).

Evaluates byte-level artifact hash equality and Master Model Fingerprint (ADR-040) alignment.
"""

from __future__ import annotations

from typing import Optional, Tuple

from aivara.model_integrity.comparison.schemas import ArtifactComparisonStatus


def compare_artifact_hashes(
    reference_hash: Optional[str],
    candidate_hash: Optional[str],
) -> Tuple[ArtifactComparisonStatus, bool]:
    """Compare raw file SHA-256 digests between reference and candidate models.

    Args:
        reference_hash: 64-char lowercase hex SHA-256 of reference artifact.
        candidate_hash: 64-char lowercase hex SHA-256 of candidate artifact.

    Returns:
        Tuple of (ArtifactComparisonStatus, is_exact_match_bool).
    """
    if not reference_hash or not candidate_hash:
        return ArtifactComparisonStatus.ARTIFACT_UNAVAILABLE, False

    ref_clean = reference_hash.strip().lower()
    cand_clean = candidate_hash.strip().lower()

    if ref_clean == cand_clean:
        return ArtifactComparisonStatus.ARTIFACT_MATCH, True

    return ArtifactComparisonStatus.ARTIFACT_DIFFERENT, False


def compare_master_fingerprints(
    reference_master: Optional[str],
    candidate_master: Optional[str],
) -> bool:
    """Compare canonical Master Model Fingerprints (ADR-040).

    Args:
        reference_master: Master fingerprint of reference model.
        candidate_master: Master fingerprint of candidate model.

    Returns:
        True if both fingerprints are present and match identically.
    """
    if not reference_master or not candidate_master:
        return False

    return reference_master.strip().lower() == candidate_master.strip().lower()
