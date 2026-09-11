"""Dependency-Aware Evidence Families and family-level dominance evaluator (Phase 6).

Implements ADR-034:
  - Groups detection dimensions into 3 Detection Families and 1 isolated Proof Family.
  - Applies Family-Level Dominance (max differential) to prevent correlated detectors from linearly stacking risk.
  - Strictly isolates Cryptographic Provenance from detection-layer numerical metrics.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple
from aivara.contributor_risk.schemas import (
    DependencyAwareEvidenceFamily,
    DetectionDimension,
    EvidenceFamilyId,
    ProvenanceIntegrityDimension,
    RiskDimensionId,
)


class EvidenceFamilyEvaluator:
    """Evaluator for constructing Dependency-Aware Evidence Families with family-level dominance."""

    @staticmethod
    def evaluate_families(
        detection_dimensions: Sequence[DetectionDimension],
        proof_dimension: ProvenanceIntegrityDimension,
    ) -> Tuple[DependencyAwareEvidenceFamily, ...]:
        """Construct the 4 Dependency-Aware Evidence Families.

        Detection Families:
          - LABEL_INTEGRITY: DIM_LABEL_RELIABILITY, DIM_TRANSITION_ASYM
          - PHYSICAL_QUALITY: DIM_QUALITY_DIVERGENCE
          - DISTRIBUTION_SHIFT: DIM_DISTRIBUTION_SHIFT

        Proof Family (Strictly Isolated):
          - CRYPTOGRAPHIC_PROVENANCE: DIM_PROVENANCE_INTEGRITY
        """
        dim_by_id: Dict[RiskDimensionId, DetectionDimension] = {
            d.dimension_id: d for d in detection_dimensions
        }

        # 1. Family: LABEL_INTEGRITY
        label_dims = (RiskDimensionId.DIM_LABEL_RELIABILITY, RiskDimensionId.DIM_TRANSITION_ASYM)
        label_family = EvidenceFamilyEvaluator._build_detection_family(
            family_id=EvidenceFamilyId.LABEL_INTEGRITY,
            family_name="Label Integrity Family",
            constituent_ids=label_dims,
            dimensions_map=dim_by_id,
        )

        # 2. Family: PHYSICAL_QUALITY
        quality_dims = (RiskDimensionId.DIM_QUALITY_DIVERGENCE,)
        quality_family = EvidenceFamilyEvaluator._build_detection_family(
            family_id=EvidenceFamilyId.PHYSICAL_QUALITY,
            family_name="Physical Quality Family",
            constituent_ids=quality_dims,
            dimensions_map=dim_by_id,
        )

        # 3. Family: DISTRIBUTION_SHIFT
        shift_dims = (RiskDimensionId.DIM_DISTRIBUTION_SHIFT,)
        shift_family = EvidenceFamilyEvaluator._build_detection_family(
            family_id=EvidenceFamilyId.DISTRIBUTION_SHIFT,
            family_name="Distribution Shift Family",
            constituent_ids=shift_dims,
            dimensions_map=dim_by_id,
        )

        # 4. Family: CRYPTOGRAPHIC_PROVENANCE (Proof Layer - STRICTLY ISOLATED)
        prov_dims = (RiskDimensionId.DIM_PROVENANCE_INTEGRITY,)
        prov_evidence_count = len(proof_dimension.primary_evidence_ids)
        prov_family = DependencyAwareEvidenceFamily(
            family_id=EvidenceFamilyId.CRYPTOGRAPHIC_PROVENANCE,
            family_name="Cryptographic Provenance Family",
            evidence_layer="proof",
            constituent_dimensions=prov_dims,
            dominant_differential=None,  # Proof layer has no statistical differential
            dominant_dimension_id=RiskDimensionId.DIM_PROVENANCE_INTEGRITY,
            evidence_count=prov_evidence_count,
            is_proof_layer=True,
        )

        return (label_family, quality_family, shift_family, prov_family)

    @staticmethod
    def _build_detection_family(
        family_id: EvidenceFamilyId,
        family_name: str,
        constituent_ids: Tuple[RiskDimensionId, ...],
        dimensions_map: Dict[RiskDimensionId, DetectionDimension],
    ) -> DependencyAwareEvidenceFamily:
        """Build detection family applying the family dominance rule (max differential)."""
        dominant_diff: Optional[float] = None
        dominant_id: Optional[RiskDimensionId] = None
        total_ev_count: int = 0

        for dim_id in constituent_ids:
            dim = dimensions_map.get(dim_id)
            if dim is None:
                continue

            total_ev_count += len(dim.primary_evidence_ids)
            diff = dim.differential

            if diff is not None:
                if dominant_diff is None or diff > dominant_diff:
                    dominant_diff = diff
                    dominant_id = dim_id

        return DependencyAwareEvidenceFamily(
            family_id=family_id,
            family_name=family_name,
            evidence_layer="detection",
            constituent_dimensions=constituent_ids,
            dominant_differential=dominant_diff,
            dominant_dimension_id=dominant_id,
            evidence_count=total_ev_count,
            is_proof_layer=False,
        )
