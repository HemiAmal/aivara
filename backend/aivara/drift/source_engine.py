"""Authoritative Contributor & Source-Aware Distribution Shift Engine.

Executes deterministic source attribute extraction, 5-stage canonicalization,
project-scoped pseudonymization, source group partitioning, exact reconciliation accounting,
Source-vs-Reference O(G) statistical comparisons via Phase 11.3 StatisticalDriftEngine,
Benjamini-Hochberg FDR error control (q* = 0.05), dual-gate significance and effect evaluation,
and confounding / Simpson's paradox protection.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import math
import random
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
import unicodedata

import numpy as np

from aivara.crypto.canonical import canonicalize
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    DataModality,
    MultipleTestingCorrectionMethod,
    ShiftDecisionState,
    SourceAttributeFallbackPolicy,
    SourceComparisonTopology,
    SourceGroupStatus,
    SourceTrustState,
    SourceType,
    StatisticalMethod,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    IncompatiblePopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.stats_continuous import compute_psi, compute_two_sample_ks
from aivara.drift.stats_categorical import compute_chi_square_test, compute_total_variation_distance
from aivara.drift.stats_multivariate import compute_kernel_mmd, compute_permutation_p_value
from aivara.drift.multiple_testing import apply_benjamini_hochberg
from aivara.drift.population import deterministic_subsample
from aivara.drift.schemas import (
    ComparisonBoundaryResult,
    SourceAnalysisContract,
    SourceAnalysisProfile,
    SourceAttributeSelector,
    SourceComparisonResult,
    SourceContext,
    SourceGroupAccounting,
    SourceGroupDescriptor,
    SourceObservation,
)

# Hard resource boundaries per frozen Phase 11.8.1 architecture
MAX_SOURCE_GROUPS_CEILING: int = 50
MAX_SOURCE_GROUP_SAMPLE_BUDGET: int = 5000
MIN_SOURCE_GROUP_SAMPLE_FLOOR: int = 30
CONFOUNDING_LABEL_TVD_THRESHOLD: float = 0.15
EXCESSIVE_FRAGMENTATION_THRESHOLD: float = 0.20


def compute_source_contract_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 cryptographic digest over canonical RFC 8785 source contract descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_source_group_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 cryptographic digest over canonical RFC 8785 source group descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_source_analysis_profile_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 cryptographic digest over canonical RFC 8785 source profile descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def canonicalize_source_id(raw_id: Any) -> str:
    """Execute authoritative 5-stage deterministic canonicalization pipeline on raw source strings.

    Pipeline:
    1. Unicode NFKC normalization
    2. Strip non-printable / control characters
    3. Trim leading/trailing whitespace & collapse multiple whitespace to single space
    4. Lowercase fold
    5. Length cap to 128 characters (fallback 'missing' on empty)
    """
    if raw_id is None:
        return "missing"

    s_raw = str(raw_id)
    if not s_raw:
        return "missing"

    # Stage 1: Unicode NFKC normalization
    s_norm = unicodedata.normalize("NFKC", s_raw)

    # Stage 2: Strip non-printable characters while preserving whitespace
    s_printable = "".join(ch for ch in s_norm if ch.isprintable() or ch.isspace())

    # Stage 3: Trim and collapse whitespace
    s_trimmed = re.sub(r"\s+", " ", s_printable).strip()

    # Stage 4: Lowercase fold
    s_folded = s_trimmed.lower()

    # Stage 5: Length cap (128) & fallback
    if not s_folded:
        return "missing"

    if len(s_folded) > 128:
        s_folded = s_folded[:128]

    return s_folded



def _subsample_payloads(payloads: List[Any], max_samples: int, seed: int) -> List[Any]:
    if len(payloads) <= max_samples:
        return payloads
    rng = random.Random(seed)
    indices = sorted(rng.sample(range(len(payloads)), max_samples))
    return [payloads[i] for i in indices]


def derive_project_scoped_pseudonym(
    project_id: str,
    canonical_source_id: str,
    salt: Optional[str] = None
) -> str:
    """
    Derives a project-scoped pseudonym ID.
    PseudonymID = SHA-256(project_id || salt || canonical_source_id)[:16]
    """
    effective_salt = salt or f"aivara-salt-{project_id}"
    raw_material = f"{project_id}{effective_salt}{canonical_source_id}".encode("utf-8")
    return hashlib.sha256(raw_material).hexdigest()[:16]


def extract_source_context(
    item: Union[Dict[str, Any], SourceObservation],
    selector: SourceAttributeSelector,
    project_id: str,
    salt: str = "aivara_source_salt",
) -> SourceContext:
    """Extract and canonicalize source context from an observation dictionary or instance."""
    if isinstance(item, SourceObservation):
        return item.source_context

    raw_val: Any = None
    if isinstance(item, dict):
        # Support nested keys (e.g. "metadata.contributor_id")
        key_parts = selector.attribute_key.split(".")
        curr: Any = item
        for p in key_parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                curr = None
                break
        raw_val = curr

    raw_str = str(raw_val) if raw_val is not None else None
    canonical_id = canonicalize_source_id(raw_str)

    trust_state = SourceTrustState.CLAIMED
    if canonical_id == "missing":
        if selector.fallback_policy == SourceAttributeFallbackPolicy.FAIL_CLOSED:
            raise ValueError(f"Missing required source attribute '{selector.attribute_key}'.")
        elif selector.fallback_policy == SourceAttributeFallbackPolicy.ASSIGN_UNKNOWN:
            canonical_id = "unknown"
            trust_state = SourceTrustState.UNKNOWN
        else:
            trust_state = SourceTrustState.UNKNOWN

    pseudonym_id = derive_project_scoped_pseudonym(project_id, canonical_id, salt=salt)

    return SourceContext(
        raw_source_id=raw_str,
        source_type=selector.source_type,
        canonical_source_id=canonical_id,
        pseudonym_id=pseudonym_id,
        trust_state=trust_state,
        metadata_version="1.0",
        metadata={},
    )


class SourceDistributionShiftEngine:
    """Authoritative Contributor and Source-Aware Distribution Shift Analysis Engine."""

    def __init__(
        self,
        statistical_engine: Optional[StatisticalDriftEngine] = None,
    ) -> None:
        self.statistical_engine = statistical_engine or StatisticalDriftEngine()

    def analyze(
        self,
        observations: Sequence[Union[Dict[str, Any], SourceObservation]],
        contract: SourceAnalysisContract,
        boundary_result: Optional[ComparisonBoundaryResult] = None,
        project_id: str = "default_project",
        reference_dataset_id: str = "reference_dataset",
        target_dataset_id: str = "target_dataset",
        salt: str = "aivara_source_salt",
    ) -> SourceAnalysisProfile:
        """Execute end-to-end source-aware distribution shift analysis.

        Args:
            observations: Time/source-indexed observation sequence.
            contract: Validated SourceAnalysisContract.
            boundary_result: Optional upstream comparison boundary.
            project_id: Target tenant project identifier.
            reference_dataset_id: Reference dataset identifier.
            target_dataset_id: Target dataset identifier.
            salt: Deterministic project-scoped pseudonymization salt.

        Returns:
            Canonical, content-addressed SourceAnalysisProfile.
        """
        if boundary_result is not None and boundary_result.contract.project_id != project_id:
            raise ProjectMismatchError(
                f"Project mismatch: boundary '{boundary_result.contract.project_id}' vs analysis '{project_id}'."
            )

        # 1. Compute and bind contract hash
        contract_dict = contract.to_canonical_dict()
        contract_hash = compute_source_contract_hash(contract_dict)
        bound_contract = contract.model_copy(update={"source_contract_hash": contract_hash})

        # 2. Partition observations into SourceContext items and groups
        total_obs = len(observations)
        source_obs_list: List[SourceObservation] = []
        missing_count = 0
        invalid_count = 0
        unknown_count = 0

        for idx, item in enumerate(observations):
            sample_id: str
            payload: Any = None
            label: Optional[str] = None
            timestamp_utc: Optional[str] = None
            metadata: Dict[str, Any] = {}

            if isinstance(item, SourceObservation):
                sample_id = item.sample_id
                s_ctx = item.source_context
                payload = item.payload
                label = item.label
                timestamp_utc = item.timestamp_utc
                metadata = item.metadata
            elif isinstance(item, dict):
                sample_id = str(item.get("sample_id", f"sample_{idx:05d}"))
                s_ctx = extract_source_context(item, bound_contract.selector, project_id, salt=salt)
                payload = item.get("payload", item.get("features", item.get("data", None)))
                label = str(item["label"]) if "label" in item and item["label"] is not None else None
                timestamp_utc = item.get("timestamp_utc", None)
                metadata = item.get("metadata", {})
            else:
                sample_id = f"sample_{idx:05d}"
                s_ctx = extract_source_context({}, bound_contract.selector, project_id, salt=salt)

            # Track accounting category
            if s_ctx.canonical_source_id == "missing":
                missing_count += 1
            elif s_ctx.canonical_source_id == "invalid":
                invalid_count += 1
            elif s_ctx.canonical_source_id == "unknown":
                unknown_count += 1

            source_obs_list.append(
                SourceObservation(
                    sample_id=sample_id,
                    source_context=s_ctx,
                    payload=payload,
                    label=label,
                    timestamp_utc=timestamp_utc,
                    metadata=metadata,
                )
            )

        # 3. Group observations by canonical_source_id
        groups_map: Dict[str, List[SourceObservation]] = {}
        for obs in source_obs_list:
            cid = obs.source_context.canonical_source_id
            if cid not in groups_map:
                groups_map[cid] = []
            groups_map[cid].append(obs)

        # Enforce maximum group limit
        total_groups_formed = len(groups_map)
        if total_groups_formed > bound_contract.max_source_groups or total_groups_formed > MAX_SOURCE_GROUPS_CEILING:
            raise ResourceLimitExceededError(
                f"Source group count ({total_groups_formed}) exceeds maximum limit ({bound_contract.max_source_groups})."
            )

        # 4. Form SourceGroupDescriptors and evaluate eligibility
        eligible_groups: Dict[str, List[SourceObservation]] = {}
        insufficient_groups: Dict[str, List[SourceObservation]] = {}
        group_descriptors: List[SourceGroupDescriptor] = []
        eligible_obs_count = 0
        insufficient_obs_count = 0

        # Sort group keys deterministically
        sorted_cids = sorted(groups_map.keys())

        for cid in sorted_cids:
            obs_group = groups_map[cid]
            cnt = len(obs_group)
            first_ctx = obs_group[0].source_context
            raw_id = first_ctx.raw_source_id or cid

            # Compute label distribution if labels present
            labels = [o.label for o in obs_group if o.label is not None]
            class_props: Dict[str, float] = {}
            if labels:
                counts = Counter(labels)
                total_lbls = len(labels)
                class_props = {k: v / total_lbls for k, v in counts.items()}

            # Track timestamps if present
            ts_list = [o.timestamp_utc for o in obs_group if o.timestamp_utc is not None]
            ts_earliest = min(ts_list) if ts_list else None
            ts_latest = max(ts_list) if ts_list else None

            # Determine eligibility status
            if cid in ("missing", "invalid", "unknown"):
                status = SourceGroupStatus.EXCLUDED
            elif cnt >= bound_contract.min_group_samples:
                status = SourceGroupStatus.ELIGIBLE
                eligible_groups[cid] = obs_group
                eligible_obs_count += cnt
            else:
                status = SourceGroupStatus.INSUFFICIENT_DATA
                insufficient_groups[cid] = obs_group
                insufficient_obs_count += cnt

            # Compute group hash
            desc_dict = {
                "canonical_source_id": cid,
                "class_proportions": {k: float(v) for k, v in sorted(class_props.items())},
                "earliest_timestamp_utc": ts_earliest or "",
                "latest_timestamp_utc": ts_latest or "",
                "pseudonym_id": first_ctx.pseudonym_id,
                "sample_count": cnt,
                "source_id": raw_id,
                "source_type": first_ctx.source_type.value,
                "status": status.value,
            }
            ghash = compute_source_group_hash(desc_dict)

            group_descriptors.append(
                SourceGroupDescriptor(
                    source_id=raw_id,
                    canonical_source_id=cid,
                    pseudonym_id=first_ctx.pseudonym_id,
                    source_type=first_ctx.source_type,
                    sample_count=cnt,
                    status=status,
                    class_proportions=class_props,
                    earliest_timestamp_utc=ts_earliest,
                    latest_timestamp_utc=ts_latest,
                    group_hash=ghash,
                )
            )

        # 5. Compute accounting and fragmentation ratio
        sub_thresh_ratio = float(insufficient_obs_count) / float(total_obs) if total_obs > 0 else 0.0
        excessive_fragmentation = sub_thresh_ratio > EXCESSIVE_FRAGMENTATION_THRESHOLD

        accounting = SourceGroupAccounting(
            total_observations=total_obs,
            eligible_observations=eligible_obs_count,
            insufficient_observations=insufficient_obs_count,
            missing_source_observations=missing_count,
            invalid_source_observations=invalid_count,
            unknown_source_observations=unknown_count,
            total_groups_formed=total_groups_formed,
            eligible_groups_count=len(eligible_groups),
            insufficient_groups_count=len(insufficient_groups),
            sub_threshold_sample_ratio=sub_thresh_ratio,
            excessive_fragmentation_detected=excessive_fragmentation,
        )

        # 6. Select reference group
        ref_cid = bound_contract.reference_source_id
        if ref_cid:
            ref_cid_norm = canonicalize_source_id(ref_cid)
        else:
            ref_cid_norm = sorted_cids[0] if sorted_cids else "reference"

        ref_descriptor: Optional[SourceGroupDescriptor] = None
        for gd in group_descriptors:
            if gd.canonical_source_id == ref_cid_norm:
                ref_descriptor = gd
                break

        # 7. Execute O(G) Source-vs-Reference statistical comparisons
        comparisons: List[SourceComparisonResult] = []
        ref_samples = eligible_groups.get(ref_cid_norm, [])

        # If no explicit reference samples in eligible groups, fallback to first eligible
        if not ref_samples and eligible_groups:
            first_eligible_cid = sorted(eligible_groups.keys())[0]
            ref_samples = eligible_groups[first_eligible_cid]
            ref_cid_norm = first_eligible_cid
            for gd in group_descriptors:
                if gd.canonical_source_id == ref_cid_norm:
                    ref_descriptor = gd
                    break

        if ref_samples and len(eligible_groups) >= 1:
            # Subsample reference if needed
            ref_payloads = [o.payload for o in ref_samples if o.payload is not None]
            if len(ref_payloads) > bound_contract.max_group_samples:
                ref_payloads = _subsample_payloads(
                    ref_payloads,
                    max_samples=bound_contract.max_group_samples,
                    seed=bound_contract.subsampling_seed,
                )

            for target_cid, target_obs_list in sorted(eligible_groups.items()):
                if target_cid == ref_cid_norm:
                    continue  # Skip self comparison in output

                target_payloads = [o.payload for o in target_obs_list if o.payload is not None]
                if len(target_payloads) > bound_contract.max_group_samples:
                    # Seed derives from (contract_seed + target_cid)
                    t_seed = int(hashlib.sha256(f"{bound_contract.subsampling_seed}:{target_cid}".encode()).hexdigest()[:8], 16)
                    target_payloads = _subsample_payloads(
                        target_payloads,
                        max_samples=bound_contract.max_group_samples,
                        seed=t_seed,
                    )

                # Check confounding via label TVD
                ref_lbl_props = ref_descriptor.class_proportions if ref_descriptor else {}
                target_desc = next((gd for gd in group_descriptors if gd.canonical_source_id == target_cid), None)
                tgt_lbl_props = target_desc.class_proportions if target_desc else {}

                label_tvd = self._calculate_label_tvd(ref_lbl_props, tgt_lbl_props)
                is_confounded = label_tvd >= CONFOUNDING_LABEL_TVD_THRESHOLD

                # Perform pairwise test
                comp_res = self._evaluate_pairwise_source_drift(
                    reference_payloads=ref_payloads,
                    target_payloads=target_payloads,
                    target_source_id=target_desc.source_id if target_desc else target_cid,
                    target_pseudonym_id=target_desc.pseudonym_id if target_desc else target_cid,
                    reference_source_id=ref_descriptor.source_id if ref_descriptor else ref_cid_norm,
                    label_tvd=label_tvd,
                    potential_label_confounding=is_confounded,
                )
                comparisons.append(comp_res)

        # 8. Apply Benjamini-Hochberg FDR control (q* = 0.05) across comparison family
        if comparisons:
            p_val_map: Dict[str, float] = {}
            for c in comparisons:
                if c.raw_p_value is not None and not math.isnan(c.raw_p_value):
                    p_val_map[c.comparison_id] = float(c.raw_p_value)
                else:
                    p_val_map[c.comparison_id] = 1.0

            bh_results = apply_benjamini_hochberg(p_val_map, q_star=bound_contract.fdr_alpha)

            adjusted_comparisons: List[SourceComparisonResult] = []
            for c in comparisons:
                res_item = bh_results.get(c.comparison_id, {})
                adj_p = res_item.get("adjusted_p_value", c.raw_p_value)
                is_stat_sig = res_item.get("is_significant", (adj_p is not None and adj_p <= bound_contract.fdr_alpha))
                is_pract_sig = c.is_practically_significant

                if is_stat_sig and is_pract_sig:
                    status = ShiftDecisionState.MATERIAL_SHIFT
                elif is_stat_sig:
                    status = ShiftDecisionState.SIGNIFICANT_SHIFT
                else:
                    status = ShiftDecisionState.NO_SHIFT_DETECTED

                adjusted_comparisons.append(
                    c.model_copy(
                        update={
                            "adjusted_p_value": adj_p,
                            "is_statistically_significant": is_stat_sig,
                            "status": status,
                        }
                    )
                )
            comparisons = adjusted_comparisons


        # 9. Determine global status and rank sources deterministically
        material_shift_count = sum(1 for c in comparisons if c.status == ShiftDecisionState.MATERIAL_SHIFT)
        confounded_count = sum(1 for c in comparisons if c.potential_label_confounding)

        if material_shift_count > 0:
            global_status = ShiftDecisionState.MATERIAL_SHIFT
        elif any(c.status == ShiftDecisionState.SIGNIFICANT_SHIFT for c in comparisons):
            global_status = ShiftDecisionState.SIGNIFICANT_SHIFT
        elif not eligible_groups:
            global_status = ShiftDecisionState.INSUFFICIENT_DATA
        else:
            global_status = ShiftDecisionState.NO_SHIFT_DETECTED

        # Rank target sources: (MaterialShift desc, MaxEffect desc, MinP asc, SampleCount desc, SourceID asc)
        ranked_source_ids = self._rank_sources(comparisons, group_descriptors)

        # 10. Synthesize findings and evidence
        findings: List[Dict[str, Any]] = []
        evidence_records: List[Dict[str, Any]] = []

        if excessive_fragmentation:
            findings.append(
                {
                    "finding_type": "EXCESSIVE_SOURCE_FRAGMENTATION",
                    "category": "SOURCE_DISTRIBUTION_ADVISORY",
                    "severity": "LOW",
                    "confidence": 0.95,
                    "description": (
                        f"Excessive source fragmentation detected: {sub_thresh_ratio * 100:.1f}% of observations "
                        f"reside in sub-threshold source groups (N < {bound_contract.min_group_samples})."
                    ),
                    "details": {
                        "sub_threshold_sample_ratio": sub_thresh_ratio,
                        "insufficient_groups_count": len(insufficient_groups),
                        "total_observations": total_obs,
                    },
                }
            )

        for c in comparisons:
            if c.status in (ShiftDecisionState.MATERIAL_SHIFT, ShiftDecisionState.SIGNIFICANT_SHIFT):
                confounding_note = (
                    " [NOTE: Potential label distribution confounding detected]"
                    if c.potential_label_confounding
                    else ""
                )
                findings.append(
                    {
                        "finding_type": "SOURCE_ASSOCIATED_DISTRIBUTION_SHIFT",
                        "category": "SOURCE_DISTRIBUTION_SHIFT",
                        "severity": "MEDIUM" if c.status == ShiftDecisionState.MATERIAL_SHIFT else "LOW",
                        "confidence": float(max(0.5, min(0.99, 1.0 - (c.adjusted_p_value or 0.05)))),
                        "description": (
                            f"Source-associated distributional divergence observed for source '{c.target_source_id}' "
                            f"relative to reference '{c.reference_source_id}' (Effect = {c.effect_size:.3f}, "
                            f"adj_p = {c.adjusted_p_value:.4f}){confounding_note}."
                        ),
                        "details": {
                            "target_source_id": c.target_source_id,
                            "target_pseudonym_id": c.target_pseudonym_id,
                            "reference_source_id": c.reference_source_id,
                            "effect_metric": c.effect_metric,
                            "effect_size": c.effect_size,
                            "adjusted_p_value": c.adjusted_p_value,
                            "potential_label_confounding": c.potential_label_confounding,
                        },
                    }
                )

        evidence_records.append(
            {
                "evidence_id": f"ev-source-{project_id[:8]}",
                "evidence_type": "source_distribution_shift",
                "evidence_layer": "detection",
                "content": {
                    "project_id": project_id,
                    "target_dataset_id": target_dataset_id,
                    "reference_dataset_id": reference_dataset_id,
                    "accounting": accounting.to_canonical_dict(),
                    "comparisons_count": len(comparisons),
                    "material_shift_count": material_shift_count,
                    "confounded_source_count": confounded_count,
                },
            }
        )

        # 11. Construct canonical profile and compute hash
        boundary_hash = boundary_result.comparison_boundary_hash if boundary_result else "0" * 64
        profile_canonical_dict = {
            "accounting": accounting.to_canonical_dict(),
            "analysis_version": "1.0",
            "comparison_boundary_hash": boundary_hash,
            "comparisons": [c.to_canonical_dict() for c in comparisons],
            "confounded_source_count": confounded_count,
            "global_status": global_status.value,
            "project_id": project_id,
            "ranked_source_ids": ranked_source_ids,
            "reference_dataset_id": reference_dataset_id,
            "schema_version": "1.0",
            "source_contract_hash": contract_hash,
            "source_groups": [g.to_canonical_dict() for g in group_descriptors],
            "target_dataset_id": target_dataset_id,
        }
        profile_hash = compute_source_analysis_profile_hash(profile_canonical_dict)

        return SourceAnalysisProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_hash,
            source_contract_hash=contract_hash,
            source_analysis_profile_hash=profile_hash,
            project_id=project_id,
            reference_dataset_id=reference_dataset_id,
            target_dataset_id=target_dataset_id,
            global_status=global_status,
            accounting=accounting,
            reference_group=ref_descriptor,
            source_groups=group_descriptors,
            comparisons=comparisons,
            ranked_source_ids=ranked_source_ids,
            confounded_source_count=confounded_count,
            warnings=[],
            limitations=[
                "Source-associated distribution shifts are observational detection evidence and do NOT imply malicious intent, fraud, or data poisoning.",
                "Marginal feature shifts may be confounded by source class specialization; evaluate label TVD caveats.",
            ],
            findings=findings,
            evidence_records=evidence_records,
        )

    def _evaluate_pairwise_source_drift(
        self,
        reference_payloads: List[Any],
        target_payloads: List[Any],
        target_source_id: str,
        target_pseudonym_id: str,
        reference_source_id: str,
        label_tvd: float = 0.0,
        potential_label_confounding: bool = False,
    ) -> SourceComparisonResult:
        """Evaluate pairwise two-sample distribution shift between reference and target source."""
        comp_id = f"comp-src-{target_pseudonym_id[:8]}"
        ref_n = len(reference_payloads)
        tgt_n = len(target_payloads)

        if ref_n < MIN_SOURCE_GROUP_SAMPLE_FLOOR or tgt_n < MIN_SOURCE_GROUP_SAMPLE_FLOOR:
            return SourceComparisonResult(
                comparison_id=comp_id,
                target_source_id=target_source_id,
                target_pseudonym_id=target_pseudonym_id,
                reference_source_id=reference_source_id,
                target_sample_count=tgt_n,
                reference_sample_count=ref_n,
                status=ShiftDecisionState.INSUFFICIENT_DATA,
                potential_label_confounding=potential_label_confounding,
                label_tvd=label_tvd,
            )

        # Inspect payload modality
        first_elem = target_payloads[0]
        if isinstance(first_elem, (list, tuple, np.ndarray)):
            arr_ref = np.asarray(reference_payloads, dtype=np.float32)
            arr_tgt = np.asarray(target_payloads, dtype=np.float32)

            if arr_ref.ndim == 1 or (arr_ref.ndim == 2 and arr_ref.shape[1] == 1):
                # 1D continuous feature
                v_ref = arr_ref.ravel()
                v_tgt = arr_tgt.ravel()
                ks_stat, p_val = compute_two_sample_ks(v_ref, v_tgt)
                psi_val, _ = compute_psi(v_ref, v_tgt)

                is_sig = p_val is not None and p_val <= 0.05
                is_pract = psi_val >= 0.10

                return SourceComparisonResult(
                    comparison_id=comp_id,
                    target_source_id=target_source_id,
                    target_pseudonym_id=target_pseudonym_id,
                    reference_source_id=reference_source_id,
                    target_sample_count=tgt_n,
                    reference_sample_count=ref_n,
                    feature_name="1d_continuous",
                    modality=DataModality.TABULAR_FEATURE,
                    statistic_method=StatisticalMethod.KOLMOGOROV_SMIRNOV_2SAMPLE.value,
                    statistic_value=float(ks_stat),
                    raw_p_value=float(p_val) if p_val is not None else None,
                    effect_size=float(psi_val),
                    effect_metric="psi",
                    is_statistically_significant=is_sig,
                    is_practically_significant=is_pract,
                    status=ShiftDecisionState.MATERIAL_SHIFT if (is_sig and is_pract) else (ShiftDecisionState.SIGNIFICANT_SHIFT if is_sig else ShiftDecisionState.NO_SHIFT_DETECTED),
                    potential_label_confounding=potential_label_confounding,
                    label_tvd=label_tvd,
                )
            else:
                # High-dimensional embedding (e.g. DINOv2 384-d)
                def mmd_fn(x: np.ndarray, y: np.ndarray) -> float:
                    stat, _ = compute_kernel_mmd(x, y)
                    return stat

                mmd_val, p_val, _ = compute_permutation_p_value(
                    arr_ref, arr_tgt, stat_fn=mmd_fn, num_permutations=100, seed=42
                )

                is_sig = p_val is not None and p_val <= 0.05
                is_pract = mmd_val >= 0.02

                return SourceComparisonResult(
                    comparison_id=comp_id,
                    target_source_id=target_source_id,
                    target_pseudonym_id=target_pseudonym_id,
                    reference_source_id=reference_source_id,
                    target_sample_count=tgt_n,
                    reference_sample_count=ref_n,
                    feature_name="embedding_multivariate",
                    modality=DataModality.LATENT_EMBEDDING,
                    statistic_method=StatisticalMethod.KERNEL_MMD.value,
                    statistic_value=float(mmd_val),
                    raw_p_value=float(p_val) if p_val is not None else None,
                    effect_size=float(mmd_val),
                    effect_metric="mmd_squared",
                    is_statistically_significant=is_sig,
                    is_practically_significant=is_pract,
                    status=ShiftDecisionState.MATERIAL_SHIFT if (is_sig and is_pract) else (ShiftDecisionState.SIGNIFICANT_SHIFT if is_sig else ShiftDecisionState.NO_SHIFT_DETECTED),
                    potential_label_confounding=potential_label_confounding,
                    label_tvd=label_tvd,
                )
        elif isinstance(first_elem, (int, float, np.floating, np.integer)):
            # Scalar continuous
            v_ref = np.asarray(reference_payloads, dtype=np.float32)
            v_tgt = np.asarray(target_payloads, dtype=np.float32)
            ks_stat, p_val = compute_two_sample_ks(v_ref, v_tgt)
            psi_val, _ = compute_psi(v_ref, v_tgt)

            is_sig = p_val is not None and p_val <= 0.05
            is_pract = psi_val >= 0.10


            return SourceComparisonResult(
                comparison_id=comp_id,
                target_source_id=target_source_id,
                target_pseudonym_id=target_pseudonym_id,
                reference_source_id=reference_source_id,
                target_sample_count=tgt_n,
                reference_sample_count=ref_n,
                feature_name="scalar_continuous",
                modality=DataModality.TABULAR_FEATURE,
                statistic_method=StatisticalMethod.KOLMOGOROV_SMIRNOV_2SAMPLE.value,
                statistic_value=float(ks_stat),
                raw_p_value=float(p_val) if p_val is not None else None,
                effect_size=float(psi_val),
                effect_metric="psi",
                is_statistically_significant=is_sig,
                is_practically_significant=is_pract,
                status=ShiftDecisionState.MATERIAL_SHIFT if (is_sig and is_pract) else (ShiftDecisionState.SIGNIFICANT_SHIFT if is_sig else ShiftDecisionState.NO_SHIFT_DETECTED),
                potential_label_confounding=potential_label_confounding,
                label_tvd=label_tvd,
            )
        else:
            # Categorical string tokens
            ref_counts = Counter(str(x) for x in reference_payloads)
            tgt_counts = Counter(str(x) for x in target_payloads)
            chi2_stat, p_val, df, unseen, missing = compute_chi_square_test(ref_counts, tgt_counts)

            n_ref = sum(ref_counts.values())
            n_tgt = sum(tgt_counts.values())
            ref_probs = {k: v / n_ref for k, v in ref_counts.items()}
            tgt_probs = {k: v / n_tgt for k, v in tgt_counts.items()}
            tvd_val = compute_total_variation_distance(ref_probs, tgt_probs)

            is_sig = p_val is not None and p_val <= 0.05
            is_pract = tvd_val >= 0.05

            return SourceComparisonResult(
                comparison_id=comp_id,
                target_source_id=target_source_id,
                target_pseudonym_id=target_pseudonym_id,
                reference_source_id=reference_source_id,
                target_sample_count=tgt_n,
                reference_sample_count=ref_n,
                feature_name="categorical_token",
                modality=DataModality.CATEGORICAL_LABEL,
                statistic_method=StatisticalMethod.CHI_SQUARE_TEST.value,
                statistic_value=float(chi2_stat),
                raw_p_value=float(p_val) if p_val is not None else None,
                effect_size=float(tvd_val),
                effect_metric="tvd",
                is_statistically_significant=is_sig,
                is_practically_significant=is_pract,
                status=ShiftDecisionState.MATERIAL_SHIFT if (is_sig and is_pract) else (ShiftDecisionState.SIGNIFICANT_SHIFT if is_sig else ShiftDecisionState.NO_SHIFT_DETECTED),
                potential_label_confounding=potential_label_confounding,
                label_tvd=label_tvd,
            )

    def _calculate_label_tvd(
        self,
        ref_props: Dict[str, float],
        tgt_props: Dict[str, float],
    ) -> float:
        """Calculate Total Variation Distance (TVD) between two discrete label proportion distributions."""
        all_classes = set(ref_props.keys()).union(set(tgt_props.keys()))
        if not all_classes:
            return 0.0

        tvd_sum = sum(abs(ref_props.get(c, 0.0) - tgt_props.get(c, 0.0)) for c in all_classes)
        return float(0.5 * tvd_sum)

    def _rank_sources(
        self,
        comparisons: List[SourceComparisonResult],
        group_descriptors: List[SourceGroupDescriptor],
    ) -> List[str]:
        """Rank target sources deterministically based on shift severity and effect size."""
        comp_map = {c.target_source_id: c for c in comparisons}
        gd_map = {gd.source_id: gd for gd in group_descriptors}

        all_target_ids = sorted(comp_map.keys())

        def sort_key(src_id: str) -> Tuple[int, float, float, int, str]:
            c = comp_map[src_id]
            gd = gd_map.get(src_id)
            sample_cnt = gd.sample_count if gd else 0

            status_prio = 0
            if c.status == ShiftDecisionState.MATERIAL_SHIFT:
                status_prio = 3
            elif c.status == ShiftDecisionState.SIGNIFICANT_SHIFT:
                status_prio = 2
            elif c.status == ShiftDecisionState.NO_SHIFT_DETECTED:
                status_prio = 1

            effect = float(c.effect_size)
            adj_p = float(c.adjusted_p_value) if c.adjusted_p_value is not None else 1.0

            # Higher status first (-status_prio), higher effect first (-effect), smaller p-val first (+adj_p), larger sample count first (-sample_cnt), tie-break source_id asc (+src_id)
            return (-status_prio, -effect, adj_p, -sample_cnt, src_id)

        return sorted(all_target_ids, key=sort_key)
