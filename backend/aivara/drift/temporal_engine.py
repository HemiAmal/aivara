"""Authoritative Temporal & Windowed Distribution Shift Engine.

Executes deterministic timestamp normalization, chronological multi-key sorting,
window partitioning (Fixed & Calibrated Sliding), Baseline-to-Windows and Adjacent-Windows
two-sample comparisons via Phase 11.3 StatisticalDriftEngine, multi-tier Benjamini-Hochberg
FDR error control, change-point candidate detection, and trajectory persistence classification.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import math
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np

from aivara.crypto.canonical import canonicalize
from aivara.drift.engine import StatisticalDriftEngine
from aivara.drift.enums import (
    BoundaryEvaluationStatus,
    DataModality,
    MultipleTestingCorrectionMethod,
    ShiftDecisionState,
    StatisticalMethod,
    TemporalComparisonTopology,
    TemporalTrajectoryState,
    TemporalWindowStrategy,
    TimestampSource,
)
from aivara.drift.exceptions import (
    DistributionBoundaryError,
    IncompatiblePopulationError,
    ProjectMismatchError,
    ResourceLimitExceededError,
)
from aivara.drift.multiple_testing import apply_benjamini_hochberg
from aivara.drift.population import deterministic_subsample
from aivara.drift.schemas import (
    ChangePointCandidate,
    ComparisonBoundaryResult,
    MultivariateDriftResult,
    StatisticalAnalysisConfig,
    StatisticalAnalysisResult,
    TemporalAnalysisContract,
    TemporalAnalysisProfile,
    TemporalComparisonResult,
    TemporalObservation,
    TemporalWindowAccounting,
    TemporalWindowDescriptor,
)

# Hard resource boundaries
MAX_TEMPORAL_WINDOWS: int = 50
MAX_WINDOW_SAMPLE_BUDGET: int = 5000
MIN_WINDOW_SAMPLE_FLOOR: int = 30


def compute_temporal_contract_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 cryptographic digest over canonical RFC 8785 temporal contract descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_temporal_window_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 cryptographic digest over canonical RFC 8785 temporal window descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_temporal_drift_profile_hash(canonical_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 cryptographic digest over canonical RFC 8785 temporal profile descriptor."""
    canonical_bytes = canonicalize(canonical_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()


def normalize_timestamp_utc(ts_input: Any, timezone_policy: str = "UTC") -> str:
    """Normalize raw timestamp input to canonical ISO 8601 UTC string (YYYY-MM-DDTHH:MM:SS.ffffffZ).

    Raises:
        ValueError: If timestamp cannot be parsed, has invalid format, or violates timezone policy.
    """
    if ts_input is None or ts_input == "":
        raise ValueError("Timestamp input is None or empty.")

    dt: datetime

    if isinstance(ts_input, datetime):
        if ts_input.tzinfo is None:
            if timezone_policy.upper() == "UTC":
                dt = ts_input.replace(tzinfo=timezone.utc)
            else:
                raise ValueError(f"Timezone-naive datetime rejected under strict policy '{timezone_policy}'.")
        else:
            dt = ts_input.astimezone(timezone.utc)
    elif isinstance(ts_input, (int, float)):
        # Treat numeric as UNIX epoch seconds
        try:
            dt = datetime.fromtimestamp(float(ts_input), tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"Numeric epoch timestamp {ts_input} out of valid range: {str(exc)}")
    elif isinstance(ts_input, str):
        s = ts_input.strip()
        # Handle trailing Z
        if s.endswith("Z") or s.endswith("z"):
            s = s[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                if timezone_policy.upper() == "UTC":
                    dt = parsed.replace(tzinfo=timezone.utc)
                else:
                    raise ValueError(f"Timezone-naive ISO string '{ts_input}' rejected under policy '{timezone_policy}'.")
            else:
                dt = parsed.astimezone(timezone.utc)
        except Exception:
            # Fallback parse standard formats
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d",
            ):
                try:
                    parsed = datetime.strptime(s, fmt)
                    dt = parsed.replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
            else:
                raise ValueError(f"Unparseable timestamp string: '{ts_input}'.")
    else:
        raise ValueError(f"Unsupported timestamp type: {type(ts_input)}")

    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc_iso_to_epoch(utc_iso: str) -> float:
    """Parse canonical ISO 8601 UTC string to float epoch seconds."""
    s = utc_iso.strip()
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    return dt.timestamp()


def sort_temporal_observations(
    observations: Sequence[TemporalObservation],
) -> List[TemporalObservation]:
    """Execute deterministic multi-key chronological sorting.

    Primary: normalized_timestamp_utc ASC
    Secondary: sample_id ASC
    """
    return sorted(
        observations,
        key=lambda obs: (obs.normalized_timestamp_utc, obs.sample_id),
    )


class TemporalDistributionShiftAnalyzer:
    """Authoritative domain orchestrator for temporal and windowed distribution-shift evaluation."""

    def __init__(self, statistical_engine: Optional[StatisticalDriftEngine] = None) -> None:
        self.statistical_engine = statistical_engine or StatisticalDriftEngine()

    def analyze(
        self,
        boundary_result: ComparisonBoundaryResult,
        temporal_contract: TemporalAnalysisContract,
        raw_observations: Sequence[Any],
        *,
        config: Optional[StatisticalAnalysisConfig] = None,
        designated_baseline_observations: Optional[Sequence[Any]] = None,
    ) -> TemporalAnalysisProfile:
        """Execute full temporal distribution shift evaluation across observation windows."""
        contract = boundary_result.contract

        # 1. Modality & Boundary Validation
        if boundary_result.status != BoundaryEvaluationStatus.VALID:
            if boundary_result.status == BoundaryEvaluationStatus.PROJECT_MISMATCH:
                raise ProjectMismatchError("Cannot evaluate temporal drift across mismatched projects.")
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                temporal_contract=temporal_contract,
                status=TemporalTrajectoryState.INVALID,
                accounting=TemporalWindowAccounting(total_observations=len(raw_observations)),
                warnings=[f"Boundary status is {boundary_result.status.value}."],
            )

        active_config = config or self.statistical_engine.default_config
        warnings: List[str] = list(boundary_result.warnings)
        limitations: List[str] = []

        # 2. Ingest & Normalize Observations
        valid_obs: List[TemporalObservation] = []
        missing_ts_count = 0
        invalid_ts_count = 0

        for idx, item in enumerate(raw_observations):
            sample_id = f"sample_{idx:06d}"
            ts_raw = None
            payload = item

            if isinstance(item, TemporalObservation):
                valid_obs.append(item)
                continue
            elif isinstance(item, dict):
                sample_id = str(item.get("id") or item.get("sample_id") or sample_id)
                ts_raw = item.get("timestamp") or item.get(temporal_contract.timestamp_field.value) or item.get("event_time") or item.get("ingested_at")
                if "payload" in item:
                    payload = item["payload"]
                elif "features" in item:
                    payload = item["features"]
                elif "embedding" in item:
                    payload = item["embedding"]
                elif "data" in item:
                    payload = item["data"]
                else:
                    payload = item
            elif isinstance(item, (tuple, list)) and len(item) >= 2:
                ts_raw = item[0]
                payload = item[1]
                if len(item) >= 3:
                    sample_id = str(item[2])
            else:
                missing_ts_count += 1
                continue

            if ts_raw is None or ts_raw == "":
                missing_ts_count += 1
                continue

            try:
                norm_ts = normalize_timestamp_utc(ts_raw, timezone_policy=temporal_contract.timezone_policy)
                valid_obs.append(
                    TemporalObservation(
                        sample_id=sample_id,
                        timestamp_raw=ts_raw,
                        normalized_timestamp_utc=norm_ts,
                        payload=payload,
                    )
                )
            except Exception:
                invalid_ts_count += 1

        total_obs_count = len(raw_observations)
        valid_ts_count = len(valid_obs)

        # 3. Check Temporal Coverage
        if total_obs_count > 0 and (missing_ts_count / total_obs_count) > 0.10:
            warnings.append(
                f"High untimestamped observation ratio: {missing_ts_count}/{total_obs_count} missing timestamps."
            )

        if valid_ts_count < temporal_contract.min_window_samples:
            acc = TemporalWindowAccounting(
                total_observations=total_obs_count,
                valid_timestamp_observations=valid_ts_count,
                missing_timestamp_observations=missing_ts_count,
                invalid_timestamp_observations=invalid_ts_count,
                total_windows_generated=0,
                valid_windows_count=0,
                sparse_windows_count=0,
            )
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                temporal_contract=temporal_contract,
                status=TemporalTrajectoryState.INSUFFICIENT_DATA,
                accounting=acc,
                warnings=warnings
                + [f"Total valid timestamped observations ({valid_ts_count}) < minimum required ({temporal_contract.min_window_samples})."],
            )

        # 4. Deterministic Multi-Key Sorting
        sorted_obs = sort_temporal_observations(valid_obs)
        earliest_ts = sorted_obs[0].normalized_timestamp_utc
        latest_ts = sorted_obs[-1].normalized_timestamp_utc
        t_start = parse_utc_iso_to_epoch(earliest_ts)
        t_end = parse_utc_iso_to_epoch(latest_ts)
        span_seconds = max(0.0, t_end - t_start)

        # Check total estimated windows against max_windows
        step_val = temporal_contract.step_size_seconds or temporal_contract.window_size_seconds
        if span_seconds > 0:
            estimated_k = math.floor(span_seconds / step_val) + 1
            if estimated_k > temporal_contract.max_windows:
                raise ResourceLimitExceededError(
                    f"Generated windows count {estimated_k} exceeds contract limit {temporal_contract.max_windows}."
                )

        # 5. Partition Observations into Windows
        window_partitions, window_descriptors = self._partition_windows(
            sorted_obs, temporal_contract, t_start, t_end
        )


        valid_windows = [w for w in window_descriptors if w.is_valid]
        sparse_windows = [w for w in window_descriptors if not w.is_valid]

        accounting = TemporalWindowAccounting(
            total_observations=total_obs_count,
            valid_timestamp_observations=valid_ts_count,
            missing_timestamp_observations=missing_ts_count,
            invalid_timestamp_observations=invalid_ts_count,
            total_windows_generated=len(window_descriptors),
            valid_windows_count=len(valid_windows),
            sparse_windows_count=len(sparse_windows),
        )

        if len(window_descriptors) > temporal_contract.max_windows:
            raise ResourceLimitExceededError(
                f"Generated windows count {len(window_descriptors)} exceeds contract limit {temporal_contract.max_windows}."
            )

        if len(valid_windows) < 2:
            return self._create_fail_closed_profile(
                boundary_result=boundary_result,
                temporal_contract=temporal_contract,
                status=TemporalTrajectoryState.INSUFFICIENT_TEMPORAL_COVERAGE,
                accounting=accounting,
                warnings=warnings + ["Fewer than 2 valid observation windows generated."],
                earliest_ts=earliest_ts,
                latest_ts=latest_ts,
                span_seconds=span_seconds,
            )

        # 6. Resolve Baseline Window
        baseline_desc: TemporalWindowDescriptor
        baseline_data: List[Any]

        if designated_baseline_observations is not None and len(designated_baseline_observations) >= temporal_contract.min_window_samples:
            baseline_data = [
                obs.payload if isinstance(obs, TemporalObservation) else obs
                for obs in designated_baseline_observations
            ]
            b_desc_dict = {
                "end_time_utc": earliest_ts,
                "is_valid": True,
                "sample_count": len(baseline_data),
                "start_time_utc": earliest_ts,
                "window_id": "designated_reference_baseline",
                "window_index": 0,
            }
            b_hash = compute_temporal_window_hash(b_desc_dict)
            baseline_desc = TemporalWindowDescriptor(
                window_index=0,
                window_id="designated_reference_baseline",
                start_time_utc=earliest_ts,
                end_time_utc=earliest_ts,
                sample_count=len(baseline_data),
                is_valid=True,
                window_hash=b_hash,
            )
        else:
            baseline_desc = window_descriptors[0]
            baseline_data = [obs.payload for obs in window_partitions[0]]

        # 7. Execute Baseline-to-Windows Comparisons (O(K))
        baseline_results: List[TemporalComparisonResult] = []
        raw_p_values_baseline: List[float] = []

        for w_idx, (w_desc, w_obs_list) in enumerate(zip(window_descriptors, window_partitions)):
            if not w_desc.is_valid or (w_desc.window_index == baseline_desc.window_index and baseline_desc.window_id == w_desc.window_id):
                continue

            target_data = [obs.payload for obs in w_obs_list]
            comp_res, p_val = self._evaluate_pairwise_window_drift(
                boundary_result=boundary_result,
                ref_desc=baseline_desc,
                tgt_desc=w_desc,
                ref_data=baseline_data,
                tgt_data=target_data,
                comp_type="baseline_to_window",
                config=active_config,
            )
            baseline_results.append(comp_res)
            raw_p_values_baseline.append(p_val)

        # 8. Apply Two-Tier Benjamini-Hochberg FDR Across Baseline Comparisons
        if baseline_results:
            p_dict_baseline = {
                comp.comparison_id: comp.raw_p_value
                for comp in baseline_results
                if comp.raw_p_value is not None
            }
            adj_dict_baseline = apply_benjamini_hochberg(p_dict_baseline, q_star=active_config.fdr_q_star)
            updated_baseline_results: List[TemporalComparisonResult] = []
            for comp_res in baseline_results:
                adj_info = adj_dict_baseline.get(comp_res.comparison_id)
                p_adj = adj_info["adjusted_p_value"] if adj_info else comp_res.raw_p_value
                is_sig = adj_info["is_significant"] if adj_info else comp_res.is_statistically_significant
                status = (
                    ShiftDecisionState.MATERIAL_SHIFT
                    if (is_sig and comp_res.is_practically_significant)
                    else (
                        ShiftDecisionState.SIGNIFICANT_SHIFT
                        if is_sig
                        else ShiftDecisionState.NO_SHIFT_DETECTED
                    )
                )
                updated_baseline_results.append(
                    comp_res.model_copy(
                        update={
                            "adjusted_p_value": p_adj,
                            "is_statistically_significant": is_sig,
                            "status": status,
                        }
                    )
                )
            baseline_results = updated_baseline_results

        # 9. Execute Adjacent-Windows Comparisons (O(K))
        adjacent_results: List[TemporalComparisonResult] = []

        for i in range(len(window_descriptors) - 1):
            w_left = window_descriptors[i]
            w_right = window_descriptors[i + 1]
            if not w_left.is_valid or not w_right.is_valid:
                continue

            data_left = [obs.payload for obs in window_partitions[i]]
            data_right = [obs.payload for obs in window_partitions[i + 1]]

            comp_res, p_val = self._evaluate_pairwise_window_drift(
                boundary_result=boundary_result,
                ref_desc=w_left,
                tgt_desc=w_right,
                ref_data=data_left,
                tgt_data=data_right,
                comp_type="adjacent_window",
                config=active_config,
            )
            adjacent_results.append(comp_res)

        if adjacent_results:
            p_dict_adjacent = {
                comp.comparison_id: comp.raw_p_value
                for comp in adjacent_results
                if comp.raw_p_value is not None
            }
            adj_dict_adj = apply_benjamini_hochberg(p_dict_adjacent, q_star=active_config.fdr_q_star)
            updated_adj_results: List[TemporalComparisonResult] = []
            for comp_res in adjacent_results:
                adj_info = adj_dict_adj.get(comp_res.comparison_id)
                p_adj = adj_info["adjusted_p_value"] if adj_info else comp_res.raw_p_value
                is_sig = adj_info["is_significant"] if adj_info else comp_res.is_statistically_significant
                status = (
                    ShiftDecisionState.MATERIAL_SHIFT
                    if (is_sig and comp_res.is_practically_significant)
                    else (
                        ShiftDecisionState.SIGNIFICANT_SHIFT
                        if is_sig
                        else ShiftDecisionState.NO_SHIFT_DETECTED
                    )
                )
                updated_adj_results.append(
                    comp_res.model_copy(
                        update={
                            "adjusted_p_value": p_adj,
                            "is_statistically_significant": is_sig,
                            "status": status,
                        }
                    )
                )
            adjacent_results = updated_adj_results


        # 10. Change-Point Candidate Detection (Local Peak in Adjacent Discrepancy)
        change_points: List[ChangePointCandidate] = []
        if adjacent_results:
            for comp in adjacent_results:
                if comp.status == ShiftDecisionState.MATERIAL_SHIFT:
                    target_w = next((w for w in window_descriptors if w.window_id == comp.target_window_id), None)
                    cand_ts = target_w.start_time_utc if target_w else earliest_ts
                    change_points.append(
                        ChangePointCandidate(
                            window_boundary_index=comp.target_window_index,
                            candidate_timestamp_utc=cand_ts,
                            adjacent_discrepancy=comp.effect_size,
                            permutation_p_value=comp.adjusted_p_value,
                            confidence=0.90 if comp.adjusted_p_value and comp.adjusted_p_value <= 0.01 else 0.80,
                            supporting_evidence=(
                                f"Adjacent discrepancy peak ({comp.statistic_method}={comp.statistic_value:.4f}, "
                                f"effect={comp.effect_size:.4f}, p_adj={comp.adjusted_p_value:.4f}) between "
                                f"{comp.reference_window_id} and {comp.target_window_id}."
                            ),
                        )
                    )

        # 11. Trajectory & Persistence Classification
        global_trajectory_status = self._classify_trajectory(baseline_results, adjacent_results)

        # 12. Seasonality Warning Checks
        if (
            temporal_contract.declared_seasonality_period_seconds is not None
            and temporal_contract.window_size_seconds < temporal_contract.declared_seasonality_period_seconds
        ):
            limitations.append(
                f"Window duration ({temporal_contract.window_size_seconds}s) is smaller than declared seasonality period "
                f"({temporal_contract.declared_seasonality_period_seconds}s). Observed drift may reflect cyclical variance."
            )

        # 13. Synthesize Findings and Evidence
        findings, evidence_records = self._generate_findings_and_evidence(
            boundary_result=boundary_result,
            temporal_contract=temporal_contract,
            trajectory_status=global_trajectory_status,
            accounting=accounting,
            baseline_comparisons=baseline_results,
            adjacent_comparisons=adjacent_results,
            change_points=change_points,
            span_seconds=span_seconds,
        )

        # 14. Cryptographic Hashing
        temp_contract_hash = (
            temporal_contract.temporal_contract_hash
            or compute_temporal_contract_hash(temporal_contract.to_canonical_dict())
        )

        profile_desc_dict = {
            "accounting": accounting.to_canonical_dict(),
            "adjacent_comparisons_count": len(adjacent_results),
            "analysis_version": "1.0",
            "baseline_comparisons_count": len(baseline_results),
            "change_points_count": len(change_points),
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "earliest_timestamp_utc": earliest_ts,
            "global_trajectory_status": global_trajectory_status.value,
            "latest_timestamp_utc": latest_ts,
            "project_id": contract.project_id,
            "reference_dataset_id": contract.reference_dataset_id,
            "schema_version": "1.0",
            "target_dataset_id": contract.target_dataset_id,
            "temporal_contract_hash": temp_contract_hash,
            "total_temporal_span_seconds": float(span_seconds),
            "windows_count": len(window_descriptors),
        }
        profile_hash = compute_temporal_drift_profile_hash(profile_desc_dict)

        return TemporalAnalysisProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            temporal_contract_hash=temp_contract_hash,
            temporal_analysis_profile_hash=profile_hash,
            project_id=contract.project_id,
            reference_dataset_id=contract.reference_dataset_id,
            target_dataset_id=contract.target_dataset_id,
            global_trajectory_status=global_trajectory_status,
            accounting=accounting,
            baseline_window=baseline_desc,
            windows=window_descriptors,
            baseline_comparisons=baseline_results,
            adjacent_comparisons=adjacent_results,
            change_points=change_points,
            earliest_timestamp_utc=earliest_ts,
            latest_timestamp_utc=latest_ts,
            total_temporal_span_seconds=span_seconds,
            warnings=sorted(list(set(warnings))),
            limitations=limitations,
            findings=findings,
            evidence_records=evidence_records,
        )

    def _partition_windows(
        self,
        sorted_obs: List[TemporalObservation],
        contract: TemporalAnalysisContract,
        t_start: float,
        t_end: float,
    ) -> Tuple[List[List[TemporalObservation]], List[TemporalWindowDescriptor]]:
        """Partition chronological observations into deterministic windows."""
        window_partitions: List[List[TemporalObservation]] = []
        descriptors: List[TemporalWindowDescriptor] = []

        w_size = contract.window_size_seconds
        step = contract.step_size_seconds or w_size

        if contract.window_strategy == TemporalWindowStrategy.SLIDING_WINDOW:
            if step < (w_size / 2.0):
                step = w_size / 2.0

        current_t = t_start
        window_idx = 0

        while current_t <= t_end and window_idx < contract.max_windows:
            w_start_epoch = current_t
            w_end_epoch = current_t + w_size

            w_start_iso = datetime.fromtimestamp(w_start_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            w_end_iso = datetime.fromtimestamp(w_end_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # Collect matching observations: [w_start_epoch, w_end_epoch)
            matching = [
                obs for obs in sorted_obs
                if w_start_epoch <= parse_utc_iso_to_epoch(obs.normalized_timestamp_utc) < w_end_epoch
                or (window_idx == 0 and parse_utc_iso_to_epoch(obs.normalized_timestamp_utc) == w_start_epoch)
            ]

            # Enforce max sample budget per window
            if len(matching) > contract.max_window_samples:
                matching = matching[: contract.max_window_samples]

            sample_cnt = len(matching)
            is_valid = sample_cnt >= contract.min_window_samples

            w_id = f"window_{window_idx:03d}_{w_start_iso[:10]}"
            w_desc_dict = {
                "end_time_utc": w_end_iso,
                "is_valid": is_valid,
                "sample_count": sample_cnt,
                "start_time_utc": w_start_iso,
                "window_id": w_id,
                "window_index": window_idx,
            }
            w_hash = compute_temporal_window_hash(w_desc_dict)

            descriptors.append(
                TemporalWindowDescriptor(
                    window_index=window_idx,
                    window_id=w_id,
                    start_time_utc=w_start_iso,
                    end_time_utc=w_end_iso,
                    sample_count=sample_cnt,
                    is_valid=is_valid,
                    window_hash=w_hash,
                )
            )
            window_partitions.append(matching)

            current_t += step
            window_idx += 1

            if current_t > t_end and len(descriptors) > 0:
                break

        return window_partitions, descriptors

    def _evaluate_pairwise_window_drift(
        self,
        boundary_result: ComparisonBoundaryResult,
        ref_desc: TemporalWindowDescriptor,
        tgt_desc: TemporalWindowDescriptor,
        ref_data: Sequence[Any],
        tgt_data: Sequence[Any],
        comp_type: str,
        config: StatisticalAnalysisConfig,
    ) -> Tuple[TemporalComparisonResult, float]:
        """Evaluate two-sample statistical discrepancy between two windows via Phase 11.3 engine."""
        comp_id = f"{comp_type}_{ref_desc.window_index}_vs_{tgt_desc.window_index}"

        # Detect data format (numerical 2D matrix, 1D vectors, or categorical)
        arr_ref = np.asarray(ref_data, dtype=np.float64)
        arr_tgt = np.asarray(tgt_data, dtype=np.float64)

        if arr_ref.ndim == 2 and arr_ref.shape[1] > 1:
            # Multivariate / Embedding evaluation
            stat_res = self.statistical_engine.evaluate_boundary(
                boundary_result=boundary_result,
                reference_embeddings=arr_ref,
                target_embeddings=arr_tgt,
                config=config,
            )
            multi_res = stat_res.multivariate_results
            stat_method = multi_res.method.value if multi_res else "kernel_mmd"
            stat_val = multi_res.statistic_value if multi_res else 0.0
            p_val = multi_res.permutation_p_value if (multi_res and multi_res.permutation_p_value is not None) else 1.0
            effect_val = stat_val
            is_practically_sig = effect_val >= config.mmd_material_threshold
        else:
            # 1D continuous feature evaluation
            v_ref = arr_ref.ravel()
            v_tgt = arr_tgt.ravel()
            stat_res = self.statistical_engine.evaluate_boundary(
                boundary_result=boundary_result,
                reference_features={"temporal_metric": v_ref},
                target_features={"temporal_metric": v_tgt},
                config=config,
            )
            f_res = stat_res.feature_results.get("temporal_metric")
            stat_method = f_res.method.value if f_res else "kolmogorov_smirnov_2sample"
            stat_val = f_res.statistic_value if f_res else 0.0
            p_val = f_res.raw_p_value if (f_res and f_res.raw_p_value is not None) else 1.0
            effect_val = f_res.effect_size if f_res else 0.0
            is_practically_sig = f_res.is_practically_significant if f_res else False

        comp_result = TemporalComparisonResult(
            comparison_id=comp_id,
            comparison_type=comp_type,
            reference_window_index=ref_desc.window_index,
            target_window_index=tgt_desc.window_index,
            reference_window_id=ref_desc.window_id,
            target_window_id=tgt_desc.window_id,
            reference_sample_count=ref_desc.sample_count,
            target_sample_count=tgt_desc.sample_count,
            statistical_analysis_hash=stat_res.analysis_result_hash,
            statistic_method=stat_method,
            statistic_value=stat_val,
            raw_p_value=p_val,
            adjusted_p_value=p_val,
            effect_size=effect_val,
            is_statistically_significant=p_val <= config.significance_level,
            is_practically_significant=is_practically_sig,
            status=ShiftDecisionState.MATERIAL_SHIFT if (p_val <= config.significance_level and is_practically_sig) else ShiftDecisionState.NO_SHIFT_DETECTED,
            details={"analysis_result_hash": stat_res.analysis_result_hash},
        )
        return comp_result, p_val

    def _classify_trajectory(
        self,
        baseline_comps: List[TemporalComparisonResult],
        adjacent_comps: List[TemporalComparisonResult],
    ) -> TemporalTrajectoryState:
        """Classify overall temporal trajectory and persistence pattern."""
        if not baseline_comps:
            return TemporalTrajectoryState.NO_MATERIAL_SHIFT

        shifted_indices = [
            comp.target_window_index for comp in baseline_comps
            if comp.status == ShiftDecisionState.MATERIAL_SHIFT
        ]

        if not shifted_indices:
            return TemporalTrajectoryState.NO_MATERIAL_SHIFT

        if len(shifted_indices) == 1:
            # Isolated shift -> transient
            return TemporalTrajectoryState.TRANSIENT_SHIFT

        # Check for consecutive shifted windows
        is_consecutive = any(
            shifted_indices[i+1] == shifted_indices[i] + 1
            for i in range(len(shifted_indices) - 1)
        )

        effects = [comp.effect_size for comp in baseline_comps]
        # Check monotonic increase across >= 3 windows -> gradual
        if len(effects) >= 3 and all(effects[i] < effects[i+1] for i in range(len(effects)-1)):
            return TemporalTrajectoryState.GRADUAL_DRIFT

        # Check acute jump > 3x threshold appearing early -> abrupt
        if adjacent_comps and any(adj.effect_size >= 0.06 for adj in adjacent_comps):
            return TemporalTrajectoryState.ABRUPT_SHIFT

        if is_consecutive:
            return TemporalTrajectoryState.PERSISTENT_SHIFT

        return TemporalTrajectoryState.TRANSIENT_SHIFT

    def _generate_findings_and_evidence(
        self,
        boundary_result: ComparisonBoundaryResult,
        temporal_contract: TemporalAnalysisContract,
        trajectory_status: TemporalTrajectoryState,
        accounting: TemporalWindowAccounting,
        baseline_comparisons: List[TemporalComparisonResult],
        adjacent_comparisons: List[TemporalComparisonResult],
        change_points: List[ChangePointCandidate],
        span_seconds: float,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Synthesize FindingModel and EvidenceModel records with neutral detection semantics."""
        contract = boundary_result.contract
        findings: List[Dict[str, Any]] = []
        evidence_records: List[Dict[str, Any]] = []

        affected_asset_id = contract.target_dataset_version_id or contract.target_dataset_id
        affected_asset_type = "dataset_version" if contract.target_dataset_version_id else "dataset"

        if trajectory_status in (TemporalTrajectoryState.PERSISTENT_SHIFT, TemporalTrajectoryState.ABRUPT_SHIFT):
            severity = "high"
            disposition = "review"
            confidence = 0.95
        elif trajectory_status == TemporalTrajectoryState.GRADUAL_DRIFT:
            severity = "medium"
            disposition = "review"
            confidence = 0.85
        elif trajectory_status == TemporalTrajectoryState.TRANSIENT_SHIFT:
            severity = "low"
            disposition = "review"
            confidence = 0.75
        else:
            severity = "info"
            disposition = "accept"
            confidence = 0.99

        cp_summary = f", {len(change_points)} change point(s) detected" if change_points else ""

        finding = {
            "project_id": contract.project_id,
            "engine_id": "temporal_distribution_shift_analyzer",
            "engine_version": "1.0",
            "evidence_layer": "detection",
            "finding_type": "temporal_distribution_shift",
            "title": f"Temporal Distribution Shift Analysis: {trajectory_status.value}",
            "description": (
                f"Chronological observation windows ({accounting.valid_windows_count} valid windows, "
                f"span={span_seconds/3600.0:.1f}h) evaluated for distribution shift: "
                f"trajectory={trajectory_status.value}{cp_summary}."
            ),
            "severity": severity,
            "confidence": confidence,
            "affected_asset_type": affected_asset_type,
            "affected_asset_id": affected_asset_id,
            "disposition": disposition,
            "analysis_mode": "temporal_windowed_two_sample_testing",
            "recommendation": (
                "Review time-series window discrepancies and investigate non-stationary operational dynamics. "
                "Note: Temporal distribution shift indicates statistical divergence across time intervals and is "
                "NOT proof of malicious intent, adversarial tampering, dataset poisoning, or contributor fraud."
            ),
            "metadata_json": {
                "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
                "temporal_analysis_id": temporal_contract.temporal_analysis_id,
                "global_trajectory_status": trajectory_status.value,
                "valid_windows_count": accounting.valid_windows_count,
                "change_points_count": len(change_points),
            },
        }
        findings.append(finding)

        evidence_data = {
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "temporal_analysis_id": temporal_contract.temporal_analysis_id,
            "global_trajectory_status": trajectory_status.value,
            "accounting": accounting.to_canonical_dict(),
            "baseline_comparisons_count": len(baseline_comparisons),
            "adjacent_comparisons_count": len(adjacent_comparisons),
            "change_points_count": len(change_points),
        }
        evidence_bytes = canonicalize(evidence_data)
        evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()

        evidence = {
            "evidence_layer": "detection",
            "evidence_type": "temporal_drift_evidence",
            "title": "Temporal Distribution Shift Evidence",
            "description": (
                f"Sequential windowed two-sample discrepancy evidence for boundary "
                f"{boundary_result.comparison_boundary_hash[:16]}."
            ),
            "data_json": evidence_data,
            "confidence": confidence,
            "evidence_hash": evidence_hash,
        }
        evidence_records.append(evidence)

        return findings, evidence_records

    def _create_fail_closed_profile(
        self,
        boundary_result: ComparisonBoundaryResult,
        temporal_contract: TemporalAnalysisContract,
        status: TemporalTrajectoryState,
        accounting: TemporalWindowAccounting,
        warnings: List[str],
        earliest_ts: Optional[str] = None,
        latest_ts: Optional[str] = None,
        span_seconds: float = 0.0,
    ) -> TemporalAnalysisProfile:
        """Create fail-closed profile on boundary error, missing temporal coverage, or invalid contract."""
        contract = boundary_result.contract
        temp_contract_hash = (
            temporal_contract.temporal_contract_hash
            or compute_temporal_contract_hash(temporal_contract.to_canonical_dict())
        )

        profile_desc_dict = {
            "accounting": accounting.to_canonical_dict(),
            "adjacent_comparisons_count": 0,
            "analysis_version": "1.0",
            "baseline_comparisons_count": 0,
            "change_points_count": 0,
            "comparison_boundary_hash": boundary_result.comparison_boundary_hash,
            "earliest_timestamp_utc": earliest_ts or "",
            "global_trajectory_status": status.value,
            "latest_timestamp_utc": latest_ts or "",
            "project_id": contract.project_id,
            "reference_dataset_id": contract.reference_dataset_id,
            "schema_version": "1.0",
            "target_dataset_id": contract.target_dataset_id,
            "temporal_contract_hash": temp_contract_hash,
            "total_temporal_span_seconds": float(span_seconds),
            "windows_count": 0,
        }
        profile_hash = compute_temporal_drift_profile_hash(profile_desc_dict)

        return TemporalAnalysisProfile(
            schema_version="1.0",
            analysis_version="1.0",
            comparison_boundary_hash=boundary_result.comparison_boundary_hash,
            temporal_contract_hash=temp_contract_hash,
            temporal_analysis_profile_hash=profile_hash,
            project_id=contract.project_id,
            reference_dataset_id=contract.reference_dataset_id,
            target_dataset_id=contract.target_dataset_id,
            global_trajectory_status=status,
            accounting=accounting,
            baseline_window=None,
            windows=[],
            baseline_comparisons=[],
            adjacent_comparisons=[],
            change_points=[],
            earliest_timestamp_utc=earliest_ts,
            latest_timestamp_utc=latest_ts,
            total_temporal_span_seconds=span_seconds,
            warnings=warnings,
            limitations=["Temporal distribution shift analysis aborted due to fail-closed state."],
            findings=[],
            evidence_records=[],
        )
