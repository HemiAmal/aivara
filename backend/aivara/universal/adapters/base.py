"""Base Domain Evidence Adapter Protocol & Abstract Interface (Phase 12.2).

Enforces:
- Exact domain declaration.
- Input validation and finite float sanitization.
- Non-destructive translation to UniversalEvidenceEnvelope.
- Provenance and ancestry preservation.
- Zero risk calculation or cross-domain damping.
"""

from __future__ import annotations

import abc
import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import (
    AdapterVersion,
    AncestryStatus,
    SubsystemDomain,
)
from aivara.universal.exceptions import (
    AdapterMismatchError,
    ConfidenceValidationError,
    InvalidEvidenceError,
    ProjectMismatchError,
    ProvenanceHashValidationError,
    SourceHashMismatchError,
)
from aivara.universal.hashing import (
    compute_payload_hash,
    validate_finite_numerical_data,
)
from aivara.universal.schemas import (
    AncestryPath,
    UniversalEvidenceEnvelope,
)


class BaseEvidenceAdapter(abc.ABC):
    """Abstract base class for domain-specific evidence normalization adapters."""

    @property
    @abc.abstractmethod
    def domain(self) -> SubsystemDomain:
        """Declared authoritative subsystem domain for this adapter."""
        pass

    @property
    def adapter_version(self) -> str:
        """Version of this domain adapter implementation."""
        return AdapterVersion.V1_0.value

    @abc.abstractmethod
    def normalize(
        self,
        raw_evidence: Union[Dict[str, Any], BaseModel],
        project_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> UniversalEvidenceEnvelope:
        """Translate upstream evidence into a canonical UniversalEvidenceEnvelope.
        
        Args:
            raw_evidence: Upstream domain evidence record or dictionary.
            project_id: Target project / tenant identifier.
            context: Optional contextual parameters (asset_id, finding_id, ancestry).
            
        Returns:
            Canonical UniversalEvidenceEnvelope instance.
        """
        pass

    def _extract_dict(self, raw: Union[Dict[str, Any], BaseModel]) -> Dict[str, Any]:
        """Safely convert BaseModel or Dict into a standard dictionary without mutating input."""
        if hasattr(raw, "model_dump"):
            return raw.model_dump(mode="python")
        elif hasattr(raw, "dict"):
            return raw.dict()
        elif isinstance(raw, dict):
            return dict(raw)
        else:
            raise InvalidEvidenceError(f"Unsupported evidence input type: {type(raw).__name__}")

    def _validate_project(self, evidence_project_id: Optional[str], target_project_id: str) -> None:
        """Enforce strict project boundary checks."""
        if not target_project_id:
            raise ProjectMismatchError("Target project_id must not be empty.")
        if evidence_project_id and evidence_project_id != target_project_id:
            raise ProjectMismatchError(
                f"Evidence project_id '{evidence_project_id}' does not match target '{target_project_id}'."
            )

    def _verify_and_resolve_source_payload_hash(
        self,
        source_dict: Dict[str, Any],
        supplied_hash: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> str:
        """Resolve and verify source payload hash against authoritative source representation.
        
        Rules:
        - If supplied_hash is present:
            - Must be valid 64-character lowercase hex string.
            - If raw_bytes or source_dict is present, recompute SHA-256 and verify match.
            - If mismatch: raise SourceHashMismatchError.
            - If match: return supplied_hash.
        - If supplied_hash is absent:
            - If raw_bytes is provided: return sha256(raw_bytes).hexdigest()
            - Else: return compute_payload_hash(source_dict)
        """
        if supplied_hash:
            s_hash = supplied_hash.strip().lower()
            if len(s_hash) != 64 or not all(c in "0123456789abcdef" for c in s_hash):
                raise InvalidEvidenceError(
                    f"Supplied source_payload_hash '{supplied_hash}' is not a valid 64-character hex string."
                )
            
            # Recompute and verify against authoritative source representation if available
            if raw_bytes is not None:
                recomputed = hashlib.sha256(raw_bytes).hexdigest()
                if s_hash != recomputed:
                    raise SourceHashMismatchError(
                        f"Supplied source_payload_hash '{s_hash}' does not match recomputed raw bytes digest '{recomputed}'."
                    )
            elif source_dict:
                recomputed = compute_payload_hash(source_dict)
                if s_hash != recomputed:
                    raise SourceHashMismatchError(
                        f"Supplied source_payload_hash '{s_hash}' does not match recomputed source data digest '{recomputed}'."
                    )
            return s_hash
        
        # No supplied hash: derive from authoritative source data
        if raw_bytes is not None:
            return hashlib.sha256(raw_bytes).hexdigest()
        return compute_payload_hash(source_dict)

    def _extract_and_validate_confidence(
        self,
        raw: Dict[str, Any],
        layer: EvidenceLayer,
    ) -> Optional[float]:
        """Extract and validate evidence confidence according to upstream semantics."""
        raw_conf = raw.get("confidence")
        if raw_conf is not None:
            try:
                conf = float(raw_conf)
            except (ValueError, TypeError) as exc:
                raise ConfidenceValidationError(f"Invalid confidence value: {raw_conf}") from exc
            
            if math.isnan(conf) or math.isinf(conf):
                raise ConfidenceValidationError(f"Confidence must be a finite float, got {conf}")
            if conf < 0.0 or conf > 1.0:
                raise ConfidenceValidationError(f"Confidence must be in [0.0, 1.0], got {conf}")
            if layer == EvidenceLayer.PROOF and conf != 1.0:
                raise ConfidenceValidationError(f"Proof-layer evidence confidence must be exactly 1.0, got {conf}")
            return conf
        
        # Missing confidence: default to 1.0 for proof layer, None for others
        if layer == EvidenceLayer.PROOF:
            return 1.0
        return None

    def _extract_and_validate_provenance(
        self,
        raw: Dict[str, Any],
    ) -> Tuple[List[str], List[str]]:
        """Extract and validate provenance record IDs and cryptographic hashes."""
        prov_ids_raw = raw.get("provenance_record_ids")
        if prov_ids_raw is None and "provenance_record_id" in raw:
            prov_ids_raw = [raw["provenance_record_id"]]
        prov_ids = [str(x) for x in (prov_ids_raw or [])]

        prov_hashes_raw = raw.get("provenance_hashes")
        if prov_hashes_raw is None and "provenance_hash" in raw:
            prov_hashes_raw = [raw["provenance_hash"]]
        prov_hashes: List[str] = []
        for h in (prov_hashes_raw or []):
            h_str = str(h).strip().lower()
            if len(h_str) != 64 or not all(c in "0123456789abcdef" for c in h_str):
                raise ProvenanceHashValidationError(
                    f"Provenance hash '{h}' is not a valid 64-character hex SHA-256 digest."
                )
            prov_hashes.append(h_str)

        return sorted(prov_ids), sorted(prov_hashes)

    def _extract_ancestry_path(
        self,
        raw: Dict[str, Any],
        ctx: Optional[Dict[str, Any]] = None,
    ) -> Tuple[AncestryPath, AncestryStatus]:
        """Extract standardized AncestryPath vector across canonical coordinates."""
        c = ctx or {}
        anc_dict = raw.get("ancestry_keys") or {}

        sample_id = (
            raw.get("sample_id")
            or raw.get("input_hash")
            or anc_dict.get("sample_id")
            or c.get("sample_id")
        )
        dataset_version_id = (
            raw.get("dataset_version_id")
            or raw.get("reference_dataset_version_id")
            or anc_dict.get("dataset_version_id")
            or c.get("dataset_version_id")
        )
        model_fingerprint = (
            raw.get("model_fingerprint")
            or raw.get("fingerprint_value")
            or raw.get("file_hash_sha256")
            or raw.get("model_hash")
            or anc_dict.get("model_fingerprint")
            or c.get("model_fingerprint")
        )
        window_id = (
            raw.get("window_id")
            or raw.get("baseline_run_id")
            or anc_dict.get("window_id")
            or c.get("window_id")
            or c.get("baseline_run_id")
        )
        source_id = (
            raw.get("source_id")
            or raw.get("contributor_id")
            or raw.get("source_group_id")
            or anc_dict.get("source_id")
            or c.get("source_id")
        )

        canonical_keys = {"sample_id", "dataset_version_id", "model_fingerprint", "window_id", "source_id"}
        extra_keys = {
            str(k): str(v)
            for k, v in anc_dict.items()
            if k not in canonical_keys and v is not None
        }

        ancestry = AncestryPath(
            sample_id=str(sample_id) if sample_id else None,
            dataset_version_id=str(dataset_version_id) if dataset_version_id else None,
            model_fingerprint=str(model_fingerprint) if model_fingerprint else None,
            window_id=str(window_id) if window_id else None,
            source_id=str(source_id) if source_id else None,
            extra_keys=extra_keys,
        )

        anc_status = AncestryStatus.VERIFIED if not ancestry.is_empty() else AncestryStatus.UNVERIFIED
        return ancestry, anc_status


