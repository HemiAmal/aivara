"""Distribution Shift Evidence Adapter (Phase 12.2 / Phase 11 Upstream).

Normalizes evidence from Distribution Shift:
- Feature and dataset drift profiles (KS, PSI, TVD, Chi-Square)
- Image visual descriptor shifts (brightness, contrast, sharpness, noise)
- Representation & embedding drift (MMD, Energy Distance, Wasserstein)
- Temporal and windowed trajectory shifts & change-point candidates
- Source-aware & contributor demographic shifts
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.adapters.base import BaseEvidenceAdapter
from aivara.universal.enums import AncestryStatus, SubsystemDomain
from aivara.universal.hashing import compute_payload_hash
from aivara.universal.schemas import AncestryPath, UniversalEvidenceEnvelope


class DistributionShiftEvidenceAdapter(BaseEvidenceAdapter):
    """Adapter for Phase 11 Distribution Shift evidence records."""

    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.DISTRIBUTION_SHIFT

    def normalize(
        self,
        raw_evidence: Union[Dict[str, Any], BaseModel],
        project_id: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> UniversalEvidenceEnvelope:
        ctx = context or {}
        raw = self._extract_dict(raw_evidence)

        # 1. Project boundary check
        ev_proj = raw.get("project_id") or ctx.get("project_id") or project_id
        self._validate_project(ev_proj, project_id)

        # 2. Extract identity
        ev_id = str(raw.get("evidence_id") or raw.get("id") or ctx.get("evidence_id") or f"ev_ds_{uuid.uuid4().hex[:12]}")
        ev_type = str(raw.get("evidence_type") or "distribution_shift_evidence")

        # 3. Layer, Severity, Confidence
        layer_raw = raw.get("evidence_layer", EvidenceLayer.DETECTION)
        if isinstance(layer_raw, str):
            layer_raw = EvidenceLayer(layer_raw.lower())

        sev_raw = raw.get("severity", Severity.INFO)
        if isinstance(sev_raw, str):
            sev_raw = Severity(sev_raw.lower())

        conf = self._extract_and_validate_confidence(raw, layer_raw)

        # 4. Asset identification
        asset_type = str(raw.get("target_asset_type") or "dataset")
        asset_id = str(raw.get("target_asset_id") or raw.get("dataset_version_id") or raw.get("affected_asset_id") or ctx.get("target_asset_id") or "unknown_asset")

        # 5. Ancestry extraction
        anc_dict = raw.get("ancestry_keys") or {}
        ds_ver_id = raw.get("dataset_version_id") or raw.get("reference_dataset_version_id") or anc_dict.get("dataset_version_id") or ctx.get("dataset_version_id")
        model_fp = raw.get("model_fingerprint") or raw.get("model_hash") or anc_dict.get("model_fingerprint") or ctx.get("model_fingerprint")
        window_id = raw.get("window_id") or anc_dict.get("window_id")
        src_id = raw.get("source_group_id") or raw.get("source_id") or anc_dict.get("source_id")
        
        ancestry = AncestryPath(
            dataset_version_id=str(ds_ver_id) if ds_ver_id else None,
            model_fingerprint=str(model_fp) if model_fp else None,
            window_id=str(window_id) if window_id else None,
            source_id=str(src_id) if src_id else None,
            extra_keys={k: str(v) for k, v in anc_dict.items() if k not in ("dataset_version_id", "model_fingerprint", "window_id", "source_id")},
        )
        anc_status = AncestryStatus.VERIFIED if not ancestry.is_empty() else AncestryStatus.UNVERIFIED

        # 6. Payloads & Hashes
        data_json = raw.get("data_json") or raw.get("metrics") or {k: v for k, v in raw.items() if k not in ("id", "evidence_id", "project_id", "source_payload_hash", "evidence_hash", "artifact_hash")}
        supplied_src_hash = raw.get("source_payload_hash") or raw.get("evidence_hash") or raw.get("artifact_hash")
        raw_bytes = ctx.get("raw_bytes")
        src_hash = self._verify_and_resolve_source_payload_hash(
            source_dict=data_json,
            supplied_hash=supplied_src_hash,
            raw_bytes=raw_bytes,
        )
        norm_hash = compute_payload_hash(data_json)

        # 7. Finding & Provenance
        finding_id = raw.get("finding_id") or ctx.get("finding_id")
        prov_ids, prov_hashes = self._extract_and_validate_provenance(raw)

        return UniversalEvidenceEnvelope(
            evidence_id=ev_id,
            project_id=project_id,
            domain=self.domain,
            evidence_type=ev_type,
            evidence_layer=layer_raw,
            severity=sev_raw,
            confidence=conf,
            primary_asset_type=asset_type,
            primary_asset_id=asset_id,
            finding_id=str(finding_id) if finding_id else None,
            source_record_id=str(raw.get("id")) if "id" in raw else None,
            source_entity_type="dataset",
            ancestry_status=anc_status,
            ancestry_path=ancestry,
            parent_evidence_ids=sorted(raw.get("parent_evidence_ids", [])),
            derived_from_evidence_ids=sorted(raw.get("derived_from_evidence_ids", [])),
            source_payload_hash=src_hash,
            normalized_payload_hash=norm_hash,
            provenance_record_ids=prov_ids,
            provenance_hashes=prov_hashes,
            data_json=data_json,
            metadata_json=raw.get("metadata_json", {}),
        )
