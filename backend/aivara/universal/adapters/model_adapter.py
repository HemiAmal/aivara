"""Model Integrity Evidence Adapter (Phase 12.2 / Phase 7 Upstream).

Normalizes evidence from Model Integrity:
- Structural model layer digests & graph topology
- Layer-by-layer weight Merkle tree inclusion proofs
- Model master file SHA-256 fingerprints
- Quantization & precision consistency deltas
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


class ModelIntegrityEvidenceAdapter(BaseEvidenceAdapter):
    """Adapter for Phase 7 Model Integrity evidence records."""

    @property
    def domain(self) -> SubsystemDomain:
        return SubsystemDomain.MODEL_INTEGRITY

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
        ev_id = str(raw.get("evidence_id") or raw.get("id") or ctx.get("evidence_id") or f"ev_mi_{uuid.uuid4().hex[:12]}")
        ev_type = str(raw.get("evidence_type") or raw.get("fingerprint_type") or "model_integrity_proof")

        # 3. Layer, Severity, Confidence
        layer_raw = raw.get("evidence_layer", EvidenceLayer.PROOF)
        if isinstance(layer_raw, str):
            layer_raw = EvidenceLayer(layer_raw.lower())

        sev_raw = raw.get("severity", Severity.INFO)
        if isinstance(sev_raw, str):
            sev_raw = Severity(sev_raw.lower())

        conf = self._extract_and_validate_confidence(raw, layer_raw)

        # 4. Asset identification
        asset_type = str(raw.get("target_asset_type") or "model")
        model_id = raw.get("model_id") or raw.get("target_asset_id") or raw.get("affected_asset_id") or ctx.get("model_id") or "unknown_model"
        asset_id = str(model_id)

        # 5. Ancestry extraction
        anc_dict = raw.get("ancestry_keys") or {}
        model_fp = raw.get("model_fingerprint") or raw.get("fingerprint_value") or raw.get("file_hash_sha256") or anc_dict.get("model_fingerprint") or ctx.get("model_fingerprint")
        
        ancestry = AncestryPath(
            model_fingerprint=str(model_fp) if model_fp else None,
            extra_keys={k: str(v) for k, v in anc_dict.items() if k != "model_fingerprint"},
        )
        anc_status = AncestryStatus.VERIFIED if not ancestry.is_empty() else AncestryStatus.UNVERIFIED

        # 6. Payloads & Hashes
        data_json = raw.get("data_json") or raw.get("payload") or {k: v for k, v in raw.items() if k not in ("id", "evidence_id", "project_id", "source_payload_hash", "artifact_hash")}
        supplied_src_hash = raw.get("source_payload_hash") or raw.get("artifact_hash")
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
            source_entity_type="model",
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
