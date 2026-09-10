"""Evidence-Finding Binding and Traceability Graph Engine (Phase 5.9).

Provides:
  - Synthesis and persistence of Findings bound to Primary and Derived Evidence.
  - Conceptual N:M mapping implemented via Primary Foreign Keys + Structured Metadata References.
  - Backward traceability graph traversal connecting Finding -> Evidence -> Sample/Model/Dataset -> Provenance.
  - Cross-project reference protection and referential consistency validation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from aivara.database.models import (
    AIModelModel,
    ContributorModel,
    DatasetModel,
    DatasetVersionModel,
    EvidenceModel,
    FindingModel,
    ModelFingerprintModel,
    ProvenanceRecordModel,
    SampleModel,
)
from aivara.evidence.exceptions import (
    CrossProjectContaminationError,
    EvidenceValidationError,
    StaleDatasetVersionError,
)
from aivara.evidence.identity import compute_evidence_hash
from aivara.evidence.schemas import (
    EvidencePayload,
    FindingSynthesisPayload,
    ProvenanceStatus,
    TraceabilityChain,
    TraceabilityNode,
)
from aivara.evidence.validators import (
    validate_finding_payload,
    validate_project_isolation,
)

logger = logging.getLogger("aivara.evidence.binding")


class EvidenceFindingBinder:
    """Orchestrator for binding evidence to findings and establishing backward traceability."""

    def __init__(self, db: Session) -> None:
        """Initialize with an active database session.

        Args:
            db: Active SQLAlchemy database session.
        """
        self.db = db

    def synthesize_finding(
        self,
        payload: FindingSynthesisPayload,
    ) -> FindingModel:
        """Synthesize a Finding and bind both primary and derived evidence items.

        Args:
            payload: FindingSynthesisPayload containing finding attributes and evidence.

        Returns:
            The persisted FindingModel instance.
        """
        validate_finding_payload(payload)

        # 1. Prepare metadata dict
        meta = dict(payload.metadata_json) if payload.metadata_json else {}

        # 2. Validate and attach secondary/derived evidence references (N:M support)
        if payload.referenced_evidence_ids:
            # Verify all referenced evidence items exist and belong to the same project
            referenced_ev_models = (
                self.db.query(EvidenceModel, FindingModel.project_id)
                .join(FindingModel, EvidenceModel.finding_id == FindingModel.id)
                .filter(EvidenceModel.id.in_(payload.referenced_evidence_ids))
                .all()
            )

            found_ids = set()
            found_hashes = []
            for ev_model, ev_project_id in referenced_ev_models:
                validate_project_isolation(
                    payload.project_id,
                    ev_project_id,
                    entity_name=f"Referenced Evidence '{ev_model.id}'",
                )
                found_ids.add(ev_model.id)
                if ev_model.evidence_hash:
                    found_hashes.append(ev_model.evidence_hash)

            missing_ids = set(payload.referenced_evidence_ids) - found_ids
            if missing_ids:
                logger.warning(
                    "Derived finding references missing evidence IDs: %s. Storing references for forward compatibility.",
                    list(missing_ids),
                )

            meta["referenced_evidence_ids"] = list(payload.referenced_evidence_ids)
            if payload.referenced_evidence_hashes:
                meta["referenced_evidence_hashes"] = list(payload.referenced_evidence_hashes)
            elif found_hashes:
                meta["referenced_evidence_hashes"] = found_hashes

        # 3. Create the FindingModel row
        finding = FindingModel(
            project_id=payload.project_id,
            audit_run_id=payload.audit_run_id,
            engine_id=payload.engine_id,
            engine_version=payload.engine_version,
            evidence_layer=payload.evidence_layer.value,
            finding_type=payload.finding_type,
            title=payload.title,
            description=payload.description,
            severity=payload.severity.value,
            confidence=payload.confidence,
            affected_asset_type=payload.affected_asset_type,
            affected_asset_id=payload.affected_asset_id,
            disposition=payload.disposition.value,
            analysis_mode=payload.analysis_mode.value,
            recommendation=payload.recommendation,
            status=payload.status,
            metadata_json=meta,
        )
        self.db.add(finding)
        self.db.flush()

        # 4. Create and bind primary evidence items (1:N primary foreign key)
        primary_hashes = []
        for ev_payload in payload.primary_evidence_items:
            ev_hash = ev_payload.evidence_hash
            if not ev_hash:
                ds_ver_id = ev_payload.dataset_version_id or meta.get("dataset_version_id") or "NONE"
                ds_fp = ev_payload.dataset_fingerprint or meta.get("dataset_fingerprint") or ("0" * 64)
                cfg_hash = ev_payload.detector_config_hash or meta.get("detector_config_hash") or ("0" * 64)
                det_id = ev_payload.detector_id or payload.engine_id
                det_ver = ev_payload.detector_version or payload.engine_version or "1.0.0"

                # Compute deterministic evidence hash if not provided
                ev_hash = compute_evidence_hash({
                    "evidence_layer": ev_payload.evidence_layer.value,
                    "evidence_type": ev_payload.evidence_type,
                    "project_id": payload.project_id,
                    "dataset_version_id": ds_ver_id,
                    "dataset_fingerprint": ds_fp,
                    "target_asset_type": ev_payload.target_asset_type,
                    "target_asset_id": ev_payload.target_asset_id,
                    "target_asset_hash": ev_payload.target_asset_hash or "NONE",
                    "detector_id": det_id,
                    "detector_version": det_ver,
                    "detector_config_hash": cfg_hash,
                    "model_fingerprint": ev_payload.model_fingerprint or "NONE",
                    "reference_fingerprint": ev_payload.reference_fingerprint or "NONE",
                    "measurements": ev_payload.measurements,
                })

            primary_hashes.append(ev_hash)

            ev_model = EvidenceModel(
                finding_id=finding.id,
                evidence_layer=ev_payload.evidence_layer.value,
                evidence_type=ev_payload.evidence_type,
                title=ev_payload.title,
                description=ev_payload.description,
                data_json=ev_payload.data_json,
                artifact_path=ev_payload.artifact_path,
                artifact_hash=ev_payload.artifact_hash,
                confidence=ev_payload.confidence,
                evidence_hash=ev_hash,
            )
            self.db.add(ev_model)

        # 5. Store primary evidence hashes in finding metadata for quick integrity verification
        if primary_hashes:
            meta["primary_evidence_hashes"] = primary_hashes
            finding.metadata_json = dict(meta)
            flag_modified(finding, "metadata_json")

        self.db.flush()
        return finding

    def build_traceability_chain(
        self,
        finding_id: str,
        project_id: str,
    ) -> TraceabilityChain:
        """Trace backward from a finding to its evidence, source data assets, and provenance records.

        Args:
            finding_id: Identifier of the target FindingModel.
            project_id: Expected project identifier for security validation.

        Returns:
            TraceabilityChain containing all resolved nodes and provenance binding status.
        """
        finding = self.db.query(FindingModel).filter(FindingModel.id == finding_id).first()
        if not finding:
            raise EvidenceValidationError(f"Finding with ID '{finding_id}' not found.")

        validate_project_isolation(project_id, finding.project_id, entity_name=f"Finding '{finding_id}'")

        nodes: Dict[str, TraceabilityNode] = {}
        primary_ev_ids: List[str] = []
        secondary_ev_ids: List[str] = []

        # 1. Finding node
        finding_node = TraceabilityNode(
            entity_type="finding",
            entity_id=finding.id,
            entity_hash=None,
            attributes={
                "finding_type": finding.finding_type,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "evidence_layer": finding.evidence_layer,
                "affected_asset_type": finding.affected_asset_type,
                "affected_asset_id": finding.affected_asset_id,
            },
            parent_ids=[],
        )
        nodes[f"finding:{finding.id}"] = finding_node

        # 2. Resolve primary evidence items
        primary_evidence_list = (
            self.db.query(EvidenceModel)
            .filter(EvidenceModel.finding_id == finding.id)
            .all()
        )

        for ev in primary_evidence_list:
            primary_ev_ids.append(ev.id)
            ev_node_id = f"evidence:{ev.id}"
            nodes[ev_node_id] = TraceabilityNode(
                entity_type="evidence",
                entity_id=ev.id,
                entity_hash=ev.evidence_hash,
                attributes={
                    "evidence_type": ev.evidence_type,
                    "title": ev.title,
                    "confidence": ev.confidence,
                    "data_json": ev.data_json,
                },
                parent_ids=[f"finding:{finding.id}"],
            )

            # Trace referenced assets inside evidence data_json
            self._trace_evidence_assets(ev, ev_node_id, project_id, nodes)

        # 3. Resolve secondary / derived evidence items
        meta = finding.metadata_json or {}
        ref_ids = meta.get("referenced_evidence_ids", [])
        if ref_ids:
            sec_ev_list = (
                self.db.query(EvidenceModel)
                .filter(EvidenceModel.id.in_(ref_ids))
                .all()
            )
            for ev in sec_ev_list:
                secondary_ev_ids.append(ev.id)
                ev_node_id = f"evidence:{ev.id}"
                if ev_node_id not in nodes:
                    nodes[ev_node_id] = TraceabilityNode(
                        entity_type="evidence",
                        entity_id=ev.id,
                        entity_hash=ev.evidence_hash,
                        attributes={
                            "evidence_type": ev.evidence_type,
                            "title": ev.title,
                            "confidence": ev.confidence,
                            "is_derived_reference": True,
                        },
                        parent_ids=[f"finding:{finding.id}"],
                    )
                    self._trace_evidence_assets(ev, ev_node_id, project_id, nodes)

        # 4. Check for associated provenance record
        prov_record_id = meta.get("provenance_record_id")
        prov_status = ProvenanceStatus.UNAVAILABLE

        if prov_record_id:
            prov_record = (
                self.db.query(ProvenanceRecordModel)
                .filter(
                    ProvenanceRecordModel.id == prov_record_id,
                    ProvenanceRecordModel.project_id == project_id,
                )
                .first()
            )
            if prov_record:
                prov_status = ProvenanceStatus.VERIFIED if prov_record.signature else ProvenanceStatus.UNAVAILABLE
                nodes[f"provenance:{prov_record.id}"] = TraceabilityNode(
                    entity_type="provenance",
                    entity_id=prov_record.id,
                    entity_hash=prov_record.record_hash,
                    attributes={
                        "record_type": prov_record.record_type,
                        "action": prov_record.action,
                        "sequence_number": prov_record.sequence_number,
                        "signature_present": bool(prov_record.signature),
                        "signer_key_id": prov_record.signer_key_id,
                    },
                    parent_ids=[f"finding:{finding.id}"],
                )
            else:
                prov_status = ProvenanceStatus.MISSING

        return TraceabilityChain(
            finding_id=finding.id,
            project_id=project_id,
            dataset_version_id=meta.get("dataset_version_id"),
            dataset_fingerprint=meta.get("dataset_fingerprint"),
            nodes=nodes,
            primary_evidence_ids=primary_ev_ids,
            secondary_evidence_ids=secondary_ev_ids,
            provenance_record_id=prov_record_id,
            provenance_status=prov_status,
        )

    def _trace_evidence_assets(
        self,
        ev: EvidenceModel,
        ev_node_id: str,
        project_id: str,
        nodes: Dict[str, TraceabilityNode],
    ) -> None:
        """Helper to extract sample, contributor, dataset version, and model nodes from evidence data."""
        data = ev.data_json or {}

        # Trace sample
        sample_id = data.get("sample_id")
        if sample_id:
            sample = self.db.query(SampleModel).filter(SampleModel.id == sample_id).first()
            if sample:
                sample_node_id = f"sample:{sample.id}"
                if sample_node_id not in nodes:
                    nodes[sample_node_id] = TraceabilityNode(
                        entity_type="sample",
                        entity_id=sample.id,
                        entity_hash=sample.file_hash_sha256,
                        attributes={
                            "file_path": sample.file_path,
                            "dataset_version_id": sample.dataset_version_id,
                        },
                        parent_ids=[ev_node_id],
                    )

        # Trace contributor
        contributor_id = data.get("contributor_id")
        if contributor_id:
            contrib = (
                self.db.query(ContributorModel)
                .filter(ContributorModel.id == contributor_id, ContributorModel.project_id == project_id)
                .first()
            )
            if contrib:
                contrib_node_id = f"contributor:{contrib.id}"
                if contrib_node_id not in nodes:
                    nodes[contrib_node_id] = TraceabilityNode(
                        entity_type="contributor",
                        entity_id=contrib.id,
                        entity_hash=None,
                        attributes={
                            "external_id": contrib.external_id,
                            "name": contrib.name,
                        },
                        parent_ids=[ev_node_id],
                    )

        # Trace AI model
        model_id = data.get("model_id")
        if model_id:
            ai_model = (
                self.db.query(AIModelModel)
                .filter(AIModelModel.id == model_id, AIModelModel.project_id == project_id)
                .first()
            )
            if ai_model:
                model_node_id = f"model:{ai_model.id}"
                if model_node_id not in nodes:
                    nodes[model_node_id] = TraceabilityNode(
                        entity_type="model",
                        entity_id=ai_model.id,
                        entity_hash=ai_model.file_hash_sha256,
                        attributes={
                            "name": ai_model.name,
                            "version": ai_model.version,
                            "format": ai_model.format,
                        },
                        parent_ids=[ev_node_id],
                    )
