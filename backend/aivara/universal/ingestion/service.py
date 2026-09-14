"""Phase 12.4 Cross-Subsystem Evidence Ingestion Service.

Authoritative orchestration pipeline for ingesting, validating, normalizing,
and binding upstream assurance evidence from Phases 5-11 into the Universal
Evidence Graph (Phase 12.3).
"""

from __future__ import annotations

import hmac
from typing import Any, Dict, List, Optional, Sequence, Set, Union

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.exceptions import (
    AdapterMismatchError,
    InvalidEvidenceError,
    ProjectMismatchError,
    UniversalResourceLimitExceededError,
    UnknownDomainError,
)
from aivara.universal.graph.builder import (
    MAX_ASSET_NODES,
    MAX_EVIDENCE_NODES,
    MAX_FINDING_NODES,
    UniversalEvidenceGraphBuilder,
)
from aivara.universal.graph.graph import UniversalEvidenceGraph
from aivara.universal.hashing import compute_canonical_jcs_bytes, compute_sha256_digest
from aivara.universal.ingestion.enums import IngestionErrorType, IngestionStatus
from aivara.universal.ingestion.exceptions import (
    AncestryConflictIngestionError,
    DomainMismatchIngestionError,
    IngestionResourceLimitError,
    IngestionValidationError,
    ProjectBoundaryIngestionError,
    SourceHashMismatchIngestionError,
    UniversalIngestionError,
)
from aivara.universal.ingestion.registry import IngestionHandlerRegistry
from aivara.universal.ingestion.schemas import (
    EvidenceIngestionRecord,
    IngestionReport,
    UpstreamEvidenceItem,
)
from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.schemas import UniversalEvidenceEnvelope


class CrossSubsystemEvidenceIngestionService:
    """Authoritative service for ingesting upstream evidence across all 7 assurance subsystems."""

    def __init__(
        self,
        registry: Optional[IngestionHandlerRegistry] = None,
        normalizer: Optional[UniversalEvidenceNormalizer] = None,
    ) -> None:
        self._registry = registry or IngestionHandlerRegistry()
        self._normalizer = normalizer or UniversalEvidenceNormalizer()

    @property
    def registry(self) -> IngestionHandlerRegistry:
        return self._registry

    @property
    def normalizer(self) -> UniversalEvidenceNormalizer:
        return self._normalizer

    def ingest_single(
        self,
        item: UpstreamEvidenceItem,
        builder: Optional[UniversalEvidenceGraphBuilder] = None,
        target_project_id: Optional[str] = None,
        seen_hashes: Optional[Set[str]] = None,
    ) -> EvidenceIngestionRecord:
        """Ingest, validate, normalize, and optionally graph-bind a single upstream evidence item."""
        if not isinstance(item, UpstreamEvidenceItem):
            raise IngestionValidationError(
                f"Expected UpstreamEvidenceItem, got {type(item).__name__}."
            )

        # 1. Project Boundary Validation
        expected_project = target_project_id or (builder.project_id if builder else item.project_id)
        if item.project_id != expected_project:
            raise ProjectBoundaryIngestionError(
                f"Evidence item project '{item.project_id}' violates project boundary '{expected_project}'."
            )

        # 2. Domain Handler Lookup & Validation
        try:
            handler = self._registry.get_handler(item.domain)
        except DomainMismatchIngestionError as err:
            raise DomainMismatchIngestionError(str(err)) from err

        # 3. Source Payload Integrity Verification
        if item.source_payload_hash:
            computed_source_hash = compute_sha256_digest(
                compute_canonical_jcs_bytes(item.data_json)
            )
            if not hmac.compare_digest(item.source_payload_hash, computed_source_hash):
                raise SourceHashMismatchIngestionError(
                    f"Source payload hash mismatch for evidence '{item.evidence_id}': "
                    f"claimed {item.source_payload_hash}, computed {computed_source_hash}."
                )

        # 4. Ancestry Conflict Check (Self-loop)
        parent_ids = []
        if item.ancestry and isinstance(item.ancestry, dict):
            parent_ids = item.ancestry.get("parent_evidence_ids", [])
        if item.evidence_id and item.evidence_id in parent_ids:
            raise AncestryConflictIngestionError(
                f"Evidence item '{item.evidence_id}' lists itself as a parent."
            )

        # 5. Domain Handler Normalization via Universal Evidence Normalizer (Phase 12.2)
        try:
            envelope = handler.validate_and_normalize(
                raw_evidence=item,
                project_id=expected_project,
                normalizer=self._normalizer,
            )
        except DomainMismatchIngestionError as dm_err:
            raise dm_err
        except ProjectMismatchError as p_err:
            raise ProjectBoundaryIngestionError(str(p_err)) from p_err
        except UniversalResourceLimitExceededError as r_err:
            raise IngestionResourceLimitError(str(r_err)) from r_err
        except (InvalidEvidenceError, ValueError, Exception) as norm_err:
            raise IngestionValidationError(f"Normalization failed: {norm_err}") from norm_err

        # 6. Deduplication Check
        is_duplicate = False
        if seen_hashes is not None and envelope.canonical_hash in seen_hashes:
            is_duplicate = True

        status = IngestionStatus.DUPLICATE_SKIPPED if is_duplicate else IngestionStatus.INGESTED
        bound_to_graph = False

        # 7. Graph Binding (Phase 12.3)
        if builder is not None and not is_duplicate:
            if builder._evidence_count >= MAX_EVIDENCE_NODES:
                raise IngestionResourceLimitError(
                    f"Evidence node ceiling ({MAX_EVIDENCE_NODES}) exceeded during ingestion."
                )
            builder.add_evidence_envelope(envelope)
            bound_to_graph = True

        if seen_hashes is not None and not is_duplicate:
            seen_hashes.add(envelope.canonical_hash)

        # 8. Ingestion Record Generation
        record_id = f"ingrec_{envelope.evidence_id}"
        record = EvidenceIngestionRecord(
            ingestion_record_id=record_id,
            project_id=envelope.project_id,
            source_domain=envelope.domain,
            source_evidence_id=envelope.evidence_id,
            source_finding_id=envelope.finding_id,
            source_payload_hash=envelope.source_payload_hash,
            normalized_evidence_id=envelope.evidence_id,
            canonical_hash=envelope.canonical_hash,
            asset_id=envelope.primary_asset_id,
            asset_type=envelope.primary_asset_type,
            evidence_layer=envelope.evidence_layer,
            severity=envelope.severity,
            confidence=envelope.confidence,
            ancestry_path=envelope.ancestry_path,
            ancestry_status=envelope.ancestry_status,
            status=status,
            bound_to_graph=bound_to_graph,
        )
        return record

    def ingest_batch(
        self,
        project_id: str,
        items: Sequence[UpstreamEvidenceItem],
        builder: Optional[UniversalEvidenceGraphBuilder] = None,
    ) -> IngestionReport:
        """Ingest a batch of upstream evidence items under strict isolation, validation, and governance."""
        if not project_id:
            raise ProjectBoundaryIngestionError("Project ID must not be empty.")

        if len(items) > MAX_EVIDENCE_NODES:
            raise IngestionResourceLimitError(
                f"Batch size {len(items)} exceeds maximum evidence ceiling {MAX_EVIDENCE_NODES}."
            )

        graph_builder = builder or UniversalEvidenceGraphBuilder(project_id=project_id)
        if graph_builder.project_id != project_id:
            raise ProjectBoundaryIngestionError(
                f"Graph builder project '{graph_builder.project_id}' does not match batch project '{project_id}'."
            )

        ingested_count = 0
        duplicate_count = 0
        rejected_count = 0
        records: List[EvidenceIngestionRecord] = []
        seen_hashes: Set[str] = set()

        for idx, item in enumerate(items):
            try:
                record = self.ingest_single(
                    item=item,
                    builder=graph_builder,
                    target_project_id=project_id,
                    seen_hashes=seen_hashes,
                )
                records.append(record)
                if record.status == IngestionStatus.INGESTED:
                    ingested_count += 1
                elif record.status == IngestionStatus.DUPLICATE_SKIPPED:
                    duplicate_count += 1
            except (
                UniversalIngestionError,
                IngestionValidationError,
                DomainMismatchIngestionError,
                ProjectBoundaryIngestionError,
                SourceHashMismatchIngestionError,
                AncestryConflictIngestionError,
                IngestionResourceLimitError,
            ) as err:
                rejected_count += 1
                rec_id = f"ingrec_failed_{idx}"
                ev_id = getattr(item, "evidence_id", f"unknown_{idx}") or f"unknown_{idx}"
                d_val = getattr(item, "domain", SubsystemDomain.DATASET_INTEGRITY)
                err_rec = EvidenceIngestionRecord(
                    ingestion_record_id=rec_id,
                    project_id=project_id,
                    source_domain=d_val if isinstance(d_val, SubsystemDomain) else SubsystemDomain.DATASET_INTEGRITY,
                    source_evidence_id=ev_id,
                    source_payload_hash="0" * 64,
                    normalized_evidence_id=ev_id,
                    canonical_hash="0" * 64,
                    asset_id="unknown",
                    asset_type="unknown",
                    evidence_layer=getattr(item, "evidence_layer", EvidenceLayer.DETECTION),
                    severity=getattr(item, "severity", Severity.INFO),
                    confidence=0.0,
                    status=IngestionStatus.REJECTED,
                    error_type=IngestionErrorType.VALIDATION_ERROR,
                    error_message=str(err),
                    bound_to_graph=False,
                )
                records.append(err_rec)
            except Exception as uncaught:
                rejected_count += 1
                rec_id = f"ingrec_uncaught_{idx}"
                ev_id = getattr(item, "evidence_id", f"unknown_{idx}") or f"unknown_{idx}"
                d_val = getattr(item, "domain", SubsystemDomain.DATASET_INTEGRITY)
                err_rec = EvidenceIngestionRecord(
                    ingestion_record_id=rec_id,
                    project_id=project_id,
                    source_domain=d_val if isinstance(d_val, SubsystemDomain) else SubsystemDomain.DATASET_INTEGRITY,
                    source_evidence_id=ev_id,
                    source_payload_hash="0" * 64,
                    normalized_evidence_id=ev_id,
                    canonical_hash="0" * 64,
                    asset_id="unknown",
                    asset_type="unknown",
                    evidence_layer=getattr(item, "evidence_layer", EvidenceLayer.DETECTION),
                    severity=getattr(item, "severity", Severity.INFO),
                    confidence=0.0,
                    status=IngestionStatus.REJECTED,
                    error_type=IngestionErrorType.UNKNOWN_ERROR,
                    error_message=str(uncaught),
                    bound_to_graph=False,
                )
                records.append(err_rec)

        # If graph builder has nodes, compute graph merkle root
        merkle_root = None
        if graph_builder._nodes:
            try:
                graph = graph_builder.validate_and_build()
                merkle_root = graph.merkle_root
            except Exception:
                merkle_root = None

        return IngestionReport(
            project_id=project_id,
            total_items=len(items),
            ingested_count=ingested_count,
            duplicate_count=duplicate_count,
            rejected_count=rejected_count,
            records=records,
            graph_merkle_root=merkle_root,
        )
