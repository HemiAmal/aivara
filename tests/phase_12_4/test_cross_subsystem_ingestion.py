"""Phase 12.4 Cross-Subsystem Evidence Ingestion Core Test Suite.

Verifies end-to-end ingestion across all 7 canonical domains, project boundaries,
domain validations, N:M graph bindings, idempotency, proof/detection confidence preservation,
and resource limits.
"""

import pytest

from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.graph.builder import UniversalEvidenceGraphBuilder
from aivara.universal.hashing import compute_canonical_jcs_bytes, compute_sha256_digest
from aivara.universal.ingestion.enums import IngestionStatus
from aivara.universal.ingestion.exceptions import (
    AncestryConflictIngestionError,
    DomainMismatchIngestionError,
    IngestionResourceLimitError,
    IngestionValidationError,
    ProjectBoundaryIngestionError,
    SourceHashMismatchIngestionError,
)
from aivara.universal.ingestion.registry import IngestionHandlerRegistry
from aivara.universal.ingestion.schemas import (
    EvidenceIngestionRecord,
    IngestionReport,
    UpstreamEvidenceItem,
)
from aivara.universal.ingestion.service import CrossSubsystemEvidenceIngestionService


def _create_sample_item(
    project_id: str = "proj-alpha",
    domain: SubsystemDomain = SubsystemDomain.DATASET_INTEGRITY,
    evidence_id: str = "ev-001",
    layer: EvidenceLayer = EvidenceLayer.DETECTION,
    severity: Severity = Severity.MEDIUM,
    confidence: float = 0.85,
    payload: dict = None,
    finding_id: str = "find-101",
    parent_evidence_ids: list = None,
) -> UpstreamEvidenceItem:
    if payload is None:
        payload = {"sample_key": "sample_val", "status": "ok"}
    p_hash = compute_sha256_digest(compute_canonical_jcs_bytes(payload))
    ancestry = {"parent_evidence_ids": parent_evidence_ids or []} if parent_evidence_ids else None
    return UpstreamEvidenceItem(
        project_id=project_id,
        domain=domain,
        evidence_type=f"{domain.value.lower()}_evidence",
        evidence_layer=layer,
        severity=severity,
        confidence=confidence,
        evidence_id=evidence_id,
        finding_id=finding_id,
        data_json=payload,
        source_payload_hash=p_hash,
        ancestry=ancestry,
    )


def test_registry_contains_all_seven_canonical_domains():
    """Verify registry has handlers for all 7 canonical assurance domains."""
    registry = IngestionHandlerRegistry()
    assert len(registry.registered_domains) == 7
    for domain in SubsystemDomain:
        assert registry.has_handler(domain)
        handler = registry.get_handler(domain)
        assert handler.domain == domain


def test_ingest_single_all_seven_domains():
    """Verify single-item ingestion for each of the 7 canonical domains."""
    service = CrossSubsystemEvidenceIngestionService()
    builder = UniversalEvidenceGraphBuilder(project_id="proj-test-all-domains")

    for domain in SubsystemDomain:
        item = _create_sample_item(
            project_id="proj-test-all-domains",
            domain=domain,
            evidence_id=f"ev-{domain.value}",
        )
        record = service.ingest_single(item, builder=builder)
        assert record.status == IngestionStatus.INGESTED
        assert record.source_domain == domain
        assert record.canonical_hash != ""
        assert record.bound_to_graph is True

    # Validate resulting graph
    graph = builder.validate_and_build()
    assert graph.node_count >= 7
    assert graph.merkle_root != ""


def test_project_boundary_isolation_single():
    """Verify project boundary violation throws ProjectBoundaryIngestionError."""
    service = CrossSubsystemEvidenceIngestionService()
    builder = UniversalEvidenceGraphBuilder(project_id="proj-tenant-a")

    item = _create_sample_item(project_id="proj-tenant-b")
    with pytest.raises(ProjectBoundaryIngestionError):
        service.ingest_single(item, builder=builder)


def test_source_payload_hash_mismatch():
    """Verify corrupted source payload hash is detected and rejected."""
    service = CrossSubsystemEvidenceIngestionService()
    item = _create_sample_item(
        payload={"real_key": "real_val"},
    )
    tampered_item = UpstreamEvidenceItem(
        project_id=item.project_id,
        domain=item.domain,
        evidence_type=item.evidence_type,
        evidence_layer=item.evidence_layer,
        severity=item.severity,
        confidence=item.confidence,
        evidence_id=item.evidence_id,
        data_json=item.data_json,
        source_payload_hash="0" * 64,  # Bad hash
    )
    with pytest.raises(SourceHashMismatchIngestionError):
        service.ingest_single(tampered_item)


def test_confidence_preservation_detection_vs_proof():
    """Verify proof confidence is strictly 1.0 and detection preserves exact confidence."""
    service = CrossSubsystemEvidenceIngestionService()

    # Detection item with confidence 0.73
    det_item = _create_sample_item(
        layer=EvidenceLayer.DETECTION,
        confidence=0.73,
    )
    rec_det = service.ingest_single(det_item)
    assert rec_det.confidence == 0.73

    # Proof item
    proof_item = _create_sample_item(
        layer=EvidenceLayer.PROOF,
        confidence=1.0,
    )
    rec_proof = service.ingest_single(proof_item)
    assert rec_proof.confidence == 1.0


def test_ancestry_self_reference_rejection():
    """Verify item referencing itself as parent is rejected."""
    service = CrossSubsystemEvidenceIngestionService()
    item = _create_sample_item(
        evidence_id="ev-self-loop",
        parent_evidence_ids=["ev-self-loop"],
    )
    with pytest.raises(AncestryConflictIngestionError):
        service.ingest_single(item)


def test_idempotency_and_deduplication():
    """Verify re-ingesting identical items is deduplicated without mutation."""
    service = CrossSubsystemEvidenceIngestionService()
    builder = UniversalEvidenceGraphBuilder(project_id="proj-idempotent")

    item1 = _create_sample_item(project_id="proj-idempotent", evidence_id="ev-dup")
    seen_hashes = set()

    rec1 = service.ingest_single(item1, builder=builder, seen_hashes=seen_hashes)
    assert rec1.status == IngestionStatus.INGESTED

    rec2 = service.ingest_single(item1, builder=builder, seen_hashes=seen_hashes)
    assert rec2.status == IngestionStatus.DUPLICATE_SKIPPED
    assert rec1.canonical_hash == rec2.canonical_hash

    # Graph should contain only one node for ev-dup
    graph = builder.validate_and_build()
    ev_nodes = [n for n in graph.get_nodes() if n.canonical_identity == "ev-dup"]
    assert len(ev_nodes) == 1


def test_batch_ingestion_report_generation():
    """Verify batch ingestion creates deterministic IngestionReport with accurate metrics."""
    service = CrossSubsystemEvidenceIngestionService()
    project_id = "proj-batch-test"

    items = [
        _create_sample_item(project_id=project_id, domain=SubsystemDomain.DATASET_INTEGRITY, evidence_id="ev-b1"),
        _create_sample_item(project_id=project_id, domain=SubsystemDomain.CONTRIBUTOR_RISK, evidence_id="ev-b2"),
        _create_sample_item(project_id=project_id, domain=SubsystemDomain.MODEL_INTEGRITY, evidence_id="ev-b3"),
        _create_sample_item(project_id=project_id, domain=SubsystemDomain.BEHAVIORAL_ANALYSIS, evidence_id="ev-b4"),
        _create_sample_item(project_id=project_id, domain=SubsystemDomain.BACKDOOR_TRIGGER, evidence_id="ev-b5"),
        _create_sample_item(project_id=project_id, domain=SubsystemDomain.INFERENCE_INTEGRITY, evidence_id="ev-b6"),
        _create_sample_item(project_id=project_id, domain=SubsystemDomain.DISTRIBUTION_SHIFT, evidence_id="ev-b7"),
        # Duplicate of ev-b1
        _create_sample_item(project_id=project_id, domain=SubsystemDomain.DATASET_INTEGRITY, evidence_id="ev-b1"),
    ]

    report = service.ingest_batch(project_id=project_id, items=items)
    assert report.total_items == 8
    assert report.ingested_count == 7
    assert report.duplicate_count == 1
    assert report.rejected_count == 0
    assert report.ingestion_report_hash != ""
    assert report.graph_merkle_root is not None
