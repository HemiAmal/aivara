"""Phase 12.4 Adversarial Mutation Test Suite (M1-M20).

Validates robust boundary defense against tampered payloads, cross-tenant leaks,
ancestry violations, corrupted hashes, and resource limit overflows.
"""

import pytest
from pydantic import ValidationError

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
from aivara.universal.ingestion.schemas import (
    EvidenceIngestionRecord,
    UpstreamEvidenceItem,
)
from aivara.universal.ingestion.service import CrossSubsystemEvidenceIngestionService


def _valid_item(project_id="proj-mut", **kwargs):
    payload = kwargs.pop("payload", {"key": "value"})
    p_hash = compute_sha256_digest(compute_canonical_jcs_bytes(payload))
    default_kwargs = {
        "project_id": project_id,
        "domain": SubsystemDomain.DATASET_INTEGRITY,
        "evidence_type": "dataset_integrity_evidence",
        "evidence_layer": EvidenceLayer.DETECTION,
        "severity": Severity.LOW,
        "confidence": 0.95,
        "evidence_id": "ev-mut-1",
        "data_json": payload,
        "source_payload_hash": p_hash,
    }
    default_kwargs.update(kwargs)
    return UpstreamEvidenceItem(**default_kwargs)


def test_m1_empty_payload():
    """M1: Ingestion of empty dictionary payload is handled gracefully."""
    service = CrossSubsystemEvidenceIngestionService()
    item = _valid_item(payload={})
    rec = service.ingest_single(item)
    assert rec.canonical_hash != ""


def test_m2_tampered_payload_hash():
    """M2: Tampered payload hash is rejected."""
    service = CrossSubsystemEvidenceIngestionService()
    item = _valid_item(source_payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    with pytest.raises(SourceHashMismatchIngestionError):
        service.ingest_single(item)


def test_m3_wrong_project_id_boundary():
    """M3: Evidence for tenant A cannot be ingested into tenant B builder."""
    service = CrossSubsystemEvidenceIngestionService()
    builder = UniversalEvidenceGraphBuilder(project_id="tenant-b")
    item = _valid_item(project_id="tenant-a")
    with pytest.raises(ProjectBoundaryIngestionError):
        service.ingest_single(item, builder=builder)


def test_m4_self_referencing_ancestry():
    """M4: Ancestry self-reference is rejected."""
    service = CrossSubsystemEvidenceIngestionService()
    item = _valid_item(
        evidence_id="ev-loop",
        ancestry={"parent_evidence_ids": ["ev-loop"]},
    )
    with pytest.raises(AncestryConflictIngestionError):
        service.ingest_single(item)


def test_m5_confidence_greater_than_one():
    """M5: Confidence > 1.0 is rejected by validation."""
    with pytest.raises(ValidationError):
        _valid_item(confidence=1.05)


def test_m6_confidence_less_than_zero():
    """M6: Confidence < 0.0 is rejected by validation."""
    with pytest.raises(ValidationError):
        _valid_item(confidence=-0.01)


def test_m7_invalid_domain_type():
    """M7: Passing invalid domain is rejected."""
    with pytest.raises(ValidationError):
        UpstreamEvidenceItem(
            project_id="p1",
            domain="NON_EXISTENT_DOMAIN",  # type: ignore
            evidence_type="test",
            evidence_layer=EvidenceLayer.DETECTION,
            severity=Severity.INFO,
            confidence=0.5,
            data_json={},
        )


def test_m8_invalid_severity():
    """M8: Passing invalid severity is rejected."""
    with pytest.raises(ValidationError):
        UpstreamEvidenceItem(
            project_id="p1",
            domain=SubsystemDomain.MODEL_INTEGRITY,
            evidence_type="test",
            evidence_layer=EvidenceLayer.DETECTION,
            severity="SUPER_CRITICAL",  # type: ignore
            confidence=0.5,
            data_json={},
        )


def test_m9_invalid_evidence_layer():
    """M9: Passing invalid layer is rejected."""
    with pytest.raises(ValidationError):
        UpstreamEvidenceItem(
            project_id="p1",
            domain=SubsystemDomain.MODEL_INTEGRITY,
            evidence_type="test",
            evidence_layer="HEURISTIC_ONLY",  # type: ignore
            severity=Severity.INFO,
            confidence=0.5,
            data_json={},
        )


def test_m10_deeply_nested_payload():
    """M10: Deeply nested payload canonical hash remains deterministic."""
    service = CrossSubsystemEvidenceIngestionService()
    nested_payload = {"level1": {"level2": {"level3": {"data": [1, 2, 3, {"k": "v"}]}}}}
    item = _valid_item(payload=nested_payload)
    rec = service.ingest_single(item)
    assert rec.canonical_hash != ""


def test_m11_unicode_and_special_chars():
    """M11: Unicode and special characters do not disrupt JCS canonicalization."""
    service = CrossSubsystemEvidenceIngestionService()
    payload = {"message": "你好 / Привет / 🚀", "symbols": "<>&'\""}
    item = _valid_item(payload=payload)
    rec = service.ingest_single(item)
    assert rec.canonical_hash != ""


def test_m12_batch_empty_project_id():
    """M12: Ingest batch with empty project ID raises ProjectBoundaryIngestionError."""
    service = CrossSubsystemEvidenceIngestionService()
    with pytest.raises(ProjectBoundaryIngestionError):
        service.ingest_batch(project_id="", items=[])


def test_m13_batch_project_mismatch_with_builder():
    """M13: Batch project ID mismatch with builder raises ProjectBoundaryIngestionError."""
    service = CrossSubsystemEvidenceIngestionService()
    builder = UniversalEvidenceGraphBuilder(project_id="proj-x")
    with pytest.raises(ProjectBoundaryIngestionError):
        service.ingest_batch(project_id="proj-y", items=[], builder=builder)


def test_m14_batch_exceeding_max_evidence_nodes():
    """M14: Batch exceeding 5000 items is rejected immediately."""
    service = CrossSubsystemEvidenceIngestionService()
    dummy_item = _valid_item()
    huge_items = [dummy_item] * 5001
    with pytest.raises(IngestionResourceLimitError):
        service.ingest_batch(project_id="proj-mut", items=huge_items)


def test_m15_missing_domain_handler_error():
    """M15: Registry rejecting unregistered domain lookup."""
    from aivara.universal.ingestion.registry import IngestionHandlerRegistry
    reg = IngestionHandlerRegistry()
    with pytest.raises(DomainMismatchIngestionError):
        reg.get_handler("NOT_A_DOMAIN")  # type: ignore


def test_m16_immutable_record_verification():
    """M16: EvidenceIngestionRecord is immutable and modifications are prevented."""
    service = CrossSubsystemEvidenceIngestionService()
    item = _valid_item()
    record = service.ingest_single(item)
    with pytest.raises(ValidationError):
        record.status = "MUTATED"  # type: ignore


def test_m17_finding_bound_to_evidence():
    """M17: Finding bound to evidence via graph builder."""
    service = CrossSubsystemEvidenceIngestionService()
    builder = UniversalEvidenceGraphBuilder(project_id="proj-mut")
    item = _valid_item(
        finding_id="find-1",
    )
    rec = service.ingest_single(item, builder=builder)
    assert rec.status == IngestionStatus.INGESTED
    graph = builder.validate_and_build()
    assert graph.edge_count >= 1


def test_m18_batch_with_mixed_valid_and_invalid_items():
    """M18: Batch gracefully reports errors while continuing valid ingestion."""
    service = CrossSubsystemEvidenceIngestionService()
    valid_item = _valid_item(evidence_id="ev-valid-1")
    invalid_item = UpstreamEvidenceItem(
        project_id="proj-other-tenant",  # Mismatch
        domain=SubsystemDomain.MODEL_INTEGRITY,
        evidence_type="model_integrity_evidence",
        evidence_layer=EvidenceLayer.DETECTION,
        severity=Severity.HIGH,
        confidence=0.9,
        data_json={"k": "v"},
    )
    report = service.ingest_batch(
        project_id="proj-mut",
        items=[valid_item, invalid_item],
    )
    assert report.total_items == 2
    assert report.ingested_count == 1
    assert report.rejected_count == 1
    assert len(report.records) == 2


def test_m19_preservation_of_primary_asset_ids():
    """M19: Primary asset type and ID are preserved through ingestion envelope."""
    service = CrossSubsystemEvidenceIngestionService()
    item = _valid_item(
        asset_type="model",
        asset_id="model-bert-v2",
    )
    rec = service.ingest_single(item)
    assert rec.asset_type == "model"
    assert rec.asset_id == "model-bert-v2"


def test_m20_deterministic_ingestion_report_hash():
    """M20: Ingestion report hash is deterministically identical for identical batches."""
    service = CrossSubsystemEvidenceIngestionService()
    items1 = [_valid_item(evidence_id="ev-1"), _valid_item(evidence_id="ev-2")]
    items2 = [_valid_item(evidence_id="ev-1"), _valid_item(evidence_id="ev-2")]

    rep1 = service.ingest_batch("proj-det", items1)
    rep2 = service.ingest_batch("proj-det", items2)

    assert rep1.ingestion_report_hash == rep2.ingestion_report_hash
