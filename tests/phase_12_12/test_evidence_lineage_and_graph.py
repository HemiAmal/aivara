"""Test 12.12.4: Evidence Lineage & N:M Graph Topology Verification."""

import pytest
from aivara.domain.schemas import EvidenceLayer, Severity
from aivara.universal.enums import SubsystemDomain
from aivara.universal.graph import (
    GraphEdgeType,
    GraphNodeType,
    UniversalEvidenceGraphBuilder,
    compute_graph_merkle_root,
)
from aivara.universal.normalizer import UniversalEvidenceNormalizer


def test_five_coordinate_ancestry_preservation():
    """Verify all 5 ancestry coordinates are extracted and preserved."""
    normalizer = UniversalEvidenceNormalizer()
    raw = {
        "evidence_id": "ev-anc-1",
        "domain": SubsystemDomain.DATASET_INTEGRITY.value,
        "evidence_layer": EvidenceLayer.DETECTION.value,
        "primary_asset_id": "asset-ds-1",
        "severity": "low",
        "confidence": 0.90,
        "ancestry_keys": {
            "sample_id": "sample-999",
            "dataset_version_id": "ds-v1.0",
            "model_fingerprint": "fp-model-sha256",
            "window_id": "win-001",
            "source_id": "src-group-A",
        },
    }
    norm = normalizer.normalize_single(raw, project_id="proj-anc")
    assert norm.ancestry_path.sample_id == "sample-999"
    assert norm.ancestry_path.dataset_version_id == "ds-v1.0"
    assert norm.ancestry_path.model_fingerprint == "fp-model-sha256"
    assert norm.ancestry_path.window_id == "win-001"
    assert norm.ancestry_path.source_id == "src-group-A"


def test_nm_finding_evidence_graph_junction():
    """Verify N:M finding to evidence junction and Merkle root calculation."""
    normalizer = UniversalEvidenceNormalizer()

    ev1 = normalizer.normalize_single({
        "evidence_id": "ev-nm-1", "domain": "MODEL_INTEGRITY", "evidence_layer": "detection", "primary_asset_id": "a1", "severity": "low", "confidence": 0.8
    }, project_id="p-nm")
    ev2 = normalizer.normalize_single({
        "evidence_id": "ev-nm-2", "domain": "DATASET_INTEGRITY", "evidence_layer": "detection", "primary_asset_id": "a1", "severity": "medium", "confidence": 0.8
    }, project_id="p-nm")

    builder = UniversalEvidenceGraphBuilder(project_id="p-nm")
    builder.add_evidence_envelope(ev1)
    builder.add_evidence_envelope(ev2)
    builder.add_finding({"finding_id": "f-1", "project_id": "p-nm"})
    builder.add_finding({"finding_id": "f-2", "project_id": "p-nm"})
    builder.add_finding_evidence_binding(finding_id="f-1", evidence_id=ev1.evidence_id, relevance_weight=1.0)
    builder.add_finding_evidence_binding(finding_id="f-1", evidence_id=ev2.evidence_id, relevance_weight=0.8)
    builder.add_finding_evidence_binding(finding_id="f-2", evidence_id=ev1.evidence_id, relevance_weight=0.5)

    graph = builder.validate_and_build()
    assert graph.node_count >= 2
    assert graph.merkle_root is not None
    assert len(graph.merkle_root) == 64

