"""Test Audit Evidence & Traceability Model (Phase 12.11)."""

import pytest
from aivara.universal.audit.enums import TraceabilityNodeType
from aivara.universal.audit.traceability import TraceabilityGraph


def test_traceability_graph_ancestor_resolution():
    """Verify bi-directional traceability graph can resolve upstream and downstream lineages."""
    graph = TraceabilityGraph(project_id="proj-audit-trace-1")

    # Build lineage: Project -> Asset -> Finding -> Evidence
    graph.add_link(TraceabilityNodeType.PROJECT, "proj-audit-trace-1", TraceabilityNodeType.ASSET, "asset-model-1")
    graph.add_link(TraceabilityNodeType.ASSET, "asset-model-1", TraceabilityNodeType.FINDING, "finding-101")
    graph.add_link(TraceabilityNodeType.FINDING, "finding-101", TraceabilityNodeType.EVIDENCE, "evidence-201")

    # Ancestor resolution for evidence
    ancestors = graph.resolve_ancestors(TraceabilityNodeType.EVIDENCE, "evidence-201")
    assert (TraceabilityNodeType.FINDING, "finding-101") in ancestors
    assert (TraceabilityNodeType.ASSET, "asset-model-1") in ancestors
    assert (TraceabilityNodeType.PROJECT, "proj-audit-trace-1") in ancestors


def test_authoritative_claim_grounding():
    """Verify material report claims are grounded with explicit source references and hashes."""
    graph = TraceabilityGraph(project_id="proj-audit-claim-1")
    claim = graph.add_claim(
        claim_id="claim-001",
        claim_type="POLICY_DECISION",
        summary="Asset evaluated to REJECT due to fatal proof tampering",
        asset_id="asset-model-1",
        decision_hash="a" * 64,
        proof_hash="b" * 64,
    )
    assert claim.claim_id == "claim-001"
    assert claim.asset_id == "asset-model-1"
    assert len(claim.claim_hash) == 64
    assert claim.decision_hash == "a" * 64
    assert claim.proof_hash == "b" * 64
