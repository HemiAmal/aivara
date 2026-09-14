"""Tests for Phase 12.9 Aggregation Schemas & Immutability (REQ-12-AGG-001, 006, 014)."""

import pytest
from pydantic import ValidationError

from aivara.universal.aggregation.config import ImmutableAggregationPolicyConfig
from aivara.universal.aggregation.enums import (
    AggregationSchemaVersion,
    AssetRole,
    DependencyEdgeType,
)
from aivara.universal.aggregation.exceptions import InvalidAssetRiskError
from aivara.universal.aggregation.schemas import (
    AssetDependencyEdge,
    AssetDependencyGraph,
    ChainPath,
    ProjectAggregationDisposition,
)
from aivara.universal.policy.enums import UniversalDecision
from aivara.universal.risk.enums import RiskLevel


def test_asset_dependency_edge_schema_and_hash():
    """AssetDependencyEdge validates finite weights and computes deterministic hash."""
    edge = AssetDependencyEdge(
        project_id="proj_schema_01",
        source_asset_id="asset_ds_01",
        target_asset_id="asset_model_01",
        edge_type=DependencyEdgeType.DERIVED_FROM,
        propagation_weight=0.85,
    )
    assert edge.project_id == "proj_schema_01"
    assert len(edge.edge_hash) == 64
    assert edge.to_canonical_dict()["propagation_weight"] == 0.85

    # Immutability check
    with pytest.raises(ValidationError):
        edge.propagation_weight = 0.50


def test_chain_path_schema_and_bounds():
    """ChainPath enforces risk bounds in [0.0, 1.0] and computes chain hash."""
    path = ChainPath(
        project_id="proj_schema_01",
        chain_id="chain_ds_to_model",
        asset_ids=["ds_01", "model_01"],
        chain_risk_score=0.425,
        hop_count=1,
    )
    assert path.chain_risk_score == 0.425
    assert len(path.chain_hash) == 64

    # Invalid out of bounds
    with pytest.raises((ValidationError, InvalidAssetRiskError)):
        ChainPath(
            project_id="proj_schema_01",
            chain_id="chain_inv",
            asset_ids=["a", "b"],
            chain_risk_score=1.5,
            hop_count=1,
        )


def test_project_aggregation_disposition_schema():
    """ProjectAggregationDisposition computes deterministic disposition hash."""
    disp = ProjectAggregationDisposition(
        project_id="proj_schema_01",
        decision=UniversalDecision.QUARANTINE,
        risk_score=0.72,
        risk_level=RiskLevel.HIGH,
        escalation_reason="Peripheral sample proof failure",
        proof_override_triggered=True,
    )
    assert disp.decision == UniversalDecision.QUARANTINE
    assert disp.proof_override_triggered is True
    assert len(disp.disposition_hash) == 64


def test_config_immutability_and_hash():
    """ImmutableAggregationPolicyConfig is frozen and content-addressed."""
    cfg = ImmutableAggregationPolicyConfig()
    assert len(cfg.config_hash) == 64
    assert cfg.schema_version == AggregationSchemaVersion.V1_0.value

    with pytest.raises(ValidationError):
        cfg.lineage_propagation_factor = 0.30
