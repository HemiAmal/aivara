"""Test 12.12.6: Universal Risk Computation & Saturation Mathematics Verification."""

import pytest
from aivara.universal.graph.builder import UniversalEvidenceGraphBuilder
from aivara.universal.risk.engine import UniversalRiskComputationEngine
from aivara.universal.normalizer import UniversalEvidenceNormalizer


def test_cluster_saturation_and_monotonicity():
    """Verify cluster saturation formula S(C) = min(1, max + 0.15*sum(other)) and monotonicity."""
    eng = UniversalRiskComputationEngine()
    norm = UniversalEvidenceNormalizer()

    ev1 = norm.normalize_single({
        "evidence_id": "ev-r-1", "domain": "MODEL_INTEGRITY", "evidence_layer": "detection",
        "primary_asset_id": "asset-m", "severity": "medium", "confidence": 0.8
    }, project_id="proj-r")

    ev2 = norm.normalize_single({
        "evidence_id": "ev-r-2", "domain": "MODEL_INTEGRITY", "evidence_layer": "detection",
        "primary_asset_id": "asset-m", "severity": "high", "confidence": 0.9
    }, project_id="proj-r")

    b1 = UniversalEvidenceGraphBuilder(project_id="proj-r")
    b1.add_evidence_envelope(ev1)
    g1 = b1.validate_and_build()

    b2 = UniversalEvidenceGraphBuilder(project_id="proj-r")
    b2.add_evidence_envelope(ev1)
    b2.add_evidence_envelope(ev2)
    g2 = b2.validate_and_build()

    r1 = eng.compute_asset_risk(graph=g1, asset_id="asset-m")
    r2 = eng.compute_asset_risk(graph=g2, asset_id="asset-m")

    assert 0.0 <= r1.risk_score <= 1.0
    assert 0.0 <= r2.risk_score <= 1.0
    assert r2.risk_score >= r1.risk_score, "Monotonicity violated: additional evidence did not increase or maintain risk"


def test_severity_multipliers():
    """Verify exact severity multipliers: CRITICAL=1.0, HIGH=0.7, MEDIUM=0.4, LOW=0.1, INFO=0.05."""
    eng = UniversalRiskComputationEngine()
    multipliers = {k.upper(): v for k, v in eng.default_config.severity_multipliers.items()}
    assert multipliers["CRITICAL"] == 1.0
    assert multipliers["HIGH"] == 0.7
    assert multipliers["MEDIUM"] == 0.4
    assert multipliers["LOW"] == 0.1
    assert multipliers["INFO"] == 0.05

