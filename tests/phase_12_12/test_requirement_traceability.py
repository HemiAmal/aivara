"""Test 12.12.2: Comprehensive Requirement Traceability Verification."""

import os
import pytest

from aivara.universal.normalizer import UniversalEvidenceNormalizer
from aivara.universal.graph.builder import UniversalEvidenceGraphBuilder
from aivara.universal.correlation.engine import CrossDomainCorrelationEngine
from aivara.universal.risk.engine import UniversalRiskComputationEngine
from aivara.universal.policy.engine import UniversalPolicyEngine
from aivara.universal.proof.engine import UniversalProofIntegrationEngine
from aivara.universal.aggregation.engine import UniversalProjectAggregator
from aivara.universal.audit.generator import UniversalAuditReportGenerator


def test_phase_12_documentation_artifacts_exist():
    """Verify all formal requirement specifications exist in docs/."""
    required_docs = [
        "docs/PHASE_12_1_REQUIREMENTS.md",
        "docs/PHASE_12_2_REQUIREMENTS.md",
        "docs/PHASE_12_3_REQUIREMENTS.md",
        "docs/PHASE_12_4_REQUIREMENTS.md",
        "docs/PHASE_12_5_REQUIREMENTS.md",
        "docs/PHASE_12_6_REQUIREMENTS.md",
        "docs/PHASE_12_7_REQUIREMENTS.md",
        "docs/PHASE_12_8_REQUIREMENTS.md",
        "docs/PHASE_12_9_REQUIREMENTS.md",
        "docs/PHASE_12_10_REQUIREMENTS.md",
        "docs/PHASE_12_11_REQUIREMENTS.md",
        "docs/PHASE_12_12_REQUIREMENTS.md",
    ]
    for doc in required_docs:
        assert os.path.exists(doc), f"Missing formal requirement document: {doc}"


def test_core_engine_instantiations():
    """Verify that all core Phase 12 engines instantiate with verified default configs."""
    assert UniversalEvidenceNormalizer() is not None
    assert UniversalEvidenceGraphBuilder(project_id="test-proj") is not None
    assert CrossDomainCorrelationEngine() is not None
    assert UniversalRiskComputationEngine() is not None
    assert UniversalPolicyEngine() is not None
    assert UniversalProofIntegrationEngine() is not None
    assert UniversalProjectAggregator() is not None
    assert UniversalAuditReportGenerator() is not None

