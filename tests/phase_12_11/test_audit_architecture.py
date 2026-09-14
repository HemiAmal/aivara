"""Test Audit Architecture, Documentation, and Requirement Traceability (Phase 12.11)."""

import os
import pytest

from aivara.universal.audit.compliance import get_standard_compliance_controls
from aivara.universal.audit.enums import ComplianceFramework, ComplianceStatus, ReportIntegrityStatus


def test_documentation_files_exist():
    """Verify all mandatory Phase 12.11 documentation artifacts exist."""
    required_docs = [
        "docs/PHASE_12_11_ARCHITECTURE.md",
        "docs/PHASE_12_11_REQUIREMENTS.md",
        "docs/PHASE_12_11_THREAT_MODEL.md",
        "docs/PHASE_12_11_VERIFICATION_PLAN.md",
    ]
    for doc in required_docs:
        assert os.path.isfile(doc), f"Missing required documentation: {doc}"


def test_standard_compliance_controls_integrity():
    """Verify standard regulatory control catalog contains required frameworks with valid hashes."""
    controls = get_standard_compliance_controls()
    assert len(controls) >= 10

    frameworks = {c.framework for c in controls}
    assert ComplianceFramework.NIST_AI_RMF in frameworks
    assert ComplianceFramework.EU_AI_ACT in frameworks
    assert ComplianceFramework.ISO_IEC_42001 in frameworks
    assert ComplianceFramework.OWASP_LLM_TOP_10 in frameworks

    for c in controls:
        assert c.control_id
        assert c.title
        assert len(c.control_hash) == 64
