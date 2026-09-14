"""Enums for Universal Audit and Compliance Reporting (Phase 12.11)."""

from enum import Enum


class ComplianceStatus(str, Enum):
    """Authoritative 6-state compliance evaluation result."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"


class ComplianceFramework(str, Enum):
    """Supported regulatory and standards compliance frameworks."""
    NIST_AI_RMF = "NIST_AI_RMF"
    EU_AI_ACT = "EU_AI_ACT"
    ISO_IEC_42001 = "ISO_IEC_42001"
    OWASP_LLM_TOP_10 = "OWASP_LLM_TOP_10"
    INTERNAL_GOVERNANCE = "INTERNAL_GOVERNANCE"


class TraceabilityNodeType(str, Enum):
    """Types of nodes in the bi-directional audit traceability graph."""
    PROJECT = "PROJECT"
    ASSET = "ASSET"
    EVIDENCE = "EVIDENCE"
    FINDING = "FINDING"
    RISK_CONTRIBUTION = "RISK_CONTRIBUTION"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    POLICY_DECISION = "POLICY_DECISION"
    PROOF_ASSESSMENT = "PROOF_ASSESSMENT"
    PROJECT_AGGREGATION = "PROJECT_AGGREGATION"
    COMPLIANCE_CONTROL = "COMPLIANCE_CONTROL"


class ReportIntegrityStatus(str, Enum):
    """Cryptographic verification status of an audit report."""
    VERIFIED = "VERIFIED"
    TAMPERED = "TAMPERED"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"


class ExportFormat(str, Enum):
    """Supported deterministic export representation formats."""
    JSON = "JSON"
    MARKDOWN = "MARKDOWN"
    TEXT = "TEXT"


class RedactionLevel(str, Enum):
    """Privacy and confidential data sanitization level."""
    NONE = "NONE"
    STANDARD = "STANDARD"
    STRICT = "STRICT"
