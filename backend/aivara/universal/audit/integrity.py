"""Cryptographic Report Integrity, Hashing, and Verification (Phase 12.11)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from aivara.universal.audit.enums import ReportIntegrityStatus
from aivara.universal.audit.schemas import AuditReportVerificationResponse, UniversalAuditReport
from aivara.universal.hashing import compute_canonical_jcs_bytes, compute_sha256_digest


def compute_canonical_report_hash(report: UniversalAuditReport) -> str:
    """Compute deterministic RFC 8785 JCS SHA-256 hash over canonical report descriptor."""
    canonical_dict = report.to_canonical_descriptor()
    jcs_bytes = compute_canonical_jcs_bytes(canonical_dict)
    return compute_sha256_digest(jcs_bytes)


def verify_report_integrity(
    report: UniversalAuditReport,
    public_key: Optional[Any] = None,
) -> AuditReportVerificationResponse:
    """Verify cryptographic integrity of an audit report fail-closed."""
    details: List[str] = []
    status = ReportIntegrityStatus.VERIFIED

    # 1. Structure check
    if not report.report_id or not report.project_id:
        return AuditReportVerificationResponse(
            report_id=report.report_id or "unknown",
            project_id=report.project_id or "unknown",
            status=ReportIntegrityStatus.INVALID,
            declared_hash=report.report_hash,
            computed_hash="",
            signature_verified=False,
            verification_details=["Missing mandatory report_id or project_id"],
        )

    # 2. Recompute canonical hash
    computed_hash = compute_canonical_report_hash(report)
    if not report.report_hash:
        status = ReportIntegrityStatus.INCOMPLETE
        details.append("Report has no declared report_hash")
    elif report.report_hash != computed_hash:
        status = ReportIntegrityStatus.TAMPERED
        details.append(f"Content hash mismatch: declared '{report.report_hash}' != computed '{computed_hash}'")
    else:
        details.append("Canonical content hash verified (RFC 8785 JCS SHA-256)")

    # 3. Optional digital signature check
    sig_verified = False
    if report.signature:
        if public_key:
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                if isinstance(public_key, Ed25519PublicKey):
                    sig_bytes = bytes.fromhex(report.signature)
                    public_key.verify(sig_bytes, bytes.fromhex(computed_hash))
                    sig_verified = True
                    details.append("Ed25519 digital signature verified")
            except Exception as ex:
                status = ReportIntegrityStatus.TAMPERED
                details.append(f"Digital signature verification failed: {str(ex)}")
        else:
            details.append("Signature present but public key not provided for verification")

    return AuditReportVerificationResponse(
        report_id=report.report_id,
        project_id=report.project_id,
        status=status,
        declared_hash=report.report_hash,
        computed_hash=computed_hash,
        signature_verified=sig_verified,
        verification_details=details,
    )
