"""FastAPI Router for Universal Audit & Compliance Reporting (Phase 12.11)."""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status

from aivara.api.envelope import ApiResponse
from aivara.core.exceptions import NotFoundException
from aivara.universal.audit.compliance import get_standard_compliance_controls
from aivara.universal.audit.diff import compare_audit_reports
from aivara.universal.audit.enums import ExportFormat, RedactionLevel, ReportIntegrityStatus
from aivara.universal.audit.export import export_report
from aivara.universal.audit.generator import UniversalAuditReportGenerator
from aivara.universal.audit.integrity import verify_report_integrity
from aivara.universal.audit.schemas import (
    AuditReportCompareRequest,
    AuditReportCreateRequest,
    AuditReportDiffResponse,
    AuditReportVerificationResponse,
    UniversalAuditReport,
)
from aivara.universal.api.service import get_universal_service
from aivara.universal.exceptions import ProjectMismatchError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/projects/{project_id}/universal/audit", tags=["Universal Audit & Compliance"])


# =====================================================================
# In-Memory Report Store
# =====================================================================

class AuditReportStore:
    """Thread-safe in-memory store for generated audit reports."""

    def __init__(self) -> None:
        self._reports: Dict[str, UniversalAuditReport] = {}
        self._lock = threading.Lock()

    def save_report(self, report: UniversalAuditReport) -> None:
        with self._lock:
            self._reports[report.report_id] = report

    def get_report(self, report_id: str, project_id: str) -> Optional[UniversalAuditReport]:
        with self._lock:
            rep = self._reports.get(report_id)
            if rep and rep.project_id == project_id:
                return rep
            return None

    def list_reports(self, project_id: str) -> List[UniversalAuditReport]:
        with self._lock:
            return [r for r in self._reports.values() if r.project_id == project_id]


_report_store_singleton = AuditReportStore()
_generator_singleton = UniversalAuditReportGenerator()


def get_report_store() -> AuditReportStore:
    return _report_store_singleton


def get_audit_generator() -> UniversalAuditReportGenerator:
    return _generator_singleton


# =====================================================================
# Endpoints
# =====================================================================

@router.post("/reports", response_model=ApiResponse[Dict[str, Any]], status_code=status.HTTP_201_CREATED)
def create_audit_report(
    project_id: str,
    request: AuditReportCreateRequest,
    store: AuditReportStore = Depends(get_report_store),
    generator: UniversalAuditReportGenerator = Depends(get_audit_generator),
) -> ApiResponse[Dict[str, Any]]:
    """Generate an authoritative Universal Audit Report from task result or project artifacts."""
    if request.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL project_id '{project_id}' does not match body project_id '{request.project_id}'",
        )

    st = store
    gen = generator
    service = get_universal_service()

    # Extract task artifacts if task_id provided
    asset_ids: List[str] = []
    evidence_items: List[Any] = []
    findings: List[Any] = []
    risk_assessments: Dict[str, Any] = {}
    policy_decisions: Dict[str, Any] = {}
    proof_assessments: Dict[str, Any] = {}
    hierarchical_assessment: Optional[Any] = None

    if request.task_id:
        task = service.task_manager.get_task(request.task_id)
        if not task or task.project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Assurance task '{request.task_id}' not found for project '{project_id}'",
            )
        asset_ids = list(task.request.asset_ids)
        evidence_items = list(task.request.evidence_items)
        risk_assessments = dict(task.risk_assessments)
        policy_decisions = dict(task.decision_assessments)
        proof_assessments = dict(task.proof_assessments)
        hierarchical_assessment = task.hierarchical_assessment
    else:
        # Fallback to stored project assessments
        for t in service.task_manager.list_tasks_for_project(project_id):
            asset_ids.extend(t.request.asset_ids)
            evidence_items.extend(t.request.evidence_items)
            risk_assessments.update(t.risk_assessments)
            policy_decisions.update(t.decision_assessments)
            proof_assessments.update(t.proof_assessments)
            if t.hierarchical_assessment:
                hierarchical_assessment = t.hierarchical_assessment

    # Count existing reports for project to set instance_version
    existing_reports = st.list_reports(project_id)
    instance_ver = len(existing_reports) + 1

    report = gen.generate_report(
        project_id=project_id,
        asset_ids=asset_ids,
        evidence_items=evidence_items,
        findings=findings,
        risk_assessments=risk_assessments,
        policy_decisions=policy_decisions,
        proof_assessments=proof_assessments,
        hierarchical_assessment=hierarchical_assessment,
        instance_version=instance_ver,
        report_name=request.report_name or "Universal Assurance Audit Report",
        redaction_level=request.redaction_level,
    )

    st.save_report(report)
    return ApiResponse(data=report.model_dump())


@router.get("/reports/{report_id}", response_model=ApiResponse[Dict[str, Any]], status_code=status.HTTP_200_OK)
def get_audit_report(
    project_id: str,
    report_id: str,
    store: AuditReportStore = Depends(get_report_store),
) -> ApiResponse[Dict[str, Any]]:
    """Retrieve an audit report by ID enforcing strict project tenancy."""
    st = store
    report = st.get_report(report_id, project_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit report '{report_id}' not found for project '{project_id}'",
        )
    return ApiResponse(data=report.model_dump())


@router.post("/reports/{report_id}/verify", response_model=ApiResponse[AuditReportVerificationResponse], status_code=status.HTTP_200_OK)
def verify_audit_report(
    project_id: str,
    report_id: str,
    store: AuditReportStore = Depends(get_report_store),
) -> ApiResponse[AuditReportVerificationResponse]:
    """Verify cryptographic integrity of an audit report."""
    st = store
    report = st.get_report(report_id, project_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit report '{report_id}' not found for project '{project_id}'",
        )
    res = verify_report_integrity(report)
    return ApiResponse(data=res)


@router.post("/reports/compare", response_model=ApiResponse[AuditReportDiffResponse], status_code=status.HTTP_200_OK)
def compare_reports(
    project_id: str,
    request: AuditReportCompareRequest,
    store: AuditReportStore = Depends(get_report_store),
) -> ApiResponse[AuditReportDiffResponse]:
    """Perform deterministic semantic diff between two audit reports within the same project."""
    if request.project_id != project_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL project_id '{project_id}' does not match body project_id '{request.project_id}'",
        )

    st = store
    base_rep = st.get_report(request.base_report_id, project_id)
    target_rep = st.get_report(request.target_report_id, project_id)

    if not base_rep:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Base report '{request.base_report_id}' not found for project '{project_id}'",
        )
    if not target_rep:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target report '{request.target_report_id}' not found for project '{project_id}'",
        )

    diff = compare_audit_reports(base_rep, target_rep)
    return ApiResponse(data=diff)


@router.get("/reports/{report_id}/export", status_code=status.HTTP_200_OK)
def export_audit_report(
    project_id: str,
    report_id: str,
    export_format: ExportFormat = Query(ExportFormat.JSON, alias="format"),
    store: AuditReportStore = Depends(get_report_store),
) -> Response:
    """Export an audit report into JSON, Markdown, or Plaintext representations."""
    st = store
    report = st.get_report(report_id, project_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit report '{report_id}' not found for project '{project_id}'",
        )

    content = export_report(report, export_format)
    media_type = "application/json"
    if export_format == ExportFormat.MARKDOWN:
        media_type = "text/markdown"
    elif export_format == ExportFormat.TEXT:
        media_type = "text/plain"

    return Response(content=content, media_type=media_type)


@router.get("/compliance/controls", response_model=ApiResponse[List[Dict[str, Any]]], status_code=status.HTTP_200_OK)
def list_compliance_controls(
    project_id: str,
) -> ApiResponse[List[Dict[str, Any]]]:
    """Retrieve catalog of standard regulatory compliance controls."""
    controls = get_standard_compliance_controls()
    return ApiResponse(data=[c.model_dump() for c in controls])
