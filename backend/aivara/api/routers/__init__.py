"""API router registration."""

from fastapi import APIRouter
from aivara.api.routers import (
    projects,
    contributors,
    datasets,
    dataset_integrity,
    scans,
    models,
    inference,
    findings,
    evidence,
    risk,
    provenance,
    audit,
    reports,
    attack_lab,
    contributor_risk,
    model_integrity,
    behavioral,
)

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(projects.router)
api_v1_router.include_router(contributors.router)
api_v1_router.include_router(contributor_risk.router)
api_v1_router.include_router(datasets.router)
api_v1_router.include_router(dataset_integrity.router)
api_v1_router.include_router(scans.router)
api_v1_router.include_router(models.router)
api_v1_router.include_router(model_integrity.router)
api_v1_router.include_router(behavioral.router)
api_v1_router.include_router(inference.router)
api_v1_router.include_router(findings.router)
api_v1_router.include_router(evidence.router)
api_v1_router.include_router(risk.router)
api_v1_router.include_router(provenance.router)
api_v1_router.include_router(audit.router)
api_v1_router.include_router(reports.router)
api_v1_router.include_router(attack_lab.router)
