"""API router registration."""

from fastapi import APIRouter
from aivara.api.routers import (
    projects,
    contributors,
    datasets,
    models,
    inference,
    findings,
    evidence,
    risk,
    provenance,
    reports,
    attack_lab,
)

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(projects.router)
api_v1_router.include_router(contributors.router)
api_v1_router.include_router(datasets.router)
api_v1_router.include_router(models.router)
api_v1_router.include_router(inference.router)
api_v1_router.include_router(findings.router)
api_v1_router.include_router(evidence.router)
api_v1_router.include_router(risk.router)
api_v1_router.include_router(provenance.router)
api_v1_router.include_router(reports.router)
api_v1_router.include_router(attack_lab.router)
