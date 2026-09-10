"""Datasets API router."""

from pathlib import Path

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from aivara.api.envelope import ApiResponse
from aivara.database.connection import get_db
from aivara.domain.schemas import DatasetRead, DatasetCreate, DatasetVersionRead, DatasetVersionCreate
from aivara.services.dataset_service import DatasetService

router = APIRouter(prefix="/datasets", tags=["datasets"])


@router.get("", response_model=ApiResponse[list[DatasetRead]])
async def list_datasets(project_id: str, db: Session = Depends(get_db)):
    """List datasets for a project."""
    service = DatasetService(db)
    return ApiResponse(data=service.list_datasets(project_id))


@router.post("", response_model=ApiResponse[DatasetRead], status_code=status.HTTP_201_CREATED)
async def create_dataset(payload: DatasetCreate, db: Session = Depends(get_db)):
    """Register a new dataset."""
    service = DatasetService(db)
    return ApiResponse(data=service.create_dataset(payload))


@router.get("/{dataset_id}", response_model=ApiResponse[DatasetRead])
async def get_dataset(dataset_id: str, db: Session = Depends(get_db)):
    """Get dataset by ID."""
    service = DatasetService(db)
    return ApiResponse(data=service.get_dataset(dataset_id))


@router.get("/{dataset_id}/versions", response_model=ApiResponse[list[DatasetVersionRead]])
async def list_dataset_versions(dataset_id: str, db: Session = Depends(get_db)):
    """List versions for a dataset."""
    service = DatasetService(db)
    return ApiResponse(data=service.list_versions(dataset_id))


@router.post("/{dataset_id}/versions", response_model=ApiResponse[DatasetVersionRead], status_code=status.HTTP_201_CREATED)
async def create_dataset_version(dataset_id: str, payload: DatasetVersionCreate, db: Session = Depends(get_db)):
    """Create a new version of a dataset."""
    service = DatasetService(db)
    # Ensure the dataset_id from path matches the payload
    payload.dataset_id = dataset_id
    return ApiResponse(data=service.create_version(payload))


# =====================================================================
# Format Detection and Ingestion Endpoints (Phase 5.10)
# =====================================================================

from aivara.api.schemas.datasets import (
    DatasetIngestRequest,
    DatasetIngestResponse,
    FormatDetectRequest,
    FormatDetectResponse,
)
from aivara.core.exceptions import NotFoundException
from aivara.database.models import DatasetModel, DatasetVersionModel, SampleModel
from aivara.dataset.detector import detect_dataset_format
from aivara.dataset.fingerprinting import fingerprint_dataset
from aivara.dataset.ingester import ingest_dataset
from aivara.domain.schemas import DatasetFormat
from aivara.evidence.validators import validate_project_isolation


@router.post(
    "/detect-format",
    response_model=ApiResponse[FormatDetectResponse],
    status_code=status.HTTP_200_OK,
    summary="Detect dataset format on local filesystem",
)
async def detect_format(payload: FormatDetectRequest):
    """Inspect directory layout to auto-detect dataset format (COCO, YOLO, ImageFolder)."""
    detected = detect_dataset_format(Path(payload.dataset_path))
    return ApiResponse(
        data=FormatDetectResponse(
            detected_format=detected.value,
            confidence=1.0,
            details={"dataset_path": payload.dataset_path},
        )
    )


@router.post(
    "/ingest",
    response_model=ApiResponse[DatasetIngestResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and normalize dataset",
)
async def ingest_dataset_endpoint(
    payload: DatasetIngestRequest,
    db: Session = Depends(get_db),
):
    """Ingest, validate, and normalize a computer vision dataset into canonical representation."""
    dataset_service = DatasetService(db)
    req_format = DatasetFormat(payload.format) if payload.format and payload.format != "auto" else None

    # 1. Resolve or create parent dataset
    if payload.dataset_id:
        ds = dataset_service.get_dataset(payload.dataset_id)
        validate_project_isolation(payload.project_id, ds.project_id, entity_name="Dataset")
        dataset_id = ds.id
    else:
        created_ds = dataset_service.create_dataset(
            DatasetCreate(
                project_id=payload.project_id,
                name=payload.dataset_name or f"Dataset from {payload.dataset_path}",
                format=req_format or DatasetFormat.IMAGEFOLDER,
            )
        )
        dataset_id = created_ds.id

    # 2. Ingest dataset using sandboxed normalization engine
    ingestion_res = ingest_dataset(
        dataset_path=payload.dataset_path,
        expected_format=req_format,
    )

    manifest = ingestion_res.manifest
    fp_res = fingerprint_dataset(target=ingestion_res, dataset_root=Path(payload.dataset_path))

    # 3. Create persistent DatasetVersionModel
    ver_create = DatasetVersionCreate(
        dataset_id=dataset_id,
        version_label=payload.version_name or "v1.0",
        dataset_hash=fp_res.dataset_hash,
        sample_count=len(manifest.samples),
        metadata_json={
            "merkle_root": fp_res.dataset_merkle_root,
            "format": ingestion_res.format.value,
        },
    )
    ver_read = dataset_service.create_version(ver_create)

    # 4. Insert SampleModel rows for persistent queryability
    for s in manifest.samples:
        sample_row = SampleModel(
            dataset_version_id=ver_read.id,
            file_path=s.relative_path,
            file_hash_sha256="0" * 64,
            metadata_json={"file_size_bytes": s.file_size_bytes},
        )
        db.add(sample_row)

    db.commit()

    return ApiResponse(
        data=DatasetIngestResponse(
            dataset_id=dataset_id,
            version_id=ver_read.id,
            project_id=payload.project_id,
            format=ingestion_res.format.value,
            sample_count=len(manifest.samples),
            annotation_count=sum(len(s.annotations) for s in manifest.samples),
            category_count=len(manifest.categories),
            dataset_fingerprint=fp_res.dataset_hash,
            merkle_root=fp_res.dataset_merkle_root,
            status="INGESTED",
            validation_warnings=ingestion_res.warnings,
        )
    )
