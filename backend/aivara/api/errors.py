"""Centralized FastAPI error handling."""

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from aivara.api.envelope import ApiErrorResponse, ErrorDetail, ResponseMeta
from aivara.core.exceptions import AivaraException, NotFoundException, ValidationException
from aivara.core.logging import get_logger
from aivara.crypto.chain import (
    DuplicateNonceError,
    DuplicateRecordError,
    DuplicateSequenceError,
    ReplayDetectedError,
)

logger = get_logger(__name__)


from aivara.dataset.exceptions import (
    DatasetIngestionError,
    PathTraversalError,
    SymlinkEscapeError,
)
from aivara.evidence.exceptions import (
    CrossProjectContaminationError,
    EvidenceError,
    EvidenceValidationError,
    ModelMismatchError,
    MissingProvenanceError,
    StaleDatasetVersionError,
    VocabularyViolationError,
)
from aivara.contributor_risk.exceptions import (
    CrossProjectContaminationError as ContributorCrossProjectError,
    SemanticSafetyViolationError,
)


def register_exception_handlers(app: FastAPI) -> None:
    """Attach global exception handlers producing standardized JSON responses."""

    @app.exception_handler(DuplicateNonceError)
    @app.exception_handler(DuplicateSequenceError)
    @app.exception_handler(DuplicateRecordError)
    @app.exception_handler(ReplayDetectedError)
    @app.exception_handler(StaleDatasetVersionError)
    @app.exception_handler(ModelMismatchError)
    async def conflict_error_handler(request: Request, exc: Exception):
        msg = getattr(exc, "message", str(exc))
        code = getattr(exc, "code", "CONFLICT_ERROR")
        details = getattr(exc, "details", None)
        logger.warning("Resource conflict: %s (code=%s)", msg, code)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=ApiErrorResponse(
                error=ErrorDetail(code=code, message=msg, details=details),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(MissingProvenanceError)
    async def missing_provenance_handler(request: Request, exc: MissingProvenanceError):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ApiErrorResponse(
                error=ErrorDetail(code=exc.code, message=exc.message, details=exc.details),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(CrossProjectContaminationError)
    @app.exception_handler(ContributorCrossProjectError)
    @app.exception_handler(VocabularyViolationError)
    @app.exception_handler(SemanticSafetyViolationError)
    @app.exception_handler(EvidenceValidationError)
    async def domain_validation_error_handler(request: Request, exc: Exception):
        msg = getattr(exc, "message", str(exc))
        code = getattr(exc, "code", "VALIDATION_ERROR")
        details = getattr(exc, "details", None)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ApiErrorResponse(
                error=ErrorDetail(code=code, message=msg, details=details),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(PathTraversalError)
    @app.exception_handler(SymlinkEscapeError)
    @app.exception_handler(DatasetIngestionError)
    async def dataset_security_error_handler(request: Request, exc: Exception):
        msg = getattr(exc, "message", str(exc))
        code = getattr(exc, "code", "DATASET_SECURITY_ERROR")
        details = getattr(exc, "details", None)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ApiErrorResponse(
                error=ErrorDetail(code=code, message=msg, details=details),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(NotFoundException)
    async def not_found_handler(request: Request, exc: NotFoundException):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ApiErrorResponse(
                error=ErrorDetail(code=exc.code, message=exc.message, details=exc.details),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(ValidationException)
    async def validation_handler(request: Request, exc: ValidationException):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ApiErrorResponse(
                error=ErrorDetail(code=exc.code, message=exc.message, details=exc.details),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ApiErrorResponse(
                error=ErrorDetail(
                    code="REQUEST_VALIDATION_ERROR",
                    message="The request payload failed validation.",
                    details=exc.errors(),
                ),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(AivaraException)
    async def generic_aivara_handler(request: Request, exc: AivaraException):
        logger.error("Domain exception: %s", exc.message)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ApiErrorResponse(
                error=ErrorDetail(code=exc.code, message=exc.message, details=exc.details),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled server error processing request: %s %s", request.method, request.url)
        # Never expose raw stack traces in production API responses
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ApiErrorResponse(
                error=ErrorDetail(
                    code="INTERNAL_SERVER_ERROR",
                    message="An unexpected internal error occurred.",
                ),
                meta=ResponseMeta(),
            ).model_dump(),
        )
