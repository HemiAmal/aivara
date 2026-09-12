import math
from typing import Any
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
from aivara.behavioral.exceptions import (
    BehavioralError,
    ExecutionProviderUnavailableError,
    ExecutionTimeoutError,
    InvalidInputTensorError,
    InvalidOutputTensorError,
    ModelExecutionError,
    ModelLoadingError,
    ResourceLimitExceededError,
    SecuritySandboxViolationError,
    UnsupportedExecutionFormatError,
)
from aivara.behavioral.provenance import (
    BehavioralEvidenceIdentityError,
    BehavioralEvidenceValidationError,
    BehavioralExecutionIdentityError,
    BehavioralProvenanceError,
    CrossProjectBindingError,
    EvidenceImmutableError,
    EvidenceTamperedError,
    IdempotencyConflictError,
    NonFiniteValueError,
    SignerUnavailableError,
)
from aivara.behavioral.anomaly import (
    BehavioralAnomalyError,
    CrossProjectAnalysisError,
    IncompatibleAnalysisContextError,
    InsufficientSupportError,
    InvalidMetricDataError,
)


def _sanitize_error_details(obj: Any) -> Any:
    if isinstance(obj, float):
        if math.isnan(obj):
            return "NaN"
        if math.isinf(obj):
            return "Infinity" if obj > 0 else "-Infinity"
        return obj
    elif isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    elif isinstance(obj, dict):
        return {str(k): _sanitize_error_details(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [_sanitize_error_details(v) for v in obj]
    elif isinstance(obj, Exception):
        return str(obj)
    return str(obj)


def register_exception_handlers(app: FastAPI) -> None:
    """Attach global exception handlers producing standardized JSON responses."""

    @app.exception_handler(DuplicateNonceError)
    @app.exception_handler(DuplicateSequenceError)
    @app.exception_handler(DuplicateRecordError)
    @app.exception_handler(ReplayDetectedError)
    @app.exception_handler(StaleDatasetVersionError)
    @app.exception_handler(ModelMismatchError)
    @app.exception_handler(EvidenceImmutableError)
    @app.exception_handler(IdempotencyConflictError)
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
    @app.exception_handler(CrossProjectBindingError)
    @app.exception_handler(CrossProjectAnalysisError)
    @app.exception_handler(VocabularyViolationError)
    @app.exception_handler(SemanticSafetyViolationError)
    @app.exception_handler(EvidenceValidationError)
    @app.exception_handler(BehavioralEvidenceValidationError)
    @app.exception_handler(InsufficientSupportError)
    @app.exception_handler(IncompatibleAnalysisContextError)
    @app.exception_handler(InvalidMetricDataError)
    @app.exception_handler(NonFiniteValueError)
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

    @app.exception_handler(ExecutionProviderUnavailableError)
    async def execution_provider_unavailable_handler(request: Request, exc: ExecutionProviderUnavailableError):
        msg = getattr(exc, "message", str(exc))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=ApiErrorResponse(
                error=ErrorDetail(code="EXECUTION_PROVIDER_UNAVAILABLE", message=msg),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(ExecutionTimeoutError)
    async def execution_timeout_handler(request: Request, exc: ExecutionTimeoutError):
        msg = getattr(exc, "message", str(exc))
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content=ApiErrorResponse(
                error=ErrorDetail(code="EXECUTION_TIMEOUT", message=msg),
                meta=ResponseMeta(),
            ).model_dump(),
        )

    @app.exception_handler(PathTraversalError)
    @app.exception_handler(SymlinkEscapeError)
    @app.exception_handler(DatasetIngestionError)
    @app.exception_handler(SecuritySandboxViolationError)
    @app.exception_handler(InvalidInputTensorError)
    @app.exception_handler(InvalidOutputTensorError)
    @app.exception_handler(UnsupportedExecutionFormatError)
    async def dataset_security_error_handler(request: Request, exc: Exception):
        msg = getattr(exc, "message", str(exc))
        code = getattr(exc, "code", "SECURITY_OR_FORMAT_ERROR")
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
                    details=_sanitize_error_details(exc.errors()),
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
