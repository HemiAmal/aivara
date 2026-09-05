"""Centralized FastAPI error handling."""

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from aivara.api.envelope import ApiErrorResponse, ErrorDetail, ResponseMeta
from aivara.core.exceptions import AivaraException, NotFoundException, ValidationException
from aivara.core.logging import get_logger

logger = get_logger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    """Attach global exception handlers producing standardized JSON responses."""

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
