"""Consistent API response envelope models."""

import uuid
from datetime import datetime, timezone
from typing import Any, Generic, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResponseMeta(BaseModel):
    timestamp: str = Field(default_factory=utcnow_iso)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    version: str = "0.1.0"


class ApiResponse(BaseModel, Generic[T]):
    status: str = "success"
    data: T
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class ApiErrorResponse(BaseModel):
    status: str = "error"
    error: ErrorDetail
    meta: ResponseMeta = Field(default_factory=ResponseMeta)
