"""Phase 12.10 Universal Risk API & Task Integration Package."""

from aivara.universal.api.enums import (
    UniversalAPISchemaVersion,
    UniversalPipelineStage,
    UniversalTaskStatus,
)
from aivara.universal.api.router import router as universal_router
from aivara.universal.api.schemas import (
    UniversalAssuranceResultResponse,
    UniversalAssuranceTaskCreateRequest,
    UniversalCapabilitiesResponse,
    UniversalProgressEvent,
    UniversalTaskResponse,
)
from aivara.universal.api.service import (
    UniversalAssuranceService,
    UniversalTask,
    UniversalTaskManager,
    get_universal_service,
    get_universal_task_manager,
)

__all__ = [
    "UniversalAPISchemaVersion",
    "UniversalPipelineStage",
    "UniversalTaskStatus",
    "UniversalAssuranceTaskCreateRequest",
    "UniversalTaskResponse",
    "UniversalProgressEvent",
    "UniversalAssuranceResultResponse",
    "UniversalCapabilitiesResponse",
    "UniversalTask",
    "UniversalTaskManager",
    "UniversalAssuranceService",
    "get_universal_task_manager",
    "get_universal_service",
    "universal_router",
]
