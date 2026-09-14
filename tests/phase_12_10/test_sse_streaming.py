"""Test Server-Sent Events (SSE) progress broadcasting for Phase 12.10."""

import asyncio
import pytest
from httpx import AsyncClient, ASGITransport

from aivara.main import app
from aivara.universal.api.enums import UniversalPipelineStage, UniversalTaskStatus
from aivara.universal.api.schemas import UniversalAssuranceTaskCreateRequest
from aivara.universal.api.service import get_universal_task_manager


@pytest.mark.asyncio
async def test_sse_event_streaming():
    """Verify that SSE endpoint streams discrete progress events and terminates cleanly."""
    project_id = "proj-sse-1"
    task_manager = get_universal_task_manager()

    req = UniversalAssuranceTaskCreateRequest(
        project_id=project_id,
        asset_ids=["asset-sse-1"],
    )
    task, _ = task_manager.create_task(project_id=project_id, request=req)

    # Simulate stage events and final cancellation to close the generator
    task.update_stage(UniversalPipelineStage.NORMALIZING_EVIDENCE, 10.0, "Normalizing")
    task.update_stage(UniversalPipelineStage.COMPUTING_RISK, 65.0, "Computing risk")
    task.cancel()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/projects/{project_id}/universal/assurance/tasks/{task.task_id}/events")
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        assert "NORMALIZING_EVIDENCE" in response.text
        assert "COMPUTING_RISK" in response.text
