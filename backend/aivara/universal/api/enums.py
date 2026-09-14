"""Enums for Universal Risk API and Task Integration (Phase 12.10)."""

from __future__ import annotations

from enum import Enum


class UniversalTaskStatus(str, Enum):
    """Lifecycle status of a universal assurance task."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class UniversalPipelineStage(str, Enum):
    """Discrete analytical pipeline stages of the universal assurance engine."""
    QUEUED = "QUEUED"
    NORMALIZING_EVIDENCE = "NORMALIZING_EVIDENCE"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    INGESTING = "INGESTING"
    CORRELATING = "CORRELATING"
    COMPUTING_RISK = "COMPUTING_RISK"
    EVALUATING_POLICY = "EVALUATING_POLICY"
    VERIFYING_PROOF = "VERIFYING_PROOF"
    AGGREGATING_PROJECT = "AGGREGATING_PROJECT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class UniversalAPISchemaVersion(str, Enum):
    """Version of the Universal Risk API schema."""
    V1_0 = "1.0"
