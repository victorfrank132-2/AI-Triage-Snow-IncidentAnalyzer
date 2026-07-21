"""Helpers for loading stage artifacts from the S3 execution record."""

from __future__ import annotations

from typing import Any

from snow_intelligence.aws import read_json, stage_uri
from snow_intelligence.runtime import TaskContext


def load_stage(context: TaskContext, stage: str) -> dict[str, Any]:
    return read_json(stage_uri(context.artifact_bucket, context.execution_id, stage))
