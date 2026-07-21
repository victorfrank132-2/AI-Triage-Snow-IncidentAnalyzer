"""Common ECS task protocol. State is exchanged through S3, not Step Functions payloads."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from snow_intelligence.aws import client, read_json, write_json
from snow_intelligence.logging import configure_logging, emit_metric, log_event


@dataclass(frozen=True)
class TaskContext:
    service: str
    stage: str
    execution_id: str
    correlation_id: str
    input_s3_uri: str
    artifact_bucket: str
    mock_mode: bool
    task_token: str | None

    @property
    def output_s3_uri(self) -> str:
        return (
            f"s3://{self.artifact_bucket}/executions/{self.execution_id}/stages/{self.stage}.json"
        )


def parse_context(service: str) -> TaskContext:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-s3-uri", default=os.getenv("INPUT_S3_URI"))
    parser.add_argument("--execution-id", default=os.getenv("EXECUTION_ID"))
    parser.add_argument("--correlation-id", default=os.getenv("CORRELATION_ID"))
    parser.add_argument("--stage", default=os.getenv("WORKFLOW_STAGE"))
    arguments = parser.parse_args()
    missing = [
        option
        for option, value in {
            "input_s3_uri": arguments.input_s3_uri,
            "execution_id": arguments.execution_id,
            "correlation_id": arguments.correlation_id,
            "stage": arguments.stage,
        }.items()
        if not value
    ]
    if missing:
        parser.error(f"missing task context: {', '.join(missing)}")
    artifact_bucket = os.environ["ARTIFACT_BUCKET"]
    return TaskContext(
        service=service,
        stage=arguments.stage,
        execution_id=arguments.execution_id,
        correlation_id=arguments.correlation_id,
        input_s3_uri=arguments.input_s3_uri,
        artifact_bucket=artifact_bucket,
        mock_mode=os.getenv("MOCK_MODE", "true").lower() == "true",
        task_token=os.getenv("TASK_TOKEN"),
    )


def run_task(
    service: str, processor: Callable[[TaskContext, dict[str, Any]], dict[str, Any]]
) -> None:
    context = parse_context(service)
    logger = configure_logging(service)
    log_event(
        logger,
        "task_started",
        service=service,
        stage=context.stage,
        execution_id=context.execution_id,
        correlation_id=context.correlation_id,
    )
    input_payload = read_json(context.input_s3_uri)
    try:
        output = processor(context, input_payload)
        write_json(context.output_s3_uri, output)
        if context.task_token:
            # The callback output stays deliberately small and contains only route metadata.
            client("stepfunctions").send_task_success(
                taskToken=context.task_token, output=json.dumps(output)
            )
        emit_metric(
            logger,
            service=service,
            stage=context.stage,
            metric_name="StageCompleted",
            value=1,
            execution_id=context.execution_id,
        )
        log_event(
            logger,
            "task_completed",
            service=service,
            stage=context.stage,
            execution_id=context.execution_id,
            output_s3_uri=context.output_s3_uri,
        )
    except Exception as error:
        if context.task_token:
            client("stepfunctions").send_task_failure(
                taskToken=context.task_token,
                error=error.__class__.__name__,
                cause="RAG routing task failed; inspect the correlated task logs.",
            )
        raise
