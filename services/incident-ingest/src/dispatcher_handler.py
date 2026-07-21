"""SQS-to-Step Functions adapter. It starts Standard workflow executions idempotently."""

from __future__ import annotations

import json
import os
from typing import Any

import boto3
from botocore.config import Config

_sfn = boto3.client(
    "stepfunctions", config=Config(retries={"total_max_attempts": 5, "mode": "adaptive"})
)


def handler(event: dict[str, Any], _context: Any) -> dict[str, list[dict[str, str]]]:
    failures: list[dict[str, str]] = []
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        try:
            _sfn.start_execution(
                stateMachineArn=os.environ["STATE_MACHINE_ARN"],
                name=message["event_id"][:80],
                input=json.dumps(message),
            )
        except _sfn.exceptions.ExecutionAlreadyExists:
            pass
        except Exception:
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
