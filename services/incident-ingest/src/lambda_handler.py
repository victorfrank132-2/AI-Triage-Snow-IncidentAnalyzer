"""API ingress only: validate, deduplicate, archive, and enqueue. No AI work runs here."""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.config import Config

_CONFIG = Config(
    retries={"total_max_attempts": 5, "mode": "adaptive"}, connect_timeout=5, read_timeout=20
)
_dynamodb = boto3.resource("dynamodb", config=_CONFIG)
_s3 = boto3.client("s3", config=_CONFIG)
_sqs = boto3.client("sqs", config=_CONFIG)


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }


def _parse_event(event: dict[str, Any]) -> dict[str, Any]:
    raw_body = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")
    payload = json.loads(raw_body)
    required = {"event_id", "incident_sys_id", "incident_number", "short_description", "operation"}
    missing = sorted(required - payload.keys())
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    if payload["operation"] not in {"insert", "update"}:
        raise ValueError("operation must be insert or update")
    return payload


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    try:
        payload = _parse_event(event)
    except (ValueError, json.JSONDecodeError) as error:
        return _response(400, {"message": "invalid ServiceNow webhook", "detail": str(error)})

    execution_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    table = _dynamodb.Table(os.environ["EXECUTION_TABLE"])
    try:
        table.put_item(
            Item={
                "pk": f"EVENT#{payload['event_id']}",
                "sk": "INGESTION",
                "execution_id": execution_id,
                "incident_sys_id": payload["incident_sys_id"],
                "status": "QUEUED",
                "created_at": now,
                "ttl": int(datetime.now(UTC).timestamp()) + 7 * 24 * 3600,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        return _response(
            202, {"message": "duplicate event accepted", "event_id": payload["event_id"]}
        )

    key = f"incidents/{payload['incident_sys_id']}/{payload['event_id']}.json"
    _s3.put_object(
        Bucket=os.environ["ARTIFACT_BUCKET"],
        Key=key,
        Body=json.dumps({"incident": payload, "archived_at": now}).encode("utf-8"),
        ContentType="application/json",
    )
    message = {
        "execution_id": execution_id,
        "correlation_id": event.get("requestContext", {}).get("requestId", execution_id),
        "incident_id": payload["incident_sys_id"],
        "event_id": payload["event_id"],
        "archive_s3_uri": f"s3://{os.environ['ARTIFACT_BUCKET']}/{key}",
        "state_table_key": f"EVENT#{payload['event_id']}",
    }
    _sqs.send_message(
        QueueUrl=os.environ["INGEST_QUEUE_URL"],
        MessageBody=json.dumps(message),
        MessageGroupId=payload["incident_sys_id"],
        MessageDeduplicationId=payload["event_id"],
    )
    return _response(202, {"execution_id": execution_id, "status": "queued"})
