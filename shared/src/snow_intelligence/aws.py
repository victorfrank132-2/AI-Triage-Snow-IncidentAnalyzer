"""AWS clients with bounded timeouts and adaptive retries. No secret retrieval helpers live here."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config

AWS_CONFIG = Config(
    retries={"total_max_attempts": 5, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=30,
    max_pool_connections=20,
    user_agent_appid="servicenow-incident-intelligence",
)


def client(service_name: str) -> Any:
    return boto3.client(service_name, config=AWS_CONFIG)


def dynamodb_table(table_name: str) -> Any:
    return boto3.resource("dynamodb", config=AWS_CONFIG).Table(table_name)


@dataclass(frozen=True)
class S3Location:
    bucket: str
    key: str

    @classmethod
    def parse(cls, uri: str) -> S3Location:
        if not uri.startswith("s3://") or "/" not in uri[5:]:
            raise ValueError(f"invalid S3 URI: {uri}")
        bucket, key = uri[5:].split("/", 1)
        return cls(bucket=bucket, key=key)


def read_json(uri: str) -> dict[str, Any]:
    location = S3Location.parse(uri)
    s3 = client("s3")
    with s3.get_object(Bucket=location.bucket, Key=location.key)["Body"] as body:
        return json.loads(body.read())


def write_json(uri: str, payload: dict[str, Any]) -> None:
    location = S3Location.parse(uri)
    client("s3").put_object(
        Bucket=location.bucket,
        Key=location.key,
        Body=json.dumps(payload, default=str).encode("utf-8"),
        ContentType="application/json",
    )


def stage_uri(artifact_bucket: str, execution_id: str, stage: str) -> str:
    return f"s3://{artifact_bucket}/executions/{execution_id}/stages/{stage}.json"
