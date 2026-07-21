"""Bedrock inference wrapper. It accepts already-redacted content only."""

from __future__ import annotations

import os
from typing import Any

from snow_intelligence.aws import client


def converse(
    *,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    guardrail_identifier: str | None = None,
    guardrail_version: str | None = None,
) -> tuple[str, dict[str, int]]:
    """Invoke Bedrock Converse with bounded output and adaptive retries.

    Model access is intentionally a deployment prerequisite. Do not change the
    configured model ID without checking the account's enabled inference profile.
    """
    model_id = os.environ["BEDROCK_MODEL_ID"]
    runtime = client("bedrock-runtime")
    request: dict[str, Any] = {
        "modelId": model_id,
        "system": [{"text": system_prompt}],
        "messages": [{"role": "user", "content": [{"text": user_prompt}]}],
        "inferenceConfig": {"maxTokens": max_tokens, "temperature": 0.2},
        "requestMetadata": {"application": "servicenow-incident-intelligence"},
    }
    if guardrail_identifier and guardrail_version:
        request["guardrailConfig"] = {
            "guardrailIdentifier": guardrail_identifier,
            "guardrailVersion": guardrail_version,
            "trace": "disabled",
        }
    response = runtime.converse(**request)
    text = "".join(block.get("text", "") for block in response["output"]["message"]["content"])
    usage = response.get("usage", {})
    return text, {
        "input_tokens": int(usage.get("inputTokens", 0)),
        "output_tokens": int(usage.get("outputTokens", 0)),
    }
