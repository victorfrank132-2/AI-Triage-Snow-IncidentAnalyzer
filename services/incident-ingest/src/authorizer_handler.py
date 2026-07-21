"""Fail-closed REST API authorizer for a ServiceNow Basic-auth webhook."""

from __future__ import annotations

import base64
import hmac
import json
import os
import time
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

_SECRETS = boto3.client("secretsmanager")
_CACHE_TTL_SECONDS = 300
_SECRET_CACHE: tuple[float, str, str] | None = None


def _allow(method_arn: str, subject: str) -> dict[str, Any]:
    return {
        "principalId": subject,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Action": "execute-api:Invoke", "Effect": "Allow", "Resource": method_arn}],
        },
    }


def _deny(method_arn: str) -> dict[str, Any]:
    return {
        "principalId": "unauthorized",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Action": "execute-api:Invoke", "Effect": "Deny", "Resource": method_arn}],
        },
    }


def _get_webhook_credentials() -> tuple[str, str]:
    global _SECRET_CACHE
    now = time.time()
    if _SECRET_CACHE and now - _SECRET_CACHE[0] < _CACHE_TTL_SECONDS:
        return _SECRET_CACHE[1], _SECRET_CACHE[2]

    secret_id = os.environ["SERVICENOW_SECRET_ARN"]
    try:
        response = _SECRETS.get_secret_value(SecretId=secret_id)
        value = json.loads(response["SecretString"])
    except (BotoCoreError, ClientError, KeyError, json.JSONDecodeError):
        return "", ""

    username = str(value.get("webhook_username") or value.get("username") or "")
    password = str(value.get("webhook_password") or value.get("password") or "")
    _SECRET_CACHE = (now, username, password)
    return username, password


def _parse_basic(token: str) -> tuple[str, str]:
    scheme, _, encoded = token.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return "", ""
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return "", ""
    username, separator, password = decoded.partition(":")
    if not separator:
        return "", ""
    return username, password


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    method_arn = event["methodArn"]
    token = event.get("authorizationToken", "")
    if os.getenv("MOCK_MODE", "false").lower() == "true" and token == "Basic bG9jYWwtdGVzdDp0b2tlbg==":
        return _allow(method_arn, "local-servicenow")
    expected_username, expected_password = _get_webhook_credentials()
    actual_username, actual_password = _parse_basic(token)
    authenticated = (
        bool(expected_username)
        and bool(expected_password)
        and hmac.compare_digest(actual_username, expected_username)
        and hmac.compare_digest(actual_password, expected_password)
    )
    return _allow(method_arn, "servicenow") if authenticated else _deny(method_arn)
