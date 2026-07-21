from __future__ import annotations

import base64
import importlib.util
import os
from pathlib import Path
from types import ModuleType
from typing import Any


class _FakeSecrets:
    def get_secret_value(self, SecretId: str) -> dict[str, str]:
        assert SecretId == "arn:aws:secretsmanager:us-east-1:111122223333:secret:test"
        return {
            "SecretString": (
                '{"webhook_username":"snow-webhook","webhook_password":"correct-password"}'
            )
        }


def _load_authorizer() -> ModuleType:
    path = Path("services/incident-ingest/src/authorizer_handler.py").resolve()
    spec = importlib.util.spec_from_file_location("authorizer_handler", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _event(username: str, password: str) -> dict[str, Any]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return {
        "methodArn": "arn:aws:execute-api:us-east-1:111122223333:api/dev/POST/servicenow/incident",
        "authorizationToken": f"Basic {token}",
    }


def test_basic_authorizer_allows_matching_secret(monkeypatch: Any) -> None:
    monkeypatch.setitem(os.environ, "SERVICENOW_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:111122223333:secret:test")
    module = _load_authorizer()
    monkeypatch.setattr(module, "_SECRETS", _FakeSecrets())

    response = module.handler(_event("snow-webhook", "correct-password"), None)

    assert response["policyDocument"]["Statement"][0]["Effect"] == "Allow"


def test_basic_authorizer_denies_wrong_password(monkeypatch: Any) -> None:
    monkeypatch.setitem(os.environ, "SERVICENOW_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:111122223333:secret:test")
    module = _load_authorizer()
    monkeypatch.setattr(module, "_SECRETS", _FakeSecrets())

    response = module.handler(_event("snow-webhook", "wrong-password"), None)

    assert response["policyDocument"]["Statement"][0]["Effect"] == "Deny"
