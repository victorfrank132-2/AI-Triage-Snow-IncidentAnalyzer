from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests
from qdrant_client import QdrantClient, models

COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "incidents-v1")
VECTOR_SIZE = int(os.getenv("QDRANT_VECTOR_SIZE", "1024"))
DISTANCE = models.Distance.COSINE


@dataclass(frozen=True)
class PayloadIndex:
    field_name: str
    field_schema: dict[str, Any]


PAYLOAD_INDEXES: tuple[PayloadIndex, ...] = (
    PayloadIndex(
        "tenant_id",
        {"type": "keyword", "on_disk": False, "is_tenant": True, "is_principal": True},
    ),
    PayloadIndex("incident_number", {"type": "keyword", "on_disk": False}),
    PayloadIndex("document_id", {"type": "keyword", "on_disk": False}),
    PayloadIndex("outcome_label", {"type": "keyword", "on_disk": False}),
    PayloadIndex("error_signature", {"type": "keyword", "on_disk": False}),
    PayloadIndex("endpoint", {"type": "keyword", "on_disk": False}),
    PayloadIndex("service", {"type": "keyword", "on_disk": False}),
    PayloadIndex("created_at", {"type": "datetime", "on_disk": False}),
)


def _env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _qdrant_url() -> str:
    raw = _env("QDRANT_URL").rstrip("/")
    if not raw.startswith(("https://", "http://")):
        raise RuntimeError("QDRANT_URL must start with https:// or http://")
    return raw


def _headers(api_key: str) -> dict[str, str]:
    return {"api-key": api_key, "Content-Type": "application/json"}


def _put_payload_index(base_url: str, api_key: str, index: PayloadIndex) -> None:
    url = urljoin(f"{base_url}/", f"collections/{COLLECTION_NAME}/index")
    body = {"field_name": index.field_name, "field_schema": index.field_schema}
    response = requests.put(url, headers=_headers(api_key), data=json.dumps(body), timeout=30)
    if response.status_code not in {200, 201}:
        raise RuntimeError(
            f"Failed creating payload index {index.field_name}: "
            f"HTTP {response.status_code} {response.text}"
        )
    print(f"payload index ready: {index.field_name}")


def configure_collection() -> None:
    url = _qdrant_url()
    api_key = _env("QDRANT_API_KEY")
    client = QdrantClient(url=url, api_key=api_key, timeout=30)

    if client.collection_exists(COLLECTION_NAME):
        info = client.get_collection(COLLECTION_NAME)
        vectors = info.config.params.vectors
        print(f"collection exists: {COLLECTION_NAME}")
        print(f"current vector config: {vectors}")
    else:
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=models.VectorParams(size=VECTOR_SIZE, distance=DISTANCE),
            on_disk_payload=True,
        )
        print(
            f"collection created: {COLLECTION_NAME} "
            f"(vector_size={VECTOR_SIZE}, distance={DISTANCE.value})"
        )

    for index in PAYLOAD_INDEXES:
        _put_payload_index(url, api_key, index)

    print("qdrant configuration complete")


def main() -> int:
    try:
        configure_collection()
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
