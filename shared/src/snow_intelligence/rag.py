"""Bedrock embedding and OpenSearch Serverless helpers for redacted RAG records."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlparse

import boto3
from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection

from snow_intelligence.aws import client
from snow_intelligence.redaction import redact_text


def embed_text(text: str) -> tuple[list[float], int]:
    """Return a normalized Titan v2 embedding for already-redacted content."""
    runtime = client("bedrock-runtime")
    response = runtime.invoke_model(
        modelId=os.getenv("BEDROCK_EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0"),
        contentType="application/json",
        accept="application/json",
        body=json.dumps(
            {
                "inputText": redact_text(text)[:50_000],
                "dimensions": 1024,
                "normalize": True,
                "embeddingTypes": ["float"],
            }
        ),
    )
    body = json.loads(response["body"].read())
    embedding = body.get("embedding")
    if not isinstance(embedding, list) or len(embedding) != 1024:
        raise ValueError("Bedrock embedding response did not contain a 1024-dimension vector")
    return [float(value) for value in embedding], int(body.get("inputTextTokenCount", 0))


def opensearch_client() -> OpenSearch:
    """Create a TLS, SigV4-signed client for an OpenSearch Serverless collection."""
    endpoint = os.environ["OPENSEARCH_COLLECTION_ENDPOINT"]
    host = urlparse(endpoint if endpoint.startswith("https://") else f"https://{endpoint}").hostname
    if not host:
        raise ValueError("OPENSEARCH_COLLECTION_ENDPOINT must be a collection endpoint")
    session = boto3.Session()
    credentials = session.get_credentials()
    if credentials is None:
        raise RuntimeError("No AWS credentials available for OpenSearch Serverless request signing")
    auth = AWSV4SignerAuth(credentials, session.region_name or os.environ["AWS_REGION"], "aoss")
    return OpenSearch(
        hosts=[{"host": host, "port": 443}],
        http_auth=auth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        pool_maxsize=20,
        timeout=10,
    )


def search_similar_cases(embedding: list[float], *, size: int = 5) -> list[dict[str, Any]]:
    response = opensearch_client().search(
        index=os.getenv("OPENSEARCH_INDEX_NAME", "incidents-v1"),
        body={
            "size": size,
            "_source": [
                "incident_summary",
                "recommendation",
                "outcome_label",
                "splunk_evidence_fingerprints",
                "metadata",
            ],
            "query": {
                "bool": {
                    "filter": [{"term": {"outcome_label": "accepted"}}],
                    "must": [{"knn": {"embedding": {"vector": embedding, "k": size}}}],
                }
            },
        },
    )
    return list(response.get("hits", {}).get("hits", []))


def index_rag_record(record: dict[str, Any], embedding: list[float]) -> None:
    document = {**record, "embedding": embedding}
    opensearch_client().index(
        index=os.getenv("OPENSEARCH_INDEX_NAME", "incidents-v1"),
        body=document,
        refresh=False,
    )
