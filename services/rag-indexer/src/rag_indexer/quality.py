"""Scheduled Fargate quality job entry point."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from snow_intelligence.logging import configure_logging, emit_metric, log_event
from snow_intelligence.rag import embed_text, opensearch_client


def refresh_quality_records() -> tuple[int, int]:
    """Refresh accepted records and tombstone patterns older than the retention window.

    This is deliberately bounded to 100 documents per scheduled invocation. Production
    tenants should persist a search-after cursor for larger corpora.
    """
    search = opensearch_client().search(
        index="incidents-v1",
        body={
            "size": 100,
            "query": {"term": {"outcome_label": "accepted"}},
            "sort": [{"created_at": "asc"}],
        },
    )
    refreshed = 0
    tombstoned = 0
    cutoff = datetime.now(UTC) - timedelta(days=365)
    for hit in search.get("hits", {}).get("hits", []):
        source = hit["_source"]
        created_at = datetime.fromisoformat(source["created_at"].replace("Z", "+00:00"))
        if created_at < cutoff:
            opensearch_client().update(
                index="incidents-v1",
                id=hit["_id"],
                body={"doc": {"outcome_label": "unknown", "stale": True}},
            )
            tombstoned += 1
            continue
        embedding, _tokens = embed_text(source["embedding_text"])
        opensearch_client().update(
            index="incidents-v1",
            id=hit["_id"],
            body={
                "doc": {
                    "embedding": embedding,
                    "embedding_refreshed_at": datetime.now(UTC).isoformat(),
                }
            },
        )
        refreshed += 1
    return refreshed, tombstoned


def main() -> None:
    logger = configure_logging("rag-quality-job")
    refreshed, tombstoned = refresh_quality_records()
    emit_metric(
        logger,
        service="rag-quality-job",
        stage="quality",
        metric_name="QualityRecordsRefreshed",
        value=refreshed,
    )
    log_event(
        logger,
        "quality_job_completed",
        service="rag-quality-job",
        refreshed=refreshed,
        tombstoned=tombstoned,
    )


if __name__ == "__main__":
    main()
