from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from snow_intelligence.rag import embed_text, search_similar_cases
from snow_intelligence.routing import choose_route
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import RagCandidate, ServiceNowIncidentPayload
from snow_intelligence.stages import load_stage


def _mock_candidates(incident: ServiceNowIncidentPayload) -> list[RagCandidate]:
    score = float(os.getenv("MOCK_RAG_SCORE", "0.0"))
    if score <= 0:
        return []
    return [
        RagCandidate(
            document_id="mock-accepted-incident",
            score=score,
            incident_summary=f"Historical pattern related to {incident.short_description}",
            recommendation="Apply the previously accepted remediation after validating current evidence.",
            outcome_label="accepted",
            evidence_fingerprints=["mock-evidence-fingerprint"],
        )
    ]


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    incident = ServiceNowIncidentPayload.model_validate(payload["incident"])
    token_count = 0
    if context.mock_mode:
        candidates = _mock_candidates(incident)
    else:
        try:
            context_stage = load_stage(context, "context")
        except Exception:
            context_stage = {}
        try:
            attachment_stage = load_stage(context, "attachments")
        except Exception:
            attachment_stage = {}

        attachment_summaries = "\n".join(
            str(item.get("summary", ""))
            for item in attachment_stage.get("evidence", [])
            if str(item.get("source", "")).lower() == "attachment"
        )
        query_text = "\n".join(
            part
            for part in [
                incident.short_description,
                incident.description or "",
                str(context_stage.get("incident_summary", "")),
                attachment_summaries,
            ]
            if part
        )
        embedding, token_count = embed_text(query_text)
        candidates = [
            RagCandidate(
                document_id=hit.get("_source", {}).get("document_id", hit["_id"]),
                score=float(hit["_score"]),
                incident_summary=hit["_source"]["incident_summary"],
                recommendation=hit["_source"]["recommendation"],
                outcome_label=hit["_source"]["outcome_label"],
                evidence_fingerprints=hit["_source"].get("splunk_evidence_fingerprints", []),
            )
            for hit in search_similar_cases(embedding)
        ]
    decision = choose_route(candidates)
    return {
        "execution_id": context.execution_id,
        "retrieved_at": datetime.now(UTC).isoformat(),
        "decision": decision.model_dump(mode="json"),
        "candidate_count": len(candidates),
        "embedding_input_tokens": token_count,
    }


if __name__ == "__main__":
    run_task("rag-retriever", process)
