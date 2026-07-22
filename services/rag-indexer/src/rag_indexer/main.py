from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from snow_intelligence.rag import embed_text, index_rag_record
from snow_intelligence.redaction import redact_text
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import RagRecord, WorkNote
from snow_intelligence.stages import load_stage


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    writer_stage = load_stage(context, "servicenow-writeback")
    context_stage = load_stage(context, "context")
    attachment_stage = load_stage(context, "attachments")
    note = WorkNote.model_validate(writer_stage["work_note"])
    incident = payload.get("incident", {})
    attachment_summaries = "\n".join(
        str(item.get("summary", ""))
        for item in attachment_stage.get("evidence", [])
        if str(item.get("source", "")).lower() == "attachment"
    )
    embedding_source_text = "\n".join(
        part
        for part in [
            str(incident.get("short_description", "")),
            str(incident.get("description", "")),
            str(context_stage.get("incident_summary", "")),
            attachment_summaries,
            note.recommendation,
            note.rationale_summary,
        ]
        if part
    )
    record = RagRecord(
        document_id=f"incident#{note.incident_number}#{context.execution_id}",
        incident_summary=str(context_stage.get("incident_summary", note.rationale_summary)),
        embedding_text=embedding_source_text,
        splunk_evidence_fingerprints=[
            item.reference for item in note.evidence if item.source == "splunk"
        ],
        final_recommendation=note.recommendation,
        outcome_label="unknown",
        created_at=datetime.now(UTC),
        metadata={"confidence": note.confidence, "execution_id": context.execution_id},
    )
    if context.mock_mode:
        index_status = "mock"
        embedding_input_tokens = 0
    else:
        record.embedding_text = redact_text(record.embedding_text)
        embedding, embedding_input_tokens = embed_text(record.embedding_text)
        index_rag_record(record.model_dump(mode="json"), embedding)
        index_status = "indexed"
    return {
        "rag_record": record.model_dump(mode="json"),
        "index_status": index_status,
        "embedding_input_tokens": embedding_input_tokens,
    }


if __name__ == "__main__":
    run_task("rag-indexer", process)
