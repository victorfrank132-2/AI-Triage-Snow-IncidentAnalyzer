from __future__ import annotations

from typing import Any

from snow_intelligence.bedrock import converse
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import EvidenceReference, RouteDecision, WorkNote
from snow_intelligence.stages import load_stage

from reasoning_agent.graph import build_graph


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    incident = payload["incident"]
    route = RouteDecision.model_validate(load_stage(context, "rag-retrieval")["decision"])
    context_stage = load_stage(context, "context")
    attachment_stage = load_stage(context, "attachments")
    splunk_stage = load_stage(context, "splunk")
    evidence = [
        *context_stage["evidence"],
        *attachment_stage["evidence"],
        *splunk_stage["evidence"],
    ]
    if route.route.value == "fast" and route.candidate:
        recommendation = route.candidate.recommendation
        rationale = route.rationale_summary
    elif context.mock_mode:
        recommendation = "Investigate the correlated service logs, validate the proposed remediation, and obtain operator approval before closure."
        rationale = "The recommendation is based on normalized incident context and guardrailed evidence references."
    else:
        recommendation, _usage = converse(
            system_prompt=(
                "Create a concise, evidence-based operational recommendation. "
                "Never disclose chain-of-thought. Return only the recommendation."
            ),
            user_prompt=f"Incident: {incident['short_description']}\nEvidence: {evidence}",
            max_tokens=700,
        )
        rationale = "Recommendation synthesized from approved evidence references."
    graph_result = build_graph().invoke(
        {
            "incident_number": incident["incident_number"],
            "route": route.route.value,
            "confidence": route.confidence,
            "recommendation": recommendation,
            "rationale_summary": rationale,
            "evidence": evidence,
        }
    )
    note = WorkNote(
        incident_number=incident["incident_number"],
        work_note_markdown=graph_result["work_note_markdown"],
        recommendation=recommendation,
        rationale_summary=rationale,
        confidence=route.confidence,
        evidence=[EvidenceReference.model_validate(item) for item in evidence],
        requires_human_review=True,
    )
    return note.model_dump(mode="json")


if __name__ == "__main__":
    run_task("reasoning-agent", process)
