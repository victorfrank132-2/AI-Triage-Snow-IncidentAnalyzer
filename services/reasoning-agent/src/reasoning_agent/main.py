from __future__ import annotations

import json
from typing import Any

from snow_intelligence.bedrock import converse
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import EvidenceReference, RouteDecision, WorkNote
from snow_intelligence.stages import load_stage

from reasoning_agent.graph import build_graph


def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2, default=str)


def _extract_structured_analysis(raw_text: str) -> dict[str, Any]:
    content = str(raw_text or "").strip()
    if not content:
        return {}

    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}

    try:
        parsed = json.loads(content[start : end + 1])
    except json.JSONDecodeError:
        return {}

    if not isinstance(parsed, dict):
        return {}
    return parsed


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    incident = payload["incident"]
    rag_stage = load_stage(context, "rag-retrieval")
    route = RouteDecision.model_validate(rag_stage["decision"])
    context_stage = load_stage(context, "context")
    attachment_stage = load_stage(context, "attachments")
    splunk_stage = load_stage(context, "splunk")
    evidence = [
        *context_stage["evidence"],
        *attachment_stage["evidence"],
        *splunk_stage["evidence"],
    ]
    structured_analysis: dict[str, Any] = {}
    llm_usage: dict[str, int] = {"input_tokens": 0, "output_tokens": 0}

    if context.mock_mode:
        recommendation = "Investigate the correlated service logs, validate the proposed remediation, and obtain operator approval before closure."
        rationale = "The recommendation is based on normalized incident context and guardrailed evidence references."
        triage_points = [
            "Review recent API failures from attachment evidence.",
            "Correlate API error patterns with Splunk query output.",
        ]
        possible_rca = "A dependent upstream service is intermittently failing under load."
    else:
        prior_context: dict[str, Any] = {
            "route": route.route.value,
            "route_confidence": route.confidence,
            "route_rationale_summary": route.rationale_summary,
            "rag_candidate_count": rag_stage.get("candidate_count", 0),
        }
        if route.candidate:
            prior_context["matched_incident_context"] = route.candidate.model_dump(mode="json")

        llm_prompt_payload = {
            "incident": {
                "incident_number": incident.get("incident_number"),
                "short_description": incident.get("short_description"),
                "description": incident.get("description"),
                "priority": incident.get("priority"),
                "state": incident.get("state"),
            },
            "context_summary": context_stage.get("incident_summary", ""),
            "splunk_query": splunk_stage.get("query", {}).get("query", ""),
            "splunk_evidence": splunk_stage.get("evidence", []),
            "attachment_evidence": attachment_stage.get("evidence", []),
            "context_evidence": context_stage.get("evidence", []),
            "prior_incident_context": prior_context,
        }

        llm_response, llm_usage = converse(
            system_prompt=(
                "You are an incident analyst. Use only supplied logs/evidence/prior-context. "
                "Return strict JSON with keys: recommendation (string), triage_points (array of strings), "
                "possible_rca (string), rationale_summary (string), disclaimer (string). "
                "Do not include chain-of-thought. Do not invent fields."
            ),
            user_prompt=_to_json(llm_prompt_payload),
            max_tokens=1400,
        )
        structured_analysis = _extract_structured_analysis(llm_response)
        recommendation = str(
            structured_analysis.get("recommendation")
            or (route.candidate.recommendation if route.candidate else "")
            or "Recommendation synthesized from approved evidence references."
        )
        rationale = str(
            structured_analysis.get("rationale_summary")
            or route.rationale_summary
            or "Recommendation synthesized from approved evidence references."
        )
        triage_points = [
            str(item)
            for item in structured_analysis.get("triage_points", [])
            if str(item or "").strip()
        ]
        possible_rca = str(structured_analysis.get("possible_rca") or rationale)

    graph_result = build_graph().invoke(
        {
            "incident_number": incident["incident_number"],
            "route": route.route.value,
            "confidence": route.confidence,
            "recommendation": recommendation,
            "rationale_summary": rationale,
            "triage_points": triage_points,
            "possible_rca": possible_rca,
            "splunk_query": splunk_stage.get("query", {}).get("query", ""),
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
    return {
        "work_note": note.model_dump(mode="json"),
        "llm_inference": {
            "route": route.route.value,
            "route_confidence": route.confidence,
            "input_summary": {
                "incident_number": incident.get("incident_number"),
                "splunk_query": splunk_stage.get("query", {}).get("query", ""),
                "prior_context_present": bool(route.candidate),
                "evidence_count": len(evidence),
            },
            "structured_analysis": structured_analysis,
            "token_usage": llm_usage,
        },
    }


if __name__ == "__main__":
    run_task("reasoning-agent", process)
