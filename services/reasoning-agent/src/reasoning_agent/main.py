from __future__ import annotations

import json
import re
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


def _unique(items: list[str]) -> list[str]:
    deduped: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if value and value not in deduped:
            deduped.append(value)
    return deduped


def _extract_observed_signals(evidence: list[dict[str, Any]]) -> dict[str, list[str]]:
    joined_text = "\n".join(str(item.get("summary", "")) for item in evidence)
    request_ids = _unique(re.findall(r"\bREQ-[A-Za-z0-9-]+\b", joined_text))
    policy_ids = _unique(re.findall(r"\bTERM-[A-Za-z0-9-]+\b", joined_text))
    quote_ids = _unique(re.findall(r"\bQ-[A-Za-z0-9-]+\b", joined_text))
    error_codes = _unique(re.findall(r"\bERR_[A-Za-z0-9_]+\b", joined_text))
    status_codes = _unique(re.findall(r"\b(?:status\s*code\s*:?\s*)?(5\d\d|4\d\d)\b", joined_text, flags=re.IGNORECASE))
    response_times = _unique(re.findall(r"\b\d{2,6}\s*ms\b", joined_text, flags=re.IGNORECASE))
    method_endpoints = _unique(
        re.findall(r"\b(?:GET|POST|PUT|DELETE|PATCH)\s+/api/[A-Za-z0-9/_-]+\b", joined_text)
    )
    api_paths = _unique(re.findall(r"\b/api/[A-Za-z0-9/_-]+\b", joined_text))
    return {
        "request_ids": request_ids,
        "policy_ids": policy_ids,
        "quote_ids": quote_ids,
        "error_codes": error_codes,
        "status_codes": status_codes,
        "response_times": response_times,
        "method_endpoints": method_endpoints,
        "api_paths": api_paths,
    }


def _extract_splunk_row_signal(evidence: list[dict[str, Any]]) -> str:
    for item in evidence:
        if str(item.get("source", "")).lower() != "splunk":
            continue
        summary = str(item.get("summary", ""))
        match = re.search(r"Splunk returned\s+(\d+)\s+guardrailed evidence rows", summary)
        if match:
            return match.group(1)
    return "unknown"


def _build_grounded_analysis(
    incident: dict[str, Any],
    evidence: list[dict[str, Any]],
    splunk_query: str,
    route: RouteDecision,
) -> dict[str, Any]:
    signals = _extract_observed_signals(evidence)
    splunk_rows = _extract_splunk_row_signal(evidence)
    endpoints = signals["method_endpoints"] or signals["api_paths"]

    summary_parts: list[str] = []
    if signals["status_codes"]:
        summary_parts.append(f"Observed HTTP status codes: {', '.join(signals['status_codes'][:5])}.")
    if signals["error_codes"]:
        summary_parts.append(f"Observed application error codes: {', '.join(signals['error_codes'][:6])}.")
    if endpoints:
        summary_parts.append(f"Impacted endpoints: {', '.join(endpoints[:6])}.")
    if signals["response_times"]:
        summary_parts.append(f"Observed response times: {', '.join(signals['response_times'][:6])}.")
    summary_parts.append(f"Splunk evidence rows returned: {splunk_rows}.")
    if not (signals["status_codes"] or signals["error_codes"] or endpoints):
        summary_parts.append(
            "Attachment and context evidence did not expose concrete API/error identifiers; further log capture is required."
        )

    triage_points = [
        *(f"Request IDs observed: {', '.join(signals['request_ids'][:6])}." if signals["request_ids"] else []),
        *(f"Policy IDs observed: {', '.join(signals['policy_ids'][:6])}." if signals["policy_ids"] else []),
        *(f"Quote IDs observed: {', '.join(signals['quote_ids'][:6])}." if signals["quote_ids"] else []),
        *(f"Error codes observed: {', '.join(signals['error_codes'][:6])}." if signals["error_codes"] else []),
        *(f"Endpoints observed: {', '.join(endpoints[:6])}." if endpoints else []),
        f"Splunk query executed against app/api indexes: {splunk_query or 'not available'}.",
        f"RAG route selected: {route.route.value} (confidence {route.confidence:.2f}).",
    ]

    possible_rca = (
        "Unconfirmed RCA: repeated application failures are observed on the listed API endpoints. "
        "Validate upstream dependency health, gateway connectivity, and timeout/error spikes for the same request IDs."
    )
    rationale_summary = (
        "Work note is evidence-grounded using extracted identifiers, endpoint patterns, and Splunk row signal. "
        "No hidden reasoning traces are included."
    )
    return {
        "recommendation": " ".join(summary_parts),
        "triage_points": _unique(triage_points),
        "possible_rca": possible_rca,
        "rationale_summary": rationale_summary,
    }


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
    splunk_query_text = splunk_stage.get("query", {}).get("query", "")
    structured_analysis: dict[str, Any] = {}
    llm_usage: dict[str, int] = {"input_tokens": 0, "output_tokens": 0}
    grounded = _build_grounded_analysis(incident, evidence, splunk_query_text, route)

    if context.mock_mode:
        recommendation = grounded["recommendation"]
        rationale = grounded["rationale_summary"]
        triage_points = grounded["triage_points"]
        possible_rca = grounded["possible_rca"]
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
                "Cite concrete identifiers/endpoints/error codes from input where available. "
                "Mark unknown when evidence is missing. Do not include chain-of-thought. Do not invent fields."
            ),
            user_prompt=_to_json(llm_prompt_payload),
            max_tokens=1400,
        )
        structured_analysis = _extract_structured_analysis(llm_response)
        llm_triage_raw = structured_analysis.get("triage_points", [])
        if isinstance(llm_triage_raw, str):
            llm_triage_iterable = [llm_triage_raw]
        elif isinstance(llm_triage_raw, list):
            llm_triage_iterable = llm_triage_raw
        else:
            llm_triage_iterable = []
        llm_triage_points = [
            str(item)
            for item in llm_triage_iterable
            if str(item or "").strip()
        ]
        recommendation = grounded["recommendation"]
        rationale = grounded["rationale_summary"]
        triage_points = _unique(grounded["triage_points"] + llm_triage_points)
        possible_rca = str(structured_analysis.get("possible_rca") or grounded["possible_rca"])

    graph_result = build_graph().invoke(
        {
            "incident_number": incident["incident_number"],
            "route": route.route.value,
            "confidence": route.confidence,
            "recommendation": recommendation,
            "rationale_summary": rationale,
            "triage_points": triage_points,
            "possible_rca": possible_rca,
            "splunk_query": splunk_query_text,
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
            "grounded_analysis": grounded,
            "token_usage": llm_usage,
        },
    }


if __name__ == "__main__":
    run_task("reasoning-agent", process)
