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
    error_messages = _unique(
        re.findall(
            r"(?:Error Message|Message)\s*[:\-]\s*([^\n\r*]+)",
            joined_text,
            flags=re.IGNORECASE,
        )
    )
    error_messages = [message.strip(" .") for message in error_messages if message.strip(" .")]
    return {
        "request_ids": request_ids,
        "policy_ids": policy_ids,
        "quote_ids": quote_ids,
        "error_codes": error_codes,
        "error_messages": error_messages,
        "status_codes": status_codes,
        "response_times": response_times,
        "method_endpoints": method_endpoints,
        "api_paths": api_paths,
    }


def _extract_attachment_log_facts(summary: str) -> dict[str, list[str]]:
    """Extract raw observable facts from a single attachment summary string."""
    text = str(summary or "")

    code_pattern = (
        r"(?:\*\*\s*)?(?:Error Code|Status Code|status)(?:\s*\*\*)?\s*[:\-]\s*([^\n\r*]+)"
        r"|(?:\*\*\s*)?(?:Error Code|Status Code|status)\s*[:\-]\s*(?:\*\*\s*)?([^\n\r*]+)"
    )
    message_pattern = (
        r"(?:\*\*\s*)?(?:Error Message|Message)(?:\s*\*\*)?\s*[:\-]\s*([^\n\r*]+)"
        r"|(?:\*\*\s*)?(?:Error Message|Message)\s*[:\-]\s*(?:\*\*\s*)?([^\n\r*]+)"
    )

    error_codes = [match[0] or match[1] for match in re.findall(code_pattern, text, re.IGNORECASE)]
    error_messages = [match[0] or match[1] for match in re.findall(message_pattern, text, re.IGNORECASE)]

    facts: dict[str, list[str]] = {
        "error_codes": _unique(error_codes),
        "error_messages": _unique(error_messages),
        "request_ids": _unique(re.findall(r"\bREQ-[A-Za-z0-9-]+\b", text)),
        "policy_ids": _unique(re.findall(r"\bTERM-[A-Za-z0-9-]+\b", text)),
        "quote_ids": _unique(re.findall(r"\bQ-[A-Za-z0-9-]+\b", text)),
        "endpoints": _unique(re.findall(r"\b(?:GET|POST|PUT|DELETE|PATCH)\s+/api/[A-Za-z0-9/_-]+\b", text)),
        "response_times": _unique(re.findall(r"\b\d{2,6}\s*ms\b", text, re.IGNORECASE)),
    }
    # strip trailing spaces/asterisks from extracted values
    for key in facts:
        facts[key] = [v.strip(" .*") for v in facts[key] if v.strip(" .*")]
    return facts


def _extract_splunk_row_signal(evidence: list[dict[str, Any]]) -> str:
    for item in evidence:
        if str(item.get("source", "")).lower() != "splunk":
            continue
        summary = str(item.get("summary", ""))
        match = re.search(r"Splunk returned\s+(\d+)\s+guardrailed evidence rows", summary)
        if match:
            return match.group(1)
    return "unknown"


def _is_log_retrieval_request(short_description: str, description: str) -> bool:
    text = f"{short_description} {description}"
    patterns = [
        r"\blast\s+\d{1,4}\s+logs?\b",
        r"\b(?:get|fetch|retrieve|retrive|pull)\s+(?:the\s+)?(?:last\s+\d{1,4}\s+)?logs?\b",
        r"\blog[-\s]*retr(?:ie)?val\b",
        r"\blog[-\s]*retrival\b",
        r"\blog[-\s]*reetrival\b",
    ]
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _build_log_retrieval_note(
    incident_number: str,
    splunk_query: str,
    evidence: list[dict[str, Any]],
) -> str:
    row_count = _extract_splunk_row_signal(evidence)
    lines = [
        "Log Retrieval",
        f"- Incident: {incident_number}",
        f"- Splunk query executed: {splunk_query or 'not available'}",
        f"- Matched rows: {row_count}",
        "- Attachments include raw outputs: splunk-results.json, splunk-case-results.json, splunk-stage.json.",
        "",
        "Triage analysis was intentionally skipped because this incident matched log-retrieval intent.",
    ]
    return "\n".join(lines)


def _build_grounded_analysis(
    incident: dict[str, Any],
    evidence: list[dict[str, Any]],
    splunk_query: str,
    route: RouteDecision,
    attachment_case_results: list[dict[str, Any]] | None = None,
    attachment_evidence_list: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    signals = _extract_observed_signals(evidence)
    splunk_rows = _extract_splunk_row_signal(evidence)
    endpoints = signals["method_endpoints"] or signals["api_paths"]

    # ── Summary: analytic sentence, not a numeric dump ──────────────────────
    if endpoints and (signals["error_codes"] or signals["status_codes"]):
        endpoint_str = ", ".join(endpoints[:3])
        error_str = ", ".join((signals["error_codes"] or signals["status_codes"])[:3])
        summary = (
            f"Service-side failures ({error_str}) observed on {endpoint_str}. "
            f"Splunk log search returned {splunk_rows} matched rows across app/api indexes."
        )
    elif endpoints:
        summary = (
            f"Failures observed on endpoints: {', '.join(endpoints[:3])}. "
            f"Splunk log search returned {splunk_rows} matched rows."
        )
    else:
        summary = (
            "No specific API endpoint pattern was identified from available evidence. "
            "Splunk log search returned {splunk_rows} matched rows; further log capture may be required."
        )

    # ── Triage points ────────────────────────────────────────────────────────
    triage_points: list[str] = []
    if signals["request_ids"]:
        triage_points.append(f"Request IDs observed: {', '.join(signals['request_ids'][:6])}.")
    if signals["policy_ids"]:
        triage_points.append(f"Policy IDs observed: {', '.join(signals['policy_ids'][:6])}.")
    if signals["quote_ids"]:
        triage_points.append(f"Quote IDs observed: {', '.join(signals['quote_ids'][:6])}.")
    if signals["error_codes"]:
        triage_points.append(f"Error codes observed: {', '.join(signals['error_codes'][:6])}.")
    if endpoints:
        triage_points.append(f"Endpoints observed: {', '.join(endpoints[:6])}.")
    triage_points.append(
        f"Splunk query executed against app/api indexes: {splunk_query or 'not available'}."
    )
    triage_points.append(f"RAG route selected: {route.route.value} (confidence {route.confidence:.2f}).")

    # ── Build lookup maps ────────────────────────────────────────────────────
    case_results = attachment_case_results or []
    attachment_name_by_ref = {
        str(item.get("sys_id", "")): str(item.get("file_name", ""))
        for item in incident.get("attachments", [])
        if str(item.get("sys_id", "")).strip()
    }
    attachment_summary_by_ref: dict[str, str] = {}
    for att_ev in (attachment_evidence_list or evidence):
        if str(att_ev.get("source", "")).lower() == "attachment":
            ref = str(att_ev.get("reference", ""))
            if ref:
                attachment_summary_by_ref[ref] = str(att_ev.get("summary", ""))

    # ── Case-by-case attachment log analysis ─────────────────────────────────
    rca_sections: list[str] = ["Case-by-case log analysis:"]
    any_case = False
    for case in case_results:
        attachment_ref = str(case.get("attachment_reference", "unknown"))
        attachment_name = (
            attachment_name_by_ref.get(attachment_ref)
            or case.get("attachment_name", "")
            or attachment_ref
        )
        row_count = case.get("row_count")
        row_text = "unknown" if row_count is None else str(row_count)

        summary_text = attachment_summary_by_ref.get(attachment_ref, "")
        facts = _extract_attachment_log_facts(summary_text)

        has_id = bool(facts["request_ids"] or facts["policy_ids"] or facts["quote_ids"])
        if not has_id and not facts["error_codes"] and not facts["error_messages"]:
            continue

        any_case = True
        rca_sections.append("")
        rca_sections.append(f"Attachment: {attachment_name}")
        rca_sections.append(f"  - Splunk rows matched: {row_text}")
        if facts["request_ids"]:
            rca_sections.append(f"  - Request ID: {', '.join(facts['request_ids'][:4])}")
        if facts["policy_ids"]:
            rca_sections.append(f"  - Policy ID: {', '.join(facts['policy_ids'][:4])}")
        if facts["quote_ids"]:
            rca_sections.append(f"  - Quote ID: {', '.join(facts['quote_ids'][:4])}")
        if facts["endpoints"]:
            rca_sections.append(f"  - Endpoint: {', '.join(facts['endpoints'][:3])}")
        if facts["error_codes"]:
            rca_sections.append(f"  - Error Code: {', '.join(facts['error_codes'][:3])}")
        for msg in facts["error_messages"][:3]:
            rca_sections.append(f"  - Error Message: {msg}")
        if facts["response_times"]:
            rca_sections.append(f"  - Response Time: {', '.join(facts['response_times'][:2])}")

    if not any_case:
        rca_sections.append("- No attachment with recognisable identifiers was matched to Splunk results.")

    # ── Recommended remediation ──────────────────────────────────────────────
    quote_related = bool(signals["quote_ids"]) or any("/quotes" in ep for ep in endpoints)
    policy_related = bool(signals["policy_ids"]) or any("/underwriting" in ep for ep in endpoints)
    service_related = bool(endpoints)

    rca_sections.append("")
    rca_sections.append("Recommended remediation:")
    if signals["error_messages"] or any(
        _extract_attachment_log_facts(s)["error_messages"]
        for s in attachment_summary_by_ref.values()
    ):
        rca_sections.append(
            "- Trace exact error messages above in service logs for the listed request IDs before restart/redeploy actions."
        )
    if quote_related:
        rca_sections.append(
            "- Validate quote/premium calculation dependencies (pricing/rules service) and recent deployment/config changes."
        )
    if policy_related:
        rca_sections.append(
            "- Validate underwriting/policy decision dependencies and upstream timeout thresholds for affected endpoints."
        )
    if service_related:
        rca_sections.append(
            "- Check gateway and service timeout/error-rate metrics for affected API endpoints during failure timestamps."
        )
    rca_sections.append("- Confirm fix with a targeted replay using the same request identifiers listed above.")
    rca_sections.append("")
    rca_sections.append(
        "Conclusion: RCA is derived from observed attachment logs and should be confirmed by service owners before remediation."
    )

    possible_rca = "\n".join(rca_sections)

    # ── RCA hints for LLM inference only (not rendered in work note) ─────────
    llm_rca_hints = {
        "service_rca": (
            "API service endpoints show repeated failure patterns; check upstream dependency and gateway timeout."
            if service_related
            else "No service endpoint pattern confidently observed."
        ),
        "quotes_rca": (
            "Quote-related endpoint failures present; validate quote/premium calculation path."
            if quote_related
            else "No quote-specific failure signal confidently observed."
        ),
        "policies_rca": (
            "Policy/underwriting signals present; validate underwriting decision dependencies."
            if policy_related
            else "No policy-specific failure signal confidently observed."
        ),
    }

    rationale_summary = (
        "Work note is evidence-grounded using extracted identifiers, endpoint patterns, and Splunk row signal. "
        "No hidden reasoning traces are included."
    )
    return {
        "recommendation": summary,
        "triage_points": _unique(triage_points),
        "possible_rca": possible_rca,
        "rationale_summary": rationale_summary,
        "llm_rca_hints": llm_rca_hints,
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
    attachment_case_results = splunk_stage.get("attachment_case_results", [])
    is_log_retrieval = bool(splunk_stage.get("log_retrieval_intent", False)) or _is_log_retrieval_request(
        str(incident.get("short_description", "")),
        str(incident.get("description", "")),
    )
    structured_analysis: dict[str, Any] = {}
    llm_usage: dict[str, int] = {"input_tokens": 0, "output_tokens": 0}
    grounded = _build_grounded_analysis(
        incident,
        evidence,
        splunk_query_text,
        route,
        attachment_case_results=attachment_case_results,
        attachment_evidence_list=attachment_stage.get("evidence", []),
    )

    if is_log_retrieval:
        recommendation = "Requested log retrieval completed."
        rationale = "Triage synthesis skipped for log-retrieval request."
        note = WorkNote(
            incident_number=incident["incident_number"],
            work_note_markdown=_build_log_retrieval_note(
                incident["incident_number"], splunk_query_text, evidence
            ),
            recommendation=recommendation,
            rationale_summary=rationale,
            confidence=route.confidence,
            evidence=[EvidenceReference.model_validate(item) for item in evidence],
            requires_human_review=False,
        )
        return {
            "work_note": note.model_dump(mode="json"),
            "llm_inference": {
                "route": route.route.value,
                "route_confidence": route.confidence,
                "input_summary": {
                    "incident_number": incident.get("incident_number"),
                    "splunk_query": splunk_query_text,
                    "prior_context_present": bool(route.candidate),
                    "evidence_count": len(evidence),
                },
                "structured_analysis": {},
                "grounded_analysis": {k: v for k, v in grounded.items() if k != "llm_rca_hints"},
                "llm_rca_hints": grounded.get("llm_rca_hints", {}),
                "token_usage": llm_usage,
                "log_retrieval_mode": True,
            },
        }

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
        recommendation = grounded["recommendation"]
        rationale = grounded["rationale_summary"]
        triage_points = grounded["triage_points"]
        possible_rca = grounded["possible_rca"]

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
            "grounded_analysis": {k: v for k, v in grounded.items() if k != "llm_rca_hints"},
            "llm_rca_hints": grounded.get("llm_rca_hints", {}),
            "token_usage": llm_usage,
        },
    }


if __name__ == "__main__":
    run_task("reasoning-agent", process)
