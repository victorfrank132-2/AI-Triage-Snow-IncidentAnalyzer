"""A deliberately bounded graph: it synthesizes evidence but never stores chain-of-thought."""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph


class ReasoningState(TypedDict, total=False):
    incident_number: str
    route: str
    confidence: float
    recommendation: str
    rationale_summary: str
    evidence: list[dict[str, Any]]
    work_note_markdown: str


def _normalize_summary(value: Any, max_length: int = 220) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."


def _triage_points(evidence: list[dict[str, Any]]) -> str:
    points: list[str] = []
    for item in evidence:
        summary = _normalize_summary(item.get("summary", ""))
        if summary and summary not in points:
            points.append(summary)
        if len(points) >= 4:
            break
    if not points:
        return "- No high-confidence triage signal was extracted."
    return "\n".join(f"- {point}" for point in points)


def _evidence_metrics(evidence: list[dict[str, Any]]) -> str:
    splunk_refs: list[str] = []
    image_refs: list[str] = []

    for item in evidence:
        source = str(item.get("source", "unknown")).strip().lower()
        reference = _normalize_summary(item.get("reference", ""), max_length=140)
        summary = _normalize_summary(item.get("summary", ""), max_length=180)
        metric = reference or summary
        if source == "splunk" and metric:
            splunk_refs.append(metric)
        if source == "attachment" and metric:
            image_refs.append(metric)

    lines: list[str] = []
    if splunk_refs:
        lines.append(f"- Splunk Query: {splunk_refs[0]}")
    else:
        lines.append("- Splunk Query: Not available.")

    if image_refs:
        lines.append(f"- Images: {image_refs[0]}")
    else:
        lines.append("- Images: Not available.")

    return "\n".join(lines)


def _compose_note(state: ReasoningState) -> ReasoningState:
    evidence = state.get("evidence", [])
    recommendation = _normalize_summary(state.get("recommendation", ""), max_length=700)
    possible_rca = _normalize_summary(state.get("rationale_summary", ""), max_length=700)
    return {
        "work_note_markdown": (
            "Summary:\n"
            f"{recommendation}\n\n"
            "Triage Points:\n"
            f"{_triage_points(evidence)}\n\n"
            "Possible RCA:\n"
            f"{possible_rca or 'RCA is not yet confirmed; continue operator validation.'}\n\n"
            "Evidence metrics (Images/Splunk Query):\n"
            f"{_evidence_metrics(evidence)}\n\n"
            "Short AI response disclaimer:\n"
            "AI-generated operational summary. Validate against logs, telemetry, and runbooks before closure."
        )
    }


def build_graph() -> Any:
    graph = StateGraph(ReasoningState)
    graph.add_node("compose_note", _compose_note)
    graph.add_edge(START, "compose_note")
    graph.add_edge("compose_note", END)
    return graph.compile()
