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


def _compact_evidence_lines(evidence: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    has_attachment_evidence = False
    for item in evidence:
        source = str(item.get("source", "unknown")).strip().lower()
        summary = _normalize_summary(item.get("summary", ""))
        if source == "attachment":
            has_attachment_evidence = True
            continue
        if summary:
            lines.append(f"- [{source}] {summary}")

    if has_attachment_evidence:
        lines.append(
            "- [attachment] Attachment-derived operational details are available in the evidence attachment file."
        )

    return "\n".join(lines) or "- No corroborating evidence was available."


def _compose_note(state: ReasoningState) -> ReasoningState:
    evidence_lines = _compact_evidence_lines(state.get("evidence", []))
    recommendation = state["recommendation"]
    return {
        "work_note_markdown": (
            "AI incident analysis\n\n"
            f"Recommendation: {recommendation}\n\n"
            "Evidence references:\n"
            f"{evidence_lines}\n\n"
            "This is an evidence-based summary for operator review; it does not contain model reasoning traces."
        )
    }


def build_graph() -> Any:
    graph = StateGraph(ReasoningState)
    graph.add_node("compose_note", _compose_note)
    graph.add_edge(START, "compose_note")
    graph.add_edge("compose_note", END)
    return graph.compile()
