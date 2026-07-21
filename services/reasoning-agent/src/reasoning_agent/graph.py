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


def _compose_note(state: ReasoningState) -> ReasoningState:
    evidence_lines = (
        "\n".join(f"- [{item['source']}] {item['summary']}" for item in state.get("evidence", []))
        or "- No corroborating evidence was available."
    )
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
