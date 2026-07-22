"""A deliberately bounded graph: it synthesizes evidence but never stores chain-of-thought."""

from __future__ import annotations

from html import escape
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph


class ReasoningState(TypedDict, total=False):
    incident_number: str
    route: str
    confidence: float
    recommendation: str
    rationale_summary: str
    triage_points: list[str]
    possible_rca: str
    splunk_query: str
    evidence: list[dict[str, Any]]
    work_note_markdown: str


def _normalize_summary(value: Any, max_length: int = 1200) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."


def _normalize_block(value: Any, max_length: int = 3500) -> str:
    lines = [line.strip() for line in str(value or "").splitlines()]
    text = "\n".join(line for line in lines if line)
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."


def _triage_points(evidence: list[dict[str, Any]]) -> str:
    points: list[str] = []
    for item in evidence:
        summary = _normalize_summary(item.get("summary", ""), max_length=900)
        if summary and summary not in points:
            points.append(summary)
        if len(points) >= 6:
            break
    if not points:
        return "- No high-confidence triage signal was extracted."
    return "\n".join(f"- {point}" for point in points)


def _render_html_lines(body: str) -> str:
    lines = [line.rstrip() for line in str(body or "").splitlines()]
    parts: list[str] = []
    in_list = False

    for raw in lines:
        line = raw.strip()
        if not line:
            if in_list:
                parts.append("</ul>")
                in_list = False
            continue

        if line.startswith("- "):
            if not in_list:
                parts.append("<ul>")
                in_list = True
            parts.append(f"<li>{escape(line[2:])}</li>")
            continue

        if in_list:
            parts.append("</ul>")
            in_list = False

        if line.lower().startswith("attachment:") or line.endswith(":"):
            parts.append(f"<p><strong>{escape(line)}</strong></p>")
        else:
            parts.append(f"<p>{escape(line)}</p>")

    if in_list:
        parts.append("</ul>")

    return "".join(parts)


def _section(title: str, body: str) -> str:
    return f"<h3>{escape(title)}</h3>{_render_html_lines(body)}"


def _compose_note(state: ReasoningState) -> ReasoningState:
    recommendation = _normalize_summary(state.get("recommendation", ""), max_length=2500)
    triage_input = state.get("triage_points", [])
    if isinstance(triage_input, str):
        triage_candidates = [triage_input]
    elif isinstance(triage_input, list):
        triage_candidates = triage_input
    else:
        triage_candidates = []
    llm_triage_points = [
        _normalize_summary(item, max_length=900)
        for item in triage_candidates
        if str(item or "").strip()
    ]
    possible_rca = _normalize_block(
        state.get("possible_rca", state.get("rationale_summary", "")), max_length=3500
    )
    triage_block = (
        "\n".join(f"- {point}" for point in llm_triage_points)
        if llm_triage_points
        else _triage_points(state.get("evidence", []))
    )
    sections = [
        _section("Summary", recommendation),
        _section("Triage Points", triage_block),
        _section(
            "Possible RCA",
            possible_rca or "RCA is not yet confirmed; continue operator validation.",
        ),
        (
            "<h3>Disclaimer</h3>"
            "<blockquote><strong>AI analysis can be wrong and should only be considered for triage assistance.</strong></blockquote>"
        ),
    ]
    return {
        "work_note_markdown": "[code]" + "".join(sections) + "[/code]"
    }


def build_graph() -> Any:
    graph = StateGraph(ReasoningState)
    graph.add_node("compose_note", _compose_note)
    graph.add_edge(START, "compose_note")
    graph.add_edge("compose_note", END)
    return graph.compile()
