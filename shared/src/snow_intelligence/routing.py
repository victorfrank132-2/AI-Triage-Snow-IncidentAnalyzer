"""Deterministic retrieval-first routing with auditable, summarized decisions."""

from __future__ import annotations

from snow_intelligence.schemas import RagCandidate, RouteDecision, RouteKind

FAST_PATH_THRESHOLD = 0.90
REFINEMENT_THRESHOLD = 0.72


def choose_route(candidates: list[RagCandidate]) -> RouteDecision:
    candidate = max(candidates, key=lambda item: item.score, default=None)
    if candidate is None:
        return RouteDecision(
            route=RouteKind.FULL,
            confidence=0.0,
            rationale_summary="No comparable resolved incident was retrieved.",
        )
    if candidate.score >= FAST_PATH_THRESHOLD and candidate.outcome_label == "accepted":
        return RouteDecision(
            route=RouteKind.FAST,
            confidence=candidate.score,
            candidate=candidate,
            rationale_summary="A previously accepted incident strongly matches the current context.",
        )
    if candidate.score >= REFINEMENT_THRESHOLD:
        return RouteDecision(
            route=RouteKind.REFINE,
            confidence=candidate.score,
            candidate=candidate,
            rationale_summary="A similar incident was found but requires lightweight evidence refinement.",
        )
    return RouteDecision(
        route=RouteKind.FULL,
        confidence=candidate.score,
        candidate=candidate,
        rationale_summary="Retrieved history is below the policy confidence threshold for reuse.",
    )
