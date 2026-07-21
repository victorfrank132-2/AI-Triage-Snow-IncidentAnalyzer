from snow_intelligence.routing import choose_route
from snow_intelligence.schemas import RagCandidate, RouteKind


def candidate(score: float, outcome: str = "accepted") -> RagCandidate:
    return RagCandidate(
        document_id="case-1",
        score=score,
        incident_summary="historical incident",
        recommendation="restart a safe component",
        outcome_label=outcome,
    )


def test_high_confidence_accepted_case_uses_fast_path() -> None:
    assert choose_route([candidate(0.93)]).route == RouteKind.FAST


def test_medium_confidence_case_uses_refinement() -> None:
    assert choose_route([candidate(0.80)]).route == RouteKind.REFINE


def test_low_confidence_case_uses_full_analysis() -> None:
    assert choose_route([candidate(0.50)]).route == RouteKind.FULL


def test_high_score_reopened_case_never_uses_fast_path() -> None:
    assert choose_route([candidate(0.95, "reopened")]).route == RouteKind.REFINE
