from __future__ import annotations

import sys
from pathlib import Path

from snow_intelligence.schemas import RouteDecision, RouteKind

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "reasoning-agent" / "src"))

from reasoning_agent.main import _build_grounded_analysis


def test_grounded_analysis_triage_points_are_full_lines() -> None:
    route = RouteDecision(
        route=RouteKind.FULL,
        confidence=0.0,
        rationale_summary="No comparable resolved incident was retrieved.",
    )
    evidence = [
        {
            "source": "attachment",
            "summary": "Error Code: 502 Request ID: REQ-763579 Policy ID: TERM-627395 Endpoint: GET /api/v1/life/underwriting Response Time: 8766 ms",
        },
        {
            "source": "splunk",
            "summary": "Splunk returned 5 guardrailed evidence rows.",
        },
    ]

    grounded = _build_grounded_analysis(
        incident={"incident_number": "INC0010110"},
        evidence=evidence,
        splunk_query='index=life_api_logs ("REQ-763579") | head 50',
        route=route,
        attachment_case_results=[
            {
                "attachment_reference": "att-1",
                "identifiers": ["REQ-763579", "TERM-627395", "GET /api/v1/life/underwriting"],
                "row_count": 5,
            }
        ],
    )

    triage_points = grounded["triage_points"]
    assert any(point.startswith("Request IDs observed:") for point in triage_points)
    assert all(len(point.strip()) > 2 for point in triage_points)
    assert "R" not in triage_points
    assert "Case-by-case log analysis:" in grounded["possible_rca"]
    assert "Service RCA:" in grounded["possible_rca"]
    assert "Quotes RCA:" in grounded["possible_rca"]
    assert "Policies RCA:" in grounded["possible_rca"]
