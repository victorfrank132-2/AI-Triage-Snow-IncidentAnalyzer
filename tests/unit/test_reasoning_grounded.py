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
            "reference": "att-1",
            "summary": "Error Code: 502 Error Message: Underwriting decision pending Request ID: REQ-763579 Policy ID: TERM-627395 Endpoint: GET /api/v1/life/underwriting Response Time: 8766 ms",
        },
        {
            "source": "splunk",
            "summary": "Splunk returned 5 guardrailed evidence rows.",
        },
    ]

    grounded = _build_grounded_analysis(
        incident={
            "incident_number": "INC0010110",
            "attachments": [{"sys_id": "att-1", "file_name": "underwriting-failure.png"}],
        },
        evidence=evidence,
        splunk_query='index=life_api_logs ("REQ-763579") | head 50',
        route=route,
        attachment_case_results=[
            {
                "attachment_reference": "att-1",
                "attachment_name": "underwriting-failure.png",
                "identifiers": ["REQ-763579", "TERM-627395", "GET /api/v1/life/underwriting"],
                "row_count": 5,
            }
        ],
        attachment_evidence_list=evidence,
    )

    triage_points = grounded["triage_points"]
    assert any(point.startswith("Request IDs observed:") for point in triage_points)
    assert all(len(point.strip()) > 2 for point in triage_points)
    assert "R" not in triage_points

    rca = grounded["possible_rca"]
    assert "Case-by-case log analysis:" in rca
    assert "underwriting-failure.png" in rca
    assert "Request ID: REQ-763579" in rca
    assert "Error Message: Underwriting decision pending" in rca
    assert "Recommended remediation:" in rca
    assert "Conclusion:" in rca
    # Service/Quotes/Policies RCA labels must NOT be in work note RCA
    assert "Service RCA:" not in rca
    assert "Quotes RCA:" not in rca
    assert "Policies RCA:" not in rca
    # They should be in llm_rca_hints only
    assert "service_rca" in grounded["llm_rca_hints"]
    assert "quotes_rca" in grounded["llm_rca_hints"]
    assert "policies_rca" in grounded["llm_rca_hints"]
