from reasoning_agent.graph import build_graph


def test_work_note_uses_evidence_and_not_hidden_reasoning() -> None:
    result = build_graph().invoke(
        {
            "recommendation": "Restart the failed worker after approval.",
            "rationale_summary": "Likely upstream timeout on underwriting dependency.",
            "evidence": [
                {"source": "splunk", "summary": "Five matching timeout events."},
                {
                    "source": "attachment",
                    "summary": (
                        "Error Code: 502 Request ID: REQ-763579 "
                        "Endpoint: GET /api/v1/life/underwriting"
                    ),
                },
            ],
        }
    )
    note = result["work_note_markdown"]
    assert "Summary:" in note
    assert "Triage Points:" in note
    assert "Possible RCA:" in note
    assert "Evidence metrics (Images/Splunk Query):" in note
    assert "**AI analysis can be wrong and should only be considered for triage assistance.**" in note
    assert "Short AI response disclaimer:" not in note
    assert "Five matching timeout events." in note
    assert "REQ-763579" in note
    assert "model reasoning traces" not in note
