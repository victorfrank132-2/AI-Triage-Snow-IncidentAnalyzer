from reasoning_agent.graph import build_graph


def test_work_note_uses_evidence_and_not_hidden_reasoning() -> None:
    result = build_graph().invoke(
        {
            "recommendation": "Restart the failed worker after approval.",
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
    assert "Five matching timeout events." in result["work_note_markdown"]
    assert "REQ-763579" not in result["work_note_markdown"]
    assert "GET /api/v1/life/underwriting" not in result["work_note_markdown"]
    assert "Attachment-derived operational details" in result["work_note_markdown"]
    assert "model reasoning traces" in result["work_note_markdown"]
