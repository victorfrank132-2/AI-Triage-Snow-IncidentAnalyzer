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
    assert note.startswith("[code]")
    assert note.endswith("[/code]")
    assert "<h3>Summary</h3>" in note
    assert "<h3>Triage Points</h3>" in note
    assert "<h3>Possible RCA</h3>" in note
    assert "<h3>Disclaimer</h3>" in note
    assert "<ul>" in note
    assert "<li>Five matching timeout events.</li>" in note
    assert "<blockquote><strong>AI analysis can be wrong and should only be considered for triage assistance.</strong></blockquote>" in note
    assert "Evidence metrics (Images/Splunk Query):" not in note
    assert "AI analysis can be wrong and should only be considered for triage assistance." in note
    assert "Short AI response disclaimer:" not in note
    assert "Five matching timeout events." in note
    assert "REQ-763579" in note
    assert "model reasoning traces" not in note
