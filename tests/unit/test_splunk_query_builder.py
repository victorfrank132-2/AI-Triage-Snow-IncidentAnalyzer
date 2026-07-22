from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "splunk-agent" / "src"))

from splunk_agent import main as splunk_main


def test_build_query_uses_expected_index_pattern_and_identifiers(monkeypatch) -> None:
    monkeypatch.delenv("SPLUNK_INDEXES", raising=False)
    extracted = splunk_main._extract_context_terms(
        "INC0010105 REQ-763579 TERM-627395 ERR_502 "
        "GET /api/v1/life/underwriting GET /api/v1/quotes/premium"
    )
    query = splunk_main._build_query(extracted)

    assert "index=life_api_logs OR index=life_ui_logs OR index=pc_api_logs OR index=pc_ui_logs" in query
    assert '"INC0010105"' not in query
    assert '"REQ-763579"' in query
    assert '"TERM-627395"' in query
    assert '"ERR_502"' in query
    assert '"GET /api/v1/life/underwriting"' in query
    assert '"/api/v1/life/underwriting"' in query
    assert '"/api/v1/quotes/premium"' in query


def test_build_attachment_case_queries_uses_each_attachment_summary(monkeypatch) -> None:
    monkeypatch.delenv("SPLUNK_INDEXES", raising=False)
    evidence = [
        {
            "source": "attachment",
            "reference": "att-1",
            "summary": "Error Code: ERR_502 Request ID: REQ-763579 Endpoint: GET /api/v1/life/underwriting",
        },
        {
            "source": "attachment",
            "reference": "att-2",
            "summary": "Request ID: REQ-889452 Endpoint: GET /api/v1/quotes/premium",
        },
    ]

    cases = splunk_main._build_attachment_case_queries(evidence, "", "")
    assert len(cases) == 2
    assert cases[0]["attachment_reference"] == "att-1"
    assert "REQ-763579" in cases[0]["query"]
    assert cases[1]["attachment_reference"] == "att-2"
    assert "REQ-889452" in cases[1]["query"]
