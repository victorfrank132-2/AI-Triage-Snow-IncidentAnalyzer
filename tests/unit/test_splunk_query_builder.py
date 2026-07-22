from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "splunk-agent" / "src"))

from splunk_agent import main as splunk_main


def test_build_query_uses_expected_index_pattern_and_identifiers(monkeypatch) -> None:
    monkeypatch.delenv("SPLUNK_INDEXES", raising=False)
    query = splunk_main._build_query(
        "INC0010105",
        "Error Code: 502 Request ID: REQ-763579 Endpoint: GET /api/v1/life/underwriting",
    )

    assert "index=life_api_logs OR index=life_ui_logs OR index=pc_api_logs OR index=pc_ui_logs" in query
    assert '"INC0010105"' in query
    assert '"REQ-763579"' in query
    assert '"/api/v1/life/underwriting"' in query
