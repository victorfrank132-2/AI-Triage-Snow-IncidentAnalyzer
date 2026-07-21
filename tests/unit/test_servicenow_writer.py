from __future__ import annotations

import sys
from pathlib import Path

from snow_intelligence.runtime import TaskContext
from snow_intelligence.schemas import WorkNote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "servicenow-writer" / "src"))

from servicenow_writer import main as writer


def test_process_posts_work_note_then_evidence_attachment(monkeypatch) -> None:
    note = WorkNote(
        incident_number="INC0010104",
        work_note_markdown="Work note body.",
        recommendation="Restart the worker after approval.",
        rationale_summary="Recommendation based on evidence references.",
        confidence=0.94,
        evidence=[
            {
                "source": "splunk",
                "reference": "splunk results",
                "summary": "Five matching timeout events.",
                "confidence": 0.9,
            }
        ],
    )

    stage_payload = note.model_dump(mode="json")
    calls: list[str] = []

    def fake_load_stage(context: TaskContext, stage: str) -> dict[str, object]:
        assert stage == "reasoning"
        return stage_payload

    def fake_write_to_servicenow(note_value: WorkNote) -> dict[str, object]:
        calls.append("write")
        assert note_value.incident_number == "INC0010104"
        return {
            "status_code": 200,
            "target": "mock://servicenow/work-notes",
            "incident_number": note_value.incident_number,
            "incident_sys_id": "sys-123",
        }

    def fake_attach_evidence_file(
        base_url: str, incident_sys_id: str, note_value: WorkNote
    ) -> dict[str, object]:
        calls.append("attach")
        assert base_url == "https://example.service-now.com"
        assert incident_sys_id == "sys-123"
        file_name, attachment_text = writer._build_evidence_attachment(note_value)
        assert file_name == "evidence-references-INC0010104.txt"
        assert "Evidence references: &splunk results & formedquery" in attachment_text
        assert "Five matching timeout events." in attachment_text
        return {
            "status_code": 201,
            "target": "mock://servicenow/attachment/file",
            "incident_sys_id": incident_sys_id,
            "file_name": file_name,
            "attachment_sys_id": "att-123",
        }

    monkeypatch.setattr(writer, "load_stage", fake_load_stage)
    monkeypatch.setattr(writer, "_write_to_servicenow", fake_write_to_servicenow)
    monkeypatch.setattr(writer, "_attach_evidence_file", fake_attach_evidence_file)
    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://example.service-now.com")

    context = TaskContext(
        service="servicenow-writer",
        stage="servicenow-writeback",
        execution_id="exec-12345678",
        correlation_id="corr-12345678",
        input_s3_uri="s3://bucket/input.json",
        artifact_bucket="bucket",
        mock_mode=False,
        task_token=None,
    )

    result = writer.process(context, {})

    assert calls == ["write", "attach"]
    assert result["writeback_receipt"]["incident_sys_id"] == "sys-123"
    assert result["evidence_attachment_receipt"]["file_name"] == "evidence-references-INC0010104.txt"