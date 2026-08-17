from __future__ import annotations

import sys
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

from snow_intelligence.runtime import TaskContext
from snow_intelligence.schemas import WorkNote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "servicenow-writer" / "src"))

from servicenow_writer import main as writer  # noqa: E402


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


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

    stage_payload = {
        "work_note": note.model_dump(mode="json"),
        "llm_inference": {
            "route": "full",
            "structured_analysis": {"possible_rca": "Upstream timeout in pricing service."},
        },
    }
    calls: list[str] = []

    def fake_load_stage(context: TaskContext, stage: str) -> dict[str, object]:
        if stage == "reasoning":
            return stage_payload
        assert stage == "splunk"
        return {
            "query": {
                "query": "index=life_api_logs (\"REQ-123\") | head 50",
                "earliest_hours_ago": 0,
                "max_rows": 50,
            },
            "results": [{"_raw": "sample log 1"}, {"_raw": "sample log 2"}],
            "attachment_case_results": [{"attachment_reference": "att-1", "results": [{"_raw": "case log"}]}],
            "evidence": [
                {
                    "source": "splunk",
                    "reference": "web-proxy-export",
                    "summary": "Splunk returned 5 rows",
                    "confidence": 0.9,
                }
            ],
        }

    def fake_write_to_servicenow(
        note_value: WorkNote, incident: dict[str, object] | None = None, llm_inference: dict[str, object] | None = None
    ) -> dict[str, object]:
        calls.append("write")
        assert note_value.incident_number == "INC0010104"
        return {
            "status_code": 200,
            "target": "mock://servicenow/work-notes",
            "incident_number": note_value.incident_number,
            "incident_sys_id": "sys-123",
        }

    def fake_attach_evidence_file(
        base_url: str,
        incident_sys_id: str,
        note_value: WorkNote,
        splunk_stage: dict[str, object],
        llm_inference: dict[str, object],
    ) -> dict[str, object]:
        calls.append("attach")
        assert base_url == "https://example.service-now.com"
        assert incident_sys_id == "sys-123"
        file_name, bundle_bytes = writer._build_analysis_bundle(
            note_value, splunk_stage, llm_inference
        )
        assert file_name == "analysis-bundle-INC0010104.zip"
        with zipfile.ZipFile(BytesIO(bundle_bytes), mode="r") as archive:
            names = set(archive.namelist())
            assert "work-note.md" in names
            assert "llm-inference.json" in names
            assert "splunk-stage.json" in names
            assert "splunk-results.json" in names
            assert "splunk-case-results.json" in names
            assert "evidence-references-INC0010104.txt" in names
            assert "Five matching timeout events." in archive.read(
                "evidence-references-INC0010104.txt"
            ).decode("utf-8")
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
    assert result["evidence_attachment_receipt"]["file_name"] == "analysis-bundle-INC0010104.zip"
    assert result["analysis_bundle_receipt"]["file_name"] == "analysis-bundle-INC0010104.zip"


def test_write_to_servicenow_auto_assigns_group_for_high_confidence_category(monkeypatch) -> None:
    note = WorkNote(
        incident_number="INC0010123",
        work_note_markdown="Work note body.",
        recommendation="Observed beneficiary verification failure.",
        rationale_summary="Evidence-grounded summary.",
        confidence=0.95,
        evidence=[],
    )
    patch_bodies: list[dict[str, Any]] = []

    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(200, {"result": [{"sys_id": "sys-123", "number": "INC0010123"}]})

    def fake_patch(*args: Any, **kwargs: Any) -> _FakeResponse:
        patch_bodies.append(kwargs["json"])
        return _FakeResponse(200, {"result": {"sys_id": "sys-123"}})

    monkeypatch.setattr(writer.requests, "get", fake_get)
    monkeypatch.setattr(writer.requests, "patch", fake_patch)
    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://example.service-now.com")
    monkeypatch.setenv("SERVICENOW_USERNAME", "bot")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "password")
    monkeypatch.setenv(
        "SERVICENOW_ASSIGNMENT_GROUP_MAP",
        '{"api_error":"c38f00f4530360100999ddeeff7b1298"}',
    )

    receipt = writer._write_to_servicenow(
        note,
        llm_inference={
            "structured_analysis": {
                "analysis_category": "api_error",
                "analysis_category_confidence": 0.93,
            }
        },
    )

    assert patch_bodies == [
        {
            "work_notes": "Work note body.",
            "assignment_group": "c38f00f4530360100999ddeeff7b1298",
        }
    ]
    assert receipt["assignment_update"]["applied"] is True


def test_write_to_servicenow_does_not_assign_group_below_threshold(monkeypatch) -> None:
    note = WorkNote(
        incident_number="INC0010123",
        work_note_markdown="Work note body.",
        recommendation="Observed beneficiary verification failure.",
        rationale_summary="Evidence-grounded summary.",
        confidence=0.88,
        evidence=[],
    )
    patch_bodies: list[dict[str, Any]] = []

    def fake_get(*args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(200, {"result": [{"sys_id": "sys-123", "number": "INC0010123"}]})

    def fake_patch(*args: Any, **kwargs: Any) -> _FakeResponse:
        patch_bodies.append(kwargs["json"])
        return _FakeResponse(200, {"result": {"sys_id": "sys-123"}})

    monkeypatch.setattr(writer.requests, "get", fake_get)
    monkeypatch.setattr(writer.requests, "patch", fake_patch)
    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://example.service-now.com")
    monkeypatch.setenv("SERVICENOW_USERNAME", "bot")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "password")
    monkeypatch.setenv(
        "SERVICENOW_ASSIGNMENT_GROUP_MAP",
        '{"api_error":"c38f00f4530360100999ddeeff7b1298"}',
    )

    receipt = writer._write_to_servicenow(
        note,
        llm_inference={
            "structured_analysis": {
                "analysis_category": "api_error",
                "analysis_category_confidence": 0.89,
            }
        },
    )

    assert patch_bodies == [{"work_notes": "Work note body."}]
    assert receipt["assignment_update"]["applied"] is False
    assert receipt["assignment_update"]["reason"] == "confidence below threshold"


def test_write_to_servicenow_creates_missing_assignment_group_when_enabled(monkeypatch) -> None:
    note = WorkNote(
        incident_number="INC0010123",
        work_note_markdown="Work note body.",
        recommendation="Observed beneficiary verification failure.",
        rationale_summary="Evidence-grounded summary.",
        confidence=0.95,
        evidence=[],
    )
    patch_bodies: list[dict[str, Any]] = []
    created_groups: list[dict[str, Any]] = []

    def fake_get(url: str, *args: Any, **kwargs: Any) -> _FakeResponse:
        if url.endswith("/api/now/table/incident"):
            return _FakeResponse(200, {"result": [{"sys_id": "sys-123", "number": "INC0010123"}]})
        if url.endswith("/api/now/table/sys_user_group"):
            return _FakeResponse(200, {"result": []})
        raise AssertionError(f"unexpected GET url: {url}")

    def fake_post(url: str, *args: Any, **kwargs: Any) -> _FakeResponse:
        assert url.endswith("/api/now/table/sys_user_group")
        created_groups.append(kwargs["json"])
        return _FakeResponse(
            201,
            {"result": {"sys_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "API Support"}},
        )

    def fake_patch(*args: Any, **kwargs: Any) -> _FakeResponse:
        patch_bodies.append(kwargs["json"])
        return _FakeResponse(200, {"result": {"sys_id": "sys-123"}})

    monkeypatch.setattr(writer.requests, "get", fake_get)
    monkeypatch.setattr(writer.requests, "post", fake_post)
    monkeypatch.setattr(writer.requests, "patch", fake_patch)
    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://example.service-now.com")
    monkeypatch.setenv("SERVICENOW_USERNAME", "bot")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "password")
    monkeypatch.setenv("SERVICENOW_AUTO_CREATE_ASSIGNMENT_GROUPS", "true")
    monkeypatch.setenv("SERVICENOW_ASSIGNMENT_GROUP_MAP", '{"api_error":"API Support"}')

    receipt = writer._write_to_servicenow(
        note,
        llm_inference={
            "structured_analysis": {
                "analysis_category": "api_error",
                "analysis_category_confidence": 0.93,
            }
        },
    )

    assert created_groups[0]["name"] == "API Support"
    assert patch_bodies == [
        {
            "work_notes": "Work note body.",
            "assignment_group": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }
    ]
    assert receipt["assignment_update"]["group_resolution"]["resolved_by"] == "created"
