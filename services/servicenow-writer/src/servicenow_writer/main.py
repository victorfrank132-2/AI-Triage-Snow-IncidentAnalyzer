from __future__ import annotations

import os
from typing import Any

import requests
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import WorkNote
from snow_intelligence.stages import load_stage


def _build_evidence_attachment(note: WorkNote) -> tuple[str, str]:
    file_name = f"evidence-references-{note.incident_number}.txt"
    lines = [
        f"Incident Number: {note.incident_number}",
        f"Confidence: {note.confidence:.2f}",
        "",
        "Evidence references: &splunk results & formedquery",
        "",
        "Rationale summary:",
        note.rationale_summary,
        "",
        "Evidence details:",
    ]
    if note.evidence:
        for item in note.evidence:
            lines.extend(
                [
                    f"- {item.source}: {item.reference}",
                    f"  Summary: {item.summary}",
                ]
            )
    else:
        lines.append("- none")
    lines.append("")
    return file_name, "\n".join(lines)


def _resolve_incident_sys_id(base_url: str, incident_number: str) -> str:
    query_url = f"{base_url}/api/now/table/incident"
    response = requests.get(
        query_url,
        params={
            "sysparm_query": f"number={incident_number}",
            "sysparm_fields": "sys_id,number",
            "sysparm_limit": "1",
        },
        auth=(os.environ["SERVICENOW_USERNAME"], os.environ["SERVICENOW_PASSWORD"]),
        headers={"Accept": "application/json"},
        timeout=(5, 20),
    )
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("result", [])
    if not rows:
        raise RuntimeError(f"incident not found for number: {incident_number}")
    return str(rows[0]["sys_id"])


def _write_to_servicenow(note: WorkNote) -> dict[str, Any]:
    """Call the tenant endpoint using runtime-injected Basic auth credentials.

    The application never reads Secrets Manager directly. Production task launch
    must resolve these values at runtime from the tenant's secret reference.
    """
    base_url = os.environ["SERVICENOW_INSTANCE_URL"].rstrip("/")
    incident_sys_id = _resolve_incident_sys_id(base_url, note.incident_number)
    url = f"{base_url}/api/now/table/incident/{incident_sys_id}"
    response = requests.patch(
        url,
        json={"work_notes": note.work_note_markdown},
        auth=(os.environ["SERVICENOW_USERNAME"], os.environ["SERVICENOW_PASSWORD"]),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=(5, 20),
    )
    response.raise_for_status()
    return {
        "status_code": response.status_code,
        "target": url,
        "incident_number": note.incident_number,
        "incident_sys_id": incident_sys_id,
    }


def _attach_evidence_file(base_url: str, incident_sys_id: str, note: WorkNote) -> dict[str, Any]:
    file_name, attachment_text = _build_evidence_attachment(note)
    response = requests.post(
        f"{base_url}/api/now/attachment/file",
        params={
            "table_name": "incident",
            "table_sys_id": incident_sys_id,
            "file_name": file_name,
        },
        files={"file": (file_name, attachment_text.encode("utf-8"), "text/plain")},
        auth=(os.environ["SERVICENOW_USERNAME"], os.environ["SERVICENOW_PASSWORD"]),
        headers={"Accept": "application/json"},
        timeout=(5, 30),
    )
    response.raise_for_status()
    payload = response.json().get("result", {})
    return {
        "status_code": response.status_code,
        "target": f"{base_url}/api/now/attachment/file",
        "incident_sys_id": incident_sys_id,
        "file_name": file_name,
        "attachment_sys_id": payload.get("sys_id"),
    }


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    note = WorkNote.model_validate(load_stage(context, "reasoning"))
    if context.mock_mode:
        receipt = {"status_code": 200, "target": "mock://servicenow/work-notes", "mock": True}
        attachment_receipt = {
            "status_code": 200,
            "target": "mock://servicenow/attachment/file",
            "file_name": _build_evidence_attachment(note)[0],
            "mock": True,
        }
    else:
        receipt = _write_to_servicenow(note)
        attachment_receipt = _attach_evidence_file(
            os.environ["SERVICENOW_INSTANCE_URL"], receipt["incident_sys_id"], note
        )
    return {
        "work_note": note.model_dump(mode="json"),
        "writeback_receipt": receipt,
        "evidence_attachment_receipt": attachment_receipt,
    }


if __name__ == "__main__":
    run_task("servicenow-writer", process)
