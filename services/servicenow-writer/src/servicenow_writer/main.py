from __future__ import annotations

import os
from typing import Any

import requests
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import WorkNote
from snow_intelligence.stages import load_stage


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


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    note = WorkNote.model_validate(load_stage(context, "reasoning"))
    if context.mock_mode:
        receipt = {"status_code": 200, "target": "mock://servicenow/work-notes", "mock": True}
    else:
        receipt = _write_to_servicenow(note)
    return {"work_note": note.model_dump(mode="json"), "writeback_receipt": receipt}


if __name__ == "__main__":
    run_task("servicenow-writer", process)
