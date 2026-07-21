from __future__ import annotations

import os
from typing import Any

import requests
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import WorkNote
from snow_intelligence.stages import load_stage


def _write_to_servicenow(note: WorkNote) -> dict[str, Any]:
    """Call the tenant endpoint using runtime-injected Basic auth credentials.

    The application never reads Secrets Manager directly. Production task launch
    must resolve these values at runtime from the tenant's secret reference.
    """
    base_url = os.environ["SERVICENOW_INSTANCE_URL"].rstrip("/")
    url = f"{base_url}/api/now/table/incident/{note.incident_number}"
    response = requests.patch(
        url,
        json={"work_notes": note.work_note_markdown},
        auth=(os.environ["SERVICENOW_USERNAME"], os.environ["SERVICENOW_PASSWORD"]),
        headers={"Content-Type": "application/json"},
        timeout=(5, 20),
    )
    response.raise_for_status()
    return {"status_code": response.status_code, "target": url}


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    note = WorkNote.model_validate(load_stage(context, "reasoning"))
    if context.mock_mode:
        receipt = {"status_code": 200, "target": "mock://servicenow/work-notes", "mock": True}
    else:
        receipt = _write_to_servicenow(note)
    return {"work_note": note.model_dump(mode="json"), "writeback_receipt": receipt}


if __name__ == "__main__":
    run_task("servicenow-writer", process)
