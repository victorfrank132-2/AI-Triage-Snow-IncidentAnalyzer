from __future__ import annotations

import os
import time
from typing import Any

import requests
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import EvidenceReference, SplunkQueryPolicy, SplunkQueryRequest
from snow_intelligence.splunk import validate_splunk_query
from snow_intelligence.stages import load_stage


def _policy() -> SplunkQueryPolicy:
    return SplunkQueryPolicy(
        allowed_indexes=set(os.getenv("SPLUNK_ALLOWED_INDEXES", "main,servicenow").split(",")),
        allowed_sourcetypes=set(
            os.getenv("SPLUNK_ALLOWED_SOURCETYPES", "app_log,servicenow").split(",")
        ),
        allowed_fields={"incident_number", "host", "service", "error_code", "severity"},
        max_time_range_hours=int(os.getenv("SPLUNK_MAX_TIME_RANGE_HOURS", "24")),
        max_result_rows=int(os.getenv("SPLUNK_MAX_RESULT_ROWS", "100")),
    )


def _execute_query(request: SplunkQueryRequest) -> tuple[str, str]:
    base_url = os.environ["SPLUNK_BASE_URL"].rstrip("/")
    auth = (os.environ["SPLUNK_USERNAME"], os.environ["SPLUNK_PASSWORD"])
    submitted = requests.post(
        f"{base_url}/services/search/jobs",
        data={"search": request.query, "earliest_time": f"-{request.earliest_hours_ago}h", "output_mode": "json"},
        auth=auth,
        timeout=(5, 20),
    )
    submitted.raise_for_status()
    search_id = submitted.json()["sid"]
    for _ in range(12):
        status = requests.get(f"{base_url}/services/search/jobs/{search_id}", params={"output_mode": "json"}, auth=auth, timeout=(5, 20))
        status.raise_for_status()
        content = status.json()["entry"][0]["content"]
        if content.get("isDone"):
            results = requests.get(f"{base_url}/services/search/jobs/{search_id}/results", params={"output_mode": "json", "count": request.max_rows}, auth=auth, timeout=(5, 20))
            results.raise_for_status()
            rows = results.json().get("results", [])
            return search_id, f"Splunk returned {len(rows)} guardrailed evidence rows."
        time.sleep(2)
    raise TimeoutError("Splunk search did not complete within the allowed polling window")


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    context_stage = load_stage(context, "context")
    incident_number = payload["incident"]["incident_number"]
    request = SplunkQueryRequest(
        query=f'index=servicenow sourcetype=servicenow incident_number="{incident_number}" | head 50',
        earliest_hours_ago=4,
        max_rows=50,
    )
    validate_splunk_query(request, _policy())
    search_id, summary = ("mock-search-job", "Mock Splunk evidence completed.") if context.mock_mode else _execute_query(request)
    evidence = EvidenceReference(
        source="splunk",
        reference=search_id,
        summary=f"{summary} Incident {incident_number}; context: {context_stage['incident_summary'][:160]}",
        confidence=0.75,
    )
    return {"query": request.model_dump(), "evidence": [evidence.model_dump()]}


if __name__ == "__main__":
    run_task("splunk-agent", process)
