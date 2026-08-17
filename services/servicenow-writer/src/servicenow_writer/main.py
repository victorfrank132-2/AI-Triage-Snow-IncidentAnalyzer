from __future__ import annotations

import io
import json
import os
import re
import zipfile
from typing import Any

import requests
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import WorkNote
from snow_intelligence.stages import load_stage

DEFAULT_ASSIGNMENT_CONFIDENCE_THRESHOLD = 0.90
SYS_ID_PATTERN = r"^[0-9a-fA-F]{32}$"


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


def _build_analysis_bundle(
    note: WorkNote, splunk_stage: dict[str, Any], llm_inference: dict[str, Any]
) -> tuple[str, bytes]:
    zip_name = f"analysis-bundle-{note.incident_number}.zip"
    evidence_file_name, evidence_text = _build_evidence_attachment(note)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("work-note.md", note.work_note_markdown)
        archive.writestr(evidence_file_name, evidence_text)
        archive.writestr("splunk-stage.json", json.dumps(splunk_stage, indent=2, ensure_ascii=True))
        archive.writestr(
            "splunk-results.json",
            json.dumps(splunk_stage.get("results", []), indent=2, ensure_ascii=True),
        )
        archive.writestr(
            "splunk-case-results.json",
            json.dumps(splunk_stage.get("attachment_case_results", []), indent=2, ensure_ascii=True),
        )
        archive.writestr("llm-inference.json", json.dumps(llm_inference, indent=2, ensure_ascii=True))
    return zip_name, buffer.getvalue()


def _load_assignment_group_map() -> dict[str, str]:
    raw = os.getenv("SERVICENOW_ASSIGNMENT_GROUP_MAP", "").strip()
    if not raw:
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("SERVICENOW_ASSIGNMENT_GROUP_MAP must be a JSON object")
    group_map: dict[str, str] = {}
    for key, value in parsed.items():
        category = str(key or "").strip().lower()
        group = str(value or "").strip()
        if category and group:
            group_map[category] = group
    return group_map


def _assignment_confidence_threshold() -> float:
    raw = os.getenv("SERVICENOW_ASSIGNMENT_CONFIDENCE_THRESHOLD", "").strip()
    if not raw:
        return DEFAULT_ASSIGNMENT_CONFIDENCE_THRESHOLD
    try:
        return max(0.0, min(1.0, float(raw)))
    except ValueError as exc:
        raise ValueError("SERVICENOW_ASSIGNMENT_CONFIDENCE_THRESHOLD must be a float") from exc


def _float_or_none(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if 1.0 < parsed <= 100.0:
        parsed = parsed / 100.0
    if parsed < 0.0 or parsed > 1.0:
        return None
    return parsed


def _analysis_category_signal(llm_inference: dict[str, Any]) -> tuple[str | None, float | None]:
    structured = llm_inference.get("structured_analysis", {})
    if not isinstance(structured, dict):
        return None, None
    category = (
        structured.get("analysis_category")
        or structured.get("category")
        or structured.get("incident_category")
        or structured.get("routing_category")
    )
    confidence = (
        structured.get("analysis_category_confidence")
        or structured.get("category_confidence")
        or structured.get("routing_confidence")
        or structured.get("confidence")
    )
    category_text = str(category or "").strip().lower()
    return (category_text or None), _float_or_none(confidence)


def _assignment_update(llm_inference: dict[str, Any]) -> dict[str, Any]:
    category, confidence = _analysis_category_signal(llm_inference)
    threshold = _assignment_confidence_threshold()
    group_map = _load_assignment_group_map()
    if category is None or confidence is None:
        return {
            "enabled": bool(group_map),
            "applied": False,
            "reason": "analysis category or confidence missing",
            "threshold": threshold,
        }
    if confidence < threshold:
        return {
            "enabled": bool(group_map),
            "applied": False,
            "category": category,
            "confidence": confidence,
            "threshold": threshold,
            "reason": "confidence below threshold",
        }
    assignment_group = group_map.get(category)
    if not assignment_group:
        return {
            "enabled": bool(group_map),
            "applied": False,
            "category": category,
            "confidence": confidence,
            "threshold": threshold,
            "reason": "no assignment group mapping for category",
        }
    return {
        "enabled": True,
        "applied": True,
        "category": category,
        "confidence": confidence,
        "threshold": threshold,
        "assignment_group": assignment_group,
    }


def _bool_env(name: str, *, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _servicenow_auth() -> tuple[str, str]:
    return os.environ["SERVICENOW_USERNAME"], os.environ["SERVICENOW_PASSWORD"]


def _resolve_assignment_group(base_url: str, assignment_group: str) -> tuple[str, dict[str, Any]]:
    group_value = assignment_group.strip()
    if re.match(SYS_ID_PATTERN, group_value):
        return group_value, {"group_input": group_value, "resolved_by": "sys_id"}

    query_url = f"{base_url}/api/now/table/sys_user_group"
    response = requests.get(
        query_url,
        params={
            "sysparm_query": f"name={group_value}",
            "sysparm_fields": "sys_id,name",
            "sysparm_limit": "1",
        },
        auth=_servicenow_auth(),
        headers={"Accept": "application/json"},
        timeout=(5, 20),
    )
    response.raise_for_status()
    rows = response.json().get("result", [])
    if rows:
        return str(rows[0]["sys_id"]), {
            "group_input": group_value,
            "resolved_by": "name",
            "group_name": rows[0].get("name", group_value),
        }

    if not _bool_env("SERVICENOW_AUTO_CREATE_ASSIGNMENT_GROUPS"):
        raise RuntimeError(f"assignment group not found: {group_value}")

    create_response = requests.post(
        query_url,
        json={
            "name": group_value,
            "description": (
                "Auto-created by ServiceNow incident intelligence routing. "
                "Review ownership and membership before production use."
            ),
        },
        auth=_servicenow_auth(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=(5, 20),
    )
    create_response.raise_for_status()
    created = create_response.json().get("result", {})
    if "sys_id" not in created:
        raise RuntimeError(f"assignment group creation returned no sys_id: {group_value}")
    return str(created["sys_id"]), {
        "group_input": group_value,
        "resolved_by": "created",
        "group_name": created.get("name", group_value),
    }


def _resolve_incident_sys_id(base_url: str, incident_number: str) -> str:
    query_url = f"{base_url}/api/now/table/incident"
    response = requests.get(
        query_url,
        params={
            "sysparm_query": f"number={incident_number}",
            "sysparm_fields": "sys_id,number",
            "sysparm_limit": "1",
        },
        auth=_servicenow_auth(),
        headers={"Accept": "application/json"},
        timeout=(5, 20),
    )
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("result", [])
    if not rows:
        raise RuntimeError(f"incident not found for number: {incident_number}")
    return str(rows[0]["sys_id"])


def _write_to_servicenow(
    note: WorkNote,
    incident: dict[str, Any] | None = None,
    llm_inference: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call the tenant endpoint using runtime-injected Basic auth credentials.

    The application never reads Secrets Manager directly. Production task launch
    must resolve these values at runtime from the tenant's secret reference.
    """
    base_url = os.environ["SERVICENOW_INSTANCE_URL"].rstrip("/")
    incident_sys_id = _resolve_incident_sys_id(base_url, note.incident_number)
    url = f"{base_url}/api/now/table/incident/{incident_sys_id}"
    assignment_update = _assignment_update(llm_inference or {})
    patch_body: dict[str, Any] = {"work_notes": note.work_note_markdown}
    if assignment_update.get("applied"):
        assignment_group, group_resolution = _resolve_assignment_group(
            base_url, str(assignment_update["assignment_group"])
        )
        assignment_update["assignment_group"] = assignment_group
        assignment_update["group_resolution"] = group_resolution
        patch_body["assignment_group"] = assignment_group
    response = requests.patch(
        url,
        json=patch_body,
        auth=_servicenow_auth(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=(5, 20),
    )
    response.raise_for_status()
    return {
        "status_code": response.status_code,
        "target": url,
        "incident_number": note.incident_number,
        "incident_sys_id": incident_sys_id,
        "assignment_update": assignment_update,
    }


def _attach_evidence_file(
    base_url: str,
    incident_sys_id: str,
    note: WorkNote,
    splunk_stage: dict[str, Any],
    llm_inference: dict[str, Any],
) -> dict[str, Any]:
    base_url = base_url.rstrip("/")
    file_name, bundle_bytes = _build_analysis_bundle(note, splunk_stage, llm_inference)
    response = requests.post(
        f"{base_url}/api/now/attachment/file",
        params={
            "table_name": "incident",
            "table_sys_id": incident_sys_id,
            "file_name": file_name,
        },
        data=bundle_bytes,
        auth=_servicenow_auth(),
        headers={"Accept": "application/json", "Content-Type": "application/zip"},
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
    reasoning_stage = load_stage(context, "reasoning")
    note_payload = reasoning_stage.get("work_note", reasoning_stage)
    note = WorkNote.model_validate(note_payload)
    llm_inference = reasoning_stage.get("llm_inference", {})
    splunk_stage = load_stage(context, "splunk")
    if context.mock_mode:
        receipt = {"status_code": 200, "target": "mock://servicenow/work-notes", "mock": True}
        bundle_name, _ = _build_analysis_bundle(note, splunk_stage, llm_inference)
        attachment_receipt = {
            "status_code": 200,
            "target": "mock://servicenow/attachment/file",
            "file_name": bundle_name,
            "mock": True,
        }
    else:
        receipt = _write_to_servicenow(note, payload.get("incident"), llm_inference)
        attachment_receipt = _attach_evidence_file(
            os.environ["SERVICENOW_INSTANCE_URL"],
            receipt["incident_sys_id"],
            note,
            splunk_stage,
            llm_inference,
        )
    return {
        "work_note": note.model_dump(mode="json"),
        "writeback_receipt": receipt,
        "analysis_bundle_receipt": attachment_receipt,
        "evidence_attachment_receipt": attachment_receipt,
    }


if __name__ == "__main__":
    run_task("servicenow-writer", process)
