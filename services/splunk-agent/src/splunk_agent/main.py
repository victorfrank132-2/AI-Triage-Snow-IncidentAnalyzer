from __future__ import annotations

import json
import os
import re
import time
from urllib.parse import urlparse
from typing import Any

import requests
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import EvidenceReference, SplunkQueryPolicy, SplunkQueryRequest
from snow_intelligence.splunk import validate_splunk_query
from snow_intelligence.stages import load_stage


_DEFAULT_SPLUNK_INDEXES = "life_api_logs,life_ui_logs,pc_api_logs,pc_ui_logs"


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _csv_list(value: str) -> list[str]:
    values: list[str] = []
    for item in value.split(","):
        normalized = item.strip()
        if normalized and normalized not in values:
            values.append(normalized)
    return values


def _query_indexes() -> list[str]:
    return _csv_list(os.getenv("SPLUNK_INDEXES", _DEFAULT_SPLUNK_INDEXES))


def _policy() -> SplunkQueryPolicy:
    configured_allowed_indexes = os.getenv("SPLUNK_ALLOWED_INDEXES", "").strip()
    allowed_indexes = (
        _csv_set(configured_allowed_indexes)
        if configured_allowed_indexes
        else set(_query_indexes())
    )
    return SplunkQueryPolicy(
        allowed_indexes=allowed_indexes,
        allowed_sourcetypes=set(
            os.getenv(
                "SPLUNK_ALLOWED_SOURCETYPES", "app_log,servicenow,life_api,life_ui,pc_api,pc_ui"
            ).split(",")
        ),
        allowed_fields={"incident_number", "host", "service", "error_code", "severity"},
        max_time_range_hours=int(os.getenv("SPLUNK_MAX_TIME_RANGE_HOURS", "24")),
        max_result_rows=int(os.getenv("SPLUNK_MAX_RESULT_ROWS", "100")),
    )


def _normalize_base_url(raw_url: str) -> str:
    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValueError("SPLUNK_BASE_URL must not be empty")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid SPLUNK_BASE_URL: {raw_url}")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _ensure_search_prefix(query: str) -> str:
    stripped = query.strip()
    return stripped if stripped.lower().startswith("search ") else f"search {stripped}"


def _earliest_time_value(earliest_hours_ago: int) -> str:
    if earliest_hours_ago <= 0:
        return "0"
    return f"-{earliest_hours_ago}h"


def _count_export_rows(response_text: str) -> int:
    text = response_text.strip()
    if not text:
        return 0

    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            rows = payload.get("rows")
            if isinstance(rows, list):
                return len(rows)
            if "result" in payload:
                return 1
        if isinstance(payload, list):
            return len(payload)
    except json.JSONDecodeError:
        pass

    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and ("result" in item or "_raw" in item or "rows" in item):
            if isinstance(item.get("rows"), list):
                count += len(item["rows"])
            else:
                count += 1
    return count


def _summary_row_count(summary: str) -> int | None:
    match = re.search(r"Splunk returned\s+(\d+)\s+guardrailed evidence rows", str(summary or ""))
    if not match:
        return None
    return int(match.group(1))


def _extract_context_terms(context_summary: str) -> list[str]:
    text = str(context_summary or "")
    terms: list[str] = []
    patterns = [
        r"\bREQ-[A-Za-z0-9-]+\b",
        r"\bTERM-[A-Za-z0-9-]+\b",
        r"\bQ-[A-Za-z0-9-]+\b",
        r"\bERR_[A-Za-z0-9_]+\b",
        r"\b(?:GET|POST|PUT|DELETE|PATCH)\s+/api/[A-Za-z0-9/_-]+\b",
        r"\b(?:GET|POST|PUT|DELETE|PATCH)\s+(/api/[A-Za-z0-9/_-]+)",
        r"\b(/api/[A-Za-z0-9/_-]+)",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            value = match.group(1) if match.lastindex else match.group(0)
            normalized = value.strip()
            if normalized and normalized not in terms:
                terms.append(normalized)
    return terms


def _fallback_terms(short_description: str, description: str) -> list[str]:
    text = f"{short_description} {description}"
    keywords = re.findall(r"\b[a-zA-Z][a-zA-Z0-9_-]{3,}\b", text.lower())
    stopwords = {
        "incident",
        "analysis",
        "provide",
        "given",
        "from",
        "with",
        "that",
        "this",
        "need",
        "needs",
        "errors",
    }
    terms: list[str] = []
    for keyword in keywords:
        if keyword in stopwords:
            continue
        if keyword not in terms:
            terms.append(keyword)
        if len(terms) >= 6:
            break
    return terms


def _build_query(identifier_terms: list[str], short_description: str = "", description: str = "") -> str:
    indexes = _query_indexes()
    index_clause = " OR ".join(f"index={index_name}" for index_name in indexes)

    filtered_identifiers: list[str] = []
    for term in identifier_terms:
        normalized = str(term or "").strip()
        if not normalized:
            continue
        if normalized.lower().startswith("inc") and normalized[3:].isdigit():
            continue
        if normalized not in filtered_identifiers:
            filtered_identifiers.append(normalized)

    if not filtered_identifiers:
        filtered_identifiers = _fallback_terms(short_description, description)

    identifiers_clause = " OR ".join(f'"{term}"' for term in filtered_identifiers[:20])
    return f"{index_clause} ({identifiers_clause}) | head 50"


def _build_attachment_case_queries(
    attachment_evidence: list[dict[str, Any]], short_description: str, description: str
) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for item in attachment_evidence:
        if str(item.get("source", "")).lower() != "attachment":
            continue
        attachment_ref = str(item.get("reference", "")).strip()
        attachment_name = str(item.get("attachment_name", "")).strip()
        identifiers = _extract_context_terms(str(item.get("summary", "")))
        if not attachment_ref or not identifiers:
            continue
        cases.append(
            {
                "attachment_reference": attachment_ref,
                "attachment_name": attachment_name,
                "identifiers": identifiers[:12],
                "query": _build_query(identifiers, short_description=short_description, description=description),
            }
        )
    return cases


def _web_proxy_login(session: requests.Session, base_url: str, username: str, password: str) -> str:
    login_url = f"{base_url}/en-US/account/login"
    login_page = session.get(login_url, timeout=(5, 20))
    login_page.raise_for_status()
    cval_match = re.search(r'"cval":(\d+)', login_page.text)
    if not cval_match:
        raise RuntimeError("Unable to parse Splunk login token")
    cval = cval_match.group(1)

    login_response = session.post(
        login_url,
        data={"username": username, "password": password, "cval": cval},
        timeout=(5, 20),
    )
    login_response.raise_for_status()

    csrf_token = cval
    for cookie_name, cookie_value in session.cookies.items():
        if cookie_name.startswith("splunkweb_csrf_token_"):
            csrf_token = cookie_value
            break
    return csrf_token


def _execute_query_web_proxy(base_url: str, request: SplunkQueryRequest) -> tuple[str, str]:
    username = os.environ["SPLUNK_USERNAME"]
    password = os.environ["SPLUNK_PASSWORD"]
    session = requests.Session()
    csrf_token = _web_proxy_login(session, base_url, username, password)
    search = _ensure_search_prefix(request.query)

    response = session.post(
        f"{base_url}/en-US/splunkd/__raw/services/search/jobs/export",
        headers={
            "Accept": "application/json",
            "Referer": f"{base_url}/en-US/app/search/search",
            "X-Requested-With": "XMLHttpRequest",
            "X-Splunk-Form-Key": csrf_token,
        },
        data={
            "search": search,
            "earliest_time": _earliest_time_value(request.earliest_hours_ago),
            "output_mode": "json_rows",
            "count": request.max_rows,
        },
        timeout=(5, 40),
    )
    response.raise_for_status()
    row_count = _count_export_rows(response.text)
    return "web-proxy-export", f"Splunk returned {row_count} guardrailed evidence rows."


def _execute_query(request: SplunkQueryRequest) -> tuple[str, str]:
    base_url = _normalize_base_url(os.environ["SPLUNK_BASE_URL"])
    auth = (os.environ["SPLUNK_USERNAME"], os.environ["SPLUNK_PASSWORD"])
    access_mode = os.getenv("SPLUNK_ACCESS_MODE", "web_proxy").strip().lower()
    if access_mode == "web_proxy":
        return _execute_query_web_proxy(base_url, request)

    query = _ensure_search_prefix(request.query)
    submitted = requests.post(
        f"{base_url}/services/search/jobs",
        data={
            "search": query,
            "earliest_time": _earliest_time_value(request.earliest_hours_ago),
            "output_mode": "json",
        },
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
    attachment_stage = load_stage(context, "attachments")
    incident_number = payload["incident"]["incident_number"]

    attachment_name_by_ref = {
        str(item.get("sys_id", "")): str(item.get("file_name", ""))
        for item in payload.get("incident", {}).get("attachments", [])
        if str(item.get("sys_id", "")).strip()
    }
    for evidence_item in attachment_stage.get("evidence", []):
        if str(evidence_item.get("source", "")).lower() != "attachment":
            continue
        ref = str(evidence_item.get("reference", ""))
        if ref in attachment_name_by_ref:
            evidence_item["attachment_name"] = attachment_name_by_ref[ref]

    attachment_text = "\n".join(
        str(item.get("summary", "")) for item in attachment_stage.get("evidence", [])
    )
    context_text = "\n".join(
        [
            str(context_stage.get("incident_summary", "")),
            str(payload["incident"].get("short_description", "")),
            str(payload["incident"].get("description", "")),
            attachment_text,
        ]
    )
    identifier_terms = _extract_context_terms(context_text)
    query = _build_query(
        identifier_terms,
        short_description=str(payload["incident"].get("short_description", "")),
        description=str(payload["incident"].get("description", "")),
    )
    request = SplunkQueryRequest(
        query=query,
        earliest_hours_ago=0,
        max_rows=50,
    )
    validate_splunk_query(request, _policy())
    search_id, summary = ("mock-search-job", "Mock Splunk evidence completed.") if context.mock_mode else _execute_query(request)

    attachment_cases = _build_attachment_case_queries(
        attachment_stage.get("evidence", []),
        short_description=str(payload["incident"].get("short_description", "")),
        description=str(payload["incident"].get("description", "")),
    )
    max_case_queries = int(os.getenv("SPLUNK_ATTACHMENT_CASE_MAX", "5"))
    case_results: list[dict[str, Any]] = []
    for case in attachment_cases[:max_case_queries]:
        case_request = SplunkQueryRequest(query=case["query"], earliest_hours_ago=0, max_rows=30)
        validate_splunk_query(case_request, _policy())
        case_search_id, case_summary = (
            (f"mock-case-{case['attachment_reference']}", "Mock Splunk evidence completed.")
            if context.mock_mode
            else _execute_query(case_request)
        )
        case_results.append(
            {
                "attachment_reference": case["attachment_reference"],
                "attachment_name": case.get("attachment_name", ""),
                "identifiers": case["identifiers"],
                "query": case["query"],
                "search_reference": case_search_id,
                "summary": case_summary,
                "row_count": _summary_row_count(case_summary),
            }
        )

    indexes_searched = ", ".join(_query_indexes())
    evidence = EvidenceReference(
        source="splunk",
        reference=search_id,
        summary=(
            f"{summary} Indexes searched: {indexes_searched}. "
            f"Incident {incident_number}; context: {context_stage['incident_summary'][:160]}. "
            f"Attachment case queries executed: {len(case_results)}"
        ),
        confidence=0.75,
    )
    return {
        "query": request.model_dump(),
        "evidence": [evidence.model_dump()],
        "attachment_case_results": case_results,
    }


if __name__ == "__main__":
    run_task("splunk-agent", process)
