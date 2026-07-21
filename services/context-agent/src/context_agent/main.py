from __future__ import annotations

from typing import Any

from snow_intelligence.bedrock import converse
from snow_intelligence.redaction import redact_text
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import EvidenceReference, ServiceNowIncidentPayload


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    incident = ServiceNowIncidentPayload.model_validate(payload["incident"])
    redacted_description = redact_text(incident.description)
    if context.mock_mode:
        summary = f"{incident.short_description}. Current state is {incident.state}; priority is {incident.priority}."
        usage = {"input_tokens": 0, "output_tokens": 0}
    else:
        summary, usage = converse(
            system_prompt=(
                "Summarize incident facts, uncertainty, and investigation goals. "
                "Do not reveal reasoning steps, secrets, or personal data."
            ),
            user_prompt=f"Short description: {redact_text(incident.short_description)}\nDescription: {redacted_description}",
            max_tokens=700,
        )
    return {
        "incident_summary": summary,
        "token_usage": usage,
        "evidence": [
            EvidenceReference(
                source="servicenow",
                reference=incident.incident_sys_id,
                summary="Normalized incident metadata and redacted description.",
                confidence=1.0,
            ).model_dump()
        ],
    }


if __name__ == "__main__":
    run_task("context-agent", process)
