from __future__ import annotations

import os
import time
from typing import Any

import requests
from snow_intelligence.aws import client
from snow_intelligence.bedrock import converse
from snow_intelligence.redaction import redact_text
from snow_intelligence.runtime import TaskContext, run_task
from snow_intelligence.schemas import EvidenceReference, ServiceNowIncidentPayload


def _extract_attachment(context: TaskContext, attachment: Any) -> str:
    allowed_types = set(os.getenv("ATTACHMENT_ALLOWED_TYPES", "application/pdf,image/png,image/jpeg").split(","))
    if attachment.content_type not in allowed_types or attachment.size_bytes > 50 * 1024 * 1024 or not attachment.download_url:
        return "Attachment skipped by size, type, or missing-URL policy."
    response = requests.get(
        str(attachment.download_url),
        auth=(os.environ["SERVICENOW_USERNAME"], os.environ["SERVICENOW_PASSWORD"]),
        timeout=(5, 60),
    )
    response.raise_for_status()
    key = f"executions/{context.execution_id}/attachments/{attachment.sys_id}"
    client("s3").put_object(Bucket=context.artifact_bucket, Key=key, Body=response.content, ContentType=attachment.content_type)
    textract = client("textract")
    job_id = textract.start_document_analysis(DocumentLocation={"S3Object": {"Bucket": context.artifact_bucket, "Name": key}}, FeatureTypes=["FORMS", "TABLES"])["JobId"]
    for _ in range(30):
        result = textract.get_document_analysis(JobId=job_id)
        if result["JobStatus"] == "SUCCEEDED":
            text = " ".join(block.get("Text", "") for block in result.get("Blocks", []) if block.get("BlockType") == "LINE")
            summary, _ = converse(system_prompt="Summarize only operational facts. Do not expose reasoning, PII, or secrets.", user_prompt=redact_text(text)[:12_000], max_tokens=500)
            return summary
        if result["JobStatus"] in {"FAILED", "PARTIAL_SUCCESS"}:
            raise RuntimeError(f"Textract attachment analysis failed: {result['JobStatus']}")
        time.sleep(2)
    raise TimeoutError("Textract attachment analysis timed out")


def process(context: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    incident = ServiceNowIncidentPayload.model_validate(payload["incident"])
    max_items = int(os.getenv("ATTACHMENT_MAX_ITEMS", "25"))
    selected_attachments = incident.attachments[:max_items]
    evidence: list[dict[str, Any]] = []
    for attachment in selected_attachments:
        summary = f"Mock attachment enrichment: {attachment.file_name}" if context.mock_mode else _extract_attachment(context, attachment)
        evidence.append(
            EvidenceReference(
                source="attachment",
                reference=attachment.sys_id,
                summary=summary,
                confidence=0.7,
            ).model_dump()
        )
    skipped = max(len(incident.attachments) - len(selected_attachments), 0)
    if skipped:
        evidence.append(
            EvidenceReference(
                source="operator",
                reference="attachment-limit",
                summary=(
                    f"Skipped {skipped} attachments after processing limit of {max_items}. "
                    "Increase ATTACHMENT_MAX_ITEMS to process more attachments in this stage."
                ),
                confidence=1.0,
            ).model_dump()
        )
    return {
        "attachment_count": len(incident.attachments),
        "attachment_count_processed": len(selected_attachments),
        "evidence": evidence,
    }


if __name__ == "__main__":
    run_task("attachment-agent", process)
