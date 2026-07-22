"""Typed, tenant-neutral contracts. Do not add credentials or raw model reasoning here."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class IncidentOperation(StrEnum):
    INSERT = "insert"
    UPDATE = "update"


class AttachmentRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sys_id: str = Field(min_length=1, max_length=64)
    file_name: str = Field(min_length=1, max_length=255)
    content_type: str = Field(default="application/octet-stream", max_length=255)
    download_url: HttpUrl | None = None
    size_bytes: int = Field(default=0, ge=0, le=50 * 1024 * 1024)


class ServiceNowIncidentPayload(BaseModel):
    """Normalized ServiceNow webhook payload accepted at the ingestion boundary."""

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(min_length=8, max_length=128)
    operation: IncidentOperation
    incident_sys_id: str = Field(min_length=1, max_length=64)
    incident_number: str = Field(min_length=1, max_length=64)
    short_description: str = Field(min_length=1, max_length=4_000)
    description: str | None = Field(default=None, max_length=32_000)
    state: str = Field(default="new", max_length=64)
    priority: str = Field(default="3", max_length=16)
    assignment_group: str | None = Field(default=None, max_length=255)
    caller: str | None = Field(default=None, max_length=255)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    attachments: list[AttachmentRef] = Field(default_factory=list)

    @field_validator("event_id", "incident_sys_id", "incident_number")
    @classmethod
    def no_control_characters(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("control characters are not permitted")
        return value.strip()


class IncidentEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(min_length=8, max_length=128)
    correlation_id: str = Field(min_length=8, max_length=128)
    incident: ServiceNowIncidentPayload
    archive_s3_uri: str = Field(pattern=r"^s3://[^/]+/.+")
    state_table_key: str = Field(min_length=1, max_length=512)


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["splunk", "servicenow", "attachment", "rag", "operator"]
    reference: str = Field(min_length=1, max_length=1_024)
    summary: str = Field(min_length=1, max_length=4_000)
    confidence: float = Field(ge=0.0, le=1.0)


class RagCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: str = Field(min_length=1, max_length=256)
    score: float = Field(ge=0.0, le=1.0)
    incident_summary: str = Field(max_length=4_000)
    recommendation: str = Field(max_length=4_000)
    outcome_label: Literal["accepted", "reopened", "edited", "unknown"] = "unknown"
    evidence_fingerprints: list[str] = Field(default_factory=list, max_length=20)


class RouteKind(StrEnum):
    FAST = "fast"
    REFINE = "refine"
    FULL = "full"


class RouteDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route: RouteKind
    confidence: float = Field(ge=0.0, le=1.0)
    rationale_summary: str = Field(max_length=1_000)
    candidate: RagCandidate | None = None


class SplunkQueryPolicy(BaseModel):
    """Tenant policy enforced before any Splunk call."""

    model_config = ConfigDict(extra="forbid")

    allowed_indexes: set[str] = Field(min_length=1)
    allowed_sourcetypes: set[str] = Field(min_length=1)
    allowed_fields: set[str] = Field(min_length=1)
    max_time_range_hours: int = Field(default=24, ge=1, le=168)
    max_result_rows: int = Field(default=100, ge=1, le=1_000)


class SplunkQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=8_000)
    earliest_hours_ago: int = Field(default=0, ge=0, le=168)
    max_rows: int = Field(default=50, ge=1, le=1_000)


class WorkNote(BaseModel):
    """A writeback-safe result. `rationale_summary` must never contain chain-of-thought."""

    model_config = ConfigDict(extra="forbid")

    incident_number: str
    work_note_markdown: str = Field(min_length=1, max_length=12_000)
    recommendation: str = Field(min_length=1, max_length=4_000)
    rationale_summary: str = Field(min_length=1, max_length=2_000)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceReference] = Field(default_factory=list, max_length=20)
    requires_human_review: bool = True


class RagRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_id: str
    incident_summary: str
    embedding_text: str
    splunk_evidence_fingerprints: list[str]
    final_recommendation: str
    outcome_label: Literal["accepted", "reopened", "edited", "unknown"]
    created_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
