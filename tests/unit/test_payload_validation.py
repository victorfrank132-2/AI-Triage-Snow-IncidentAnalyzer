from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from snow_intelligence.schemas import ServiceNowIncidentPayload


def test_incident_payload_accepts_minimal_valid_event() -> None:
    payload = ServiceNowIncidentPayload.model_validate(
        {
            "event_id": "evt-12345678",
            "operation": "insert",
            "incident_sys_id": "sys-123",
            "incident_number": "INC0010001",
            "short_description": "VPN authentication failure",
            "updated_at": datetime.now(UTC).isoformat(),
        }
    )
    assert payload.incident_number == "INC0010001"


def test_incident_payload_rejects_unknown_operation() -> None:
    with pytest.raises(ValidationError):
        ServiceNowIncidentPayload.model_validate(
            {
                "event_id": "evt-12345678",
                "operation": "delete",
                "incident_sys_id": "sys-123",
                "incident_number": "INC0010001",
                "short_description": "VPN authentication failure",
            }
        )
