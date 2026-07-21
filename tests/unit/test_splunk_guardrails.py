import pytest
from snow_intelligence.schemas import SplunkQueryPolicy, SplunkQueryRequest
from snow_intelligence.splunk import SplunkPolicyViolation, validate_splunk_query

POLICY = SplunkQueryPolicy(
    allowed_indexes={"servicenow"},
    allowed_sourcetypes={"servicenow"},
    allowed_fields={"incident_number", "host", "error_code"},
    max_time_range_hours=24,
    max_result_rows=100,
)


def test_guardrails_allow_approved_read_query() -> None:
    validate_splunk_query(
        SplunkQueryRequest(
            query='index=servicenow sourcetype=servicenow incident_number="INC1" | head 20'
        ),
        POLICY,
    )


def test_guardrails_reject_write_capable_command() -> None:
    with pytest.raises(SplunkPolicyViolation):
        validate_splunk_query(
            SplunkQueryRequest(
                query='index=servicenow incident_number="INC1" | outputlookup forbidden'
            ),
            POLICY,
        )


def test_guardrails_reject_unapproved_index() -> None:
    with pytest.raises(SplunkPolicyViolation):
        validate_splunk_query(
            SplunkQueryRequest(query='index=_internal incident_number="INC1"'), POLICY
        )
