# ServiceNow webhook API contract

`POST /servicenow/incident`

Production transport uses a Regional API Gateway REST API protected by AWS WAF and a fail-closed Lambda authorizer. For this tenant, ServiceNow sends HTTP Basic auth in the `Authorization` header; the authorizer compares it with the `webhook_username` and `webhook_password` fields stored in Secrets Manager. mTLS can also be enabled on a Regional custom domain through CDK context when required.

```json
{
  "event_id": "evt-20260720-0001",
  "operation": "insert",
  "incident_sys_id": "abc123",
  "incident_number": "INC0010001",
  "short_description": "Payments API is timing out",
  "description": "The caller reports repeated timeout errors.",
  "state": "new",
  "priority": "2",
  "assignment_group": "Platform Operations",
  "attachments": [{
    "sys_id": "attachment123",
    "file_name": "timeout-screenshot.png",
    "content_type": "image/png",
    "download_url": "https://tenant.service-now.com/api/now/attachment/attachment123/file",
    "size_bytes": 10240
  }]
}
```

Response `202` includes an `execution_id`. An idempotent repeat returns `202` with the same event accepted but does not enqueue a second workflow. Attachments are referenced at ingress and downloaded only by the Fargate attachment task through a tenant-specific, allow-listed integration.
