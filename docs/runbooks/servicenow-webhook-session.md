# ServiceNow webhook configuration session

This runbook is a guided session to connect your ServiceNow outbound webhook to the deployed AWS endpoint.

Estimated time: 30 to 45 minutes

## Session goal

Route ServiceNow incident creation events to the AWS API Gateway path:

- POST /servicenow/incident

and confirm that a webhook call is accepted with HTTP 202.

## What you need before starting

1. AWS deployment is complete and stacks are healthy.
2. ServiceNow integration user for webhook auth is created.
3. Permissions to update AWS Secrets Manager and configure a ServiceNow outbound REST message.
4. AWS CLI authenticated to the correct account and region.

## Step 1 - Capture the AWS webhook endpoint

From repo root, run:

```powershell
$Outputs = Get-Content infrastructure\cdk-outputs.json | ConvertFrom-Json
$Endpoint = $Outputs.SnowCompute.WebhookEndpoint
$Endpoint
```

Expected shape:

https://<api-id>.execute-api.<region>.amazonaws.com/dev/servicenow/incident

Save this value. You will paste it into ServiceNow.

## Step 2 - Set webhook credentials in Secrets Manager

Your Lambda authorizer compares incoming HTTP Basic auth to:

- webhook_username
- webhook_password

stored in secret:

- snow-incident-intelligence/dev/servicenow

Use your approved secret workflow to set or rotate these keys. Keep them aligned with the ServiceNow outbound credential you will configure in Step 3.

Optional verification (no secret values returned):

```powershell
aws secretsmanager describe-secret --secret-id snow-incident-intelligence/dev/servicenow
```

## Step 3 - Configure ServiceNow outbound webhook

In ServiceNow, create or update an outbound REST message (or webhook integration) with these values:

1. Method: POST
2. Endpoint URL: value from Step 1
3. Authentication: Basic Auth
4. Username: webhook_username value from Step 2
5. Password: webhook_password value from Step 2
6. Headers:
   - Content-Type: application/json

Request body should follow the contract in docs/api-contract.md.

Minimum payload fields:

- event_id
- operation
- incident_sys_id
- incident_number
- short_description
- description

For this repository, you can send additional fields beyond the minimum contract. The ingest Lambda archives the full JSON payload, and downstream models permit extra incident fields.

## Step 4 - Trigger only on incident creation

Configure the trigger to fire only when an Incident record is inserted.

Recommended settings:

1. Table: incident
2. When: after insert
3. Condition: active is true (optional, based on your process)
4. Operation in payload: always set to insert

Do not trigger on update, resolve, or reopen for this setup.

Exact ServiceNow Business Rule settings:

1. Name: AWS Incident Insert Webhook
2. Table: Incident [incident]
3. Active: true
4. Advanced: true
5. When: after
6. Insert: true
7. Update: false
8. Delete: false
9. Query: false
10. Condition: current.active == true
11. Order: 100

Paste-ready Business Rule script:

- docs/runbooks/snippets/incident-insert-webhook-business-rule.js

This script sends insert events only, includes every non-empty incident field, and includes attachment metadata plus authenticated attachment download URLs.

## Step 5 - Build full incident payload including attachments

Use a ServiceNow script action or scripted REST payload transform to send:

1. Required top-level fields used by AWS ingestion.
2. A complete incident field map with all non-empty values.
3. Attachment metadata list with download URLs for every attachment.

Example script (ServiceNow server-side JavaScript):

```javascript
(function buildPayload(current) {
  var payload = {};

  // Required fields for AWS ingestion.
  payload.event_id = "evt-" + current.sys_id + "-" + new GlideDateTime().getNumericValue();
  payload.operation = "insert";
  payload.incident_sys_id = String(current.getValue("sys_id"));
  payload.incident_number = String(current.getValue("number"));
  payload.short_description = String(current.getValue("short_description") || "");
  payload.description = String(current.getValue("description") || "");
  payload.state = String(current.getValue("state") || "");
  payload.priority = String(current.getValue("priority") || "");
  payload.assignment_group = String(current.getDisplayValue("assignment_group") || "");
  payload.caller = String(current.getDisplayValue("caller_id") || "");
  payload.updated_at = String(current.getValue("sys_updated_on") || "");

  // Send every readable incident field as raw values.
  var allFields = {};
  var elements = current.getElements();
  for (var i = 0; i < elements.size(); i++) {
    var element = elements.get(i);
    var name = String(element.getName());
    var value = current.getValue(name);
    if (value !== null && value !== "") {
      allFields[name] = String(value);
    }
  }
  payload.incident_all_fields = allFields;

  // Optional display-value map for human-readable context.
  var displayFields = {};
  for (var j = 0; j < elements.size(); j++) {
    var displayElement = elements.get(j);
    var displayName = String(displayElement.getName());
    var displayValue = current.getDisplayValue(displayName);
    if (displayValue !== null && displayValue !== "") {
      displayFields[displayName] = String(displayValue);
    }
  }
  payload.incident_display_fields = displayFields;

  // Include all attachment metadata and direct download URLs.
  var attachments = [];
  var agr = new GlideRecord("sys_attachment");
  agr.addQuery("table_name", "incident");
  agr.addQuery("table_sys_id", String(current.getValue("sys_id")));
  agr.orderBy("sys_created_on");
  agr.query();
  while (agr.next()) {
    var attachmentSysId = String(agr.getValue("sys_id"));
    attachments.push({
      sys_id: attachmentSysId,
      file_name: String(agr.getValue("file_name") || ""),
      content_type: String(agr.getValue("content_type") || "application/octet-stream"),
      size_bytes: parseInt(agr.getValue("size_bytes") || "0", 10),
      download_url: String(gs.getProperty("glide.servlet.uri")) + "api/now/attachment/" + attachmentSysId + "/file"
    });
  }
  payload.attachments = attachments;

  return JSON.stringify(payload);
})(current);
```

Notes:

1. Keep attachment URLs authenticated and tenant-local (no public sharing).
2. The runtime accepts the full attachments list in the webhook payload. Attachment enrichment processes up to ATTACHMENT_MAX_ITEMS (default 25) per execution; increase this variable when you need deeper attachment processing.

## Step 6 - Send a test webhook from ServiceNow

Trigger a test incident event from ServiceNow and confirm:

1. HTTP status is 202.
2. Response body includes execution_id.

If 401 is returned:

- Recheck webhook_username and webhook_password in both ServiceNow and Secrets Manager.
- Wait up to 5 minutes if authorizer cache is still warm after credential rotation.

If 403 is returned:

- Check WAF rules and API Gateway stage/resource mapping.

If 5xx is returned:

- Check API Gateway execution logs and Lambda logs for authorizer and ingest handlers.

## Step 7 - Validate downstream processing in AWS

After a successful 202:

1. Confirm new object in intake S3 bucket.
2. Confirm idempotency and metadata record in DynamoDB.
3. Confirm message accepted in SQS FIFO queue.
4. Confirm Step Functions execution started by dispatcher Lambda.

## Quick smoke test from workstation (optional)

Use this to validate endpoint and auth independent of ServiceNow.

```powershell
$WebhookEndpoint = "https://replace-me.execute-api.us-east-1.amazonaws.com/dev/servicenow/incident"
$WebhookUser = "replace-me"
$WebhookPass = "replace-me"

$Pair = "$WebhookUser:$WebhookPass"
$Encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Pair))
$Headers = @{
  Authorization = "Basic $Encoded"
  "Content-Type" = "application/json"
}

$Body = @{
  event_id = "evt-$(Get-Date -Format yyyyMMddHHmmss)"
  operation = "insert"
  incident_sys_id = "abc123"
  incident_number = "INC0010001"
  short_description = "Webhook smoke test"
  description = "ServiceNow webhook to AWS endpoint smoke test"
  state = "new"
  priority = "2"
  incident_all_fields = @{
    number = "INC0010001"
    category = "software"
    subcategory = "api"
    impact = "2"
    urgency = "2"
    opened_by = "integration.user"
  }
  incident_display_fields = @{
    state = "New"
    priority = "2 - High"
  }
  attachments = @(
    @{
      sys_id = "attachment123"
      file_name = "error-screenshot.png"
      content_type = "image/png"
      size_bytes = 10240
      download_url = "https://your-instance.service-now.com/api/now/attachment/attachment123/file"
    }
  )
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri $WebhookEndpoint -Headers $Headers -Body $Body
```

## Completion checklist

1. ServiceNow trigger runs only on incident insert.
2. ServiceNow endpoint points to AWS WebhookEndpoint.
3. ServiceNow Basic auth values match Secrets Manager webhook credentials.
4. Payload includes required fields, incident_all_fields, incident_display_fields, and attachments.
5. Test event returns HTTP 202 and execution_id.
6. Event is visible through S3, DynamoDB, SQS, and Step Functions.
7. Team runbook updated with final ServiceNow object names and owners.
