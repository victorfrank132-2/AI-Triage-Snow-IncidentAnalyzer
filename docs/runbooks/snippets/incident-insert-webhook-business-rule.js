// Name: AWS Incident Insert Webhook
// Table: Incident [incident]
// Active: true
// Advanced: true
// When: after
// Insert: true
// Update: false
// Delete: false
// Query: false
// Condition: current.active == true
// Order: 100
// Notes:
// 1) Create a REST Message in ServiceNow named "AWS Incident Webhook" with method "postIncident".
// 2) Configure that REST Message method with:
//    - HTTP Method: POST
//    - Endpoint: your AWS WebhookEndpoint (from cdk-outputs)
//    - Authentication: Basic Auth (webhook_username / webhook_password)
//    - Header: Content-Type=application/json

(function executeRule(current, previous /* null when async */) {
  try {
    var payload = buildPayload(current);

    // Uses a configured REST Message + method so credentials are not hardcoded in script.
    var request = new sn_ws.RESTMessageV2("AWS Incident Webhook", "postIncident");
    request.setRequestHeader("Content-Type", "application/json");
    request.setRequestBody(JSON.stringify(payload));

    var response = request.execute();
    var status = response.getStatusCode();
    var body = response.getBody();

    if (status !== 202) {
      gs.error("AWS Incident webhook failed for " + current.number + ": status=" + status + " body=" + body);
      return;
    }

    gs.info("AWS Incident webhook queued for " + current.number + ": " + body);
  } catch (error) {
    gs.error("AWS Incident webhook exception for " + current.number + ": " + error.message);
  }

  function buildPayload(gr) {
    var payload = {};

    // Required ingestion keys.
    payload.event_id = "evt-" + gr.getUniqueValue() + "-" + new GlideDateTime().getNumericValue();
    payload.operation = "insert";
    payload.incident_sys_id = String(gr.getValue("sys_id"));
    payload.incident_number = String(gr.getValue("number") || "");
    payload.short_description = String(gr.getValue("short_description") || "");
    payload.description = String(gr.getValue("description") || "");

    // Common top-level keys used in downstream processing.
    payload.state = String(gr.getValue("state") || "");
    payload.priority = String(gr.getValue("priority") || "");
    payload.assignment_group = String(gr.getDisplayValue("assignment_group") || "");
    payload.caller = String(gr.getDisplayValue("caller_id") || "");
    payload.updated_at = String(gr.getValue("sys_updated_on") || "");

    // Full raw field map: all non-empty incident fields.
    var allFields = {};
    var elements = gr.getElements();
    for (var i = 0; i < elements.size(); i++) {
      var element = elements.get(i);
      var fieldName = String(element.getName());
      var rawValue = gr.getValue(fieldName);
      if (rawValue !== null && rawValue !== "") {
        allFields[fieldName] = String(rawValue);
      }
    }
    payload.incident_all_fields = allFields;

    // Full display map for readability.
    var displayFields = {};
    for (var j = 0; j < elements.size(); j++) {
      var displayElement = elements.get(j);
      var displayName = String(displayElement.getName());
      var displayValue = gr.getDisplayValue(displayName);
      if (displayValue !== null && displayValue !== "") {
        displayFields[displayName] = String(displayValue);
      }
    }
    payload.incident_display_fields = displayFields;

    // Attachment metadata and download links.
    var attachments = [];
    var attachmentGr = new GlideRecord("sys_attachment");
    attachmentGr.addQuery("table_name", "incident");
    attachmentGr.addQuery("table_sys_id", String(gr.getValue("sys_id")));
    attachmentGr.orderBy("sys_created_on");
    attachmentGr.query();

    var instanceBase = String(gs.getProperty("glide.servlet.uri") || "");
    while (attachmentGr.next()) {
      var attachmentSysId = String(attachmentGr.getValue("sys_id"));
      attachments.push({
        sys_id: attachmentSysId,
        file_name: String(attachmentGr.getValue("file_name") || ""),
        content_type: String(attachmentGr.getValue("content_type") || "application/octet-stream"),
        size_bytes: parseInt(attachmentGr.getValue("size_bytes") || "0", 10),
        download_url: instanceBase + "api/now/attachment/" + attachmentSysId + "/file"
      });
    }

    payload.attachments = attachments;
    return payload;
  }
})(current, previous);
