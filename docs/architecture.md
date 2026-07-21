# Production architecture

## Workload boundaries

- API Gateway Regional REST API is protected by WAF and a fail-closed Lambda authorizer. For this tenant, the authorizer validates ServiceNow HTTP Basic auth against Secrets Manager values. Production can also enable mTLS on a Regional custom domain and disable the default execute-api endpoint.
- The ingestion Lambda only validates the event, conditionally writes an idempotency record, archives incident metadata and attachment references in S3, and enqueues a FIFO message by incident ID.
- A small SQS dispatcher Lambda starts a Standard Step Functions execution. Its only role is durable hand-off from FIFO delivery to workflow execution; it performs no AI processing.
- Every agent is a one-off ECS Fargate task in private subnets. Task results are encrypted S3 artifacts. This prevents large attachment or evidence payloads from crossing the 256 KiB Step Functions state limit.
- The RAG task uses the Standard workflow callback pattern to return only its small route decision. Full artifacts remain in S3.

## RAG lifecycle

The `rag-indexer` stores a redacted incident summary, embedding text, Splunk evidence fingerprints, recommendation, and an initial `unknown` outcome label. A later ServiceNow resolution/reopen/edit webhook updates the outcome. The weekly Fargate quality task re-ranks accepted outcomes, tombstones stale patterns, and refreshes embeddings.

Fast path requires an accepted historical case and confidence at or above 0.90. Medium confidence at or above 0.72 performs lightweight context and Splunk refinement. Other cases run the full multi-agent path.

## Security controls

- No raw chain-of-thought is stored or logged. Work notes retain a concise rationale summary and evidence references only.
- Customer-managed KMS keys encrypt artifacts, DynamoDB, SQS, CloudWatch Logs, and Secrets Manager secrets.
- S3 buckets and SQS queues block insecure transport; buckets block public access and retain versions.
- Production Fargate tasks run in private subnets with HTTPS-only egress, VPC endpoints for core AWS APIs, and per-stage task roles. Cost-optimized dev mode runs one-off Fargate tasks in public subnets with no inbound rules and HTTPS-only egress to remove idle NAT Gateway and interface endpoint charges.
- Splunk queries are read-only and constrained by an allow-list of indexes, sourcetypes, fields, time ranges, and result counts.
- PII/secret redaction runs before any model call. Bedrock guardrail configuration is supported by the shared inference wrapper and must be pinned before production use.

## Observability and operations

Structured JSON logs include `execution_id`, `correlation_id`, service, and stage. Low-cardinality EMF metrics cover stage completion, latency, errors, retries, token counts, confidence, and route hit rate. Step Functions and Lambda X-Ray tracing are enabled; Fargate images include OpenTelemetry dependencies and are ready for an ADOT collector sidecar configuration. CloudTrail records management activity, and the operations dashboard contains alarm status and workflow KPIs.
