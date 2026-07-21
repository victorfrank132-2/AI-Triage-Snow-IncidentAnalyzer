# Operations runbook

## Failed workflow or DLQ message

1. Use the correlation ID from the API response or ServiceNow work note to search structured CloudWatch logs.
2. Open the Standard Step Functions execution history and identify the failed stage. Do not copy attachment contents, secrets, or raw prompts into tickets.
3. Inspect only the stage artifact references permitted for the responder role.
4. Correct the external dependency, replay an idempotent event with a new approved event ID, and document the operator decision.

## Splunk timeout or policy rejection

1. Check the Splunk endpoint reachability from the Fargate private subnet and the service timeout metric.
2. Review the generated query metadata, not credentials or sensitive payloads.
3. Expand allow-lists only through a reviewed policy change. Never permit write-capable SPL commands.

## Bedrock throttling

1. Check the Bedrock throttle metric, model quota, and configured explicit `maxTokens` values.
2. Reduce concurrency or output bounds first; then request an approved quota increase or use a validated inference profile.
3. Do not retry validation or access-denied failures.

