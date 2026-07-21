# CDK Nag reviewed exceptions

Every suppression is registered in `infrastructure/app.py` with an explicit rationale.

- `SMG4`: ServiceNow and Splunk Basic auth credentials cannot use an AWS-provided automatic rotation template. A tenant-specific rotation workflow must be implemented and tested before production credentials are stored.
- `S1`: CloudTrail is enabled for management events. Add dedicated server-access log buckets and S3 data events in the production account baseline before a regulated deployment.
- `SQS3`: The workflow failure queue is intentionally terminal to avoid a recursive dead-letter queue; it is alarmed and has an operations runbook.
- `ECS2`: Only non-sensitive identifiers and endpoints are plain task configuration. ServiceNow and Splunk credentials are injected from Secrets Manager at task start.
- `L1`: Python 3.12 is pinned for validated Lambda compatibility. Review the latest Lambda runtime during every quarterly platform review.
- `COG4`: The webhook uses a custom Basic auth authorizer because ServiceNow is an external machine client, not a Cognito user-pool user.
- `IAM4` and `IAM5`: Remaining findings are CDK-generated service-role policies or suffix wildcards required for S3 objects, ECS task ARNs, and callback credentials. Each application task role is scoped to its required service resources.
