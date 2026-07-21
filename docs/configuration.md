# Tenant configuration

Do not send passwords, API tokens, or client secrets in chat, source control, Docker build arguments, or CodeBuild plaintext environment variables.

## Secrets Manager JSON values

Populate these two CDK-created secret containers after the initial infrastructure deployment.

`snow-incident-intelligence/dev/servicenow`

```json
{
  "instance_url": "https://your-instance.service-now.com",
  "username": "your-servicenow-bot",
  "password": "replace-with-password",
  "webhook_username": "your-servicenow-webhook-user",
  "webhook_password": "replace-with-webhook-password"
}
```

`snow-incident-intelligence/dev/splunk`

```json
{
  "base_url": "https://splunk.example.com:8089",
  "username": "your-splunk-service-user",
  "password": "replace-with-password"
}
```

Use distinct least-privilege accounts for ServiceNow writeback, ServiceNow webhook ingress, and Splunk when your tenant allows it. The authorizer reads the ServiceNow secret by ARN and compares the incoming HTTP `Authorization: Basic ...` value in memory; do not store a manually encoded header. Rotate credentials through each provider's approved workflow. ECS tasks resolve secrets at task launch, so running ECS services need a forced deployment after rotation; one-off Step Functions tasks pick up the latest value when each task starts. The Lambda authorizer caches webhook credentials for up to five minutes.

## CDK deployment parameters

Provide these non-secret values with `cdk deploy` or through the CodeBuild deployment environment:

- `ContainerImageTag` - set by CodeBuild from the immutable source revision
- `MtlsDomainName`, `MtlsCertificateArn`, `MtlsTruststoreUri` when mTLS is enabled

## Cost-optimized dev mode

The default `dev` context enables `cost_optimized_dev=true`. This keeps the full ServiceNow, Splunk, RAG, Step Functions, and ECS Fargate workflow functional while removing the largest idle network costs:

- NAT Gateways are not created.
- Interface VPC endpoints are not created.
- One-off Fargate tasks run in public subnets with public IPs, no inbound security-group rules, and HTTPS-only egress.
- OpenSearch Serverless network access is public, but data access still requires IAM and the generated access policy.

For production, deploy with `-c cost_optimized_dev=false` to restore private subnet execution, NAT Gateways, interface endpoints, and the private OpenSearch Serverless VPC endpoint.

## CodeBuild inputs

The CDK delivery stack creates a privileged, direct-source CodeBuild project using `buildspec-containers.yml`. Supply `SourceRepositoryOwner`, `SourceRepositoryName`, and `SourceBranchName` as CloudFormation parameters and authorize CodeBuild's GitHub source credential in the AWS console. The stack supplies these non-secret environment variables automatically:

- `ECR_REGISTRY`
- `ECR_RAG_RETRIEVER_URI`, `ECR_CONTEXT_AGENT_URI`, `ECR_ATTACHMENT_AGENT_URI`
- `ECR_SPLUNK_AGENT_URI`, `ECR_REASONING_AGENT_URI`, `ECR_SERVICENOW_WRITER_URI`, `ECR_RAG_INDEXER_URI`

The project has ECR push permissions only for these repositories and the CDK bootstrap deploy/file-publishing roles needed to deploy `SnowCompute`. If enterprise policy requires AWS CodeConnections, replace the direct-source project with a CodePipeline source action using an approved connection.
