# Deployment runbook

## Prerequisites

1. Use an isolated AWS account for development and a separate production account.
2. Confirm AWS CLI authentication and the intended Region. Bedrock model access and any required Anthropic usage form must be approved before deployment.
3. Install Docker, Python 3.12+, Node.js 20+, and the CDK CLI.
4. Create or import the ServiceNow and Splunk secret containers through the approved secrets-management process. Do not put values in source, CDK context, task definitions, shell history, or logs.
5. For production mTLS, prepare an ACM certificate, a Regional DNS record, and an S3 PEM truststore. The REST API custom domain must use `TLS_1_2`; disable the default API endpoint after the custom domain is mapped.

## Commands

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pip install -r infrastructure\requirements.txt

cd infrastructure
cdk bootstrap aws://ACCOUNT_ID/us-east-1
cdk synth --strict
cdk diff --all
cdk deploy --all --require-approval broadening
```

Optional local helper (packages source, uploads to S3, and starts CodeBuild deploy pipeline):

```powershell
python scripts/deploy_local.py
```

For a development mock deployment, leave `mock_mode=true`, `mtls_enabled=false`, and `cost_optimized_dev=true` in `infrastructure/cdk.json`. This avoids idle NAT Gateway and interface endpoint charges. For production, pass `-c mock_mode=false -c mtls_enabled=true -c cost_optimized_dev=false` and supply the CloudFormation parameters for the approved Bedrock model and mTLS domain, certificate, and truststore.

## Post-deploy verification

1. Confirm all CloudFormation stacks complete and all ECS task definitions use Fargate launch type with `awsvpc` networking.
2. Replace secret placeholders through the approved secret workflow and configure the ServiceNow and Splunk endpoint values.
3. Send a synthetic event to the development webhook with `Bearer local-test-token`.
4. In Step Functions, confirm the RAG callback returns `fast`, `refine`, or `full`; set `MOCK_RAG_SCORE` in an isolated test task to exercise each route.
5. Confirm encrypted stage artifacts in S3, a mock ServiceNow writeback receipt, and a RAG record artifact.
6. Confirm CloudWatch dashboard widgets, X-Ray traces, CloudTrail events, WAF sampled requests, and DLQ alarms.
