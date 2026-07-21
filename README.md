# ServiceNow Incident Intelligence on AWS

Enterprise incident intelligence that accepts ServiceNow webhooks, preserves an auditable incident record, routes through retrieval-first RAG, runs bounded multi-agent analysis on ECS Fargate, and posts a reviewable work note back to ServiceNow.

## Architecture

```text
ServiceNow -> WAF -> API Gateway REST API -> Ingest Lambda -> S3 + DynamoDB + SQS FIFO
                                                                  |
                                                          Dispatcher Lambda
                                                                  |
                                                     Step Functions Standard
                                                                  |
             +------------------ retrieval callback from Fargate ------------------+
             | fast: reasoning -> writeback -> RAG capture                         |
             | refine: context -> Splunk -> reasoning -> writeback -> RAG capture  |
             | full: context -> attachments/Textract -> Splunk -> reasoning -> ... |
             +-----------------------------------------------------------------------+

RAG: Bedrock embeddings + OpenSearch Serverless VECTORSEARCH
Quality: EventBridge schedule -> Fargate RAG quality task
Audit: CloudTrail + encrypted CloudWatch Logs + X-Ray/ADOT-ready trace correlation
```

All AI and document-processing code runs in ECS Fargate. Lambda is limited to webhook ingress, authorization, idempotency, archival, queue dispatch, and infrastructure support. The CDK contains no EC2 resources.

## Repository layout

```text
infrastructure/          CDK app and Networking, Data, Compute, Security, Observability stacks
services/                Lambda ingress plus Fargate task images, one directory per stage
shared/                  Pydantic contracts, redaction, JSON logging, AWS clients, routing policies
tests/                   Unit and opt-in cloud integration tests
docs/                    Architecture, contracts, state machine reference, runbooks
.github/workflows/       CI workflow
scripts/                 Developer helpers
```

Read [docs/architecture.md](docs/architecture.md), [docs/api-contract.md](docs/api-contract.md), and [docs/runbooks/deployment.md](docs/runbooks/deployment.md) before deployment.

