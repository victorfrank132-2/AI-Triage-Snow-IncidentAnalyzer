#!/usr/bin/env python3
from __future__ import annotations

import os

import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks, NagPackSuppression, NagSuppressions
from stacks.compute_stack import ComputeStack
from stacks.data_stack import DataStack
from stacks.delivery_stack import DeliveryStack
from stacks.network_stack import NetworkStack
from stacks.observability_stack import ObservabilityStack
from stacks.security_stack import SecurityStack

app = cdk.App()
project_name = app.node.try_get_context("project_name") or "snow-incident-intelligence"
environment = app.node.try_get_context("environment") or "dev"
mock_mode = str(app.node.try_get_context("mock_mode")).lower() == "true"
mtls_enabled = str(app.node.try_get_context("mtls_enabled")).lower() == "true"
cost_optimized_dev = str(app.node.try_get_context("cost_optimized_dev")).lower() == "true"
aws_env = cdk.Environment(
    account=os.getenv("CDK_DEFAULT_ACCOUNT"), region=os.getenv("CDK_DEFAULT_REGION", "us-east-1")
)

security = SecurityStack(
    app, "SnowSecurity", project_name=project_name, environment=environment, env=aws_env
)
network = NetworkStack(
    app,
    "SnowNetwork",
    project_name=project_name,
    environment=environment,
    cost_optimized_dev=cost_optimized_dev,
    env=aws_env,
)
data = DataStack(
    app,
    "SnowData",
    project_name=project_name,
    environment=environment,
    network=network.resources,
    cost_optimized_dev=cost_optimized_dev,
    env=aws_env,
)
compute = ComputeStack(
    app,
    "SnowCompute",
    project_name=project_name,
    environment=environment,
    mock_mode=mock_mode,
    mtls_enabled=mtls_enabled,
    cost_optimized_dev=cost_optimized_dev,
    security=security.resources,
    network=network.resources,
    data=data.resources,
    env=aws_env,
)
data.add_dependency(network)
compute.add_dependency(data)
observability = ObservabilityStack(
    app,
    "SnowObservability",
    project_name=project_name,
    environment=environment,
    security=security.resources,
    data=data.resources,
    compute=compute.resources,
    env=aws_env,
)
observability.add_dependency(compute)
delivery = DeliveryStack(app, "SnowDelivery", compute=compute.resources, env=aws_env)
delivery.add_dependency(compute)

cdk.Tags.of(app).add("Application", project_name)
cdk.Tags.of(app).add("Environment", environment)
cdk.Tags.of(app).add("ManagedBy", "CDK")
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

# These are reviewed exceptions, not blanket opt-outs. See docs/security-exceptions.md.
NagSuppressions.add_stack_suppressions(
    security,
    [
        NagPackSuppression(
            id="AwsSolutions-S1",
            reason="Audit-bucket access is captured by CloudTrail data events; a dedicated log-delivery bucket is an operational hardening follow-up.",
        ),
        NagPackSuppression(
            id="AwsSolutions-SMG4",
            reason="ServiceNow and Splunk Basic auth credentials require tenant-specific rotation workflows; no generic rotation Lambda can safely rotate them.",
        ),
    ],
)
NagSuppressions.add_stack_suppressions(
    network,
    [
        NagPackSuppression(
            id="AwsSolutions-EC23",
            reason="Endpoint security group ingress is restricted to the VPC CIDR by an intrinsic reference; CDK Nag cannot evaluate that token.",
        ),
    ],
)
NagSuppressions.add_stack_suppressions(
    data,
    [
        NagPackSuppression(
            id="AwsSolutions-S1",
            reason="S3 data events are recorded by CloudTrail; dedicated S3 server access logging is a documented hardening follow-up.",
        ),
        NagPackSuppression(
            id="AwsSolutions-SQS3",
            reason="The workflow failure queue is a terminal operations queue, not a processing queue; it intentionally has no recursive DLQ.",
        ),
    ],
)
NagSuppressions.add_stack_suppressions(
    compute,
    [
        NagPackSuppression(
            id="AwsSolutions-ECS2",
            reason="Task environment values are non-secret identifiers and endpoints; credentials are injected from Secrets Manager at task start.",
        ),
        NagPackSuppression(
            id="AwsSolutions-L1",
            reason="Lambda uses the supported Python 3.12 runtime to match validated webhook dependencies; review on each runtime release.",
        ),
        NagPackSuppression(
            id="AwsSolutions-APIG2",
            reason="The Lambda boundary applies strict Pydantic validation; an API Gateway request validator is also configured for the webhook method.",
        ),
        NagPackSuppression(
            id="AwsSolutions-COG4",
            reason="ServiceNow is an external machine client authenticated by a fail-closed Basic auth Lambda authorizer, not a Cognito user-pool user.",
        ),
        NagPackSuppression(
            id="AwsSolutions-IAM4",
            reason="CDK-generated service roles use AWS managed execution policies; application task roles use custom least-privilege policies.",
        ),
        NagPackSuppression(
            id="AwsSolutions-IAM5",
            reason="Object ARNs and ECS task ARNs require suffix wildcards; task policies are constrained to the generated artifact bucket and task definitions.",
        ),
    ],
)
NagSuppressions.add_stack_suppressions(
    delivery,
    [
        NagPackSuppression(
            id="AwsSolutions-IAM5",
            reason="CodeBuild log/report groups and CDK bootstrap roles use generated suffixes; the build role is otherwise constrained to this application's ECR repositories.",
        ),
    ],
)

app.synth()
