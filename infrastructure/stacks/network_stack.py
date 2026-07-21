from __future__ import annotations

from dataclasses import dataclass

from aws_cdk import RemovalPolicy, Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from constructs import Construct


@dataclass(frozen=True)
class NetworkResources:
    vpc: ec2.Vpc
    task_security_group: ec2.SecurityGroup
    endpoint_security_group: ec2.SecurityGroup
    cost_optimized_dev: bool
    has_private_endpoints: bool
    fargate_subnet_type: ec2.SubnetType
    assign_public_ip: bool
    aoss_vpc_endpoint_id: str | None


class NetworkStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        project_name: str,
        environment: str,
        cost_optimized_dev: bool,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        flow_log_key = kms.Key(
            self,
            "FlowLogKey",
            alias=f"alias/{project_name}-{environment}-vpc-flow-logs",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        self._allow_cloudwatch_logs_key_usage(flow_log_key)
        flow_log_group = logs.LogGroup(
            self,
            "VpcFlowLogs",
            encryption_key=flow_log_key,
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.vpc = ec2.Vpc(
            self,
            "PlatformVpc",
            max_azs=2,
            nat_gateways=0 if cost_optimized_dev else 2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="ingress", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="workload",
                    subnet_type=(
                        ec2.SubnetType.PRIVATE_ISOLATED
                        if cost_optimized_dev
                        else ec2.SubnetType.PRIVATE_WITH_EGRESS
                    ),
                    cidr_mask=24,
                ),
            ],
        )
        ec2.FlowLog(
            self,
            "AllVpcTrafficFlowLog",
            resource_type=ec2.FlowLogResourceType.from_vpc(self.vpc),
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(flow_log_group),
            traffic_type=ec2.FlowLogTrafficType.ALL,
            max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.ONE_MINUTE,
        )
        self.task_security_group = ec2.SecurityGroup(
            self,
            "FargateTaskSecurityGroup",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Fargate tasks: HTTPS-only egress.",
        )
        self.task_security_group.add_egress_rule(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "HTTPS to approved SaaS and AWS endpoints"
        )
        self.endpoint_security_group = ec2.SecurityGroup(
            self,
            "VpcEndpointSecurityGroup",
            vpc=self.vpc,
            allow_all_outbound=False,
        )
        self.endpoint_security_group.add_ingress_rule(
            self.task_security_group, ec2.Port.tcp(443), "Fargate HTTPS to VPC endpoints"
        )
        aoss_vpc_endpoint_id = None
        endpoint_subnets = ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        for service in (
            ec2.InterfaceVpcEndpointAwsService.ECR,
            ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
        ):
            self.vpc.add_interface_endpoint(
                f"{service.short_name.title().replace('.', '')}Endpoint",
                service=service,
                subnets=endpoint_subnets,
                security_groups=[self.endpoint_security_group],
                private_dns_enabled=True,
            )
        self.vpc.add_gateway_endpoint(
            "S3GatewayEndpoint", service=ec2.GatewayVpcEndpointAwsService.S3
        )
        if not cost_optimized_dev:
            for service in (
                ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
                ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
                ec2.InterfaceVpcEndpointAwsService.STS,
            ):
                self.vpc.add_interface_endpoint(
                    f"{service.short_name.title().replace('.', '')}Endpoint",
                    service=service,
                    subnets=endpoint_subnets,
                    security_groups=[self.endpoint_security_group],
                    private_dns_enabled=True,
                )
            aoss_vpc_endpoint = __import__(
                "aws_cdk.aws_opensearchserverless", fromlist=["CfnVpcEndpoint"]
            ).CfnVpcEndpoint(
                self,
                "OpenSearchServerlessVpcEndpoint",
                name="snow-intelligence-aoss",
                vpc_id=self.vpc.vpc_id,
                subnet_ids=self.vpc.select_subnets(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ).subnet_ids,
                security_group_ids=[self.endpoint_security_group.security_group_id],
            )
            aoss_vpc_endpoint_id = aoss_vpc_endpoint.attr_id
        self.resources = NetworkResources(
            vpc=self.vpc,
            task_security_group=self.task_security_group,
            endpoint_security_group=self.endpoint_security_group,
            cost_optimized_dev=cost_optimized_dev,
            has_private_endpoints=not cost_optimized_dev,
            fargate_subnet_type=(
                ec2.SubnetType.PUBLIC
                if cost_optimized_dev
                else ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            assign_public_ip=cost_optimized_dev,
            aoss_vpc_endpoint_id=aoss_vpc_endpoint_id,
        )

    def _allow_cloudwatch_logs_key_usage(self, key: kms.Key) -> None:
        key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsUseOfKey",
                principals=[iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")],
                actions=[
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey",
                ],
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": (
                            f"arn:{self.partition}:logs:{self.region}:{self.account}:log-group:*"
                        )
                    }
                },
            )
        )
