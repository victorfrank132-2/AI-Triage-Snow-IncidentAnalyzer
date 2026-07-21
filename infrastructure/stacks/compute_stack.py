from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aws_cdk import (
    CfnOutput,
    CfnParameter,
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import (
    aws_apigateway as apigateway,
)
from aws_cdk import (
    aws_ec2 as ec2,
)
from aws_cdk import (
    aws_ecr as ecr,
)
from aws_cdk import (
    aws_ecs as ecs,
)
from aws_cdk import (
    aws_events as events,
)
from aws_cdk import (
    aws_events_targets as event_targets,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_lambda as lambda_,
)
from aws_cdk import (
    aws_lambda_event_sources as lambda_event_sources,
)
from aws_cdk import (
    aws_logs as logs,
)
from aws_cdk import (
    aws_secretsmanager as secretsmanager,
)
from aws_cdk import (
    aws_stepfunctions as sfn,
)
from aws_cdk import (
    aws_stepfunctions_tasks as sfn_tasks,
)
from aws_cdk import (
    aws_wafv2 as wafv2,
)
from constructs import Construct

from stacks.data_stack import DataResources
from stacks.network_stack import NetworkResources
from stacks.security_stack import SecurityResources


@dataclass(frozen=True)
class ComputeResources:
    api: apigateway.RestApi
    ingest_function: lambda_.Function
    dispatcher_function: lambda_.Function
    state_machine: sfn.StateMachine
    cluster: ecs.Cluster
    repositories: dict[str, ecr.Repository]


class ComputeStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        project_name: str,
        environment: str,
        mock_mode: bool,
        mtls_enabled: bool,
        cost_optimized_dev: bool,
        security: SecurityResources,
        network: NetworkResources,
        data: DataResources,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.project_root = Path(__file__).resolve().parents[2]
        self.project_name = project_name
        self.deployment_environment = environment
        self.security = security
        self.network = network
        self.data = data
        self.mock_mode = mock_mode
        self.mtls_enabled = mtls_enabled
        self.cost_optimized_dev = cost_optimized_dev
        self.task_roles = {
            stage: iam.Role(
                self,
                f"{stage.title().replace('-', '')}TaskRole",
                role_name=f"{project_name}-{environment}-{stage}",
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
                description=f"Least-privilege task role for {stage}.",
            )
            for stage in (
                "rag-retriever",
                "context-agent",
                "attachment-agent",
                "splunk-agent",
                "reasoning-agent",
                "servicenow-writer",
                "rag-indexer",
                "rag-quality-job",
            )
        }
        self.bedrock_model_id = CfnParameter(
            self,
            "BedrockModelId",
            type="String",
            default="us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            description="Approved Bedrock model or inference profile ID. Verify access before deployment.",
        )
        self.bedrock_model_arn = CfnParameter(
            self,
            "BedrockModelArn",
            type="String",
            default="arn:aws:bedrock:*::foundation-model/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            description="IAM resource ARN approved for Bedrock InvokeModel. Use the exact profile/model resources for production.",
        )
        self.bedrock_embedding_model_id = CfnParameter(
            self,
            "BedrockEmbeddingModelId",
            type="String",
            default="amazon.titan-embed-text-v2:0",
            description="Approved Bedrock embedding model ID for the RAG vector index.",
        )
        self.bedrock_embedding_model_arn = CfnParameter(
            self,
            "BedrockEmbeddingModelArn",
            type="String",
            default="arn:aws:bedrock:*::foundation-model/amazon.titan-embed-text-v2:0",
            description="IAM resource ARN approved for Bedrock embedding invocation.",
        )
        self.container_image_tag = CfnParameter(
            self,
            "ContainerImageTag",
            type="String",
            default="bootstrap",
            description="Immutable ECR image tag produced by CodeBuild.",
        )
        self.cluster = ecs.Cluster(
            self,
            "IncidentIntelligenceCluster",
            vpc=network.vpc,
            container_insights_v2=ecs.ContainerInsights.ENABLED,
            execute_command_configuration=ecs.ExecuteCommandConfiguration(
                logging=ecs.ExecuteCommandLogging.OVERRIDE,
                log_configuration=ecs.ExecuteCommandLogConfiguration(
                    cloud_watch_log_group=logs.LogGroup(
                        self,
                        "EcsExecAuditLogs",
                        encryption_key=security.log_key,
                        retention=logs.RetentionDays.ONE_YEAR,
                    )
                ),
            ),
        )
        self.task_definitions: dict[str, ecs.FargateTaskDefinition] = {}
        self.containers: dict[str, ecs.ContainerDefinition] = {}
        self.modules: dict[str, str] = {}
        self.repositories = {
            service: ecr.Repository(
                self,
                f"{service.title().replace('-', '')}Repository",
                repository_name=f"{project_name}-{environment}-{service}",
                image_scan_on_push=True,
                image_tag_mutability=ecr.TagMutability.IMMUTABLE,
                encryption=ecr.RepositoryEncryption.KMS,
                removal_policy=RemovalPolicy.RETAIN,
            )
            for service in (
                "rag-retriever",
                "context-agent",
                "attachment-agent",
                "splunk-agent",
                "reasoning-agent",
                "servicenow-writer",
                "rag-indexer",
            )
        }
        for repository in self.repositories.values():
            repository.add_lifecycle_rule(max_image_count=20, description="Retain the latest immutable build images.")
        service_to_module = {
            "rag-retriever": "rag_retriever.main",
            "context-agent": "context_agent.main",
            "attachment-agent": "attachment_agent.main",
            "splunk-agent": "splunk_agent.main",
            "reasoning-agent": "reasoning_agent.main",
            "servicenow-writer": "servicenow_writer.main",
            "rag-indexer": "rag_indexer.main",
        }
        for service, module in service_to_module.items():
            self._create_task_definition(service, module)
        self._create_task_definition(
            "rag-quality-job", "rag_indexer.quality", image_service="rag-indexer"
        )
        self.state_machine = self._create_state_machine()
        self.ingest_function, self.dispatcher_function, self.api = self._create_ingress()
        self._create_quality_schedule()
        self._create_failure_event_rule()
        self.resources = ComputeResources(
            api=self.api,
            ingest_function=self.ingest_function,
            dispatcher_function=self.dispatcher_function,
            state_machine=self.state_machine,
            cluster=self.cluster,
            repositories=self.repositories,
        )
        CfnOutput(self, "WebhookEndpoint", value=f"{self.api.url}servicenow/incident")
        CfnOutput(self, "StateMachineArn", value=self.state_machine.state_machine_arn)

    def _create_task_definition(
        self, service: str, module: str, *, image_service: str | None = None
    ) -> None:
        image_service = image_service or service
        log_group = logs.LogGroup(
            self,
            f"{service.title().replace('-', '')}LogGroup",
            log_group_name=f"/ecs/{self.project_name}/{self.deployment_environment}/{service}",
            encryption_key=self.security.log_key,
            retention=logs.RetentionDays.ONE_YEAR,
        )
        task_role = self.task_roles[service]
        task_definition = ecs.FargateTaskDefinition(
            self,
            f"{service.title().replace('-', '')}TaskDefinition",
            cpu=1024,
            memory_limit_mib=2048,
            task_role=task_role,
            runtime_platform=ecs.RuntimePlatform(
                cpu_architecture=ecs.CpuArchitecture.X86_64,
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
            ),
        )
        container = task_definition.add_container(
            "app",
            image=ecs.ContainerImage.from_ecr_repository(
                self.repositories[image_service], tag=self.container_image_tag.value_as_string
            ),
            command=["python", "-m", module],
            environment={
                "ARTIFACT_BUCKET": self.data.artifact_bucket.bucket_name,
                "MOCK_MODE": str(self.mock_mode).lower(),
                "BEDROCK_MODEL_ID": self.bedrock_model_id.value_as_string,
                "BEDROCK_EMBEDDING_MODEL_ID": self.bedrock_embedding_model_id.value_as_string,
                "OPENSEARCH_COLLECTION_ENDPOINT": self.data.rag_collection.attr_collection_endpoint,
                "OPENSEARCH_INDEX_NAME": "incidents-v1",
            },
            logging=ecs.LogDrivers.aws_logs(stream_prefix=service, log_group=log_group),
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", f"python -c 'import {module.split('.')[0]}' || exit 1"],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                retries=3,
                start_period=Duration.seconds(10),
            ),
            stop_timeout=Duration.seconds(60),
        )
        if service in {"attachment-agent", "servicenow-writer", "splunk-agent"}:
            execution_role = task_definition.obtain_execution_role()
            self.security.secret_key.grant_decrypt(execution_role)
        self.data.artifact_bucket.grant_read_write(task_role)
        if service in {
            "context-agent",
            "attachment-agent",
            "reasoning-agent",
            "rag-retriever",
            "rag-indexer",
            "rag-quality-job",
        }:
            task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["bedrock:InvokeModel"],
                    resources=[
                        self.bedrock_model_arn.value_as_string,
                        f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/{self.bedrock_model_id.value_as_string}",
                    ],
                )
            )
        if service in {"rag-retriever", "rag-indexer", "rag-quality-job"}:
            task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["bedrock:InvokeModel"],
                    resources=[
                        self.bedrock_embedding_model_arn.value_as_string,
                        f"arn:aws:bedrock:{self.region}:{self.account}:inference-profile/{self.bedrock_embedding_model_id.value_as_string}",
                    ],
                )
            )
        if service == "attachment-agent":
            task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["textract:StartDocumentAnalysis", "textract:GetDocumentAnalysis"],
                    resources=["*"],
                )
            )
        if service in {"rag-retriever", "rag-indexer", "rag-quality-job"}:
            task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["aoss:APIAccessAll"], resources=[self.data.rag_collection.attr_arn]
                )
            )
        if service == "rag-retriever":
            task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["states:SendTaskSuccess", "states:SendTaskFailure"], resources=["*"]
                )
            )
        if service == "servicenow-writer":
            servicenow_secret = secretsmanager.Secret.from_secret_complete_arn(
                self,
                "ServiceNowRuntimeSecret",
                self.security.servicenow_secret.secret_arn,
            )
            container.add_secret(
                "SERVICENOW_USERNAME",
                ecs.Secret.from_secrets_manager(servicenow_secret, "username"),
            )
            container.add_secret("SERVICENOW_PASSWORD", ecs.Secret.from_secrets_manager(servicenow_secret, "password"))
            container.add_secret("SERVICENOW_INSTANCE_URL", ecs.Secret.from_secrets_manager(servicenow_secret, "instance_url"))
        if service == "attachment-agent":
            attachment_secret = secretsmanager.Secret.from_secret_complete_arn(self, "AttachmentServiceNowRuntimeSecret", self.security.servicenow_secret.secret_arn)
            container.add_secret("SERVICENOW_USERNAME", ecs.Secret.from_secrets_manager(attachment_secret, "username"))
            container.add_secret("SERVICENOW_PASSWORD", ecs.Secret.from_secrets_manager(attachment_secret, "password"))
        if service == "splunk-agent":
            splunk_secret = secretsmanager.Secret.from_secret_complete_arn(
                self,
                "SplunkRuntimeSecret",
                self.security.splunk_secret.secret_arn,
            )
            container.add_secret(
                "SPLUNK_USERNAME",
                ecs.Secret.from_secrets_manager(splunk_secret, "username"),
            )
            container.add_secret("SPLUNK_PASSWORD", ecs.Secret.from_secrets_manager(splunk_secret, "password"))
            container.add_secret("SPLUNK_BASE_URL", ecs.Secret.from_secrets_manager(splunk_secret, "base_url"))
        self.task_definitions[service] = task_definition
        self.containers[service] = container
        self.modules[service] = module

    def _workflow_task(
        self,
        state_id: str,
        service: str,
        stage: str,
        *,
        callback: bool = False,
    ) -> sfn_tasks.EcsRunTask:
        environment = [
            sfn_tasks.TaskEnvironmentVariable(
                name="INPUT_S3_URI", value=sfn.JsonPath.string_at("$.archive_s3_uri")
            ),
            sfn_tasks.TaskEnvironmentVariable(
                name="EXECUTION_ID", value=sfn.JsonPath.string_at("$.execution_id")
            ),
            sfn_tasks.TaskEnvironmentVariable(
                name="CORRELATION_ID", value=sfn.JsonPath.string_at("$.correlation_id")
            ),
            sfn_tasks.TaskEnvironmentVariable(name="WORKFLOW_STAGE", value=stage),
        ]
        integration_pattern = sfn.IntegrationPattern.RUN_JOB
        if callback:
            integration_pattern = sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN
            environment.append(
                sfn_tasks.TaskEnvironmentVariable(name="TASK_TOKEN", value=sfn.JsonPath.task_token)
            )
        task = sfn_tasks.EcsRunTask(
            self,
            state_id,
            integration_pattern=integration_pattern,
            cluster=self.cluster,
            task_definition=self.task_definitions[service],
            launch_target=sfn_tasks.EcsFargateLaunchTarget(
                platform_version=ecs.FargatePlatformVersion.LATEST
            ),
            assign_public_ip=self.network.assign_public_ip,
            security_groups=[self.network.task_security_group],
            subnets=ec2.SubnetSelection(subnet_type=self.network.fargate_subnet_type),
            container_overrides=[
                sfn_tasks.ContainerOverride(
                    container_definition=self.containers[service],
                    environment=environment,
                )
            ],
            result_path="$.routing" if callback else sfn.JsonPath.DISCARD,
            task_timeout=sfn.Timeout.duration(Duration.minutes(15)),
        )
        task.add_retry(
            errors=["States.Timeout", "States.TaskFailed", "AmazonECS.Unknown"],
            interval=Duration.seconds(2),
            max_attempts=3,
            backoff_rate=2.0,
        )
        return task

    def _create_state_machine(self) -> sfn.StateMachine:
        failure = sfn.Fail(
            self,
            "WorkflowFailed",
            error="IncidentIntelligenceFailed",
            cause="See execution_id-correlated logs and artifacts.",
        )
        fallback = sfn.Pass(
            self,
            "CompensateAndEscalate",
            result=sfn.Result.from_object(
                {"status": "needs_human_review", "action": "preserve artifacts and investigate"}
            ),
            result_path="$.fallback",
        ).next(failure)
        rag = self._workflow_task(
            "RetrieveSimilarCases", "rag-retriever", "rag-retrieval", callback=True
        )
        success = sfn.Succeed(self, "WorkflowSucceeded")

        # Step Functions states cannot have more than one `Next`. Build an independent
        # task chain per routing branch, even when stages run the same ECS task definition.
        fast_reasoning = self._workflow_task(
            "FastProduceRecommendation", "reasoning-agent", "reasoning"
        )
        fast_writer = self._workflow_task(
            "FastPostServiceNowWorkNote", "servicenow-writer", "servicenow-writeback"
        )
        fast_indexer = self._workflow_task("FastCaptureRagOutcome", "rag-indexer", "rag-index")
        refine_context = self._workflow_task("RefineUnderstandContext", "context-agent", "context")
        refine_splunk = self._workflow_task("RefineCollectSplunkEvidence", "splunk-agent", "splunk")
        refine_reasoning = self._workflow_task(
            "RefineProduceRecommendation", "reasoning-agent", "reasoning"
        )
        refine_writer = self._workflow_task(
            "RefinePostServiceNowWorkNote", "servicenow-writer", "servicenow-writeback"
        )
        refine_indexer = self._workflow_task("RefineCaptureRagOutcome", "rag-indexer", "rag-index")
        full_context = self._workflow_task("UnderstandContext", "context-agent", "context")
        full_attachments = self._workflow_task(
            "EnrichAttachments", "attachment-agent", "attachments"
        )
        full_splunk = self._workflow_task("CollectSplunkEvidence", "splunk-agent", "splunk")
        full_reasoning = self._workflow_task(
            "ProduceRecommendation", "reasoning-agent", "reasoning"
        )
        full_writer = self._workflow_task(
            "PostServiceNowWorkNote", "servicenow-writer", "servicenow-writeback"
        )
        full_indexer = self._workflow_task("CaptureRagOutcome", "rag-indexer", "rag-index")
        tasks = (
            rag,
            fast_reasoning,
            fast_writer,
            fast_indexer,
            refine_context,
            refine_splunk,
            refine_reasoning,
            refine_writer,
            refine_indexer,
            full_context,
            full_attachments,
            full_splunk,
            full_reasoning,
            full_writer,
            full_indexer,
        )
        for task in tasks:
            task.add_catch(fallback, result_path="$.error")

        fast_chain = fast_reasoning.next(fast_writer).next(fast_indexer).next(success)
        refine_chain = (
            refine_context.next(refine_splunk)
            .next(refine_reasoning)
            .next(refine_writer)
            .next(refine_indexer)
            .next(success)
        )
        full_chain = (
            full_context.next(full_attachments)
            .next(full_splunk)
            .next(full_reasoning)
            .next(full_writer)
            .next(full_indexer)
            .next(success)
        )
        choice = sfn.Choice(self, "RouteByRagConfidence")
        choice.when(sfn.Condition.string_equals("$.routing.decision.route", "fast"), fast_chain)
        choice.when(sfn.Condition.string_equals("$.routing.decision.route", "refine"), refine_chain)
        choice.otherwise(full_chain)
        definition = rag.next(choice)
        return sfn.StateMachine(
            self,
            "IncidentIntelligenceWorkflow",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            state_machine_type=sfn.StateMachineType.STANDARD,
            tracing_enabled=True,
            logs=sfn.LogOptions(
                destination=logs.LogGroup(
                    self,
                    "WorkflowLogGroup",
                    encryption_key=self.security.log_key,
                    retention=logs.RetentionDays.ONE_YEAR,
                ),
                level=sfn.LogLevel.ALL,
                include_execution_data=False,
            ),
            timeout=Duration.hours(2),
        )

    def _create_ingress(self) -> tuple[lambda_.Function, lambda_.Function, apigateway.RestApi]:
        source = str(self.project_root / "services" / "incident-ingest" / "src")
        common_environment = {
            "ARTIFACT_BUCKET": self.data.artifact_bucket.bucket_name,
            "EXECUTION_TABLE": self.data.execution_table.table_name,
            "INGEST_QUEUE_URL": self.data.ingest_queue.queue_url,
        }
        ingest = lambda_.Function(
            self,
            "WebhookIngestFunction",
            function_name=f"{self.project_name}-{self.deployment_environment}-ingest",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="lambda_handler.handler",
            code=lambda_.Code.from_asset(source),
            timeout=Duration.seconds(30),
            memory_size=512,
            tracing=lambda_.Tracing.ACTIVE,
            log_retention=logs.RetentionDays.ONE_YEAR,
            environment=common_environment,
        )
        self.data.artifact_bucket.grant_put(ingest)
        self.data.execution_table.grant_write_data(ingest)
        self.data.ingest_queue.grant_send_messages(ingest)
        dispatcher = lambda_.Function(
            self,
            "WorkflowDispatcherFunction",
            function_name=f"{self.project_name}-{self.deployment_environment}-dispatcher",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="dispatcher_handler.handler",
            code=lambda_.Code.from_asset(source),
            timeout=Duration.seconds(30),
            memory_size=256,
            tracing=lambda_.Tracing.ACTIVE,
            log_retention=logs.RetentionDays.ONE_YEAR,
            environment={"STATE_MACHINE_ARN": self.state_machine.state_machine_arn},
        )
        self.state_machine.grant_start_execution(dispatcher)
        dispatcher.add_event_source(
            lambda_event_sources.SqsEventSource(
                self.data.ingest_queue,
                batch_size=1,
                report_batch_item_failures=True,
                max_concurrency=10,
            )
        )
        authorizer = lambda_.Function(
            self,
            "ServiceNowWebhookAuthorizerFunction",
            function_name=f"{self.project_name}-{self.deployment_environment}-authorizer",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="authorizer_handler.handler",
            code=lambda_.Code.from_asset(source),
            timeout=Duration.seconds(10),
            memory_size=256,
            tracing=lambda_.Tracing.ACTIVE,
            log_retention=logs.RetentionDays.ONE_YEAR,
            environment={
                "MOCK_MODE": str(self.mock_mode).lower(),
                "SERVICENOW_SECRET_ARN": self.security.servicenow_secret.secret_arn,
            },
        )
        authorizer.add_to_role_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[self.security.servicenow_secret.secret_arn],
            )
        )
        authorizer.add_to_role_policy(
            iam.PolicyStatement(
                actions=["kms:Decrypt"],
                resources=[self.security.secret_key.key_arn],
                conditions={
                    "StringEquals": {
                        "kms:ViaService": f"secretsmanager.{self.region}.amazonaws.com"
                    }
                },
            )
        )
        api_access_logs = logs.LogGroup(
            self,
            "ApiAccessLogs",
            encryption_key=self.security.log_key,
            retention=logs.RetentionDays.ONE_YEAR,
        )
        api = apigateway.RestApi(
            self,
            "ServiceNowWebhookApi",
            rest_api_name=f"{self.project_name}-{self.deployment_environment}-webhook",
            endpoint_types=[apigateway.EndpointType.REGIONAL],
            disable_execute_api_endpoint=self.mtls_enabled,
            deploy_options=apigateway.StageOptions(
                stage_name=self.deployment_environment,
                tracing_enabled=True,
                metrics_enabled=True,
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=False,
                access_log_destination=apigateway.LogGroupLogDestination(api_access_logs),
                access_log_format=apigateway.AccessLogFormat.json_with_standard_fields(
                    caller=False,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=False,
                ),
            ),
        )
        token_authorizer = apigateway.TokenAuthorizer(
            self,
            "ServiceNowWebhookAuthorizer",
            handler=authorizer,
            identity_source="method.request.header.Authorization",
            results_cache_ttl=Duration.minutes(5),
        )
        incident_resource = api.root.add_resource("servicenow").add_resource("incident")
        webhook_validator = api.add_request_validator(
            "WebhookRequestValidator",
            validate_request_body=True,
            validate_request_parameters=True,
        )
        incident_resource.add_method(
            "POST",
            apigateway.LambdaIntegration(ingest, proxy=True),
            authorization_type=apigateway.AuthorizationType.CUSTOM,
            authorizer=token_authorizer,
            request_validator=webhook_validator,
        )
        wafv2.CfnWebACLAssociation(
            self,
            "WebhookWafAssociation",
            resource_arn=f"arn:{self.partition}:apigateway:{self.region}::/restapis/{api.rest_api_id}/stages/{api.deployment_stage.stage_name}",
            web_acl_arn=self.security.web_acl.attr_arn,
        )
        if self.mtls_enabled:
            self._configure_mtls_domain(api)
        return ingest, dispatcher, api

    def _configure_mtls_domain(self, api: apigateway.RestApi) -> None:
        domain_name = CfnParameter(
            self,
            "MtlsDomainName",
            type="String",
            description="Regional custom domain for ServiceNow mTLS.",
        )
        certificate_arn = CfnParameter(
            self,
            "MtlsCertificateArn",
            type="String",
            description="ACM server certificate ARN for the mTLS domain.",
        )
        truststore_uri = CfnParameter(
            self, "MtlsTruststoreUri", type="String", description="s3:// URI to the PEM truststore."
        )
        domain = apigateway.CfnDomainName(
            self,
            "ServiceNowMtlsDomain",
            domain_name=domain_name.value_as_string,
            endpoint_configuration=apigateway.CfnDomainName.EndpointConfigurationProperty(
                types=["REGIONAL"]
            ),
            regional_certificate_arn=certificate_arn.value_as_string,
            security_policy="TLS_1_2",
            mutual_tls_authentication=apigateway.CfnDomainName.MutualTlsAuthenticationProperty(
                truststore_uri=truststore_uri.value_as_string
            ),
        )
        apigateway.CfnBasePathMapping(
            self,
            "ServiceNowMtlsBasePathMapping",
            domain_name=domain.ref,
            rest_api_id=api.rest_api_id,
            stage=api.deployment_stage.stage_name,
        )

    def _create_quality_schedule(self) -> None:
        events.Rule(
            self,
            "RagQualitySchedule",
            schedule=events.Schedule.rate(Duration.days(7)),
            targets=[
                event_targets.EcsTask(
                    cluster=self.cluster,
                    task_definition=self.task_definitions["rag-quality-job"],
                    task_count=1,
                    subnet_selection=ec2.SubnetSelection(
                        subnet_type=self.network.fargate_subnet_type
                    ),
                    assign_public_ip=self.network.assign_public_ip,
                    security_groups=[self.network.task_security_group],
                    launch_type=ecs.LaunchType.FARGATE,
                )
            ],
        )

    def _create_failure_event_rule(self) -> None:
        events.Rule(
            self,
            "WorkflowFailureRule",
            event_pattern=events.EventPattern(
                source=["aws.states"],
                detail_type=["Step Functions Execution Status Change"],
                detail={"status": ["FAILED", "TIMED_OUT", "ABORTED"]},
            ),
            targets=[event_targets.SqsQueue(self.data.workflow_dlq)],
        )
