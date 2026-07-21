from __future__ import annotations

from aws_cdk import CfnOutput, Duration, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from constructs import Construct

from stacks.compute_stack import ComputeResources
from stacks.data_stack import DataResources
from stacks.security_stack import SecurityResources


class ObservabilityStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        project_name: str,
        environment: str,
        security: SecurityResources,
        data: DataResources,
        compute: ComputeResources,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        error_rate_alarm = cloudwatch.Alarm(
            self,
            "WebhookErrorRateAlarm",
            metric=cloudwatch.MathExpression(
                expression="IF(requests > 0, errors * 100 / requests, 0)",
                using_metrics={
                    "errors": compute.ingest_function.metric_errors(period=Duration.minutes(1)),
                    "requests": compute.ingest_function.metric_invocations(
                        period=Duration.minutes(1)
                    ),
                },
                period=Duration.minutes(1),
            ),
            threshold=5,
            evaluation_periods=3,
            datapoints_to_alarm=2,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        dlq_alarm = cloudwatch.Alarm(
            self,
            "IngestDlqDepthAlarm",
            metric=data.ingest_dlq.metric_approximate_number_of_messages_visible(
                period=Duration.minutes(1)
            ),
            threshold=0,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        workflow_failure_alarm = cloudwatch.Alarm(
            self,
            "WorkflowFailureAlarm",
            metric=cloudwatch.Metric(
                namespace="AWS/States",
                metric_name="ExecutionsFailed",
                dimensions_map={"StateMachineArn": compute.state_machine.state_machine_arn},
                statistic="sum",
                period=Duration.minutes(5),
            ),
            threshold=0,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        bedrock_throttle_alarm = cloudwatch.Alarm(
            self,
            "BedrockThrottleAlarm",
            metric=cloudwatch.Metric(
                namespace="ServiceNowIncidentIntelligence",
                metric_name="BedrockThrottled",
                dimensions_map={"Service": "reasoning-agent", "Stage": "reasoning"},
                statistic="sum",
                period=Duration.minutes(5),
            ),
            threshold=0,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        splunk_timeout_alarm = cloudwatch.Alarm(
            self,
            "SplunkTimeoutAlarm",
            metric=cloudwatch.Metric(
                namespace="ServiceNowIncidentIntelligence",
                metric_name="SplunkTimeout",
                dimensions_map={"Service": "splunk-agent", "Stage": "splunk"},
                statistic="sum",
                period=Duration.minutes(5),
            ),
            threshold=0,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        dashboard = cloudwatch.Dashboard(
            self,
            "OperationsDashboard",
            dashboard_name=f"{project_name}-{environment}-operations",
            start="-PT8H",
            period_override=cloudwatch.PeriodOverride.INHERIT,
        )
        dashboard.add_widgets(
            cloudwatch.TextWidget(
                width=24,
                height=1,
                markdown="# ServiceNow Incident Intelligence - Operations",
            ),
            cloudwatch.AlarmWidget(
                width=6, height=6, alarm=error_rate_alarm, title="Webhook error rate"
            ),
            cloudwatch.AlarmWidget(width=6, height=6, alarm=dlq_alarm, title="Ingest DLQ"),
            cloudwatch.AlarmWidget(
                width=6, height=6, alarm=workflow_failure_alarm, title="Workflow failures"
            ),
            cloudwatch.AlarmWidget(
                width=6, height=6, alarm=bedrock_throttle_alarm, title="Bedrock throttles"
            ),
            cloudwatch.GraphWidget(
                width=12,
                height=6,
                title="Webhook invocations and errors",
                left=[compute.ingest_function.metric_invocations(period=Duration.minutes(1))],
                right=[compute.ingest_function.metric_errors(period=Duration.minutes(1))],
            ),
            cloudwatch.GraphWidget(
                width=12,
                height=6,
                title="Workflow success and failures",
                left=[
                    cloudwatch.Metric(
                        namespace="AWS/States",
                        metric_name="ExecutionsSucceeded",
                        dimensions_map={"StateMachineArn": compute.state_machine.state_machine_arn},
                        statistic="sum",
                        period=Duration.minutes(5),
                    ),
                    cloudwatch.Metric(
                        namespace="AWS/States",
                        metric_name="ExecutionsFailed",
                        dimensions_map={"StateMachineArn": compute.state_machine.state_machine_arn},
                        statistic="sum",
                        period=Duration.minutes(5),
                    ),
                ],
            ),
            cloudwatch.AlarmWidget(
                width=12, height=6, alarm=splunk_timeout_alarm, title="Splunk timeouts"
            ),
        )
        CfnOutput(self, "OperationsDashboardName", value=dashboard.dashboard_name)
