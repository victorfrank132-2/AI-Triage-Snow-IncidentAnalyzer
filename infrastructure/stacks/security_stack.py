from __future__ import annotations

from dataclasses import dataclass

from aws_cdk import (
    CfnOutput,
    RemovalPolicy,
    Stack,
)
from aws_cdk import (
    aws_cloudtrail as cloudtrail,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_kms as kms,
)
from aws_cdk import (
    aws_s3 as s3,
)
from aws_cdk import (
    aws_secretsmanager as secretsmanager,
)
from aws_cdk import (
    aws_wafv2 as wafv2,
)
from constructs import Construct


@dataclass(frozen=True)
class SecurityResources:
    log_key: kms.Key
    secret_key: kms.Key
    web_acl: wafv2.CfnWebACL
    servicenow_secret: secretsmanager.Secret
    splunk_secret: secretsmanager.Secret


class SecurityStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        project_name: str,
        environment: str,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.log_key = kms.Key(
            self,
            "LogKey",
            alias=f"alias/{project_name}-{environment}-logs",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        self._allow_cloudwatch_logs_key_usage(self.log_key)
        self.secret_key = kms.Key(
            self,
            "SecretKey",
            alias=f"alias/{project_name}-{environment}-secrets",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.audit_bucket = s3.Bucket(
            self,
            "AuditBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.log_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.trail = cloudtrail.Trail(
            self,
            "PlatformAuditTrail",
            bucket=self.audit_bucket,
            enable_file_validation=True,
            include_global_service_events=True,
            is_multi_region_trail=True,
        )
        self.servicenow_secret = self._placeholder_secret(
            "ServiceNowCredentials",
            f"{project_name}/{environment}/servicenow",
            "Tenant ServiceNow Basic auth credentials. Replace placeholders before production use.",
            '{"instance_url":"https://your-instance.service-now.com","username":"REPLACE_WITH_SERVICENOW_USER","password":"REPLACE_WITH_SERVICENOW_PASSWORD","webhook_username":"REPLACE_WITH_WEBHOOK_USER","webhook_password":"REPLACE_WITH_WEBHOOK_PASSWORD"}',
        )
        self.splunk_secret = self._placeholder_secret(
            "SplunkCredentials",
            f"{project_name}/{environment}/splunk",
            "Tenant Splunk Basic auth credentials. Replace placeholders before production use.",
            '{"base_url":"https://splunk.example.com:8089","username":"REPLACE_WITH_SPLUNK_USER","password":"REPLACE_WITH_SPLUNK_PASSWORD"}',
        )
        self.web_acl = wafv2.CfnWebACL(
            self,
            "WebhookWebAcl",
            scope="REGIONAL",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name=f"{project_name}-{environment}-webhook-waf",
                sampled_requests_enabled=True,
            ),
            rules=[
                wafv2.CfnWebACL.RuleProperty(
                    name="AWSManagedCommonRules",
                    priority=0,
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="AWSManagedRulesCommonRuleSet", vendor_name="AWS"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="common-rules",
                        sampled_requests_enabled=True,
                    ),
                ),
                wafv2.CfnWebACL.RuleProperty(
                    name="WebhookRateLimit",
                    priority=1,
                    action=wafv2.CfnWebACL.RuleActionProperty(block={}),
                    statement=wafv2.CfnWebACL.StatementProperty(
                        rate_based_statement=wafv2.CfnWebACL.RateBasedStatementProperty(
                            aggregate_key_type="IP", limit=2_000
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="rate-limit",
                        sampled_requests_enabled=True,
                    ),
                ),
            ],
        )
        self.resources = SecurityResources(
            log_key=self.log_key,
            secret_key=self.secret_key,
            web_acl=self.web_acl,
            servicenow_secret=self.servicenow_secret,
            splunk_secret=self.splunk_secret,
        )
        CfnOutput(self, "WebhookWebAclArn", value=self.web_acl.attr_arn)

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

    def _placeholder_secret(
        self, construct_id: str, name: str, description: str, secret_json: str
    ) -> secretsmanager.Secret:
        return secretsmanager.Secret(
            self,
            construct_id,
            secret_name=name,
            description=description,
            encryption_key=self.secret_key,
            removal_policy=RemovalPolicy.RETAIN,
            # A non-credential placeholder makes first deployment repeatable. The deployment
            # runbook requires replacing it through the approved secret-management workflow.
            secret_string_value=__import__("aws_cdk").SecretValue.unsafe_plain_text(
                secret_json
            ),
        )
