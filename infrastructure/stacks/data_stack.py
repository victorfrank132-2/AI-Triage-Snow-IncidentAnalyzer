from __future__ import annotations

import json
from dataclasses import dataclass

from aws_cdk import CfnResource, Duration, RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_kms as kms
from aws_cdk import aws_opensearchserverless as aoss
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sqs as sqs
from constructs import Construct

from stacks.network_stack import NetworkResources


@dataclass(frozen=True)
class DataResources:
    data_key: kms.Key
    artifact_bucket: s3.Bucket
    execution_table: dynamodb.Table
    ingest_queue: sqs.Queue
    ingest_dlq: sqs.Queue
    workflow_dlq: sqs.Queue
    rag_collection: aoss.CfnCollection
    rag_index: CfnResource


class DataStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        project_name: str,
        environment: str,
        network: NetworkResources,
        cost_optimized_dev: bool,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.data_key = kms.Key(
            self,
            "DataKey",
            alias=f"alias/{project_name}-{environment}-data",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.artifact_bucket = s3.Bucket(
            self,
            "IncidentArtifactBucket",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.data_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            lifecycle_rules=[
                s3.LifecycleRule(
                    noncurrent_version_expiration=Duration.days(30), expiration=Duration.days(365)
                )
            ],
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.execution_table = dynamodb.Table(
            self,
            "ExecutionStateTable",
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.data_key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.ingest_dlq = sqs.Queue(
            self,
            "IngestDlq",
            queue_name="snow-incident-ingest-dlq.fifo",
            fifo=True,
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=self.data_key,
            enforce_ssl=True,
            retention_period=Duration.days(14),
        )
        self.ingest_queue = sqs.Queue(
            self,
            "IngestQueue",
            queue_name="snow-incident-ingest.fifo",
            fifo=True,
            content_based_deduplication=False,
            deduplication_scope=sqs.DeduplicationScope.MESSAGE_GROUP,
            fifo_throughput_limit=sqs.FifoThroughputLimit.PER_MESSAGE_GROUP_ID,
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=self.data_key,
            enforce_ssl=True,
            visibility_timeout=Duration.minutes(6),
            dead_letter_queue=sqs.DeadLetterQueue(max_receive_count=5, queue=self.ingest_dlq),
        )
        self.workflow_dlq = sqs.Queue(
            self,
            "WorkflowFailureDlq",
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=self.data_key,
            enforce_ssl=True,
            retention_period=Duration.days(14),
        )
        encryption_policy = aoss.CfnSecurityPolicy(
            self,
            "RagEncryptionPolicy",
            name="snow-rag-encryption",
            type="encryption",
            policy=json.dumps(
                {
                    "Rules": [{"ResourceType": "collection", "Resource": ["collection/snow-rag"]}],
                    "AWSOwnedKey": False,
                    "KmsARN": self.data_key.key_arn,
                }
            ),
        )
        network_policy_rules: list[dict[str, object]] = [
            {"ResourceType": "collection", "Resource": ["collection/snow-rag"]},
            {"ResourceType": "dashboard", "Resource": ["collection/snow-rag"]},
        ]
        network_policy_entry: dict[str, object] = {"Rules": network_policy_rules}
        if cost_optimized_dev:
            network_policy_entry["AllowFromPublic"] = True
        else:
            network_policy_entry["AllowFromPublic"] = False
            network_policy_entry["SourceVPCEs"] = [network.aoss_vpc_endpoint_id]
        network_policy = aoss.CfnSecurityPolicy(
            self,
            "RagNetworkPolicy",
            name="snow-rag-network",
            type="network",
            policy=json.dumps([network_policy_entry]),
        )
        self.rag_collection = aoss.CfnCollection(
            self, "RagVectorCollection", name="snow-rag", type="VECTORSEARCH"
        )
        self.rag_collection.add_dependency(encryption_policy)
        self.rag_collection.add_dependency(network_policy)
        principals = [
            f"arn:{self.partition}:iam::{self.account}:root",
            (
                f"arn:{self.partition}:iam::{self.account}:role/"
                f"cdk-hnb659fds-cfn-exec-role-{self.account}-{self.region}"
            ),
        ]
        principals.extend(
            f"arn:{self.partition}:iam::{self.account}:role/{project_name}-{environment}-{stage}"
            for stage in ("rag-retriever", "rag-indexer", "rag-quality-job")
        )
        access_policy = aoss.CfnAccessPolicy(
            self,
            "RagDataAccessPolicy",
            name="snow-rag-data-access",
            type="data",
            policy=json.dumps(
                [
                    {
                        "Description": "RAG Fargate task access",
                        "Principal": principals,
                        "Rules": [
                            {
                                "ResourceType": "collection",
                                "Resource": ["collection/snow-rag"],
                                "Permission": ["aoss:DescribeCollectionItems"],
                            },
                            {
                                "ResourceType": "index",
                                "Resource": ["index/snow-rag/incidents-v1"],
                                "Permission": [
                                    "aoss:CreateIndex",
                                    "aoss:DescribeIndex",
                                    "aoss:ReadDocument",
                                    "aoss:WriteDocument",
                                ],
                            },
                        ],
                    }
                ]
            ),
        )
        self.rag_index = CfnResource(
            self,
            "RagVectorIndex",
            type="AWS::OpenSearchServerless::Index",
            properties={
                "CollectionEndpoint": self.rag_collection.attr_collection_endpoint,
                "IndexName": "incidents-v1",
                "Settings": {
                    "Index": {"Knn": True, "KnnAlgoParamEfSearch": 100, "RefreshInterval": "10s"}
                },
                "Mappings": {
                    "Properties": {
                        "embedding": {
                            "Type": "knn_vector",
                            "Dimension": 1024,
                            "SpaceType": "cosinesimil",
                        },
                        "incident_summary": {"Type": "text"},
                        "recommendation": {"Type": "text"},
                        "outcome_label": {"Type": "keyword"},
                        "created_at": {"Type": "keyword"},
                        "document_id": {"Type": "keyword"},
                    }
                },
            },
        )
        self.rag_index.add_dependency(access_policy)
        self.resources = DataResources(
            data_key=self.data_key,
            artifact_bucket=self.artifact_bucket,
            execution_table=self.execution_table,
            ingest_queue=self.ingest_queue,
            ingest_dlq=self.ingest_dlq,
            workflow_dlq=self.workflow_dlq,
            rag_collection=self.rag_collection,
            rag_index=self.rag_index,
        )
