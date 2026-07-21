from __future__ import annotations

from aws_cdk import CfnParameter, RemovalPolicy, Stack
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from constructs import Construct

from stacks.compute_stack import ComputeResources


class DeliveryStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, *, compute: ComputeResources, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)
        build_key = kms.Key(self, "BuildArtifactKey", enable_key_rotation=True, removal_policy=RemovalPolicy.RETAIN)
        repository_owner = CfnParameter(self, "SourceRepositoryOwner", type="String", description="Source repository owner or organization.")
        repository_name = CfnParameter(self, "SourceRepositoryName", type="String", description="Source repository name.")
        branch_name = CfnParameter(self, "SourceBranchName", type="String", default="main")
        environment = {"ECR_REGISTRY": f"{self.account}.dkr.ecr.{self.region}.{self.url_suffix}"}
        for name, repository in compute.repositories.items():
            environment[f"ECR_{name.upper().replace('-', '_')}_URI"] = repository.repository_uri
        build = codebuild.Project(
            self,
            "ContainerBuildAndDeploy",
            source=codebuild.Source.git_hub(
                owner=repository_owner.value_as_string,
                repo=repository_name.value_as_string,
                branch_or_ref=branch_name.value_as_string,
                webhook=False,
            ),
            build_spec=codebuild.BuildSpec.from_source_filename("buildspec-containers.yml"),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=True,
                environment_variables={key: codebuild.BuildEnvironmentVariable(value=value) for key, value in environment.items()},
            ),
            timeout=__import__("aws_cdk").Duration.minutes(60),
            encryption_key=build_key,
        )
        for repository in compute.repositories.values():
            repository.grant_pull_push(build)
        build.add_to_role_policy(iam.PolicyStatement(actions=["sts:AssumeRole"], resources=[f"arn:{self.partition}:iam::{self.account}:role/cdk-hnb659fds-*-role-{self.account}-{self.region}"]))
