from __future__ import annotations

import datetime
import json
import os
import pathlib
import tempfile
import subprocess
import zipfile


CODEBUILD_PROJECT_NAME = "ContainerBuildAndDeploy4262-AopAOBDGavEO"
SOURCE_BUCKET = "snowdata-incidentartifactbucket4b5e6e39-t23eru91y2fm"
SOURCE_PREFIX = "codebuild-sources"
EXCLUDE_DIRS = {".git", ".venv", "node_modules", "cdk.out", "__pycache__"}
EXCLUDE_FILES = {"debug.log"}


def _should_include(path: pathlib.Path) -> bool:
    if path.name in EXCLUDE_FILES:
        return False
    if path.suffix in {".pyc", ".pyo"}:
        return False
    return not any(part in EXCLUDE_DIRS for part in path.parts)


def _create_source_zip(root: pathlib.Path, image_tag: str) -> pathlib.Path:
    temp_dir = pathlib.Path(tempfile.gettempdir())
    zip_path = temp_dir / f"snow-incident-intelligence-{image_tag}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in root.rglob("*"):
            if path.is_dir() or not _should_include(path.relative_to(root)):
                continue
            archive.write(path, path.relative_to(root).as_posix())
    return zip_path


def main() -> None:
    root = pathlib.Path(__file__).resolve().parents[1]
    os.chdir(root)
    os.environ["CDK_DEFAULT_ACCOUNT"] = "928743223785"
    os.environ["CDK_DEFAULT_REGION"] = "us-east-1"
    image_tag = "s3" + datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    print(f"Using image tag {image_tag}")
    source_zip = _create_source_zip(root, image_tag)
    source_key = f"{SOURCE_PREFIX}/{source_zip.name}"
    source_location = f"{SOURCE_BUCKET}/{source_key}"
    print(f"Uploading source archive -> s3://{SOURCE_BUCKET}/{source_key}")
    upload = subprocess.run(
        [
            "aws",
            "s3api",
            "put-object",
            "--bucket",
            SOURCE_BUCKET,
            "--key",
            source_key,
            "--body",
            str(source_zip),
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    upload_result = json.loads(upload.stdout)
    source_version = upload_result.get("VersionId")
    if not source_version:
        raise RuntimeError("S3 bucket did not return a VersionId for the source zip")
    print(f"Starting CodeBuild project {CODEBUILD_PROJECT_NAME}")
    start = subprocess.run(
        [
            "aws",
            "codebuild",
            "start-build",
            "--project-name",
            CODEBUILD_PROJECT_NAME,
            "--source-type-override",
            "S3",
            "--source-location-override",
            source_location,
            "--source-version",
            source_version,
            "--buildspec-override",
            "buildspec-full-deploy-only.yml",
            "--environment-variables-override",
            f"name=IMAGE_TAG,value={image_tag},type=PLAINTEXT",
            "--output",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if start.returncode != 0:
        print(start.stdout)
        print(start.stderr)
        raise RuntimeError(f"CodeBuild start-build failed with exit code {start.returncode}")
    build = json.loads(start.stdout)["build"]
    build_id = build["id"]
    build_arn = build["arn"]
    print(f"Started build {build_id}")
    while True:
        poll = subprocess.run(
            ["aws", "codebuild", "batch-get-builds", "--ids", build_id, "--output", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        build_info = json.loads(poll.stdout)["builds"][0]
        status = build_info["buildStatus"]
        print(f"Build status: {status}")
        if status not in {"IN_PROGRESS", "QUEUED", "SUBMITTED"}:
            if status != "SUCCEEDED":
                raise RuntimeError(f"CodeBuild failed with status {status}: {build_info.get('phases', [])}")
            break
    print(f"CodeBuild completed successfully: {build_arn}")


if __name__ == "__main__":
    main()
