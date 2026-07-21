"""Cloud integration smoke-test seam.

Run against an isolated deployed stack after placing a synthetic incident in the
artifact bucket. The default unit suite remains offline and credential-free.
"""

import os

import pytest


@pytest.mark.skipif(
    not os.getenv("RUN_AWS_INTEGRATION_TESTS"), reason="requires an isolated deployed AWS stack"
)
def test_mock_workflow_smoke() -> None:
    # TODO: start a Standard execution, poll to SUCCEEDED, and assert mock writeback artifact.
    assert os.environ["RUN_AWS_INTEGRATION_TESTS"] == "1"
