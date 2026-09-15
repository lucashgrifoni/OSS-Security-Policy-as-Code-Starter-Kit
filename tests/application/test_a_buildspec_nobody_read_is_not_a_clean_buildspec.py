"""AWS was the only CI family here whose controls could not degrade, even in principle.

``AwsCiAnalysis`` has carried ``parse_errors`` since it was written, and no evaluator read it:
``azure.py``, ``cicd.py``, ``github.py`` and ``gitlab.py`` all consult theirs, ``aws.py``
contained zero references to the field.

The consequence is a lost failure rather than a false clean, which is why it survived a sweep
looking only for PASS. Measured on the tree at v10.0.22, one buildspec over the input size cap
holding a hardcoded AWS key:

    AWS-SECRET-038   FAIL -> "No Parameter Store or Secrets Manager env references detected"
    AWS-SEC-039      FAIL -> (same shape)
    AWS-SCA-040      FAIL -> (same shape)
    AWS-SBOM-041     FAIL -> (same shape)
    AWS-PROV-043     FAIL -> (same shape)

Each of those replacement messages is a statement about the contents of a file nobody read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators import _shared as sh
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

#: A buildspec that exports a hardcoded AWS key. The example key from the AWS documentation, so
#: no real credential lives in this repository's fixtures.
LEAKY = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
)

#: Padding past MAX_CI_CONFIG_BYTES. The audited repository chooses this file's size, which is
#: exactly why there is a cap and exactly why refusing a file cannot mean "nothing is wrong".
OVERSIZE = LEAKY + "# pad\n" * 200_000

CONTENT_SCANNING = ["AWS-SECRET-038", "AWS-SEC-039", "AWS-SCA-040", "AWS-SBOM-041", "AWS-PROV-043"]


def _ctx(root: Path) -> sh.EvalContext:
    return sh.EvalContext(
        repo_root=root,
        profile_id="github-level-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=analyze_aws_ci(root),
        scorecard=None,
    )


def _repo(tmp_path: Path, body: str) -> Path:
    (tmp_path / "buildspec.yml").write_text(body, encoding="utf-8")
    return tmp_path


def test_the_parser_records_what_it_refused() -> None:
    """The channel exists; this asserts it is populated, so the tests below are not vacuous."""

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "buildspec.yml").write_text(OVERSIZE, encoding="utf-8")
        assert analyze_aws_ci(root).parse_errors


@pytest.mark.parametrize("control_id", CONTENT_SCANNING)
def test_a_refused_buildspec_never_produces_a_claim_about_its_contents(control_id: str, tmp_path: Path) -> None:
    outcome = EVALUATOR_REGISTRY[control_id](_ctx(_repo(tmp_path, OVERSIZE)))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "could not be read" in outcome.reason
    assert "buildspec.yml" in outcome.reason


@pytest.mark.parametrize("control_id", CONTENT_SCANNING)
def test_a_buildspec_it_could_read_is_still_judged(control_id: str, tmp_path: Path) -> None:
    """The over-withdrawal guard. AWS-SECRET-038 must still find the key it always found."""

    outcome = EVALUATOR_REGISTRY[control_id](_ctx(_repo(tmp_path, LEAKY)))

    assert outcome.status is ControlStatus.FAIL
    assert "could not be read" not in outcome.reason


def test_a_repository_with_no_buildspec_is_still_not_applicable(tmp_path: Path) -> None:
    """A real absence keeps answering not-applicable: the withdrawal needs an unread file."""

    outcome = EVALUATOR_REGISTRY["AWS-SECRET-038"](_ctx(tmp_path))

    assert outcome.status is ControlStatus.NOT_APPLICABLE


def test_aws_now_has_the_channel_every_other_ci_family_had() -> None:
    """A source-derived assertion: the field is consumed, not merely declared.

    Written this way because the defect was precisely that the field existed and nothing read
    it, which no behavioural test of the old code would have noticed.
    """

    import inspect

    from oss_policy_kit.application.evaluators import aws

    assert "parse_errors" in inspect.getsource(aws)
