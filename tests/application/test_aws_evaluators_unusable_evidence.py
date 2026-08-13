"""AWS evaluators handed evidence that exists but cannot be trusted.

Three states are easy to confuse and must stay distinct: no evidence file, an evidence file
that fails its schema, and an evidence file still carrying scaffold placeholders. All three
have to keep the control off PASS, and none may raise.

The middle two had never been exercised on these evaluators. They are the states an adopter
actually reaches -- someone ran `scaffold-evidence`, never filled it in, and expects
`evaluate` to notice. A control that passed on a template would certify a posture nobody
attested to.

Every test asserts the status is not PASS in addition to naming the expected one, so a
wrong-but-still-blocking status is distinguished from a false pass.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import aws as awsev
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> awsev.EvalContext:
    return awsev.EvalContext(
        repo_root=tmp_path,
        profile_id="aws-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _evidence(tmp_path: Path, name: str, payload: Any) -> Path:
    path = tmp_path / ".oss-policy-kit" / "evidence" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


_PIPELINE = "aws-codepipeline.json"
_CODEBUILD = "aws-codebuild-project.json"

_EVALUATORS = [
    ("eval_aws_cp_044", _PIPELINE),
    ("eval_aws_cb_045", _CODEBUILD),
    ("eval_aws_pipeiam_056", _PIPELINE),
    ("eval_aws_cbident_057", _CODEBUILD),
]


# --------------------------------------------------------------------------- #
# no evidence at all
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("evaluator", "_filename"), _EVALUATORS)
def test_a_missing_evidence_file_never_passes(tmp_path: Path, evaluator: str, _filename: str) -> None:
    """Nothing to read is not a clean bill of health."""

    outcome = getattr(awsev, evaluator)(_ctx(tmp_path))

    assert outcome.status is not ControlStatus.PASS
    assert outcome.remediation.strip()


# --------------------------------------------------------------------------- #
# evidence that does not match its schema
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("evaluator", "filename"), _EVALUATORS)
def test_evidence_that_fails_its_schema_is_reviewed_not_passed(tmp_path: Path, evaluator: str, filename: str) -> None:
    """A file that is JSON but not this document must not be read as posture."""

    _evidence(tmp_path, filename, {"unexpected": "shape"})

    outcome = getattr(awsev, evaluator)(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert outcome.status is not ControlStatus.PASS
    assert outcome.reason.strip()


@pytest.mark.parametrize(("evaluator", "filename"), _EVALUATORS)
def test_evidence_that_is_not_json_at_all_is_reviewed_not_passed(tmp_path: Path, evaluator: str, filename: str) -> None:
    """Truncated or hand-edited files reach evaluators as unparseable text."""

    _evidence(tmp_path, filename, "{not json")

    outcome = getattr(awsev, evaluator)(_ctx(tmp_path))

    assert outcome.status is not ControlStatus.PASS


@pytest.mark.parametrize(("evaluator", "filename"), _EVALUATORS)
def test_the_remediation_points_at_the_schema_to_regenerate_from(tmp_path: Path, evaluator: str, filename: str) -> None:
    """ "Invalid evidence" with no instruction leaves the adopter stuck."""

    _evidence(tmp_path, filename, {"unexpected": "shape"})

    outcome = getattr(awsev, evaluator)(_ctx(tmp_path))

    assert "schema" in outcome.remediation.lower()


# --------------------------------------------------------------------------- #
# the scaffold nobody filled in
# --------------------------------------------------------------------------- #


def _pipeline_evidence(**over: Any) -> dict[str, Any]:
    """Schema-valid CodePipeline evidence whose posture is entirely affirmative.

    Every boolean is a real boolean so the document passes validation. That is what makes
    the placeholder test below meaningful: the *only* thing standing between this document
    and a PASS is the placeholder token, so a test built on a schema-invalid file would
    prove nothing about the placeholder check.
    """

    payload: dict[str, Any] = {
        "schema_version": "aws-codepipeline/v1",
        "attested_at": "2026-06-15",
        "attested_by": "platform-team",
        "pipeline": "release-pipeline",
        "posture": {
            "manual_approval_before_production": True,
            "artifact_store_encryption_enabled": True,
            "production_execution_mode_not_parallel": True,
        },
        "iam": {"pipeline_service_role_arn_configured": True},
    }
    payload.update(over)
    return payload


def test_the_affirmative_baseline_earns_self_attested_credit(tmp_path: Path) -> None:
    """Hand-attested evidence earns SELF_ATTESTED, not PASS -- the distinction ADR-030 draws.

    Establishes that the fixture is one token away from the best outcome it can reach, so
    the placeholder test below is measuring the placeholder and nothing else.
    """

    _evidence(tmp_path, _PIPELINE, _pipeline_evidence())

    assert awsev.eval_aws_cp_044(_ctx(tmp_path)).status is ControlStatus.SELF_ATTESTED


@pytest.mark.parametrize("token", ["REPLACE_ME", "TODO", "<your-org>"])
def test_a_scaffold_still_holding_a_placeholder_earns_no_credit(tmp_path: Path, token: str) -> None:
    """The state an adopter actually reaches: scaffolded, attested by nobody.

    The document is otherwise schema-valid and entirely affirmative, so the placeholder is
    the only thing between it and credit. It must earn none -- not PASS, and not even the
    self-attested credit the same document earns once a real name replaces the token.

    Written this way after a first version put the placeholder in a boolean field, which
    failed schema validation and never reached this branch at all.
    """

    _evidence(tmp_path, _PIPELINE, _pipeline_evidence(attested_by=token))

    outcome = awsev.eval_aws_cp_044(_ctx(tmp_path))

    assert outcome.status is not ControlStatus.PASS
    assert outcome.status is not ControlStatus.SELF_ATTESTED
    assert outcome.remediation.strip()


# --------------------------------------------------------------------------- #
# the IAM helper, and which states it hands back to its caller
# --------------------------------------------------------------------------- #


def test_the_pipeline_iam_helper_answers_none_when_there_is_no_evidence(tmp_path: Path) -> None:
    """None means "this helper cannot contribute", leaving the caller's own logic to run."""

    assert awsev._aws_pipeiam_evidence_outcome(tmp_path / "missing.json") is None


def test_the_pipeline_iam_helper_reports_unusable_evidence_instead_of_deferring(tmp_path: Path) -> None:
    """A file it cannot read is the helper's to report -- the caller would call it missing.

    Deferring here is what produced "No evidence file found at the expected path" for a file
    that was present all along, so the state stops at the reader that discovered it.
    """

    path = _evidence(tmp_path, _PIPELINE, {"unexpected": "shape"})

    outcome = awsev._aws_pipeiam_evidence_outcome(path)

    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "schema" in outcome.remediation.lower()


def test_the_pipeline_iam_helper_answers_none_when_the_role_is_not_configured(tmp_path: Path) -> None:
    """Readable evidence that simply does not claim the role is not a finding here.

    The document is schema-valid so the branch under test is reached at all; an earlier
    version of this fixture omitted `attested_at` and never got past validation.
    """

    path = _evidence(
        tmp_path,
        _PIPELINE,
        {
            "schema_version": "aws-codepipeline/v1",
            "attested_at": "2026-06-15",
            "attested_by": "platform-team",
            "pipeline": "release-pipeline",
            "posture": {
                "manual_approval_before_production": True,
                "artifact_store_encryption_enabled": True,
                "production_execution_mode_not_parallel": True,
            },
            "iam": {"pipeline_service_role_arn_configured": False},
        },
    )

    assert awsev._aws_pipeiam_evidence_outcome(path) is None
