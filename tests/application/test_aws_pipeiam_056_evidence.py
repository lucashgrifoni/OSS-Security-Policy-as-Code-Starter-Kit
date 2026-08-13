"""The two AWS identity controls must describe the situation they actually checked.

AWS-PIPEIAM-056 reads `.oss-policy-kit/evidence/aws-codepipeline.json`, the same file its sibling
AWS-CP-044 reads. It used to answer one fixed sentence for every state it could not turn into a
verdict, and that sentence made two claims the code had never established: that no evidence file
was found (said while the file sat unreadable on disk) and that a signal had been detected in a
pipeline export (said whether or not one existed).

Both are the same fault, so both are pinned here: the unreadable-file half against the sibling
that already got it right, and the signal half against the two repositories that differ only in
whether the signal is there.

AWS-CBIDENT-057, one function below it, made the same unconditional signal claim over its own
evidence file, and kept making it after AWS-PIPEIAM-056 stopped. It is pinned at the bottom of
this module by the same shape of test, because the claim the pair shared is why either is here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oss_policy_kit.application.evaluators import aws as awsev
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_EVIDENCE = "aws-codepipeline.json"


def _ctx(tmp_path: Path, aws: AwsCiAnalysis | None = None) -> awsev.EvalContext:
    return awsev.EvalContext(
        repo_root=tmp_path,
        profile_id="aws-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=aws or AwsCiAnalysis(),
        scorecard=None,
    )


def _write_unreadable_evidence(tmp_path: Path) -> Path:
    """Write CodePipeline evidence that is valid JSON but missing a required field.

    Everything the control looks at is present and affirmative -- including the `iam` block it
    needs for a PASS -- so the only thing standing between this document and credit is the
    schema violation. That is what makes the file "present but unreadable" rather than absent.
    """

    payload: dict[str, Any] = {
        "schema_version": "aws-codepipeline/v1",
        # `attested_at` is required by evidence-aws-codepipeline.schema.json and left out here.
        "attested_by": "aws-api-collection",
        "pipeline": "release-pipeline",
        "posture": {
            "manual_approval_before_production": True,
            "artifact_store_encryption_enabled": True,
            "production_execution_mode_not_parallel": True,
        },
        "iam": {"pipeline_service_role_arn_configured": True},
    }
    path = tmp_path / ".oss-policy-kit" / "evidence" / _EVIDENCE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# a file that is present and unreadable is never reported as absent
# --------------------------------------------------------------------------- #


def test_a_schema_invalid_file_is_reported_as_unreadable_not_as_missing(tmp_path: Path) -> None:
    """The operator has to learn that the file on disk is the thing to fix."""

    path = _write_unreadable_evidence(tmp_path)

    outcome = awsev.eval_aws_pipeiam_056(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED  # ADR-045
    assert "does not match schema" in outcome.reason
    assert "'attested_at' is a required property" in outcome.reason
    assert "evidence-aws-codepipeline.schema.json" in outcome.remediation
    assert outcome.evidence_sources == [str(path.resolve())]


def test_the_siblings_reading_that_file_answer_it_the_same_way(tmp_path: Path) -> None:
    """AWS-CP-044 reads the same document; two verdicts on one file is the defect itself."""

    _write_unreadable_evidence(tmp_path)

    pipeiam = awsev.eval_aws_pipeiam_056(_ctx(tmp_path))
    sibling = awsev.eval_aws_cp_044(_ctx(tmp_path))

    assert pipeiam.status is sibling.status
    assert pipeiam.reason == sibling.reason
    assert pipeiam.remediation == sibling.remediation
    assert pipeiam.evidence_sources == sibling.evidence_sources


# --------------------------------------------------------------------------- #
# the signal is only claimed where the signal is
# --------------------------------------------------------------------------- #


def test_a_repository_with_no_pipeline_export_is_not_told_a_signal_was_found(tmp_path: Path) -> None:
    """Nothing was scanned and nothing was found, so nothing may be reported as detected."""

    outcome = awsev.eval_aws_pipeiam_056(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "A committed pipeline export declares" not in outcome.reason
    assert "no committed pipeline export declares" in outcome.reason


def test_the_two_repositories_that_differ_by_the_signal_get_different_reasons(tmp_path: Path) -> None:
    """One repository has the export and one does not; a shared sentence describes only one."""

    export = tmp_path / "pipelines" / "aws" / "codepipeline.json"
    with_export = awsev.eval_aws_pipeiam_056(
        _ctx(tmp_path, AwsCiAnalysis(codepipeline_committed_iam_role_paths=[export]))
    )
    without_export = awsev.eval_aws_pipeiam_056(_ctx(tmp_path))

    assert with_export.status is without_export.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert with_export.reason != without_export.reason
    assert "A committed pipeline export declares" in with_export.reason
    assert with_export.evidence_sources == [str(export.resolve())]


# --------------------------------------------------------------------------- #
# AWS-CBIDENT-057 conditions the same claim on a check of its own
# --------------------------------------------------------------------------- #


def test_a_repository_with_no_buildspec_is_not_told_a_signal_was_found(tmp_path: Path) -> None:
    """There is no buildspec here to scan, so no reading of one may be reported."""

    outcome = awsev.eval_aws_cbident_057(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "keyword signal" not in outcome.reason
    assert "no buildspec is present in the supported paths" in outcome.reason
    assert outcome.evidence_sources == []


def test_the_two_repositories_that_differ_by_the_buildspec_get_different_reasons(tmp_path: Path) -> None:
    """One repository has a buildspec and one does not; a shared sentence describes only one."""

    buildspec = tmp_path / "buildspec.yml"
    with_buildspec = awsev.eval_aws_cbident_057(_ctx(tmp_path, AwsCiAnalysis(buildspec_paths=[buildspec])))
    without_buildspec = awsev.eval_aws_cbident_057(_ctx(tmp_path))

    assert with_buildspec.status is without_buildspec.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert with_buildspec.reason != without_buildspec.reason
    assert "A buildspec is present in the supported paths" in with_buildspec.reason
    assert with_buildspec.evidence_sources == [str(buildspec.resolve())]


def test_neither_identity_control_reports_a_detection_it_never_made(tmp_path: Path) -> None:
    """The pair diverged once over this exact sentence; it has to stay gone from both."""

    ctx = _ctx(tmp_path)

    for outcome in (awsev.eval_aws_pipeiam_056(ctx), awsev.eval_aws_cbident_057(ctx)):
        assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
        assert "was detected" not in outcome.reason
