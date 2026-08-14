"""Both verdicts of every GitLab pipeline control, not just the empty-repo one.

Each of GL-PIPE-007 through GL-PIPE-012 scans a pipeline (or a project evidence file) for a
posture signal. Only the "no pipeline at all" arm was exercised, which meant a control could
have stopped recognising its own signal entirely and nothing would have failed -- every
repository would simply have started reporting the same not-applicable it always did.

So each control appears twice: a pipeline that declares the signal, and one that does not.
The pairing is what makes either half meaningful, because a scan that matched everything and a
scan that matched nothing each pass one of the two on their own.

The refusal statuses differ by control on purpose and the tests keep that visible: only 007
`fail`s, because a pipeline with no `id_tokens:` is using long-lived credentials and that is
the finding. 008, 009, 010 and 012 stay `manual-review-required`, because the thing they look
for can legitimately be absent or configured somewhere this scan cannot see -- a project on
shared runners has no tags to declare, and an audit destination lives outside the repository.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import gitlab as gl
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_BARE_PIPELINE = "build:\n  image: python:3.12\n  script:\n    - echo hi\n"


def _ctx(root: Path, pipeline: str = _BARE_PIPELINE) -> EvalContext:
    (root / ".gitlab-ci.yml").write_text(pipeline, encoding="utf-8")
    return EvalContext(
        repo_root=root,
        profile_id="gitlab-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        gitlab_ci=analyze_gitlab_ci(root),
    )


# --------------------------------------------------------------------------- #
# GL-PIPE-007 — OIDC id_tokens
# --------------------------------------------------------------------------- #


def test_a_pipeline_declaring_id_tokens_passes_oidc(tmp_path: Path) -> None:
    pipeline = "deploy:\n  image: python:3.12\n  id_tokens:\n    AWS: {aud: sts.amazonaws.com}\n  script: echo hi\n"
    outcome = gl.eval_gl_pipe_007(_ctx(tmp_path, pipeline))
    assert outcome.status is ControlStatus.PASS
    assert "id_tokens" in outcome.reason


def test_a_pipeline_without_id_tokens_fails_oidc(tmp_path: Path) -> None:
    """Absence is the finding here: the alternative is long-lived credentials."""

    outcome = gl.eval_gl_pipe_007(_ctx(tmp_path))
    assert outcome.status is ControlStatus.FAIL
    assert "id_tokens" in outcome.reason


# --------------------------------------------------------------------------- #
# GL-PIPE-008 — runner tag scoping
# --------------------------------------------------------------------------- #


def test_a_pipeline_scoping_runners_by_tag_passes(tmp_path: Path) -> None:
    pipeline = "build:\n  image: python:3.12\n  tags:\n    - hardened\n  script: echo hi\n"
    assert gl.eval_gl_pipe_008(_ctx(tmp_path, pipeline)).status is ControlStatus.PASS


def test_a_pipeline_with_no_runner_tags_asks_a_human(tmp_path: Path) -> None:
    """Manual review rather than fail: a project may legitimately use only shared runners."""

    assert gl.eval_gl_pipe_008(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# GL-PIPE-009 — audit-event streaming
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("doc", ["AUDIT.md", "docs/audit-streaming.md", "RELEASE_OPERATIONS.md"])
def test_audit_streaming_documented_in_any_known_location_passes(doc: str, tmp_path: Path) -> None:
    """The control looks in several documented places; all of them have to count."""

    path = tmp_path / doc
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Audit events stream to the central SIEM (audit_event export).\n", encoding="utf-8")
    outcome = gl.eval_gl_pipe_009(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS
    assert doc.rsplit("/", 1)[-1] in outcome.reason


def test_audit_streaming_mentioned_in_the_pipeline_itself_passes(tmp_path: Path) -> None:
    pipeline = "audit:\n  image: python:3.12\n  script:\n    - ship audit_event stream\n"
    assert gl.eval_gl_pipe_009(_ctx(tmp_path, pipeline)).status is ControlStatus.PASS


def test_no_audit_streaming_reference_asks_a_human(tmp_path: Path) -> None:
    """Manual review, not fail: the destination may be configured outside the repository."""

    assert gl.eval_gl_pipe_009(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_an_unreadable_candidate_document_does_not_break_the_scan(tmp_path: Path) -> None:
    """A directory where a file was expected must be stepped over, not raised on."""

    (tmp_path / "AUDIT.md").mkdir()
    assert gl.eval_gl_pipe_009(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# GL-PIPE-010 — environment approvals
# --------------------------------------------------------------------------- #


def test_a_pipeline_declaring_an_environment_passes(tmp_path: Path) -> None:
    pipeline = "deploy:\n  image: python:3.12\n  environment:\n    name: production\n  script: echo hi\n"
    assert gl.eval_gl_pipe_010(_ctx(tmp_path, pipeline)).status is ControlStatus.PASS


def test_a_pipeline_with_no_environment_declaration_asks_a_human(tmp_path: Path) -> None:
    assert gl.eval_gl_pipe_010(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# GL-PIPE-011 — merge-request approvals (project evidence)
# --------------------------------------------------------------------------- #


def _mr_evidence(root: Path, payload: object) -> None:
    d = root / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (d / "gitlab-mr-rules.json").write_text(text, encoding="utf-8")


#: A document that satisfies the shipped `evidence-gitlab-mr-rules.schema.json`.
_COMPLETE_MR_EVIDENCE = {
    "schema_version": "gitlab-mr-rules/v1",
    "attested_at": "2026-08-14",
    "attested_by": "lucas",
    "project": "group/project",
    "min_approvers": 2,
}


def test_mr_evidence_recording_an_approver_passes(tmp_path: Path) -> None:
    """This used to pass with a bare ``{"min_approvers": 2}``.

    The control now validates against the schema the kit has always shipped for this file,
    and that schema has always listed `schema_version`, `attested_at`, `attested_by` and
    `project` as required. Nothing loaded it, so a one-key document earned a PASS — as did an
    untouched scaffold still carrying REPLACE_ME placeholders.
    """

    _mr_evidence(tmp_path, _COMPLETE_MR_EVIDENCE)
    outcome = gl.eval_gl_pipe_011(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS
    assert "min_approvers=2" in outcome.reason


def test_mr_evidence_missing_the_documented_fields_no_longer_passes(tmp_path: Path) -> None:
    """The behaviour change stated as a requirement, so it cannot regress silently."""

    _mr_evidence(tmp_path, {"min_approvers": 2})
    outcome = gl.eval_gl_pipe_011(_ctx(tmp_path))
    assert outcome.status is not ControlStatus.PASS
    assert "schema" in outcome.reason.lower(), outcome.reason


@pytest.mark.parametrize(
    "payload",
    [{"min_approvers": 0}, {}, ["not", "a", "mapping"], "{ broken json"],
)
def test_mr_evidence_that_proves_nothing_does_not_pass(payload: object, tmp_path: Path) -> None:
    """Zero approvers, a missing key, the wrong shape and unreadable JSON are all 'not proven'."""

    _mr_evidence(tmp_path, payload)
    assert gl.eval_gl_pipe_011(_ctx(tmp_path)).status is not ControlStatus.PASS


# --------------------------------------------------------------------------- #
# GL-PIPE-012 — artifact retention / signing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("signal", ["expire_in: 1 week", "cosign sign", "sigstore", "rekor"])
def test_a_pipeline_declaring_retention_or_signing_passes(signal: str, tmp_path: Path) -> None:
    pipeline = f"build:\n  image: python:3.12\n  script:\n    - {signal}\n"
    assert gl.eval_gl_pipe_012(_ctx(tmp_path, pipeline)).status is ControlStatus.PASS


def test_a_pipeline_with_neither_retention_nor_signing_asks_a_human(tmp_path: Path) -> None:
    assert gl.eval_gl_pipe_012(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# No pipeline at all
# --------------------------------------------------------------------------- #


#: GL-PIPE-001 is deliberately absent: it asks whether a pipeline exists at all, so its
#: absence is the finding rather than a reason to skip. It gets its own test below.
_ALL_PIPELINE_CONTROLS = [
    gl.eval_gl_pipe_002,
    gl.eval_gl_pipe_003,
    gl.eval_gl_pipe_004,
    gl.eval_gl_pipe_005,
    gl.eval_gl_pipe_006,
    gl.eval_gl_pipe_007,
    gl.eval_gl_pipe_008,
    gl.eval_gl_pipe_010,
    gl.eval_gl_pipe_012,
]


@pytest.mark.parametrize("evaluate", _ALL_PIPELINE_CONTROLS, ids=lambda f: f.__name__)
def test_a_repository_with_no_gitlab_pipeline_is_not_applicable(evaluate: object, tmp_path: Path) -> None:
    """No .gitlab-ci.yml means these controls have nothing to judge, and must say so.

    Scoring them as failures would penalise every repository that does not use GitLab CI,
    which is most of them.
    """

    ctx = EvalContext(
        repo_root=tmp_path,
        profile_id="gitlab-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        gitlab_ci=analyze_gitlab_ci(tmp_path),
    )
    outcome = evaluate(ctx)  # type: ignore[operator]
    assert outcome.status is ControlStatus.NOT_APPLICABLE
    assert outcome.status is not ControlStatus.FAIL


def test_mr_approvals_without_any_evidence_file_does_not_pass(tmp_path: Path) -> None:
    """GL-PIPE-011 reads a project setting; with no evidence there is nothing to confirm."""

    assert gl.eval_gl_pipe_011(_ctx(tmp_path)).status is not ControlStatus.PASS


def test_the_missing_pipeline_itself_is_a_failure_not_a_skip(tmp_path: Path) -> None:
    """GL-PIPE-001 asks whether a pipeline exists; not-applicable would excuse the gap."""

    ctx = EvalContext(
        repo_root=tmp_path,
        profile_id="gitlab-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        gitlab_ci=analyze_gitlab_ci(tmp_path),
    )
    outcome = gl.eval_gl_pipe_001(ctx)
    assert outcome.status is ControlStatus.FAIL
    assert ".gitlab-ci.yml" in outcome.reason
