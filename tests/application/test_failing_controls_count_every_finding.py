"""A failing control must account for every finding, not just the first one.

Four evaluators reported the first finding and stopped: ``CI-PIN-008``, both branches of
``CI-LEAST-009``, and ``GH-WF-020``. The verdict was right in every direction and the gate
was sound, so nothing failed and nothing noticed -- but the evidence understated the
remediation work by however many findings the repository had. A repository with nine
unpinned action references was told about one, so the operator pinned it, re-ran, and was
handed the next: the cost is re-runs proportional to the violations, and for a tool whose
product is audit evidence, an artifact that says "one" about nine is the wrong kind of
incomplete.

Each test uses more findings than the preview limit where it can, so a fix that merely
widened the slice from one to five would still fail the count assertions.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from oss_policy_kit.application.evaluators import (
    EvalContext,
    eval_ci_least_009,
    eval_ci_pin_008,
    eval_gh_wf_020,
)
from oss_policy_kit.application.evaluators._shared import EVIDENCE_PREVIEW_LIMIT
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows


def _ctx(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-1",
        workflows=analyze_workflows(tmp_path),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(tmp_path: Path, name: str, content: str) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(textwrap.dedent(content), encoding="utf-8")


def _three_workflows_with_three_mutable_refs_each(tmp_path: Path) -> None:
    for i in (1, 2, 3):
        _write(
            tmp_path,
            f"wf{i}.yml",
            f"""\
            name: wf{i}
            on: push
            permissions: write-all
            jobs:
              build{i}:
                runs-on: ubuntu-latest
                permissions:
                  contents: write
                steps:
                  - uses: actions/checkout@v4
                  - uses: actions/setup-python@v5
                  - uses: some/third-party-action@main
            """,
        )


def test_ci_pin_008_counts_every_mutable_ref_not_only_the_first(tmp_path: Path) -> None:
    _three_workflows_with_three_mutable_refs_each(tmp_path)
    analysis = analyze_workflows(tmp_path)
    assert len(analysis.mutable_action_refs) == 9, "fixture no longer produces nine refs"

    out = eval_ci_pin_008(_ctx(tmp_path))

    assert out.status == ControlStatus.FAIL
    assert "9 mutable action reference(s)" in out.reason
    assert "3 workflow file(s)" in out.reason


def test_ci_pin_008_lists_more_than_one_ref_and_says_what_it_left_out(tmp_path: Path) -> None:
    _three_workflows_with_three_mutable_refs_each(tmp_path)

    out = eval_ci_pin_008(_ctx(tmp_path))

    assert len(out.evidence_sources) == EVIDENCE_PREVIEW_LIMIT
    assert f"Listing {EVIDENCE_PREVIEW_LIMIT} of 9" in out.reason
    assert len(set(out.evidence_sources)) == EVIDENCE_PREVIEW_LIMIT


def test_ci_pin_008_does_not_claim_a_remainder_it_does_not_have(tmp_path: Path) -> None:
    """Two findings fit under the cap, so there is nothing to say about a remainder."""

    _write(
        tmp_path,
        "wf.yml",
        """\
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-python@v5
        """,
    )

    out = eval_ci_pin_008(_ctx(tmp_path))

    assert out.status == ControlStatus.FAIL
    assert "2 mutable action reference(s)" in out.reason
    assert "Listing" not in out.reason
    assert len(out.evidence_sources) == 2


def test_ci_least_009_counts_every_workflow_with_broad_permissions(tmp_path: Path) -> None:
    _three_workflows_with_three_mutable_refs_each(tmp_path)
    analysis = analyze_workflows(tmp_path)
    assert len(analysis.suspicious_permissions) == 3

    out = eval_ci_least_009(_ctx(tmp_path))

    assert out.status == ControlStatus.FAIL
    assert "3 workflow file(s)" in out.reason
    assert len(out.evidence_sources) == 3
    for i in (1, 2, 3):
        assert f"wf{i}.yml" in out.reason


def test_ci_least_009_caps_the_file_list_and_says_how_many_it_capped(tmp_path: Path) -> None:
    """Seven offending files exceed the preview limit, which is what the cap is for.

    A repository can have far more violations than a reason can usefully carry. The cap
    keeps one control from becoming a wall of text; the count is what stops the capped
    list from being another way of understating the work.
    """

    for i in range(1, 8):
        _write(
            tmp_path,
            f"wf{i}.yml",
            f"""\
            name: wf{i}
            on: push
            permissions: write-all
            jobs:
              build{i}:
                runs-on: ubuntu-latest
                steps:
                  - run: echo {i}
            """,
        )
    analysis = analyze_workflows(tmp_path)
    assert len(analysis.suspicious_permissions) == 7

    out = eval_ci_least_009(_ctx(tmp_path))

    assert out.status == ControlStatus.FAIL
    assert "7 workflow file(s)" in out.reason
    assert f"listing {EVIDENCE_PREVIEW_LIMIT} of 7" in out.reason
    assert len(out.evidence_sources) == EVIDENCE_PREVIEW_LIMIT
    assert len(set(out.evidence_sources)) == EVIDENCE_PREVIEW_LIMIT


def _one_workflow_three_deploy_jobs(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "deploy.yml",
        """\
        name: deploy
        on: push
        jobs:
          jobA:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: docker push ghcr.io/acme/app:latest
          jobB:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: docker push ghcr.io/acme/app:beta
          jobC:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: docker push ghcr.io/acme/app:dev
        """,
    )


def test_ci_least_009_implicit_counts_every_risk_and_every_job(tmp_path: Path) -> None:
    _one_workflow_three_deploy_jobs(tmp_path)
    analysis = analyze_workflows(tmp_path)
    assert len(analysis.implicit_permission_risks) == 6
    assert not analysis.suspicious_permissions, "fixture must reach the implicit branch"

    out = eval_ci_least_009(_ctx(tmp_path))

    assert out.status == ControlStatus.FAIL
    assert "Implicit broad-permissions risk" in out.reason
    assert "6 finding(s)" in out.reason
    assert "3 workflow job(s)" in out.reason
    for job in ("jobA", "jobB", "jobC"):
        assert job in out.reason


def test_ci_least_009_implicit_reason_stays_readable(tmp_path: Path) -> None:
    """Six full sentences would bury the count that matters; locations are what scale."""

    _one_workflow_three_deploy_jobs(tmp_path)

    out = eval_ci_least_009(_ctx(tmp_path))

    assert len(out.reason) < 400, f"reason grew to {len(out.reason)} chars"


def test_ci_least_009_implicit_does_not_repeat_one_file_per_finding(tmp_path: Path) -> None:
    """Six findings share one file; six identical references would be noise, not evidence."""

    _one_workflow_three_deploy_jobs(tmp_path)

    out = eval_ci_least_009(_ctx(tmp_path))

    assert len(out.evidence_sources) == 1
    assert out.evidence_sources[0].endswith("deploy.yml")


def test_gh_wf_020_counts_every_broad_job_not_only_the_first(tmp_path: Path) -> None:
    _three_workflows_with_three_mutable_refs_each(tmp_path)
    analysis = analyze_workflows(tmp_path)
    assert len(analysis.broad_job_permissions) == 3

    out = eval_gh_wf_020(_ctx(tmp_path))

    assert out.status == ControlStatus.FAIL
    assert "3 job(s)" in out.reason
    assert len(out.evidence_sources) == 3
    for i in (1, 2, 3):
        assert f"wf{i}.yml" in out.reason


def test_gh_wf_020_names_one_file_once_when_several_jobs_share_it(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "many.yml",
        """\
        on: push
        permissions: read-all
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - run: echo a
          b:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - run: echo b
        """,
    )
    analysis = analyze_workflows(tmp_path)
    assert len(analysis.broad_job_permissions) == 2

    out = eval_gh_wf_020(_ctx(tmp_path))

    assert out.status == ControlStatus.FAIL
    assert "2 job(s)" in out.reason
    assert len(out.evidence_sources) == 1, "one file, named once"
