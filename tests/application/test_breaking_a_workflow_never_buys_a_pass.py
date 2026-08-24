"""A workflow that did not parse contributed nothing, so no control may claim absence from it.

Four controls in this codebase already consult `WorkflowAnalysis.parse_errors` before saying "not
detected", and one of them carries the reasoning verbatim: *the break bought the pass*. Five
controls were never converted. For them, adding a single invalid character to a workflow moved the
verdict from FAIL to PASS, or to NOT_APPLICABLE -- and the report then stated positively that the
thing does not exist in a repository where it plainly does.

`NOT_APPLICABLE` is the worse of the two landings: `engine._SCORING_EXCLUDED` drops it from the
weighted score and `fail_on_violated` counts only `fail` and `manual-review-required`, so no
`--fail-on` value can make it block.

This is ADR-045 on a surface the ADR's own sweep did not reach -- the same way `eval_slsa_src_004`
was missed earlier in this campaign, because it reached the state through a fall-through rather
than an explicit error branch.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import (
    eval_gh_prov_023,
    eval_gh_rel_021,
    eval_gh_wf_018,
    eval_gh_wf_019,
    eval_gl_pipe_002,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

#: A workflow that a repository author can break with one character, carrying the very things the
#: controls below look for: a self-hosted runner on a PR trigger, and `secrets: inherit`.
_REAL = """name: ci
on: [pull_request]
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hi
  call:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
"""
_BROKEN = _REAL.replace("on: [pull_request]", "on: [pull_request")

_GITHUB_CONTROLS = [
    ("GH-WF-018", eval_gh_wf_018),
    ("GH-WF-019", eval_gh_wf_019),
    ("GH-REL-021", eval_gh_rel_021),
    ("GH-PROV-023", eval_gh_prov_023),
]


def _ctx(repo: Path) -> SimpleNamespace:
    return SimpleNamespace(
        repo_root=repo,
        workflows=analyze_workflows(repo),
        gitlab_ci=analyze_gitlab_ci(repo),
    )


def _repo(root: Path, body: str) -> Path:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text(body, encoding="utf-8")
    return root


@pytest.mark.parametrize(("control_id", "evaluate"), _GITHUB_CONTROLS, ids=[c[0] for c in _GITHUB_CONTROLS])
def test_a_workflow_that_did_not_parse_is_not_evidence_of_absence(
    tmp_path: Path, control_id: str, evaluate: object
) -> None:
    broken = evaluate(_ctx(_repo(tmp_path / "broken", _BROKEN)))  # type: ignore[operator]

    assert broken.status not in (ControlStatus.PASS, ControlStatus.NOT_APPLICABLE), (
        f"{control_id}: the only workflow in the repository failed to parse and the control "
        f"answered {broken.status.value}, which states positively that the thing is absent. "
        f"Nothing was read, so nothing could be detected: {broken.reason}"
    )


@pytest.mark.parametrize(("control_id", "evaluate"), _GITHUB_CONTROLS, ids=[c[0] for c in _GITHUB_CONTROLS])
def test_a_workflow_that_parses_is_still_judged(tmp_path: Path, control_id: str, evaluate: object) -> None:
    """The counterpart. A guard that answered manual-review-required always would pass the test above."""

    parsed = evaluate(_ctx(_repo(tmp_path / "ok", _REAL)))  # type: ignore[operator]

    assert parsed.status is not ControlStatus.MANUAL_REVIEW_REQUIRED, (
        f"{control_id}: the workflow parses cleanly and the control still refused to judge it: {parsed.reason}"
    )


def test_a_gitlab_pipeline_that_did_not_parse_is_not_evidence_of_absence(tmp_path: Path) -> None:
    repo = tmp_path / "gl"
    repo.mkdir()
    (repo / ".gitlab-ci.yml").write_text("stages: [build\nbuild:\n  script:\n    - echo hi\n", encoding="utf-8")

    outcome = eval_gl_pipe_002(_ctx(repo))

    assert outcome.status not in (ControlStatus.PASS, ControlStatus.NOT_APPLICABLE), (
        f"GL-PIPE-002: the pipeline file failed to parse and the control answered "
        f"{outcome.status.value}: {outcome.reason}"
    )
