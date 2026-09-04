"""A CodeQL step that is commented out has not been configured, and must not earn a PASS.

`_codeql_action_outcome` read each workflow with `read_text` and asked whether the raw
string contained `github/codeql-action/...`. A `#` in front of the line does not change a
substring, so a workflow whose CodeQL step had been commented out -- the ordinary way a
team parks a job it means to restore -- reported:

    SEC-CODEQL-010 : PASS | confidence high
    github/codeql-action usage detected in ci.yml.

CodeQL does not run there. This is a security control passing on evidence that does not
execute, at the highest confidence the kit has, and it is the class the project already
fixed for four controls: a comment cannot change what a pipeline DOES, so a comment must
not change a verdict.

`strip_yaml_comments` already exists for exactly this and preserves every line and column,
so a finding still points where it did.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.evaluators.cicd import _codeql_action_outcome
from oss_policy_kit.cli.main import app

runner = CliRunner()

_PINNED_CODEQL = "github/codeql-action/analyze@ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd # v4"

_LIVE = f"""name: CI
on: [push]
permissions:
  contents: read
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: {_PINNED_CODEQL}
"""

#: The ordinary way a team parks a job: commented out, with a note saying why.
_PARKED = f"""name: CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      # Removed because it was too slow; revisit next quarter.
      # - uses: {_PINNED_CODEQL}
"""


def _repo(tmp_path: Path, workflow: str, *, name: str = "ci.yml") -> Path:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / name).write_text(workflow, encoding="utf-8")
    return repo


class _Workflows:
    def __init__(self, paths: list[Path]) -> None:
        self.workflow_paths = paths


class _Ctx:
    def __init__(self, repo: Path) -> None:
        self.repo_root = repo
        self.workflows = _Workflows(sorted((repo / ".github" / "workflows").glob("*.yml")))


def test_a_commented_out_codeql_step_is_not_codeql(tmp_path: Path) -> None:
    outcome = _codeql_action_outcome(_Ctx(_repo(tmp_path, _PARKED)))  # type: ignore[arg-type]

    assert outcome is None, (
        "a workflow whose only mention of codeql-action is inside a comment produced "
        f"{outcome.status.value if outcome else None!r}: {outcome.reason if outcome else ''!r}. "
        "CodeQL does not run there."
    )


def test_a_real_codeql_step_still_passes(tmp_path: Path) -> None:
    """The other half. A fix that stopped detecting real CodeQL would be worse than the bug."""

    outcome = _codeql_action_outcome(_Ctx(_repo(tmp_path, _LIVE)))  # type: ignore[arg-type]

    assert outcome is not None, "a live, pinned codeql-action step was not detected"
    assert outcome.status.value == "pass"
    assert "ci.yml" in outcome.reason


@pytest.mark.parametrize(
    ("workflow", "expected"),
    [
        (_LIVE, True),
        (_PARKED, False),
        # A quoted string is executed configuration, not a comment: it still counts.
        (
            "name: CI\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            f'      - run: echo "{_PINNED_CODEQL}"\n',
            True,
        ),
        # An inline trailing comment after a real step must not hide the real step.
        (
            "name: CI\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - uses: {_PINNED_CODEQL}  # pinned by hand\n",
            True,
        ),
    ],
    ids=["live", "commented-out", "inside-a-string", "trailing-comment"],
)
def test_the_boundary_between_comment_and_configuration(tmp_path: Path, workflow: str, expected: bool) -> None:
    outcome = _codeql_action_outcome(_Ctx(_repo(tmp_path, workflow)))  # type: ignore[arg-type]
    assert (outcome is not None) is expected, f"detected={outcome is not None}, expected={expected} for:\n{workflow}"


def test_the_report_does_not_claim_codeql_from_a_comment(tmp_path: Path) -> None:
    """End to end: what the operator reads is what has to be true."""

    repo = _repo(tmp_path, _PARKED)
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        ["evaluate", "--target", str(repo), "--profile", "github-level-1", "--output-dir", str(out)],
    )
    assert result.exit_code in (0, 1), result.output[-300:]

    report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    codeql = next(c for c in report["controls"] if c["id"] == "SEC-CODEQL-010")

    assert not (codeql["state"] == "PASS" and "codeql-action usage detected" in codeql["message"]), (
        f"the report tells the operator CodeQL is configured: {codeql['message']!r}"
    )
