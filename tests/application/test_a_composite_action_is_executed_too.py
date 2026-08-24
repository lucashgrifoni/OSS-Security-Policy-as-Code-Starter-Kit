"""CI-PIN-008 claims third-party actions are pinned; it has to look where they are declared.

A composite action is a file in the working tree (`action.yml`) whose `runs.steps[].uses` are
executed exactly like a workflow step's. Workflow discovery reads `.github/workflows/*` and
nothing else, and `_iter_step_uses` indexes `jobs` -> `steps`, a shape a composite action does
not have. So the refs inside one were never read.

Reproduced through the public CLI before this test existed, on a repository whose workflow is
pinned entirely to commit SHAs and whose composite action runs `some-vendor/publish@main`:

    CI-PIN-008  PASS    "Third-party actions pinned to immutable references"

That is a false claim about the repository, not a missing feature: a third-party action pinned to
a *branch* is executed on every run.

The known-limitations lists in `docs/architecture.md` and `docs/results-guide.md` do name
composite actions, and it is worth being exact about what they say, because it does not cover
this. Both frame the limit as "local evaluation can inspect only what exists in the working tree"
and disclaim the *runtime behavior* of composite actions -- alongside branch protection and
org-level settings, which genuinely are outside a clone. A `uses:` line is a static fact in a
file that is right there; reading it simulates nothing. And `results-guide.md` states that where
the kit cannot settle a question it answers `not-evaluated` or `manual-review-required` -- so
even reading the limitation generously, a clean PASS was never the documented behaviour.

Boundary this file also pins: only the two conventional locations are scanned -- `action.yml` /
`action.yaml` at the repository root, and under `.github/actions/`. A repository-wide sweep would
walk `examples/` and vendored trees, where a deliberately-insecure fixture would be reported as
the adopter's own defect.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import _shared as s
from oss_policy_kit.application.evaluators.cicd import eval_ci_pin_008
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

_PINNED_WORKFLOW = """name: ci
on:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: ./.github/actions/build
"""

_COMPOSITE_MUTABLE = """name: build
description: does the real work
runs:
  using: composite
  steps:
    - uses: some-vendor/publish@main
"""

_COMPOSITE_PINNED = """name: build
description: does the real work
runs:
  using: composite
  steps:
    - uses: some-vendor/publish@11bd71901bbe5b1630ceea73d27597364c9af683
"""


def _ctx(repo_root: Path) -> s.EvalContext:
    return s.EvalContext(
        repo_root=repo_root,
        profile_id="github-level-1",
        workflows=analyze_workflows(repo_root),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _repo(root: Path, *, workflow: str | None = None, composite: str | None = None, at_root: str | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if workflow is not None:
        (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
        (root / ".github" / "workflows" / "ci.yml").write_text(workflow, encoding="utf-8")
    if composite is not None:
        (root / ".github" / "actions" / "build").mkdir(parents=True, exist_ok=True)
        (root / ".github" / "actions" / "build" / "action.yml").write_text(composite, encoding="utf-8")
    if at_root is not None:
        (root / "action.yml").write_text(at_root, encoding="utf-8")
    return root


def test_an_unpinned_action_inside_a_composite_action_is_not_a_pass(tmp_path: Path) -> None:
    """The reproduction: a spotless workflow must not vouch for what the composite action runs."""

    repo = _repo(tmp_path / "repo", workflow=_PINNED_WORKFLOW, composite=_COMPOSITE_MUTABLE)

    outcome = eval_ci_pin_008(_ctx(repo))

    assert outcome.status is ControlStatus.FAIL, (
        f"a third-party action pinned to a branch earned {outcome.status.value}: {outcome.reason}"
    )


def test_a_composite_action_pinned_by_sha_is_still_a_pass(tmp_path: Path) -> None:
    """The mirror case -- reading more files must not invent failures for repositories doing it right."""

    repo = _repo(tmp_path / "repo", workflow=_PINNED_WORKFLOW, composite=_COMPOSITE_PINNED)

    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.PASS


def test_a_repository_that_only_ships_an_action_is_still_evaluated(tmp_path: Path) -> None:
    """An action repository has no workflows, and still executes third-party actions.

    `not-applicable` is a positive claim -- "this control does not apply here" -- and it is wrong
    for a repository whose entire product is an action.
    """

    repo = _repo(tmp_path / "repo", at_root=_COMPOSITE_MUTABLE)

    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.FAIL


def test_a_repository_with_neither_is_still_not_applicable(tmp_path: Path) -> None:
    """And a repository that runs no actions at all keeps the honest `not-applicable`."""

    repo = tmp_path / "empty"
    repo.mkdir()

    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.NOT_APPLICABLE


def test_a_composite_action_that_cannot_be_parsed_is_recorded(tmp_path: Path) -> None:
    """An unreadable action.yml must be recorded, not silently treated as holding nothing."""

    repo = _repo(tmp_path / "repo", workflow=_PINNED_WORKFLOW, composite="runs: [this: is: not: valid\n")

    analysis = analyze_workflows(repo)

    assert any("action.yml" in path.name for path, _ in analysis.parse_errors)


def test_a_commented_out_uses_inside_a_composite_action_does_not_fail_it(tmp_path: Path) -> None:
    """The same rule the workflow scanner already follows: a comment is not a step.

    Reading composite actions through the parsed structure rather than the raw text is what keeps
    this fix from reintroducing the false positive `_scan_parsed_uses_for_mutable` was written to
    remove.
    """

    commented = (
        "name: build\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    # - uses: some-vendor/publish@main\n"
        "    - shell: bash\n"
        "      run: echo hi\n"
    )
    repo = _repo(tmp_path / "repo", workflow=_PINNED_WORKFLOW, composite=commented)

    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.PASS


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("name: js\nruns:\n  using: node20\n  main: dist/index.js\n", id="javascript-action"),
        pytest.param("name: docker\nruns:\n  using: docker\n  image: Dockerfile\n", id="docker-action"),
        pytest.param("name: metadata-only\ndescription: no runs block at all\n", id="no-runs-block"),
    ],
)
def test_an_action_that_is_not_composite_contributes_nothing_and_is_not_an_error(tmp_path: Path, body: str) -> None:
    """Only composite actions have steps; the other kinds are valid and simply declare no `uses:`.

    Worth pinning separately from the parse-error case: a JavaScript or Docker action is the most
    common kind there is, and reporting one as unreadable would manufacture a degraded verdict out
    of a perfectly ordinary file.
    """

    repo = _repo(tmp_path / "repo", workflow=_PINNED_WORKFLOW, composite=body)

    analysis = analyze_workflows(repo)

    assert not analysis.parse_errors, (
        f"a valid non-composite action was recorded as unreadable: {analysis.parse_errors}"
    )
    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.PASS


def test_an_action_file_that_is_not_a_mapping_is_recorded(tmp_path: Path) -> None:
    """A list or a bare scalar where the action metadata should be is unreadable, and says so."""

    repo = _repo(tmp_path / "repo", workflow=_PINNED_WORKFLOW, composite="- just\n- a\n- list\n")

    analysis = analyze_workflows(repo)

    assert any("must be a mapping" in message for _, message in analysis.parse_errors)


@pytest.mark.parametrize("where", ["examples/vulnerable-repo", "node_modules/some-dep", "vendor/thing"])
def test_an_action_outside_the_two_conventional_locations_is_not_charged_to_the_adopter(
    tmp_path: Path, where: str
) -> None:
    """A vendored or fixture `action.yml` is not the adopter's declaration of what their CI runs."""

    repo = _repo(tmp_path / "repo", workflow=_PINNED_WORKFLOW)
    nested = repo / where
    nested.mkdir(parents=True, exist_ok=True)
    (nested / "action.yml").write_text(_COMPOSITE_MUTABLE, encoding="utf-8")

    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.PASS
