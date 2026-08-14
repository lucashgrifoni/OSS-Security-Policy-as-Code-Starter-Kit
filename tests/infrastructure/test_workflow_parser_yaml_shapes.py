"""Workflow YAML that is valid but not the shape the scanner assumed.

Three kinds of input live here. A `uses:` whose reference is a `${{ }}` expression, which
cannot be pin-checked because the value is only known at run time and must be skipped rather
than reported as unpinned. Jobs and steps that are not mappings, which YAML permits and a
`.get()` on them would crash. And a checkout step with no token, where "no token" and "a
non-default token" are different answers.

The property throughout is that an unparseable *part* never becomes a finding and never takes
down the scan: a workflow the parser cannot fully read has to leave the rest of the analysis
intact, because the alternative is a scanner that reports a clean repository the moment it
meets a construct it did not expect.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure import workflow_parser as wp
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows


def _workflow(root: Path, body: str, name: str = "ci.yml") -> Path:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    path = wf / name
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# uses: expressions
# --------------------------------------------------------------------------- #


def test_an_action_reference_built_from_an_expression_is_not_called_unpinned(tmp_path: Path) -> None:
    """`uses: ${{ env.ACTION }}` has no ref to check; calling it unpinned would be a false positive."""

    _workflow(
        tmp_path,
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ${{ env.ACTION }}\n",
    )
    analysis = analyze_workflows(tmp_path)
    refs = [ref for _, ref in analysis.mutable_action_refs]
    assert not any("${{" in r for r in refs), refs


def test_a_reusable_workflow_called_through_an_expression_is_skipped(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        "name: ci\non: push\njobs:\n  call:\n    uses: ${{ env.WORKFLOW }}\n",
    )
    analysis = analyze_workflows(tmp_path)
    assert analysis.parse_errors == []
    assert analysis.reusable_workflow_mutable_ref_paths == []


def test_a_real_unpinned_action_is_still_reported(tmp_path: Path) -> None:
    """The counterpart: a parser that skipped every `uses:` would pass the two above."""

    _workflow(
        tmp_path,
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
    )
    refs = [ref for _, ref in analyze_workflows(tmp_path).mutable_action_refs]
    assert "actions/checkout@v4" in refs, refs


# --------------------------------------------------------------------------- #
# Jobs and steps that are not mappings
# --------------------------------------------------------------------------- #


def test_a_jobs_block_that_is_not_a_mapping_leaves_the_scan_intact(tmp_path: Path) -> None:
    _workflow(tmp_path, "name: ci\non: push\njobs:\n  - not-a-job\n")
    analysis = analyze_workflows(tmp_path)
    assert analysis.workflow_paths, "the file should still be counted as a workflow"


def test_a_job_that_is_not_a_mapping_is_stepped_over(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        "name: ci\non: push\njobs:\n  broken: just-a-string\n  good:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
    )
    refs = [ref for _, ref in analyze_workflows(tmp_path).mutable_action_refs]
    assert "actions/checkout@v4" in refs, "the healthy job beside the broken one was skipped"


def test_a_workflow_with_no_jobs_at_all_is_not_an_error(tmp_path: Path) -> None:
    _workflow(tmp_path, "name: ci\non: push\n")
    assert analyze_workflows(tmp_path).parse_errors == []


# --------------------------------------------------------------------------- #
# checkout token
# --------------------------------------------------------------------------- #


def test_a_checkout_without_a_token_input_uses_the_default(tmp_path: Path) -> None:
    """No `token:` means GITHUB_TOKEN; that is not the same as an explicit non-default one."""

    _workflow(
        tmp_path,
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n",
    )
    assert analyze_workflows(tmp_path).parse_errors == []


@pytest.mark.parametrize("token", ["", "   "])
def test_a_blank_checkout_token_is_treated_as_the_default(token: str, tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n        with:\n"
        f'          token: "{token}"\n',
    )
    assert analyze_workflows(tmp_path).parse_errors == []


# --------------------------------------------------------------------------- #
# OIDC posture
# --------------------------------------------------------------------------- #


def test_oidc_detection_survives_a_jobs_block_of_the_wrong_type(tmp_path: Path) -> None:
    _workflow(tmp_path, "name: ci\non: push\njobs: not-a-mapping\n")
    analysis = analyze_workflows(tmp_path)
    assert analysis.workflow_paths
    assert analysis.parse_errors == []


# --------------------------------------------------------------------------- #
# Helpers called directly, for shapes a workflow file cannot express
# --------------------------------------------------------------------------- #


def test_a_reusable_workflow_called_twice_is_recorded_once(tmp_path: Path) -> None:
    """Two calls to the same reusable workflow are one finding, not two."""

    content = (
        "jobs:\n"
        "  a:\n    uses: org/repo/.github/workflows/build.yml@main\n"
        "  b:\n    uses: org/repo/.github/workflows/build.yml@main\n"
    )
    mutable: list[Path] = []
    calls: list[Path] = []
    wp._scan_reusable_workflow_pins(content, tmp_path / "ci.yml", mutable_out=mutable, call_out=calls)
    assert calls == [tmp_path / "ci.yml"]
    assert mutable == [tmp_path / "ci.yml"]


def test_a_reusable_call_that_is_not_a_workflow_path_is_ignored(tmp_path: Path) -> None:
    """`uses: org/action@v1` at job level is not a reusable workflow call."""

    mutable: list[Path] = []
    calls: list[Path] = []
    wp._scan_reusable_workflow_pins(
        "jobs:\n  a:\n    uses: org/some-action@v1\n", tmp_path / "ci.yml", mutable_out=mutable, call_out=calls
    )
    assert calls == []
    assert mutable == []


def test_the_same_permission_risk_is_only_reported_once(tmp_path: Path) -> None:
    """`seen` exists so one job does not produce the same warning repeatedly."""

    out: list[tuple[Path, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for _ in range(3):
        wp._add_perm_risk(out, seen, "build", "write-all", tmp_path / "ci.yml", "too broad")
    assert len(out) == 1, out


def test_a_different_risk_on_the_same_job_is_still_reported(tmp_path: Path) -> None:
    out: list[tuple[Path, str, str]] = []
    seen: set[tuple[str, str]] = set()
    wp._add_perm_risk(out, seen, "build", "write-all", tmp_path / "ci.yml", "too broad")
    wp._add_perm_risk(out, seen, "build", "id-token", tmp_path / "ci.yml", "oidc")
    assert len(out) == 2, out


def test_implicit_permission_scan_stops_when_jobs_is_not_a_mapping(tmp_path: Path) -> None:
    """A list of jobs is valid YAML and has no job names to attribute a risk to."""

    out: list[tuple[Path, str, str]] = []
    wp._collect_implicit_permission_risks({"jobs": ["a", "b"]}, tmp_path / "ci.yml", out)
    assert out == []


def test_oidc_posture_is_false_when_jobs_is_not_a_mapping() -> None:
    """A malformed `jobs:` yields no OIDC signal rather than raising."""

    assert wp._workflow_has_oidc_posture({"jobs": ["a"]}) is False


def test_oidc_posture_is_true_when_the_workflow_declares_the_token() -> None:
    """The counterpart, so the test above cannot pass merely by always returning False.

    This pair used to be written against the raw workflow TEXT, and the second one asserted
    that `"permissions:\\n  id-token: write\\n"` as a string made the posture true even with
    `jobs` malformed. That was the GH-DEPLOY-022 defect stated as a requirement: the text of
    a workflow is not the workflow, and a comment carries the same words.
    """

    assert wp._workflow_has_oidc_posture({"permissions": {"id-token": "write"}, "jobs": ["a"]}) is True
