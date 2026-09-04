"""A `merge_group` trigger is the same trigger in every shape GitHub accepts.

``GH-MERGEQ-053`` decided from a raw-text match, ``^\\s*merge_group:\\s*$``, so it only ever
recognised the trigger written as a block-mapping key. GitHub accepts the trigger list as a
mapping, as a flow sequence (``on: [push, merge_group]``), as a block sequence, and as a bare
string, and all of them enable the merge queue. The kit reported "No merge queue (merge_group)
or merge-queue documentation signal detected in workflows" for a repository whose workflow
declares one, and this control is `lifecycle: stable`.

The direction matters. A false FAIL is not a harmless conservatism here: `--fail-on fail` is
how the kit is wired into a pipeline, so this blocks a release for a repository that is
configured correctly.

The workflow parser already resolves the trigger block through ``_on_block``, which knows that
an unquoted ``on:`` is the YAML 1.1 boolean ``True``. The detection now reads that structure,
the same move the file already made for ``dependency-review-action`` and the attestation
signals after raw matching credited steps that were commented out.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

_BODY = """permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: echo ok
"""


def _repo(tmp_path: Path, header: str) -> Path:
    repo = tmp_path / "repo"
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(header + _BODY, encoding="utf-8")
    return repo


@pytest.mark.parametrize(
    ("header", "why"),
    [
        ("name: ci\non:\n  push:\n  merge_group:\n", "a block mapping key"),
        ("name: ci\non:\n  push:\n  merge_group:\n    types: [checks_requested]\n", "a mapping with types"),
        ("name: ci\non: [push, merge_group]\n", "a flow sequence"),
        ("name: ci\non:\n  - push\n  - merge_group\n", "a block sequence"),
        ("name: ci\non: merge_group\n", "a bare string"),
        ('name: ci\n"on":\n  push:\n  merge_group:\n', "a quoted `on` key"),
        ("name: ci\non:\n  push:\n  merge_group: {}\n", "an explicit empty mapping"),
    ],
    ids=[
        "block-mapping",
        "mapping-with-types",
        "flow-sequence",
        "block-sequence",
        "bare-string",
        "quoted-on",
        "empty-mapping",
    ],
)
def test_every_shape_of_the_trigger_is_the_same_trigger(tmp_path: Path, header: str, why: str) -> None:
    analysis = analyze_workflows(_repo(tmp_path, header))

    assert analysis.merge_queue_signal_paths, (
        f"the workflow declares merge_group as {why}, which enables the merge queue, yet no signal was recorded"
    )


@pytest.mark.parametrize(
    ("header", "why"),
    [
        ("name: ci\non:\n  push:\n", "no merge_group trigger at all"),
        ("name: ci\non:\n  push:\n# merge_group:\n", "the trigger is commented out"),
        ("name: ci\non:\n  push:\n  merge_group_experiment:\n", "a different trigger name that starts the same"),
    ],
    ids=["no-trigger", "commented-out", "similar-name"],
)
def test_a_workflow_without_the_trigger_records_no_signal(tmp_path: Path, header: str, why: str) -> None:
    """The other half: a detector that fires on anything is worth as little as one that never does."""

    analysis = analyze_workflows(_repo(tmp_path, header))

    assert not analysis.merge_queue_signal_paths, f"{why}, yet a merge-queue signal was recorded"


def test_the_documented_merge_queue_prose_signal_still_counts(tmp_path: Path) -> None:
    """The prose fallback is deliberate and stays: the control names it in its own message.

    It is what lets a repository whose merge queue is configured outside these workflows say
    so, and the control declares itself `assurance: signal` at low confidence for exactly that
    reason. The prose has to be in a real value: comments are stripped before this scan runs,
    which is what stops a switched-off step from buying a verdict.
    """

    repo = _repo(tmp_path, "name: ci\non:\n  push:\n")
    (repo / ".github" / "workflows" / "gate.yml").write_text(
        "name: merge-queue gate\non:\n  push:\njobs: {}\n",
        encoding="utf-8",
    )

    assert analyze_workflows(repo).merge_queue_signal_paths


def test_prose_inside_a_comment_buys_nothing(tmp_path: Path) -> None:
    """Comments are stripped before the raw scan, and this is the guard for that.

    A comment claiming a merge queue exists is not evidence that one does -- the same reason a
    commented-out step no longer earns a security PASS.
    """

    repo = _repo(tmp_path, "name: ci\non:\n  push:\n# Merges are gated by the org merge-queue policy.\n")

    assert not analyze_workflows(repo).merge_queue_signal_paths


def test_the_signal_names_the_workflow_that_carries_it(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "name: ci\non: [push, merge_group]\n")

    paths = analyze_workflows(repo).merge_queue_signal_paths

    assert [p.name for p in paths] == ["ci.yml"]
