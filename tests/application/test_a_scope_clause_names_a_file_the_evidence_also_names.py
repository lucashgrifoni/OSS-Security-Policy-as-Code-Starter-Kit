"""A control that says it could not read a file has to hand back that file.

Five controls keep a FAIL and append `unchecked_workflows_note`, so their prose reads
"This run could not read ci.yml, so the result does not cover it." All five passed
`evidence_sources=[]`, so the sentence reached a human and nothing reached a consumer.
`CI-PIN-008`, evaluating the same repository in the same run, carried the path.

Keeping the FAIL is deliberate and is not what this changes. The rule is written in
`unchecked_workflows_note`'s own docstring: withdrawing a FAIL because one workflow was
unreadable takes a failure out of `--fail-on fail`, and for an adopter who genuinely lacks
the control and has one unreadable workflow, that turns a red pipeline green. So the
verdict stays and stops overstating its reach. What was missing is the other half of
"stops overstating": the reader of the JSON or the SARIF could not see which file.

Measured against a repository holding a 1.7 MiB `.github/workflows/ci.yml` that the input
size cap refuses. Before: `SEC-CODEQL-010` and `SEC-DEPREV-011` both FAIL with
`references: []`. After: both still FAIL, both reference the file, and the prose is
unchanged.

The last two tests are the ones meant to last. One derives the set of call sites from the
evaluator package, so a sixth control appending the note without the paths is caught where
it is written. The other checks the sentence and the references name the same files, which
is the way these two drift apart.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest
from tests.conftest import ROOT

from oss_policy_kit.application.input_limits import MAX_CI_CONFIG_BYTES

EVALUATORS = ROOT / "src" / "oss_policy_kit" / "application" / "evaluators"

#: The controls that keep a FAIL and append the scope clause, by the function that builds
#: them. Derived membership is asserted below; this is only for readable failures.
_CONTROLS_THAT_APPEND_THE_NOTE = {
    "eval_sec_codeql_010": "SEC-CODEQL-010",
    "eval_sec_deprev_011": "SEC-DEPREV-011",
    "eval_sec_secrets_050": "SEC-SECRETS-050",
    "eval_gh_mergeq_053": "GH-MERGEQ-053",
    "eval_cont_image_003": "CONT-IMAGE-003",
}


def _repo_with_an_unreadable_workflow(tmp_path: Path) -> Path:
    """A workflow past the input size cap, so nothing in it is ever scanned."""

    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "README.md").write_text("# repo\n", encoding="utf-8")
    head = (
        "name: ci\non: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: github/codeql-action/init@df409f7d9260372bd5f19e5b04e83cb3c43714ae # v3\n"
    )
    # The file has to land past MAX_CI_CONFIG_BYTES or it is simply read and the control
    # passes, which is what the first draft of this fixture measured: 30,000 short lines
    # came to about 840 KB, under the 1 MiB cap, and SEC-CODEQL-010 answered PASS because
    # the CodeQL step in the header was found. The assertion below is the fixture checking
    # its own premise.
    padding = "\n".join(
        f"      # padding line {i}, long enough that thirty thousand of them clear the cap" for i in range(30_000)
    )
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.write_text(head + padding + "\n", encoding="utf-8")
    assert workflow.stat().st_size > MAX_CI_CONFIG_BYTES, (
        f"fixture is {workflow.stat().st_size} bytes, under the {MAX_CI_CONFIG_BYTES}-byte cap, "
        "so the workflow would be read and the control would pass for the wrong reason"
    )
    return repo


def _evaluate(repo: Path) -> dict[str, dict[str, object]]:
    result = subprocess.run(  # noqa: S603 - fixed argv, shell=False
        [
            sys.executable,
            "-P",
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(repo / "out"),
            "--fail-on",
            "none",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, f"evaluate failed: {result.stderr[-400:]}"
    payload = json.loads((repo / "out" / "evaluation-report.json").read_text(encoding="utf-8"))
    return {control["id"]: control for control in payload["controls"]}


@pytest.fixture(scope="module")
def controls(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, object]]:
    return _evaluate(_repo_with_an_unreadable_workflow(tmp_path_factory.mktemp("f12")))


@pytest.mark.parametrize("control_id", ["SEC-CODEQL-010", "SEC-DEPREV-011"])
def test_the_control_hands_back_the_file_it_could_not_read(
    control_id: str, controls: dict[str, dict[str, object]]
) -> None:
    control = controls[control_id]
    message = str(control.get("message") or "")
    references = [str(r["value"]) for r in (control.get("evidence") or {}).get("references") or []]  # type: ignore[union-attr]

    assert "could not read ci.yml" in message, f"the scope clause is gone: {message}"
    assert any(value.endswith("ci.yml") for value in references), (
        f"{control_id} names ci.yml in prose and references {references}; a consumer reading "
        "the JSON or the SARIF is told nothing"
    )


@pytest.mark.parametrize("control_id", ["SEC-CODEQL-010", "SEC-DEPREV-011"])
def test_the_verdict_is_still_fail(control_id: str, controls: dict[str, dict[str, object]]) -> None:
    """The doctrine, asserted. Downgrading here would turn a red pipeline green."""

    assert controls[control_id]["state"] == "FAIL", (
        "an unreadable workflow must not withdraw a FAIL: see the rule in unchecked_workflows_note's docstring"
    )


def test_the_sentence_and_the_references_name_the_same_file(controls: dict[str, dict[str, object]]) -> None:
    """The way these two drift: one is edited and the other is not."""

    for control_id in ("SEC-CODEQL-010", "SEC-DEPREV-011"):
        control = controls[control_id]
        references = {Path(str(r["value"])).name for r in (control.get("evidence") or {}).get("references") or []}  # type: ignore[union-attr]
        message = str(control.get("message") or "")
        named = {word.strip(".,") for word in message.split() if word.strip(".,").endswith((".yml", ".yaml"))}

        assert named == references, f"{control_id}: prose names {named}, references name {references}"


def test_every_control_that_appends_the_note_also_hands_back_the_paths() -> None:
    """Derived from the package, so the sixth one is caught where it is written."""

    offenders: list[str] = []
    for path in sorted(EVALUATORS.glob("*.py")):
        if path.name == "_shared.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = ast.unparse(node)
            if "unchecked_workflows_note(" not in body:
                continue
            if "unchecked_workflow_paths(" not in body:
                offenders.append(f"{path.name}:{node.lineno} ({node.name})")

    assert not offenders, (
        "these evaluators say in prose that a workflow could not be read and hand back no "
        f"reference to it: {', '.join(offenders)}. Pass "
        "evidence_sources=unchecked_workflow_paths(ctx.workflows)."
    )


def test_the_guard_above_would_notice_a_sixth_one() -> None:
    """The mutation, in-process: the note without the paths must be flagged."""

    source = (
        "def eval_x(ctx):\n"
        "    return EvalOutcome(status=ControlStatus.FAIL,\n"
        '        reason=f"No signal.{unchecked_workflows_note(ctx.workflows)}",\n'
        "        evidence_sources=[])\n"
    )
    function = ast.parse(source).body[0]
    body = ast.unparse(function)

    assert "unchecked_workflows_note(" in body
    assert "unchecked_workflow_paths(" not in body, "the detection this file relies on does not fire"


def test_the_helper_and_the_note_read_the_same_two_lists() -> None:
    """They are separate functions, and the point is that they cannot disagree."""

    from oss_policy_kit.application.evaluators._shared import (
        unchecked_workflow_paths,
        unchecked_workflows_note,
    )

    class _Workflows:
        parse_errors = [(Path("a/broken.yml"), "bad yaml")]
        unread_paths = [Path("b/toobig.yaml")]

    note = unchecked_workflows_note(_Workflows())
    paths = {Path(p).name for p in unchecked_workflow_paths(_Workflows())}

    assert "broken.yml" in note and "toobig.yaml" in note
    assert paths == {"broken.yml", "toobig.yaml"}


def test_a_repository_whose_workflows_all_read_gets_no_stray_reference() -> None:
    """The other direction: the helper is empty when the note is empty."""

    from oss_policy_kit.application.evaluators._shared import (
        unchecked_workflow_paths,
        unchecked_workflows_note,
    )

    class _Clean:
        parse_errors: list[tuple[Path, str]] = []
        unread_paths: list[Path] = []

    assert unchecked_workflows_note(_Clean()) == ""
    assert unchecked_workflow_paths(_Clean()) == []


def test_the_named_set_matches_the_function_map() -> None:
    """Keeps the readable list above honest against the package."""

    found = set()
    for path in sorted(EVALUATORS.glob("*.py")):
        if path.name == "_shared.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and "unchecked_workflows_note(" in ast.unparse(
                node
            ):
                found.add(node.name)

    assert found == set(_CONTROLS_THAT_APPEND_THE_NOTE), (
        f"the set of controls appending the scope clause changed: {sorted(found)}"
    )
