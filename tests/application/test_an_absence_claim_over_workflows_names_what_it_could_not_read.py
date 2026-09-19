"""A control that says "not in your workflows" must say which ones it could not read.

`SEC-DEPREV-011` already does this, and a test already covers it. It was the only one.
Four siblings answered FAIL on absence with the same unqualified sentence: `SEC-CODEQL-010`,
`SEC-SECRETS-050`, `GH-MERGEQ-053` and `CONT-IMAGE-003`. Against a repository with one
readable workflow and one that will not parse, each stated an absence it had not established.

Two more matched the static shape and were measured out of it. `CI-WF-005` reaches its FAIL
only when `workflow_paths` is empty, and an unreadable file is still listed there, so its
absence claim is about a repository with no workflow files at all. `GH-PROV-023` degrades to
`manual-review-required` whenever a workflow goes unread, so its FAIL branch is reached only
when everything was read. In both, the clause would have appended an empty string forever.
They still take part below, and skip with the reason measured.

The FAIL itself is right and stays. `_shared.unchecked_workflows_note` exists for exactly
this and `unread_workflow_degradation` does not apply: withdrawing a FAIL would take the
failure out of `--fail-on fail`, so a target that genuinely lacks the control and has one
unreadable workflow would get a green pipeline. Only the sentence was overstating.

The set is derived rather than listed. A control added later with the same shape joins the
parametrisation on its own, which is the property a hand-written list of six cannot have,
and how this family came to have six members nobody had counted.
"""

from __future__ import annotations

import ast
import pathlib
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import cicd, github, supply_chain
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

_MODULES = (cicd, github, supply_chain)

#: A workflow that is valid YAML nowhere: the parser records it and reads nothing from it.
_UNPARSEABLE = "name: ci\non: [push\njobs: {{{\n"

#: A second workflow that parses and carries no security signal. Without it several controls
#: take an earlier branch, and a guard whose subjects all skip proves nothing.
_READABLE = "name: build\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"


def _absence_is_fail() -> list[str]:
    """Names of evaluators that read workflows and answer FAIL when they find nothing.

    The criterion is the one that sorts this whole family: what the control concludes from
    finding nothing decides which of the two `_shared` helpers it may use. Taken from the
    source rather than from a list, and ordered by line because `ast.walk` is breadth-first
    and the last `Return` it yields is not the last one in the file.
    """

    names: list[str] = []
    for module in _MODULES:
        text = pathlib.Path(module.__file__ or "").read_text(encoding="utf-8")
        tree = ast.parse(text)
        for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("eval_")):
            source = ast.get_source_segment(text, fn) or ""
            if "ctx.workflows" not in source:
                continue
            returns = sorted(
                (n for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None),
                key=lambda n: n.lineno,
            )
            if returns and "ControlStatus.FAIL" in ast.unparse(returns[-1]):
                names.append(f"{module.__name__.rsplit('.', 1)[-1]}.{fn.name}")
    return sorted(names)


_EVALUATORS = _absence_is_fail()


def _callable(dotted: str) -> Any:
    module_name, function_name = dotted.split(".")
    return getattr({m.__name__.rsplit(".", 1)[-1]: m for m in _MODULES}[module_name], function_name)


def _build_ctx(root: Path) -> EvalContext:
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "good.yml").write_text(_READABLE, encoding="utf-8")
    (workflows / "broken.yml").write_text(_UNPARSEABLE, encoding="utf-8")
    # CONT-IMAGE-003 answers `not-applicable` without one, and that is a different claim.
    (root / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    return EvalContext(
        repo_root=root,
        profile_id="github-level-1",
        workflows=analyze_workflows(root),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


@pytest.fixture
def ctx_with_an_unreadable_workflow(tmp_path: Path) -> EvalContext:
    return _build_ctx(tmp_path)


def test_the_family_is_not_empty() -> None:
    """Anti-vacuum: a derivation that finds nothing would make every case below pass."""

    assert len(_EVALUATORS) >= 7, (
        f"the derivation found {len(_EVALUATORS)} evaluators that answer FAIL on absence over "
        "workflows; it found seven when this guard was written, so it has stopped matching"
    )


@pytest.mark.parametrize("dotted", _EVALUATORS)
def test_an_absence_claim_names_the_workflow_it_could_not_read(
    dotted: str, ctx_with_an_unreadable_workflow: EvalContext
) -> None:
    outcome = _callable(dotted)(ctx_with_an_unreadable_workflow)
    if outcome.status is not ControlStatus.FAIL:
        pytest.skip(f"{dotted} did not answer FAIL on this fixture, so it claims no absence here")

    assert "broken.yml" in outcome.reason, (
        f"{dotted} answers FAIL and its reason does not name `broken.yml`, the one workflow in "
        f"the repository and the one it could not read. The sentence claims an absence across "
        f"workflows it never inspected. Reason was: {outcome.reason!r}"
    )


def test_the_fixture_really_is_unreadable(ctx_with_an_unreadable_workflow: EvalContext) -> None:
    """Without this, an accidentally-valid fixture would make every case above skip or pass."""

    workflows = ctx_with_an_unreadable_workflow.workflows
    unreadable = {p.name for p, _ in workflows.parse_errors} | {p.name for p in workflows.unread_paths}

    assert unreadable == {"broken.yml"}, f"the fixture parsed fine, so nothing is unread: {unreadable}"
    assert {p.name for p in workflows.workflow_paths} == {"good.yml", "broken.yml"}


def test_four_of_them_actually_reach_the_branch_under_test(tmp_path: Path) -> None:
    """A parametrisation where every case skips is green and worthless.

    Four was the measured number when this was written. Fewer means a control stopped
    reaching its own FAIL branch on this fixture, and the guard stopped watching it.
    """

    ctx = _build_ctx(tmp_path)
    reached = sum(1 for dotted in _EVALUATORS if _callable(dotted)(ctx).status is ControlStatus.FAIL)

    assert reached >= 4, f"only {reached} of {len(_EVALUATORS)} reached a FAIL on the fixture"
