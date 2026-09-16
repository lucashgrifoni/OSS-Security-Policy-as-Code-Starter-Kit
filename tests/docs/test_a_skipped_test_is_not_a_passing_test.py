"""A test gated on an environment variable nobody sets runs in no environment at all.

`tests/integration/test_collect_evidence_github.py` skips unless `GITHUB_TOKEN` is in the
environment. In GitHub Actions that variable is not set automatically: the token is available
as `secrets.GITHUB_TOKEN` and reaches a step only through an explicit `env:`. No job passed it,
and nobody exports it locally, so the module skipped everywhere it has ever run. pytest reported
a skip, which is the quietest possible way to report nothing, and the suite counted it as a file
that exists rather than as a check that ran.

The gate itself is right. A live API call does not belong in the required check, where a GitHub
incident would block every merge in the repository. What was missing is the other half: a place
where it does run. `.github/workflows/live-collector-canary.yml` is that place, scheduled weekly
and dispatchable, never a required check.

This guard derives the pairing rather than naming the file: every env-gated test module found in
the tree must be wired to a workflow step that sets its variable and runs that module. Add
another such module tomorrow without wiring it up and this fails, instead of the module joining
the first one in permanent silence.

What it does NOT check: that the canary job passes, or that the token it receives has the scope
the test needs. A workflow can set the variable to an empty string and satisfy this file while
the module skips exactly as before, which is why the job passes `github.token` and the step runs
pytest with `-rs` so a skip prints its reason into the run.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

from tests.conftest import ROOT

_TESTS = ROOT / "tests"
_WORKFLOWS = ROOT / ".github" / "workflows"
_ENV_NAME = re.compile(r"environ(?:\.get\(|\[)['\"]([A-Z_][A-Z0-9_]*)['\"]")


def _env_gated_modules() -> list[tuple[Path, str]]:
    """Every test module whose collection depends on an environment variable, by AST.

    Reads `pytest.mark.skipif` calls rather than a maintained list, so a module added later is
    covered without anyone remembering this file exists.
    """

    found: list[tuple[Path, str]] = []
    for path in sorted(_TESTS.rglob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - a file that will not parse fails elsewhere
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "skipif"):
                continue
            source = ast.unparse(node)
            for name in _ENV_NAME.findall(source):
                found.append((path, name))
    return found


def _steps_that_set(name: str) -> list[dict[str, object]]:
    """Every workflow step whose `env:` carries *name*.

    `yaml.safe_load` turns the `on:` key into the boolean True, which is why nothing here
    reads it: jobs and steps are what this guard needs, and they are ordinary string keys.
    """

    steps: list[dict[str, object]] = []
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        for job in (document.get("jobs") or {}).values():
            for step in (job or {}).get("steps") or []:
                if name in ((step or {}).get("env") or {}):
                    steps.append(step)
    return steps


def test_every_env_gated_test_has_somewhere_it_actually_runs() -> None:
    unwired: list[str] = []
    for path, name in _env_gated_modules():
        relative = path.relative_to(ROOT).as_posix()
        directory = path.parent.relative_to(ROOT).as_posix()
        wired = any(
            relative in str(step.get("run", "")) or directory in str(step.get("run", ""))
            for step in _steps_that_set(name)
        )
        if not wired:
            unwired.append(f"{relative} needs {name}, and no workflow step sets it and runs the file")

    assert not unwired, (
        "these tests skip in every environment, so they report a skip instead of a result:\n  " + "\n  ".join(unwired)
    )


def test_the_sweep_found_something_to_check() -> None:
    """The check above passes vacuously if the AST walk returns nothing.

    A renamed decorator or a restructured gate would empty the list and turn this file into
    decoration, which is the exact defect it exists to catch, one level up.
    """

    assert _env_gated_modules(), "no env-gated test module was parsed out of the tests tree"
