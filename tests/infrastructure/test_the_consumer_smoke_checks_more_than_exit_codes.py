"""The consumer smoke has to prove the wheel did something, not that a process ended.

Three defects in one script, all of them the same shape: a check that cannot fail for the
reason it exists.

`_run` captured stdout and stderr and returned only the return code, so a red summary named
a step and gave nothing to act on. The selfcheck step writes a report and nothing looked for
it, so every check passed for a run that wrote no report at all. And every step invoked
`-m oss_policy_kit`, never the `oss-policy-kit` executable the wheel installs, which is what
the documentation tells an adopter to type: a broken `[project.scripts]` would have shipped
with the whole summary green.

Measured on a real run of the script against a freshly built wheel, before and after: the
step list went from 10 to 12, the console script answered `--version` with exit 0, and the
artifact step found the report. Pointing that step at a filename the selfcheck does not
write makes the script exit 1 and name `selfcheck_wrote_a_report`.

The fourth item is in `docs/release-readiness.md`, which credited this script with an sdist
install it cannot perform. It handles wheels only, and refuses anything not ending in
`.whl`.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from types import ModuleType

import pytest
from tests.conftest import ROOT

_SCRIPT_PATH = ROOT / "scripts" / "consumer_smoke.py"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("consumer_smoke", _SCRIPT_PATH)
    assert spec and spec.loader, "could not locate scripts/consumer_smoke.py"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def test_a_step_can_carry_why_it_failed() -> None:
    """Without the field there is nowhere to put the reason, whatever the runner does."""

    step = _script().SmokeStep(name="x", argv=["--version"], exit_code=1, expected_exit_code=0)

    assert hasattr(step, "stderr_excerpt")
    assert step.stderr_excerpt == "", "the excerpt has to default to empty, not to None"


def test_the_runner_returns_the_output_beside_the_code() -> None:
    """`_run` returning a bare int is what made the captured streams pointless."""

    import inspect

    signature = inspect.signature(_script()._run)

    assert str(signature.return_annotation) in {"tuple[int, str]", "typing.Tuple[int, str]"}, (
        f"_run returns {signature.return_annotation}; a bare code cannot carry the reason"
    )


def test_the_console_script_is_resolved_inside_the_virtualenv(tmp_path) -> None:
    """The entry point an adopter types, which nothing exercised."""

    resolved = _script()._console_script(tmp_path)

    assert resolved.parent.parent == tmp_path, "the executable has to come from the venv under test"
    assert resolved.parent.name == ("Scripts" if os.name == "nt" else "bin")
    assert resolved.name.startswith("oss-policy-kit")


def test_the_script_runs_the_console_script_and_checks_the_artifact() -> None:
    """Both additions are wired into the step list rather than living beside it.

    Read from the source because building a wheel and a virtualenv inside a unit test would
    take a minute and reach the network. The behaviour itself was measured by running the
    script; this keeps the wiring from being removed afterwards.
    """

    source = _SCRIPT_PATH.read_text(encoding="utf-8")

    assert "add_console(" in source, "no step invokes the installed console script"
    assert "selfcheck_wrote_a_report" in source, "nothing checks that the selfcheck wrote its report"
    assert source.count('Path("out") / "consumer-smoke-selfcheck"') == 1, (
        "the selfcheck output path is spelled more than once, so the step that writes it and "
        "the check that looks for it can drift apart"
    )


def test_the_release_checklist_no_longer_credits_it_with_an_sdist_install() -> None:
    """It handles wheels only, and `_validate_wheel_glob` refuses anything else."""

    checklist = (ROOT / "docs" / "release-readiness.md").read_text(encoding="utf-8")
    line = next(line for line in checklist.splitlines() if "consumer_smoke.py" in line and line.startswith("- [ ]"))

    assert "sdist install" not in line, f"the checklist still promises an sdist install: {line}"
    assert "console script" in line, "the checklist does not mention what the script now covers"


@pytest.mark.parametrize("suffix", [".tar.gz", ".zip", ""])
def test_the_script_still_refuses_anything_that_is_not_a_wheel(suffix: str) -> None:
    """The reason the checklist line was wrong, asserted rather than assumed."""

    with pytest.raises(SystemExit):
        _script()._validate_wheel_glob(f"dist/oss_policy_kit-1.0.0{suffix}")
