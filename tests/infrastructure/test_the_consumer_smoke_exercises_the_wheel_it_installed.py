"""The consumer smoke must run the wheel it installed, whatever the operator's environment.

`scripts/consumer_smoke.py` installs the built wheel into a throwaway venv and then runs
the CLI. It passed no `env` to any of its four subprocesses, so they inherited the parent's.
An operator with `PYTHONPATH` pointing at a `src/` got a run that installed the artifact and
then exercised the working tree, finished green, and proved nothing about what was built.
The release checklist leans on that script, and no workflow runs it, so nothing else would
have noticed.

Measured on a virtual environment that has the package installed:

    no PYTHONPATH  -> the venv's copy
    PYTHONPATH set -> the tree PYTHONPATH names

The `cwd` is a separate question and the answer is that it is fine. The steps evaluate
`examples/hardened-repo` and the fixtures by relative path, so the script has to run from
the checkout, and running there shadows nothing: the repo root holds no top-level
`oss_policy_kit` package, only `src/oss_policy_kit`. `PYTHONPATH` is the whole vector, which
is why the fix is only about the environment.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
from tests.conftest import ROOT


def _script() -> ModuleType:
    path = ROOT / "scripts" / "consumer_smoke.py"
    spec = importlib.util.spec_from_file_location("consumer_smoke", path)
    assert spec and spec.loader, "could not locate scripts/consumer_smoke.py"
    module = importlib.util.module_from_spec(spec)
    # Registered before execution because the script defines dataclasses, and @dataclass
    # resolves its annotations through sys.modules[cls.__module__]; a module that is not
    # there yet fails with an AttributeError inside dataclasses itself.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


@pytest.mark.parametrize("variable", ["PYTHONPATH", "PYTHONHOME"])
def test_the_child_environment_drops_the_import_path_overrides(variable: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(variable, str(ROOT / "src"))

    assert variable not in _script()._child_env()


def test_the_child_environment_keeps_everything_else(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stripped environment would break the run in other ways: only these two go."""

    monkeypatch.setenv("OSS_POLICY_KIT_SMOKE_MARKER", "kept")
    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src"))

    env = _script()._child_env()

    assert env.get("OSS_POLICY_KIT_SMOKE_MARKER") == "kept"
    assert set(os.environ) - set(env) == {"PYTHONPATH"}


def test_a_cleaned_environment_actually_changes_what_a_child_can_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mechanism, end to end, rather than a property of the dict.

    Deliberately a module nobody has installed. The first version of this case imported
    `oss_policy_kit` and asserted the resolved path was not `<repo>/src`, which passed here
    and failed on CI: CI installs the project with `pip install -e .`, so `<repo>/src` is
    exactly where a clean environment resolves it. The assertion could not hold there, and
    the difference was not the operating system or the Python version but which tree the
    editable install points at. A module that exists only under `PYTHONPATH` removes the
    question.
    """

    (tmp_path / "smoke_probe.py").write_text("VALUE = 'from PYTHONPATH'\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    argv = [sys.executable, "-c", "import smoke_probe; print(smoke_probe.VALUE)"]

    reachable = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, capture_output=True, text=True, encoding="utf-8", env=dict(os.environ), check=False
    )
    hidden = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, capture_output=True, text=True, encoding="utf-8", env=_script()._child_env(), check=False
    )

    assert reachable.returncode == 0 and "from PYTHONPATH" in reachable.stdout, (
        "PYTHONPATH did not reach the child at all, so this environment cannot demonstrate "
        f"the shadowing the fix is about: {reachable.stderr!r}"
    )
    assert hidden.returncode != 0, (
        "a child started from the cleaned environment still imported a module that exists "
        "only under PYTHONPATH, so the cleaning did not take effect"
    )


def test_every_subprocess_in_the_script_passes_the_cleaned_environment() -> None:
    """Four call sites today. A fifth added without `env=` reopens the hole silently."""

    source = (ROOT / "scripts" / "consumer_smoke.py").read_text(encoding="utf-8")
    launches = source.count("subprocess.run(")
    cleaned = source.count("env=_child_env()")

    assert launches >= 4, f"the script starts {launches} subprocesses; it started four when this was written"
    assert cleaned == launches, (
        f"{launches} subprocesses start and {cleaned} of them pass the cleaned environment. "
        "One that inherits PYTHONPATH can import the working tree instead of the wheel."
    )
