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


def test_a_cleaned_environment_actually_changes_which_package_a_child_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mechanism, end to end, rather than a property of the dict.

    Without it the two cases above only say that a key was removed from a mapping. This one
    shows the removal decides which `oss_policy_kit` a subprocess imports, which is the
    thing the script exists to get right.
    """

    argv = [sys.executable, "-c", "import oss_policy_kit as m; print(m.__file__)"]
    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src"))
    polluted = dict(os.environ)
    # Passed whole rather than merged over the polluted one: a dict merge cannot remove a
    # key, so {**polluted, **cleaned} keeps PYTHONPATH and the case proves nothing. The
    # first version of this test did exactly that and failed, which is how it was caught.
    cleaned_env = _script()._child_env()

    with_pollution = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, capture_output=True, text=True, encoding="utf-8", env=polluted, check=True
    ).stdout.strip()
    cleaned = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cleaned_env,
        check=True,
    ).stdout.strip()

    assert with_pollution != cleaned or str(ROOT / "src") not in with_pollution, (
        "PYTHONPATH did not change the resolved package here, so this environment cannot "
        "demonstrate the shadowing the fix is about"
    )
    assert str(ROOT / "src") not in cleaned, (
        f"a child started from the cleaned environment still imported {cleaned}, which is the "
        "tree PYTHONPATH named rather than what the venv installed"
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
