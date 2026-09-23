"""`scripts/check_dist_ships_no_bytecode.py`, and the Package job that gives it something to refuse.

``pyproject.toml`` excludes ``__pycache__`` and ``*.py[co]`` from package data, and nothing
checked the rule. Every build that could have exercised it started from a fresh checkout with
no bytecode in it, so each clean wheel was an answer to a question nobody asked.

The job now compiles ``src/`` before it builds. Without that step the check would pass on an
empty tree, which is the defect it exists to close, so the order is pinned here too.
"""

from __future__ import annotations

import importlib.util
import io
import tarfile
import tomllib
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from tests.conftest import ROOT


def _script() -> ModuleType:
    """Import `scripts/check_dist_ships_no_bytecode.py`, which is not on the import path."""

    path = ROOT / "scripts" / "check_dist_ships_no_bytecode.py"
    spec = importlib.util.spec_from_file_location("check_dist_ships_no_bytecode", path)
    assert spec and spec.loader, "could not locate scripts/check_dist_ships_no_bytecode.py"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SCRIPT = _script()
bytecode_members = _SCRIPT.bytecode_members

_CACHED = "oss_policy_kit/data/schema/__pycache__/__init__.cpython-312.pyc"


@pytest.mark.parametrize(
    "member",
    [_CACHED, "oss_policy_kit/data/schema/__pycache__/", "oss_policy_kit/legacy.pyo", "oss_policy_kit/stray.pyc"],
)
def test_bytecode_is_refused(member: str) -> None:
    assert bytecode_members(["oss_policy_kit/__init__.py", member]) == [member]


@pytest.mark.parametrize(
    "member",
    ["oss_policy_kit/__init__.py", "oss_policy_kit/data/pycparser.yaml", "oss_policy_kit/py.typed"],
)
def test_source_and_data_are_not_bytecode(member: str) -> None:
    """``.pyc`` is a suffix and ``__pycache__`` a directory; neither is a substring match."""

    assert bytecode_members([member]) == []


def _wheel(path: Path, *members: str) -> None:
    with zipfile.ZipFile(path, "w") as handle:
        for member in members:
            handle.writestr(member, b"")


def _sdist(path: Path, *members: str) -> None:
    with tarfile.open(path, "w:gz") as handle:
        for member in members:
            handle.addfile(tarfile.TarInfo(f"oss_policy_kit-1.0.0/src/{member}"), io.BytesIO(b""))


def test_a_wheel_with_bytecode_fails_the_check(tmp_path: Path) -> None:
    _wheel(tmp_path / "oss_policy_kit-1.0.0-py3-none-any.whl", "oss_policy_kit/__init__.py", _CACHED)
    _sdist(tmp_path / "oss_policy_kit-1.0.0.tar.gz", "oss_policy_kit/__init__.py")

    assert _SCRIPT.main([str(tmp_path)]) == 1


def test_an_sdist_with_bytecode_fails_the_check(tmp_path: Path) -> None:
    _wheel(tmp_path / "oss_policy_kit-1.0.0-py3-none-any.whl", "oss_policy_kit/__init__.py")
    _sdist(tmp_path / "oss_policy_kit-1.0.0.tar.gz", "oss_policy_kit/__init__.py", _CACHED)

    assert _SCRIPT.main([str(tmp_path)]) == 1


def test_clean_distributions_pass(tmp_path: Path) -> None:
    _wheel(tmp_path / "oss_policy_kit-1.0.0-py3-none-any.whl", "oss_policy_kit/__init__.py")
    _sdist(tmp_path / "oss_policy_kit-1.0.0.tar.gz", "oss_policy_kit/__init__.py")

    assert _SCRIPT.main([str(tmp_path)]) == 0


def test_no_distribution_is_an_error_not_a_pass(tmp_path: Path) -> None:
    """An empty ``dist/`` has nothing clean in it; reading it as clean is the original defect."""

    assert _SCRIPT.main([str(tmp_path)]) == 2


def _package_runs() -> list[str]:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "github-ci-cd.yml").read_text(encoding="utf-8"))
    return [str(step.get("run", "")) for step in workflow["jobs"]["package"]["steps"]]


def test_the_package_job_compiles_the_source_before_it_builds_and_checks_after() -> None:
    runs = _package_runs()
    build = runs.index("python -m build")
    compiled = [i for i, run in enumerate(runs) if "compileall" in run and "src/oss_policy_kit" in run]
    checked = [i for i, run in enumerate(runs) if "check_dist_ships_no_bytecode.py" in run]

    assert compiled and max(compiled) < build, (
        "nothing is compiled before the build, so the check has nothing to refuse"
    )
    assert checked and min(checked) > build, "the bytecode check does not run on the built distribution"


def test_the_exclusion_rule_is_still_declared() -> None:
    """The second layer. Today the narrow package-data patterns alone keep bytecode out."""

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    rule = declared["tool"]["setuptools"]["exclude-package-data"]["oss_policy_kit"]

    assert {"**/__pycache__", "**/__pycache__/**", "**/*.py[co]"} <= set(rule)
