"""`scripts/check_sdist_test_slice.py` must accept two states and refuse the third.

The defect it exists for: the sdist carried the eight top-level modules of `tests/` and
not `tests/conftest.py`, two of them import that module, and pytest inside the unpacked
sdist answered `ModuleNotFoundError` and aborted collection. Eight test files shipped and
none of them ran.

The rule is therefore not "ship no tests". Shipping the whole suite is a reasonable choice
and packagers ask for it. Shipping a part of it that raises on import is not, because it
looks like coverage and is none.

These cases feed the pure function synthetic member lists rather than building an sdist.
The build needs setuptools, which a 3.12 virtual environment no longer installs, so a test
that built one would either reach the network or fail depending on the environment. The
artifact itself is checked by the `Package` job, which already has one built.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from tests.conftest import ROOT


def _script() -> ModuleType:
    """Import `scripts/check_sdist_test_slice.py`, which is not on the import path."""

    path = ROOT / "scripts" / "check_sdist_test_slice.py"
    spec = importlib.util.spec_from_file_location("check_sdist_test_slice", path)
    assert spec and spec.loader, "could not locate scripts/check_sdist_test_slice.py"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


unrunnable_test_slice = _script().unrunnable_test_slice

_STEM = "oss_policy_kit-10.0.24"


def _members(*paths: str) -> list[str]:
    return [f"{_STEM}/{path}" for path in paths]


def test_a_slice_without_conftest_is_refused() -> None:
    offenders = unrunnable_test_slice(_members("PKG-INFO", "tests/test_a.py", "tests/test_b.py"))

    assert offenders == ["tests/test_a.py", "tests/test_b.py"]


def test_an_sdist_with_no_tests_is_accepted() -> None:
    assert unrunnable_test_slice(_members("PKG-INFO", "src/oss_policy_kit/__init__.py")) == []


def test_an_sdist_shipping_conftest_with_them_is_accepted() -> None:
    """The other accepted state: the whole suite, which a packager can actually run."""

    members = _members("tests/conftest.py", "tests/test_a.py", "tests/application/test_b.py")

    assert unrunnable_test_slice(members) == []


def test_conftest_alone_is_not_a_slice() -> None:
    """It imports nothing of its own, so it cannot be the thing that fails to import."""

    assert unrunnable_test_slice(_members("tests/conftest.py")) == []


def test_a_non_python_file_under_tests_is_not_a_module() -> None:
    """Fixtures are data. They ship or they do not; neither makes collection abort."""

    assert unrunnable_test_slice(_members("tests/fixtures/repo/SECURITY.md")) == []


@pytest.mark.parametrize("stem", ["oss_policy_kit-1.0.0", "oss_policy_kit-99.9.9rc1"])
def test_the_version_in_the_prefix_is_not_part_of_the_comparison(stem: str) -> None:
    """The prefix changes every release, so a check keyed on it would pass by accident."""

    assert unrunnable_test_slice([f"{stem}/tests/test_a.py"]) == ["tests/test_a.py"]


def test_this_repository_prunes_tests_from_the_sdist() -> None:
    """The configuration that makes the above hold for the artifact this project publishes."""

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert any(line.strip() == "prune tests" for line in manifest.splitlines()), (
        "MANIFEST.in no longer prunes tests, so the setuptools default decides what ships "
        "again. That default is what produced the slice this guard exists for."
    )


def test_the_script_reports_a_missing_dist_rather_than_passing(tmp_path: Path) -> None:
    """An empty `dist/` must not read as a clean result."""

    assert _script().main([str(tmp_path)]) == 2
