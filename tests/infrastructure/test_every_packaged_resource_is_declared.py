"""A resource that exists under the package must be one the wheel actually carries.

This already happened once. `test_v10_0_7_workflow_templates_are_packaged.py` records it:
`pyproject.toml` declared `data/**/*.yaml` and `data/**/*.json`, the workflow templates were
`.yml`, and the wheel shipped no templates at all. `init --with-workflow` -- half of the
README quickstart -- exited 2 on every real install while the suite stayed green, because
pytest runs from the repository root where the unpackaged copy is still reachable.

That guard pins the behaviour of those particular templates. The rule underneath it is not
pinned anywhere: add `data/thresholds.toml` or `data/notice.txt` tomorrow, and it silently
does not ship, and nothing says so until an adopter hits the same class of error.

So this checks the declaration against the tree, which needs no build: expand every
`package-data` pattern the way setuptools will, and require the result to cover every
non-Python file under the package.

Verified against a real wheel while writing this (10.0.15, built locally): 223 files under
`src/oss_policy_kit`, 223 of them present in the wheel, and no file in the wheel that is not
in the tree. This test is what keeps that true.
"""

from __future__ import annotations

import glob
import tomllib

from tests.conftest import ROOT

_PACKAGE = ROOT / "src" / "oss_policy_kit"
_IGNORED_SUFFIXES = {".py", ".pyc", ".pyo"}


def _declared_patterns() -> list[str]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        config = tomllib.load(handle)
    package_data = config["tool"]["setuptools"]["package-data"]
    return list(package_data["oss_policy_kit"])


def _resources_on_disk() -> set[str]:
    """Every non-Python file under the package, relative to it."""

    return {
        path.relative_to(_PACKAGE).as_posix()
        for path in _PACKAGE.rglob("*")
        if path.is_file() and path.suffix not in _IGNORED_SUFFIXES and "__pycache__" not in path.parts
    }


def _covered_by_declaration() -> set[str]:
    """What the declared patterns actually expand to, matched the way setuptools matches.

    `glob` with `recursive=True` is what makes `data/**/*.yaml` mean what it means in
    `pyproject.toml`; without it `**` collapses to a single segment and the deeper files
    look uncovered.
    """

    covered: set[str] = set()
    for pattern in _declared_patterns():
        covered |= {match.replace("\\", "/") for match in glob.glob(pattern, root_dir=str(_PACKAGE), recursive=True)}
    return covered


def test_the_package_actually_carries_resources() -> None:
    """Otherwise the assertion below would hold over an empty set."""

    resources = _resources_on_disk()
    assert resources, (
        "no non-Python resources found under src/oss_policy_kit. The schemas, catalog, "
        "profiles and templates all live there, so finding none means this guard is looking "
        "in the wrong place and proves nothing."
    )


def test_every_resource_under_the_package_is_declared_as_package_data() -> None:
    undeclared = sorted(_resources_on_disk() - _covered_by_declaration())

    assert not undeclared, (
        "these files live inside the package but no `package-data` pattern in pyproject.toml "
        "matches them, so `pip install` leaves them out of the wheel:\n  "
        + "\n  ".join(undeclared)
        + "\n\nThe declared patterns are: "
        + ", ".join(_declared_patterns())
        + "\nThis is the v10.0.7 fault exactly: the templates were `.yml` and the declaration "
        "only said `.yaml`."
    )
