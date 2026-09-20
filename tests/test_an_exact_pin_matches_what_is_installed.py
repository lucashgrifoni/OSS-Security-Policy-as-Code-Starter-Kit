"""An exact pin is a claim about the environment, and nothing was checking it.

`pyproject.toml` pins `ruff==0.16.7` and says why: "ruff format output changes between
versions; keep CI and local identical". On 2026-09-20 a local environment had 0.16.0.
`ruff format --check .` reported "855 files already formatted" and CI failed all three
Quality legs in 43 seconds on two files, because 0.16.7 formats a long signature and a
docstring opening with a quote differently.

Nothing warned about it. The pin is a dependency declaration; installing the package is
what honours it, and an environment built before the pin moved keeps the old version
until someone reinstalls. CI installs from `pyproject.toml` every run, so CI is always
right and only a developer's environment can drift, which is the environment where the
mistake is cheapest to make and most expensive to find.

This reads the pins out of `pyproject.toml` rather than naming ruff, so a second exact
pin is covered the day it is added.

A package that is not installed is not a disagreement, so it is reported rather than
failed: the suite can run without the linting tools. What would be a silent pass is the
pin list coming back empty, so that is asserted separately.
"""

from __future__ import annotations

import re
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

#: `name==version`, ignoring extras, markers and anything after the version.
_EXACT_PIN = re.compile(r"^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s,;]+)")


def _exact_pins() -> dict[str, str]:
    """Every `name==version` in the project's dependency groups."""

    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data.get("project", {})
    requirements: list[str] = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        requirements.extend(group)
    for group in data.get("dependency-groups", {}).values():
        requirements.extend(r for r in group if isinstance(r, str))

    pins: dict[str, str] = {}
    for raw in requirements:
        match = _EXACT_PIN.match(raw.strip())
        if match:
            pins[match.group(1)] = match.group(2)
    return pins


def test_the_pin_list_is_not_empty() -> None:
    """An empty list would make the check below pass without checking anything."""

    pins = _exact_pins()
    assert pins, f"no exact pins parsed out of {PYPROJECT.name}; the parser or the file changed"


def test_no_installed_package_disagrees_with_its_exact_pin() -> None:
    """The environment running this suite honours every pin it has installed."""

    wrong: list[str] = []
    checked = 0
    absent: list[str] = []
    for name, pinned in sorted(_exact_pins().items()):
        try:
            installed = version(name)
        except PackageNotFoundError:
            absent.append(name)
            continue
        checked += 1
        if installed != pinned:
            wrong.append(f"{name}: pinned {pinned}, installed {installed}")

    assert not wrong, (
        "this environment disagrees with pyproject.toml, so a local check can pass while "
        "CI fails on the same command. Reinstall with `pip install -e .[dev]`:\n  "
        + "\n  ".join(wrong)
        + f"\n({checked} pin(s) checked, not installed here: {absent or 'none'})"
    )


def test_the_pin_that_prompted_this_is_still_pinned_exactly() -> None:
    """ruff is pinned for a reason written next to it; a floor would not hold the format.

    Named deliberately, unlike the sweep above. If someone relaxes this one to a floor,
    the sweep stops covering it and says nothing, because there is no longer a pin to
    disagree with.
    """

    assert "ruff" in _exact_pins(), (
        "ruff is no longer pinned to an exact version. Its format output changes between "
        "releases, so a floor lets CI and a local run disagree about the same files."
    )
