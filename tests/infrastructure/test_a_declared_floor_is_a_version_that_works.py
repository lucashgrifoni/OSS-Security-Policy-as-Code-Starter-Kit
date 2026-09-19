"""The wheel declared a dependency contract that was false in two directions at once.

`pyproject.toml` said `typer>=0.12.5`. `cli/common.py` imports `typer.core.HAS_RICH`, which
first exists in typer 0.19.0, and `cli/common.py` is imported by every command module. So any
resolution in the seven releases from 0.12.5 to 0.18.0 produced an install pip calls successful
and a CLI where every command exits 1 with an ImportError before it does anything. It passes
today only because pip picks the newest typer; a constraints file, an offline index, a mirror or
a co-installed transitive pin all reach the broken range.

In the other direction, six shipped modules import `rich` at module scope and `rich` appeared in
no `Requires-Dist` line. It reached every environment through typer's own requirements, which
made the kit's import-time correctness depend on a promise made in someone else's metadata over
a typer range the kit left unbounded. typer publishes a slim distribution without rich.

Metadata is frozen into the artifact at build time, so neither could be corrected after a tag.

Two guards, derived rather than listed:

- every third-party module the package imports at module scope is a declared dependency;
- every declared floor is at least the version that first provides what the code needs, recorded
  here with the symbol and the call site that sets it.

The recorded minimums are the part a human has to maintain, so each one carries the reason it is
what it is. A floor nobody can justify is the defect this file exists to catch.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from importlib.metadata import packages_distributions

from packaging.requirements import Requirement
from packaging.version import Version
from tests.conftest import ROOT

SRC = ROOT / "src" / "oss_policy_kit"
PYPROJECT = ROOT / "pyproject.toml"
RUNTIME_IN = ROOT / ".github" / "requirements" / "runtime-all.in"

#: ``distribution -> (minimum, what first appears there, the call site that needs it)``.
#:
#: typer 0.26 rather than 0.19: 0.19.0 is where ``typer.core.HAS_RICH`` appears, so it is the
#: product minimum, but the repository's own suite fails below 0.26 because
#: ``tests/cli/test_a_stream_that_is_gone_is_not_a_defect.py`` requires typer to raise its own
#: vendored ``click.exceptions.Abort``, and typer vendors click from 0.26.0. A floor the project's
#: tests fail at is not a floor the project supports.
_RECORDED_MINIMUM: dict[str, tuple[str, str, str]] = {
    "typer": ("0.26", "typer vendors its own click, and typer.core.HAS_RICH exists from 0.19.0", "cli/common.py:18"),
    "rich": ("13.8.0", "the floor typer itself declares from 0.25; the kit uses nothing newer", "cli/common.py:16"),
}


def _declared() -> dict[str, Requirement]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    out: dict[str, Requirement] = {}
    for raw in data["project"]["dependencies"]:
        requirement = Requirement(raw)
        out[requirement.name.lower().replace("_", "-")] = requirement
    return out


def _runtime_closure() -> set[str]:
    """The runtime requirement strings the lock input has to mirror: base plus the ``all`` extra."""

    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    raw = list(data["project"]["dependencies"]) + list(data["project"]["optional-dependencies"]["all"])
    return {str(Requirement(item)) for item in raw}


def _module_scope_imports() -> dict[str, str]:
    """``import root -> the file:line that imports it`` for imports that run at import time.

    Imports inside a function, a ``try`` block or ``if TYPE_CHECKING`` are excluded: those are the
    shapes the codebase uses for an optional dependency, and an optional dependency does not have
    to be declared in the base requirements.
    """

    found: dict[str, str] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for statement in _unconditional(tree.body):
            where = f"{path.relative_to(SRC).as_posix()}:{statement.lineno}"
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    found.setdefault(alias.name.split(".")[0], where)
            elif isinstance(statement, ast.ImportFrom) and statement.level == 0 and statement.module:
                found.setdefault(statement.module.split(".")[0], where)
    return found


def _unconditional(body: list[ast.stmt]) -> list[ast.stmt]:
    """Statements that run on every import, descending only into an ``if`` that is not a guard.

    ``try`` is not descended into, and neither is ``if TYPE_CHECKING``: both are how this codebase
    spells an optional dependency, and an optional dependency belongs in an extra rather than in
    the base requirements.
    """

    out: list[ast.stmt] = []
    for statement in body:
        if isinstance(statement, ast.If) and not _is_type_checking(statement.test):
            out.extend(_unconditional(statement.body))
        elif not isinstance(statement, ast.Try):
            out.append(statement)
    return out


def _is_type_checking(test: ast.expr) -> bool:
    name = test.id if isinstance(test, ast.Name) else getattr(test, "attr", None)
    return name == "TYPE_CHECKING"


def _distribution_for(root: str) -> str | None:
    mapping = packages_distributions()
    names = mapping.get(root)
    return names[0].lower().replace("_", "-") if names else None


def test_every_module_scope_third_party_import_is_a_declared_dependency() -> None:
    declared = _declared()
    undeclared: dict[str, str] = {}

    for root, where in _module_scope_imports().items():
        if root in sys.stdlib_module_names or root == "oss_policy_kit":
            continue
        distribution = _distribution_for(root)
        if distribution is None or distribution in declared:
            continue
        undeclared[f"{root} -> {distribution}"] = where

    assert not undeclared, (
        "imported at module scope and not in [project] dependencies, so an install that does not "
        f"happen to receive it dies at import: {undeclared}"
    )


def test_each_recorded_minimum_is_at_or_below_the_declared_floor() -> None:
    declared = _declared()
    wrong: dict[str, str] = {}

    for name, (minimum, why, where) in _RECORDED_MINIMUM.items():
        requirement = declared.get(name)
        if requirement is None:
            wrong[name] = f"not declared at all, but {where} needs >= {minimum}: {why}"
            continue
        floors = [Version(spec.version) for spec in requirement.specifier if spec.operator in {">=", "==", "~="}]
        if not floors:
            wrong[name] = f"declared with no lower bound, but {where} needs >= {minimum}: {why}"
        elif max(floors) < Version(minimum):
            wrong[name] = f"declared >= {max(floors)}, but {where} needs >= {minimum}: {why}"

    assert not wrong, f"declared floors that promise an environment the code does not run in: {wrong}"


def test_the_runtime_lock_input_mirrors_pyproject() -> None:
    """The half-applied fix: pyproject moves and the hashed lock keeps resolving the old floor."""

    stated = {
        str(Requirement(line.strip()))
        for line in RUNTIME_IN.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    closure = _runtime_closure()

    assert stated == closure, (
        f"runtime-all.in and pyproject disagree; only in the lock input: {sorted(stated - closure)}; "
        f"only in pyproject: {sorted(closure - stated)}"
    )


def test_the_guard_is_reading_something() -> None:
    """An anti-vacuum floor: each assertion above passes trivially on an empty parse."""

    imports = _module_scope_imports()

    assert len(imports) >= 20, f"only {len(imports)} module-scope imports were parsed across src/"
    assert "typer" in imports, "typer is imported at module scope throughout the CLI and was not seen"
    assert _distribution_for("yaml") == "pyyaml", "the import-root to distribution mapping is not resolving"
    assert _declared(), "no dependencies were read out of pyproject.toml"
