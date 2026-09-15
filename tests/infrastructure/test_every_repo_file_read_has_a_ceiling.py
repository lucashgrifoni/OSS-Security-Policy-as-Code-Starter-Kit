"""The audited repository must not decide how long its own audit runs.

Every file this kit reads out of the repository under audit is written by that repository, and
when the kit runs in CI against a fork it is written by whoever opened the pull request. A read
with no ceiling hands them the clock.

One ceiling existed, on the CI-config path, and 78 other reads had none: a Dockerfile, a README,
a SECURITY.md, a lockfile, a `.git/config`. The gap was invisible because each site looked
reasonable on its own -- `path.read_text(...)` is what reading a file looks like.

This guard is derived rather than listed, in the same shape as the filesystem-walk guard beside
it. It parses the source, finds every call to a reader, and asks whether anything in the
enclosing function bounds it. A new uncapped read fails here on the commit that introduces it,
which is the only time it is cheap to fix.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit"

READERS = frozenset({"read_text", "read_bytes"})

#: Anything naming one of these inside the enclosing function bounds the read.
CEILING_MARKERS = (
    "oversize_reason",
    "capped_repo_text",
    "read_repo_text",
    "load_yaml_file",
    "MAX_",
)

#: Functions whose read cannot be reached by the audited repository, each with why. An entry
#: here is a claim that the bytes come from somewhere the kit controls.
_NOT_REPOSITORY_INPUT: dict[tuple[str, str], str] = {
    ("infrastructure/source_text.py", "decode_source"): "takes bytes; it never opens a file",
    ("application/evaluators/_shared.py", "capped_repo_text"): "is the ceiling",
    ("application/evaluators/_shared.py", "capped_repo_bytes"): "is the ceiling",
    ("application/evaluators_common.py", "capped_evidence_text"): "is the ceiling",
    # The kit's own packaged data, shipped inside the wheel. The audited repository cannot
    # write these, and a cap on them would refuse the kit's own schemas.
    ("application/evaluators_common.py", "load_packaged_schema"): "reads a schema from the wheel",
    ("application/evidence_loading.py", "load_evidence_schema"): "reads a schema from the wheel",
    ("application/loader.py", "_profile_spec_validator"): "reads the profile schema from the wheel",
    ("application/osps_coverage.py", "_load_raw"): "reads the packaged OSPS baseline",
    ("application/init_writer.py", "_resolve_workflow_template"): "reads the kit's own templates",
    # The kit's own output directory, read back so a half-published run can be rolled back.
    # Refusing a large one would block the rollback rather than protect anything.
    ("application/reporting.py", "_capture_prior_content"): "reads the report dir for rollback",
}


def _module_key(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


def _uncapped_reads() -> list[tuple[str, str, int]]:
    found: list[tuple[str, str, int]] = []
    for py in sorted(SRC.rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        text = py.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError:  # pragma: no cover - a syntax error fails louder elsewhere
            continue
        key = _module_key(py)
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]:
            if (key, fn.name) in _NOT_REPOSITORY_INPUT:
                continue
            body = ast.get_source_segment(text, fn) or ""
            if any(marker in body for marker in CEILING_MARKERS):
                continue
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Attribute) and node.func.attr in READERS:
                    found.append((key, fn.name, node.lineno))
    return found


def test_the_guard_can_see_the_source() -> None:
    """Anti-vacuum: a sweep that parses nothing passes and proves nothing."""

    modules = [p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts]
    assert len(modules) > 100


def test_every_read_of_a_repository_file_is_bounded() -> None:
    offenders = _uncapped_reads()

    assert not offenders, (
        "these reads of a repository-controlled file have no ceiling, so the audited "
        "repository decides how long its own audit runs:\n"
        + "\n".join(f"    {mod}:{line}  in {fn}()" for mod, fn, line in offenders)
        + "\n\n  Route the read through `capped_repo_text` (keeps OSError propagating) or "
        "`read_repo_text` (reports the refusal), or call `oversize_reason` first. Add it to "
        "_NOT_REPOSITORY_INPUT only if the bytes cannot come from the audited repository, and "
        "say why."
    )


@pytest.mark.parametrize(("module", "function"), sorted(_NOT_REPOSITORY_INPUT))
def test_no_exemption_outlives_the_read_it_was_written_for(module: str, function: str) -> None:
    """An exemption that survives its function silently pre-approves whatever replaces it."""

    path = SRC / module
    assert path.is_file(), f"{module} no longer exists; drop its exemption"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}
    assert function in names, f"{module}:{function}() is gone; drop its exemption"
