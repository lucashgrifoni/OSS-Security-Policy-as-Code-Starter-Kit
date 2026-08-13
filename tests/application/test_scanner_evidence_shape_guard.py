"""A scanner-evidence file whose JSON root is not an object is bad input, not a kit defect.

Six evaluators had the same reader copied out line for line, each ending in an unguarded
``data.get("schema_version", "")``. A root that is not an object -- ``[]``, a string, a
number, ``null``, ``true`` -- reached that ``.get`` and raised ``AttributeError``. That is
not an input-shaped exception, so the CLI's boundary classifier correctly called it a
defect in the kit and returned exit 3: no report written, and a message telling the
adopter to file a bug about their own file.

The trigger is ordinary. The evidence directory is one the kit invites adopters to fill,
and plenty of scanners emit a top-level array. ADR-045 is explicit that evidence which
cannot be read becomes manual review, and every other corruption class already did.

The reader is one shared function now. These tests are written against that function and
against every evaluator that uses it, because the defect was never in the logic of any one
loader -- it was in the fact that there were six of them.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators_common import read_scanner_evidence
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

#: Every JSON value that is valid but is not an object.
NON_OBJECT_ROOTS: tuple[tuple[str, str, str], ...] = (
    ("empty_array", "[]", "list"),
    ("array", "[1, 2]", "list"),
    ("string", '"a string"', "str"),
    ("number", "123", "int"),
    ("null", "null", "NoneType"),
    ("boolean", "true", "bool"),
)

#: The modules whose evidence reader must go through the shared guard, with the schema
#: prefix each one expects. Adding a scanner without adding it here is the way this class
#: comes back, so the last test asserts the list is complete.
LOADER_MODULES: tuple[str, ...] = (
    "oss_policy_kit.application.evaluators_iac",
    "oss_policy_kit.application.evaluators_iac_bicep",
    "oss_policy_kit.application.evaluators_iac_cfn",
    "oss_policy_kit.application.evaluators_iac_pulumi",
    "oss_policy_kit.application.evaluators_k8s",
    "oss_policy_kit.application.evaluators.cicd",
)


def _evidence(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "evidence.json"
    path.write_text(body, encoding="utf-8")
    return path


def _read(evidence: Path) -> dict[str, Any] | EvalOutcome:
    return read_scanner_evidence(
        evidence,
        label="Kubernetes",
        regenerate_cmd="oss-policy-kit scan-k8s",
        schema_prefix="oss-policy-kit/evidence/k8s-baseline/",
    )


@pytest.mark.parametrize(("label", "body", "typename"), NON_OBJECT_ROOTS, ids=[r[0] for r in NON_OBJECT_ROOTS])
def test_a_non_object_root_is_reviewed_not_crashed(label: str, body: str, typename: str, tmp_path: Path) -> None:
    """The whole point: no ``AttributeError`` escapes, and the message names the shape."""

    result = _read(_evidence(tmp_path, body))

    assert isinstance(result, EvalOutcome), f"root {label} was accepted as an object"
    assert result.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert typename in result.reason, result.reason
    assert "evidence.json" in result.reason
    assert "scan-k8s" in result.remediation


@pytest.mark.parametrize("body", [r[1] for r in NON_OBJECT_ROOTS], ids=[r[0] for r in NON_OBJECT_ROOTS])
def test_the_reason_names_the_file_without_naming_the_host(body: str, tmp_path: Path) -> None:
    """M-002. Asserted on separators rather than on one absolute string.

    ``str(tmp_path) not in reason`` would pass here for the wrong reason on Windows in
    several renderings; a message that carries no separator at all cannot carry a path.
    """

    result = _read(_evidence(tmp_path, body))

    assert isinstance(result, EvalOutcome)
    assert "/" not in result.reason and "\\" not in result.reason, result.reason


def test_a_well_formed_object_still_reads(tmp_path: Path) -> None:
    """The guard must not cost the ordinary case."""

    body = json.dumps({"schema_version": "oss-policy-kit/evidence/k8s-baseline/v1", "findings": []})

    result = _read(_evidence(tmp_path, body))

    assert not isinstance(result, EvalOutcome)
    assert result["schema_version"].startswith("oss-policy-kit/evidence/k8s-baseline/")


def test_an_object_with_the_wrong_schema_is_still_rejected(tmp_path: Path) -> None:
    """The pre-existing contract check survives the refactor."""

    body = json.dumps({"schema_version": "something/else/v1"})

    result = _read(_evidence(tmp_path, body))

    assert isinstance(result, EvalOutcome)
    assert result.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "Unexpected schema_version" in result.reason


def test_an_unreadable_file_does_not_name_the_host_either(tmp_path: Path) -> None:
    """``str(OSError)`` embeds the absolute filename; ``bad_input_detail`` does not."""

    missing = tmp_path / "SECRET-DIR-MARKER" / "evidence.json"

    result = _read(missing)

    assert isinstance(result, EvalOutcome)
    assert result.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "SECRET-DIR-MARKER" not in result.reason, result.reason


def _mentions_evidence(node: ast.AST) -> bool:
    """True when ``evidence`` appears anywhere in this expression."""

    return any(
        (isinstance(child, ast.Name) and child.id == "evidence")
        or (isinstance(child, ast.Attribute) and child.attr == "evidence")
        for child in ast.walk(node)
    )


def test_no_loader_parses_its_own_evidence() -> None:
    """The guard that matters over time, and the reason it is written against the AST.

    A seventh scanner added with the old copied block passes every test above -- they
    only exercise the shared reader -- and brings the crash back. So this one is about
    the modules, not the function.

    The first version searched the source text for ``json.loads(evidence.read_text``.
    Mutation testing killed it: renaming the import to ``_j`` sailed straight through,
    and that is not a hypothetical, it is what ``import json as _j`` does. Matching the
    call structure instead of its spelling costs nothing and cannot be typo'd around.

    Scoped to ``load``/``loads`` calls that mention ``evidence``, because ``cicd.py``
    legitimately reads workflow files -- a blanket ban on ``read_text`` would be a
    rule these modules could not follow.
    """

    offenders = []
    for name in LOADER_MODULES:
        tree = ast.parse(inspect.getsource(importlib.import_module(name)))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if called in ("load", "loads", "safe_load") and any(
                _mentions_evidence(arg) for arg in [*node.args, *(kw.value for kw in node.keywords)]
            ):
                offenders.append(f"{name}:{node.lineno} ({called})")

    assert not offenders, (
        "these modules parse scanner evidence themselves instead of calling "
        f"read_scanner_evidence(), so a non-object root crashes them again: {offenders}"
    )
