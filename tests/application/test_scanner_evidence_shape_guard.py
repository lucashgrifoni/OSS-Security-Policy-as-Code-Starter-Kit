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
import pkgutil
from collections.abc import Iterator
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

#: Modules allowed to parse an evidence path directly, each for a stated reason.
#: Anything not listed here that does it is the defect coming back.
#:
#: These are exemptions, not absolutions. Every one was verified behaviourally before being
#: written down -- 64 combinations of input file against a wrong-shaped root ([], "s", 42,
#: null, true) driven through the real CLI, all exit 0. They read documents with no
#: ``schema_version`` contract, or packaged data rather than adopter evidence, so the shared
#: reader does not fit them; each guards the shape before use.
#:
#: The point of the list is not the entries. It is that adding one is a decision somebody has
#: to make and justify, instead of a crash an adopter discovers.
EVIDENCE_PARSER_EXEMPTIONS: dict[str, str] = {
    "oss_policy_kit.application.evaluators_common": "defines the shared reader and the schema validator",
    "oss_policy_kit.application.evaluators._shared": "branch-protection evidence; own contract, guarded",
    "oss_policy_kit.application.evaluators.ai": "llm-release-integrity and mcp-tool-descriptions; guarded",
    "oss_policy_kit.application.evaluators.cra": "reads a SARIF drop, not a scan-* evidence file",
    "oss_policy_kit.application.evaluators.github": "provenance-artifact evidence; guarded",
    "oss_policy_kit.application.evaluators.gitlab": "gitlab-mr-rules.json; no schema_version, guarded",
    "oss_policy_kit.application.evaluators.governance": "conformance verdict file; no schema_version, guarded",
    "oss_policy_kit.application.evaluators.supply_chain": "sbom-quality evidence; guarded",
    "oss_policy_kit.application.engine": "loads the packaged catalog, not adopter evidence",
    "oss_policy_kit.application.finding_normalization": "normalises findings documents; own contract",
    "oss_policy_kit.application.findings_report": "renders a findings document; own contract",
    "oss_policy_kit.application.osps_coverage": "reads the packaged OSPS map",
    "oss_policy_kit.infrastructure.aws_ci_parser": "parses buildspec / pipeline files, not evidence",
}


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


def _reads_a_file(node: ast.AST) -> bool:
    """True when this expression reads a file off disk.

    Matched on the CALL, not on what anyone named the variable. The first version of this
    looked for an ``ast.Name`` called ``evidence``, so ``evidence_path``, ``evidence_file``,
    ``report`` or ``p`` walked straight past -- and one module in the package was already
    doing the banned thing and being missed for exactly that reason.

    That mattered more than the miss itself: the docstring below claimed the check "cannot be
    spelled around", which is the third completeness claim in this release that turned out to
    be untrue. Naming the shape instead of the variable is what makes the claim honest.
    """

    return any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Attribute)
        and child.func.attr in ("read_text", "read_bytes", "open")
        for child in ast.walk(node)
    )


def _iter_package_modules(package_name: str) -> Iterator[tuple[str, ast.Module]]:
    """Every importable module in *package_name*, parsed."""

    package = importlib.import_module(package_name)
    for info in pkgutil.walk_packages(package.__path__, prefix=f"{package_name}."):
        try:
            module = importlib.import_module(info.name)
            source = inspect.getsource(module)
        except (ImportError, OSError, TypeError):  # pragma: no cover - defensive
            continue
        yield info.name, ast.parse(source)


def test_no_module_parses_an_evidence_path_itself() -> None:
    """The guard that matters over time -- and it has to be DERIVED to be worth anything.

    A seventh scanner added with the old copied block passes every test above, because they
    only exercise the shared reader. So this one is about the modules.

    The first version hard-coded the six modules that had been fixed. That made the file's
    own claim -- "a seventh scanner added with the old copied block would reintroduce the
    crash, this fails when that happens" -- false: a seventh module is not in a list written
    before it existed. Adversarial review caught the overclaim, which is the same defect this
    release spent the day fixing in the product: asserting more than the check establishes.
    It now walks the whole package.

    The version before that searched the source TEXT for ``json.loads(evidence.read_text``.
    Mutation testing killed it: ``import json as _j`` sailed straight through. Matching the
    call structure cannot be spelled around.

    Scoped to ``load``/``loads``/``safe_load`` calls whose argument mentions ``evidence``,
    because plenty of modules legitimately read workflow and manifest files -- a blanket ban
    on ``read_text`` would be a rule nothing could follow.
    """

    offenders = []
    for name, tree in _iter_package_modules("oss_policy_kit"):
        if name in EVIDENCE_PARSER_EXEMPTIONS:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if called in ("load", "loads", "safe_load") and any(
                _reads_a_file(arg) for arg in [*node.args, *(kw.value for kw in node.keywords)]
            ):
                offenders.append(f"{name}:{node.lineno} ({called})")

    assert not offenders, (
        "these modules parse an evidence path themselves instead of calling "
        f"read_scanner_evidence(), so a non-object root crashes them again: {offenders}"
    )


def test_nothing_navigates_a_document_with_the_or_empty_dict_idiom() -> None:
    """``(x or {}).get(...)`` reads like a null-safe walk and is not one.

    ``or`` substitutes only for a FALSY value, so a truthy non-mapping -- a string, a number,
    a list -- goes straight through to ``.get`` and raises ``AttributeError``: exit 3, no
    report, and the adopter told to file a bug about their own file.

    This idiom produced two separate rounds of that crash in one release cycle, in files
    nobody had listed the round before. Naming the sites did not stop it; forbidding the
    shape does. Use ``as_mapping()`` instead -- it reads the same and is actually safe.
    """

    offenders = []
    for name, tree in _iter_package_modules("oss_policy_kit"):
        for node in ast.walk(tree):
            # `(<anything> or {}).get(...)` / `(<anything> or []).<attr>`
            if not isinstance(node, ast.Attribute):
                continue
            value = node.value
            if not isinstance(value, ast.BoolOp) or not isinstance(value.op, ast.Or):
                continue
            tail = value.values[-1]
            empty_dict = isinstance(tail, ast.Dict) and not tail.keys
            empty_list = isinstance(tail, ast.List) and not tail.elts
            if empty_dict or empty_list:
                offenders.append(f"{name}:{node.lineno}")

    assert not offenders, (
        "these navigate a parsed document with `(x or {}) .attr`, which raises on a truthy "
        f"non-mapping instead of substituting. Use as_mapping(): {offenders}"
    )


def test_the_evidence_parser_walk_actually_reaches_the_modules() -> None:
    """A derived check that walks nothing passes for the wrong reason."""

    names = {name for name, _tree in _iter_package_modules("oss_policy_kit")}

    assert "oss_policy_kit.application.evaluators_k8s" in names
    assert "oss_policy_kit.application.evaluators.cicd" in names
    assert "oss_policy_kit.cli.emit_vex" in names
    assert len(names) > 50, f"only {len(names)} modules walked -- the sweep is not reaching the package"
