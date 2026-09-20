"""Three readers took an operator-supplied path and read the whole file before checking it.

Each one has a depth guard, and each depth guard measures a string that is already in
memory, so the guard the code advertises runs after the cost it exists to prevent. Every
comparable reader in this kit is bounded first: `adapters/scorecard_json.py` caps its YAML
loader with `MAX_EVIDENCE_BYTES` fifty lines below the JSON loader that capped nothing.

Found by sweeping `src/` for raw reads and sorting them rather than by reading a diff. Of
37, three ship packaged data, three are the cap helpers themselves, 22 already have a size
check in the same function, and the rest needed a look. These three are the ones where a
path the operator names reaches `read_text` with nothing in between.

The ceiling is measured rather than picked. The shipped sample reports are about 1.3 KB
per control, and the largest shipped profile has 39 controls, so `MAX_EVIDENCE_BYTES`
leaves room for a report over a hundred times larger than any the kit writes.

The last test is the sweep itself, so the next raw read has to be justified where it is
added instead of waiting for someone to run this by hand again.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest
from tests.conftest import ROOT

from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES
from oss_policy_kit.domain.errors import InvalidInputError, LoadError

SRC = ROOT / "src" / "oss_policy_kit"


def _oversized(path: pathlib.Path, payload: dict[str, object]) -> pathlib.Path:
    """A document that is valid and one byte past the ceiling.

    Padding goes in a string field rather than as trailing bytes, so the file is still
    parseable: a reader that skipped the size check would succeed, which is what makes
    the refusal meaningful.
    """

    body = dict(payload)
    body["_padding"] = "x" * (MAX_EVIDENCE_BYTES + 1)
    path.write_text(json.dumps(body), encoding="utf-8")
    assert path.stat().st_size > MAX_EVIDENCE_BYTES
    return path


def test_the_drift_reader_refuses_an_oversized_report(tmp_path: pathlib.Path) -> None:
    from oss_policy_kit.application.drift import load_report_json

    report = json.loads((ROOT / "docs" / "sample-reports" / "vulnerable" / "evaluation-report.json").read_text("utf-8"))
    path = _oversized(tmp_path / "evaluation-report.json", report)

    with pytest.raises(InvalidInputError, match="bytes"):
        load_report_json(path, label="--before report")


def test_the_export_evidence_reader_refuses_an_oversized_report(tmp_path: pathlib.Path) -> None:
    from oss_policy_kit.cli.export_evidence import _read_report

    report = json.loads((ROOT / "docs" / "sample-reports" / "vulnerable" / "evaluation-report.json").read_text("utf-8"))
    path = _oversized(tmp_path / "evaluation-report.json", report)

    with pytest.raises(InvalidInputError, match="bytes"):
        _read_report(path)


def test_the_scorecard_json_reader_refuses_an_oversized_document(tmp_path: pathlib.Path) -> None:
    from oss_policy_kit.adapters.scorecard_json import load_scorecard_json

    path = _oversized(tmp_path / "scorecard.json", {"checks": []})

    with pytest.raises(LoadError, match="bytes"):
        load_scorecard_json(path)


def test_a_document_under_the_ceiling_still_loads(tmp_path: pathlib.Path) -> None:
    """The other direction. A cap that also refuses ordinary input is an outage."""

    from oss_policy_kit.application.drift import load_report_json

    source = ROOT / "docs" / "sample-reports" / "vulnerable" / "evaluation-report.json"
    path = tmp_path / "evaluation-report.json"
    path.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")

    assert load_report_json(path, label="--before report")["contract_version"]


#: Raw reads that need no size check, and why. Anything not here has to pass through a
#: capped helper or carry a size check in its own function.
_NEEDS_NO_BOUND = {
    # Shipped inside the wheel: `importlib.resources`, not a path anyone supplies.
    "application/evaluators_common.py",
    "application/evidence_loading.py",
    "application/loader.py",
    "application/osps_coverage.py",
    # The cap helpers. A raw read here is the implementation of the bound.
    "application/input_limits.py",
    "application/evaluators/_shared.py",
    # `_resolve_workflow_template` reads the packaged template through
    # `resources.files(...)`, and falls back to a repo-local copy only when the package
    # data is absent, which an installed wheel never is.
    "application/init_writer.py",
    # `_capture_prior_content` copies whatever is already in the output directory so a
    # failed write can be rolled back. A size refusal here would mean declining to
    # preserve a large file the kit did not write, which is worse than reading it; the
    # fix, if it is ever wanted, is to mark it non-restorable rather than to cap it.
    "application/reporting.py",
    # `load_committed_codepipeline_document` reads a file out of the scanned repository,
    # which is the input that matters most, and it is already bounded one frame up:
    # `_scan_codepipeline_export` calls `oversize_reason(path, MAX_CI_CONFIG_BYTES)` and
    # records a parse error before anything reads the document. Traced rather than
    # assumed: that function is the only caller of the minimal-stub check, and the
    # minimal-stub check is the only other caller of the loader. Adding a second cap
    # inside the loader would be redundant today; what would make it necessary is a new
    # caller reaching the loader without passing through the scan, and neither function
    # is named as private, so that is a real possibility rather than a hypothetical.
    "infrastructure/aws_ci_parser.py",
}


def test_no_new_raw_read_appears_without_a_bound() -> None:
    """Derived from the tree, so the next one is caught where it is added."""

    raw_names = {"read_text", "read_bytes"}
    size_signals = ("st_size", "MAX_", "_MAX", "too_big", "oversize", "size_limit")
    offenders: list[str] = []

    for path in sorted(SRC.rglob("*.py")):
        relative = path.relative_to(SRC).as_posix()
        if relative in _NEEDS_NO_BOUND:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        owners: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for inner in ast.walk(node):
                    if hasattr(inner, "lineno"):
                        owners.setdefault(inner.lineno, node)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
            if name not in raw_names:
                continue
            call = ast.unparse(node)
            if ".joinpath(" in call or "ir.files(" in call:
                continue
            owner = owners.get(node.lineno)
            body = ast.unparse(owner) if owner is not None else ""
            if any(signal in body for signal in size_signals):
                continue
            label = getattr(owner, "name", "<module>")
            offenders.append(f"{relative}:{node.lineno} ({label})")

    assert not offenders, (
        "a file is read whole with no size check in the same function: "
        + ", ".join(offenders)
        + ". Use a capped helper, add an oversize_reason() check, or add the module to "
        "_NEEDS_NO_BOUND with the reason it cannot be handed an unbounded file."
    )


def test_the_sweep_above_can_still_see_an_unbounded_read() -> None:
    """The mutation, in-process: a bare read in a function with no size check is caught."""

    tree = ast.parse("def load(path):\n    return path.read_text(encoding='utf-8')\n")
    function = tree.body[0]
    assert isinstance(function, ast.FunctionDef)
    body = ast.unparse(function)

    assert "read_text" in body
    assert not any(signal in body for signal in ("st_size", "MAX_", "oversize")), (
        "the signal list has grown wide enough to excuse an ordinary unbounded read"
    )
