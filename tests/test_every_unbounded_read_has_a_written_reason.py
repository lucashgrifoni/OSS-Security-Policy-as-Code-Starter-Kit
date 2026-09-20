"""A file is not read whole until something has looked at how big it is.

This class was tracked as a number for months and the number kept moving, ~248, then
304, then 37, because nobody had sorted it. A count cannot be finished and cannot be
checked. This can: the sweep is derived from the source, and every read that still has
no bound is named here with the reason it does not need one.

Adding a read without a bound turns this red. Removing the reason for one that is
allowed turns it red too, so a stale exemption cannot outlive its argument.

The buckets, for the 37 raw reads in `src/` as of this commit:

    7   implement a cap; they are the helpers the others call
    3   ship packaged data through importlib.resources
    24  check the size in the same function before reading
    3   listed below with a reason
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "oss_policy_kit"

#: Helpers that take a byte bound; a read routed through one is already bounded.
_CAPPED_CALLS = frozenset(
    {
        "read_text_capped",
        "load_capped_document",
        "capped_repo_text",
        "capped_repo_bytes",
        "capped_evidence_text",
        "read_repo_text",
    }
)
#: Called anywhere in the enclosing function, these mean the size was looked at. `stat`
#: on its own is deliberately not here: it is used for other things, and accepting it
#: would let an unbounded read hide behind an unrelated call.
_SIZE_CHECKS = frozenset({"oversize_reason", "is_oversize", "st_size"})
#: The functions that IMPLEMENT a bound necessarily read without one.
_CAP_IMPLEMENTORS = _CAPPED_CALLS | {"load_yaml_file", "oversize_reason"}

_RAW_READS = frozenset({"read_text", "read_bytes"})

#: Reads with no bound, and why each one is allowed to stay that way. Traced, not
#: assumed: each reason below was checked against the current source.
ALLOWED: dict[str, str] = {
    "application/finding_sarif.py::_load_runs": (
        "Both callers refuse an oversize drop immediately before calling it, with "
        "MAX_SARIF_BYTES. Keeping the check in the callers is what stops it drifting "
        "from the evaluate path, which reads the same drops. A third caller that "
        "skipped the check would reintroduce this, and nothing but review catches that."
    ),
    "application/reporting.py::_capture_prior_content": (
        "Reads whatever is already in the output directory so a failed write can put it "
        "back. A bound here would decline to preserve a large file this package did not "
        "write, which is worse than the unbounded read. Making it non-restorable instead "
        "is a behaviour change and is deferred rather than smuggled in."
    ),
    "infrastructure/aws_ci_parser.py::load_committed_codepipeline_document": (
        "Reads from the scanned repository and is bounded one frame up by "
        "_scan_codepipeline_export. A naive bound would be worse than none: the loader "
        "returns None on failure, and None makes the export invisible rather than "
        "recorded, which is a false absence rather than a refusal."
    ),
}


def _unbounded_reads() -> dict[str, str]:
    """Every raw read whose enclosing function does not bound it, as `path::function`."""

    found: dict[str, str] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)):
            if fn.name in _CAP_IMPLEMENTORS:
                continue
            body = ast.unparse(fn)
            if any(check in body for check in _SIZE_CHECKS):
                continue
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr not in _RAW_READS:
                    continue
                call = ast.unparse(node)
                if any(helper in call for helper in _CAPPED_CALLS):
                    continue
                if "ir.files(" in call or "resources.files(" in call:
                    continue  # packaged data, shipped by this project
                found[f"{path.relative_to(SRC).as_posix()}::{fn.name}"] = call
    return found


def test_the_sweep_reaches_the_source() -> None:
    """A sweep that parses nothing would pass every assertion below."""

    reads = sum(
        1
        for path in SRC.rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _RAW_READS
    )
    assert reads >= 30, f"only {reads} raw reads found; the sweep is not reading src/"


def test_no_unbounded_read_lacks_a_reason() -> None:
    """A new read with no size check has to be argued for here, or bounded."""

    undocumented = {k: v for k, v in _unbounded_reads().items() if k not in ALLOWED}
    assert not undocumented, (
        "these read a file whole with nothing checking its size first. Bound it with "
        "oversize_reason before the read, or add it to ALLOWED with the reason:\n  "
        + "\n  ".join(f"{k}  {v}" for k, v in sorted(undocumented.items()))
    )


def test_no_reason_outlives_the_read_it_excused() -> None:
    """An exemption for a read that is now bounded, or gone, is removed."""

    stale = sorted(set(ALLOWED) - set(_unbounded_reads()))
    assert not stale, f"these are bounded or gone now; drop them from ALLOWED: {stale}"


def test_every_reason_says_something() -> None:
    """A one-word exemption is not an argument. Each entry has to carry the reason."""

    thin = sorted(k for k, v in ALLOWED.items() if len(v.split()) < 20)
    assert not thin, f"these exemptions do not explain themselves: {thin}"
