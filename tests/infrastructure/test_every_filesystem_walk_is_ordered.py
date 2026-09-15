"""Every filesystem walk in ``src/`` is ordered, or is on a list of walks that cannot care.

`rglob`, `glob`, `iterdir` and `os.walk` yield in filesystem order: roughly alphabetical on
NTFS, hash order on ext4. A scanner that stops at a file cap therefore scans *different files*
on different machines, and one that reports `evidence_sources=[... for p in found[:5]]` reports
*different evidence* for the same clone. For a kit whose contract is reproducible evidence that
is the silently-wrong class, not a cosmetic one.

This was not hypothetical. On 2026-09-02 two scanners walked unordered and stopped at 200 and
400 files; the defect surfaced only as a coverage number, because the assertions in the tests
covering them passed in either order (`e18534e`). At that point 35 walks were already ordered
and 18 were not, so the invariant existed in the codebase with nothing holding it there.

The waiver list below is deliberately short and is not a baseline. A walk goes on it only when
the ORDER CANNOT CHANGE THE RESULT -- the call feeds a boolean, a set, or a frozenset -- never
because ordering it looked expensive or awkward. If a walk is capped, sliced, or contributes a
path to a report, it is ordered, not waived.

Three ways to be ordered, all detected from the syntax rather than trusted from a comment:

- ``sorted-inline``      the call sits inside a ``sorted(...)``
- ``sorted-at-return``   the enclosing function returns ``sorted(...)``
- ``sorted-in-loop-body`` an ``os.walk`` whose body sorts ``dirnames`` and ``filenames``,
  which keeps the walk lazy -- ``sorted()`` around ``os.walk`` would defeat the file cap it
  exists to serve.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"

#: Attribute names that yield directory entries in filesystem order.
_WALK_ATTRS = frozenset({"rglob", "glob", "iterdir", "scandir"})

#: Receivers whose ``.walk()`` traverses something that is not a filesystem. Matching `walk`
#: on the receiver name rather than on ``os`` alone is deliberate: Python 3.12 added
#: ``Path.walk()``, so a future ``repo_root.walk()`` would be a real unordered filesystem walk
#: that a rule looking only for ``os.walk`` would wave straight through. Over-matching here
#: costs an explicit waiver; under-matching costs a silent hole, which is the failure this
#: module exists to prevent.
_NON_FILESYSTEM_WALK_RECEIVERS = frozenset({"ast"})

#: A floor under the number of walks found, so a change to the AST matching below cannot
#: reduce this module to asserting that an empty set is empty. 51 were found on 2026-09-02.
_MINIMUM_WALKS_FOUND = 40

#: Walks whose order cannot reach any output, keyed by (path relative to src/, function).
#: Each value says why the result is order-independent. Adding an entry here is a claim that
#: no caller can observe the order -- not that ordering was inconvenient.
_ORDER_CANNOT_MATTER: dict[tuple[str, str], str] = {
    ("oss_policy_kit/application/batch_evaluate.py", "_glob_has_match"): (
        "returns `next(iter(...)) is not None` -- existence only, uncapped, so any order that "
        "contains a match finds one"
    ),
    ("oss_policy_kit/application/evaluators/_shared.py", "_has_license"): (
        "returns True on the first license-shaped name, uncapped; a repo either has one or does not"
    ),
    ("oss_policy_kit/application/evaluators/_shared.py", "_holds_a_non_empty_file"): (
        "returns True on the first non-empty file, uncapped -- a boolean about the directory"
    ),
    ("oss_policy_kit/application/evaluators/cra.py", "eval_cra_art13_sbd_001"): (
        "`any(adr.is_file() for adr in ...)` -- uncapped boolean, no path is reported from it"
    ),
    ("oss_policy_kit/application/profile_hints.py", "schema_backed_evidence_filenames"): (
        "the entries become a frozenset; membership is all any caller asks of it"
    ),
    ("oss_policy_kit/application/profile_hints.py", "_detect_simple_stacks"): (
        "`if list(glob(...)) or list(glob(...))` -- truthiness of a .csproj/.sln probe"
    ),
    ("oss_policy_kit/cli/profiles.py", "_iter_bundled_profiles"): (
        "builds a set of profile ids used only for membership; the listing beside it is sorted"
    ),
}


def _walk_calls(tree: ast.Module) -> list[ast.Call]:
    """Every call that yields directory entries: ``x.rglob()``/``glob``/``iterdir``/``os.walk``."""

    found: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attr = node.func.attr
        receiver = node.func.value
        is_fs_walk = attr == "walk" and not (
            isinstance(receiver, ast.Name) and receiver.id in _NON_FILESYSTEM_WALK_RECEIVERS
        )
        if attr in _WALK_ATTRS or is_fs_walk:
            found.append(node)
    return found


def _contains_sorted(node: ast.AST) -> bool:
    def _is_sorted_call(n: ast.AST) -> bool:
        return isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "sorted"

    return any(_is_sorted_call(n) for n in ast.walk(node))


def _is_sorted_inline(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    """True when the call sits lexically inside a ``sorted(...)`` within the same statement."""

    cur: ast.AST = call
    while cur in parents:
        cur = parents[cur]
        if isinstance(cur, ast.Call) and isinstance(cur.func, ast.Name) and cur.func.id == "sorted":
            return True
        if isinstance(cur, ast.stmt):
            return False
    return False


def _is_sorted_at_return(func: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
    """True when the enclosing function hands back a ``sorted(...)`` result."""

    if func is None:
        return False
    return any(isinstance(n, ast.Return) and n.value is not None and _contains_sorted(n.value) for n in ast.walk(func))


def _is_sorted_in_loop_body(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> bool:
    """True for an ``os.walk`` whose loop body sorts both ``dirnames`` and ``filenames``.

    Kept separate from `sorted-inline` because wrapping ``os.walk`` in ``sorted()`` would
    materialise the whole tree and defeat the file cap these walkers exist to honour. Sorting
    inside the body keeps the walk lazy and still deterministic.
    """

    cur: ast.AST = call
    while cur in parents:
        cur = parents[cur]
        if isinstance(cur, ast.For):
            body = ast.Module(body=cur.body, type_ignores=[])
            sorts_dirnames = any(isinstance(n, ast.Assign) and _contains_sorted(n.value) for n in ast.walk(body))
            sorts_filenames = any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "sort"
                for n in ast.walk(body)
            )
            return sorts_dirnames and sorts_filenames
    return False


def _scan() -> tuple[list[tuple[str, int, str]], list[tuple[str, int, str]]]:
    """Return (every walk site, the ones with no ordering mechanism), as (path, line, function)."""

    every: list[tuple[str, int, str]] = []
    unordered: list[tuple[str, int, str]] = []

    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents: dict[ast.AST, ast.AST] = {}
        enclosing: dict[ast.AST, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for inner in ast.walk(node):
                    enclosing.setdefault(inner, node)

        rel = path.relative_to(_SRC).as_posix()
        for call in _walk_calls(tree):
            func = enclosing.get(call)
            site = (rel, call.lineno, func.name if func else "<module>")
            every.append(site)
            ordered = (
                _is_sorted_inline(call, parents) or _is_sorted_at_return(func) or _is_sorted_in_loop_body(call, parents)
            )
            if not ordered:
                unordered.append(site)
    return every, unordered


def test_the_scan_actually_finds_the_walks() -> None:
    """A guard that enumerates nothing would pass however the scanners were written."""

    every, _ = _scan()
    assert len(every) >= _MINIMUM_WALKS_FOUND, (
        f"found only {len(every)} filesystem walks under src/, below the floor of "
        f"{_MINIMUM_WALKS_FOUND}. Either a lot of scanning code was deleted, or `_walk_calls` "
        "stopped recognising them -- in which case the assertion below passes for the wrong reason."
    )


def test_every_walk_is_ordered_or_provably_cannot_care() -> None:
    _, unordered = _scan()
    offenders = [(p, line, fn) for p, line, fn in unordered if (p, fn) not in _ORDER_CANNOT_MATTER]

    assert not offenders, (
        "a filesystem walk yields in filesystem order and nothing puts it back:\n"
        + "\n".join(f"  src/{p}:{line}  in {fn}()" for p, line, fn in offenders)
        + "\n\nOn ext4 that order is not even stable between runs, so a capped or sliced scan "
        "reads different files -- and reports different evidence -- for the same repository.\n"
        "Wrap the call in `sorted(...)`, return `sorted(...)` from the function, or (for os.walk, "
        "where sorting the call would defeat the file cap) sort `dirnames` and `filenames` in the "
        "loop body. Add it to _ORDER_CANNOT_MATTER only if the order cannot reach any output -- a "
        "boolean, a set, a frozenset -- and say why."
    )


def test_no_waiver_outlives_the_walk_it_was_written_for() -> None:
    """The converse: a waiver that no longer matches a real unordered walk is stale."""

    _, unordered = _scan()
    still_unordered = {(p, fn) for p, _line, fn in unordered}
    stale = sorted(set(_ORDER_CANNOT_MATTER) - still_unordered)

    assert not stale, (
        "these waivers no longer describe an unordered walk:\n"
        + "\n".join(f"  src/{p}  in {fn}()" for p, fn in stale)
        + "\n\nEither the walk is sorted now, or it moved, or it is gone. Delete the entry from "
        "_ORDER_CANNOT_MATTER. A waiver that outlives its reason is worse than one never granted: "
        "it silently pre-approves whatever takes that function's place."
    )
