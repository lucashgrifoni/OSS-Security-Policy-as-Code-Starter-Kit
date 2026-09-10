"""A subprocess that captures text must say which encoding it is reading.

`subprocess.run(..., text=True)` with no `encoding=` decodes with the locale codec. On Windows
that is cp1252, which has no mapping for a large part of byte space, and the decode happens in
a reader thread. What the caller sees when it fails is the part that makes this expensive:

    rc=0    stdout=None

The call SUCCEEDS. The exception dies in the thread, nothing is raised, and the caller gets a
successful subprocess with no output. Measured on this tree against a helper writing a single
0x90 byte -- `text=True` returned `None`, `encoding="utf-8"` returned all 52 characters.

The consequences found when this was fixed: `_parse_semgrep_findings(None)` raises
`AttributeError` on the scan path, `check_public_hygiene` would fail on `None.splitlines()`,
and `test_a_manifest_encoding_is_not_a_missing_dependency` was losing its own diagnostic output
on every single run -- reported as a warning, never as a failure, so it stayed green for as
long as it existed.

This test derives the rule from the source rather than from a list, so a call added tomorrow is
covered without anyone remembering to add it here.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNED_TREES = ("src", "tests", "scripts")
CAPTURING_CALLS = frozenset({"run", "Popen", "check_output"})


def _keyword(call: ast.Call, name: str) -> ast.keyword | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw
    return None


def _is_true(node: ast.expr) -> bool:
    try:
        return ast.literal_eval(node) is True
    except (ValueError, SyntaxError):
        return False


def _subprocess_calls_capturing_text(tree: ast.AST) -> list[ast.Call]:
    """Calls that ask subprocess to hand back decoded text."""

    found: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in CAPTURING_CALLS:
            continue
        if not (isinstance(func.value, ast.Name) and func.value.id == "subprocess"):
            continue
        text = _keyword(node, "text") or _keyword(node, "universal_newlines")
        if text is None or not _is_true(text.value):
            continue
        if not (_keyword(node, "capture_output") or _keyword(node, "stdout")):
            continue
        found.append(node)
    return found


def _python_files() -> list[Path]:
    files: list[Path] = []
    for tree in SCANNED_TREES:
        root = REPO_ROOT / tree
        if root.is_dir():
            files.extend(sorted(root.rglob("*.py")))
    return files


def test_every_captured_text_subprocess_names_its_encoding() -> None:
    """The rule itself, across the whole tree."""

    offenders: list[str] = []
    for path in _python_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - a file that will not parse fails elsewhere
            continue
        for call in _subprocess_calls_capturing_text(tree):
            if _keyword(call, "encoding") is None:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{call.lineno}")

    assert not offenders, (
        "these calls capture text with the locale codec, which on Windows returns "
        "`stdout=None` with `rc=0` when a byte does not decode:\n  " + "\n  ".join(offenders)
    )


def test_the_scan_sees_a_call_that_breaks_the_rule() -> None:
    """The canary. A zero above is worth nothing unless the scan can produce a non-zero.

    Without this, deleting the walk and returning an empty list would pass the rule test
    forever, which is the shape of a guard that reports success by looking at nothing.
    """

    source = "import subprocess\ndef f():\n    return subprocess.run(['x'], capture_output=True, text=True)\n"

    calls = _subprocess_calls_capturing_text(ast.parse(source))

    assert len(calls) == 1
    assert _keyword(calls[0], "encoding") is None


def test_the_scan_does_not_flag_a_call_that_follows_the_rule() -> None:
    """The other side of the canary: a guard that flagged everything would also pass above."""

    source = (
        "import subprocess\n"
        "def f():\n"
        "    return subprocess.run(['x'], capture_output=True, text=True, encoding='utf-8')\n"
    )

    calls = _subprocess_calls_capturing_text(ast.parse(source))

    assert len(calls) == 1
    assert _keyword(calls[0], "encoding") is not None


def test_the_scan_ignores_a_call_that_does_not_capture() -> None:
    """No captured output, no decode, nothing to declare."""

    source = "import subprocess\ndef f():\n    return subprocess.run(['x'], text=True)\n"

    assert _subprocess_calls_capturing_text(ast.parse(source)) == []


def test_the_scan_actually_reaches_the_repository() -> None:
    """A file list that came back empty would make the rule vacuous rather than satisfied."""

    files = _python_files()

    assert len(files) > 100, f"only {len(files)} python files found; the scan is not reaching the tree"
