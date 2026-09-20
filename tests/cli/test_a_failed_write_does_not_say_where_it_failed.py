"""`str(OSError)` carries the absolute filename, so no message may render one whole.

Rendering one whole gives the errno, the reason, and the filename the operating system
reports. Six handlers put that straight into text an operator reads. Two were measured
handing back an absolute path for input the operator had typed as a relative one: the
SARIF reader, which resolves before it reads, and `collect-evidence`, which resolves its
destination before it writes and so answered `--output-dir notadir` with the full path,
account name included.

The package already had the answer in two forms, used by nine other handlers:

  `bad_input_detail(exc)`   returns the reason without the path, and says so.
  `exc.strerror or exc`     `strerror` for an error the operating system raised, which
                            has no path in it. The whole exception is reached only when
                            there is no `strerror`, and that means somebody hand-built
                            the OSError to carry a message, so it has no filename either.

That second form matters more than it looks. `collect-evidence` raises
`OSError("GITHUB_TOKEN is not set. Export a token with...")` as a carrier, and an earlier
version of this fix routed it through `bad_input_detail`, which turned that sentence into
"it could not be read (unreadable)". The test below holds both directions.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.finding_sarif import _load_runs
from oss_policy_kit.cli import evidence as evidence_mod
from oss_policy_kit.cli.emit_vex import _write_vex_output
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()

#: A token that can only appear in output by way of an absolute path. Comparing against
#: `str(tmp_path)` is unreliable on Windows, where the exception carries the 8.3 short
#: form while the Path renders long, so a leak test written that way passes for the wrong
#: reason.
MARKER = "abspathmarker7q"


# --- the messages ---------------------------------------------------------------------


def test_the_sarif_reader_does_not_name_the_file_it_could_not_read(tmp_path: Path) -> None:
    root = tmp_path / MARKER
    root.mkdir()

    _, error = _load_runs(root / "missing.sarif")

    assert error is not None
    assert MARKER not in error
    assert "Errno" not in error
    assert "could not be read" in error


def test_emit_vex_does_not_name_the_path_it_could_not_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / MARKER
    root.mkdir()
    (root / "taken").mkdir()
    monkeypatch.chdir(root)

    with pytest.raises(InvalidInputError) as caught:
        _write_vex_output("{}", Path("taken"), [], {})

    message = str(caught.value)
    assert MARKER not in message
    assert "Errno" not in message
    assert "taken" in message, "the path the operator typed is theirs and stays"


def _stub_collector(monkeypatch: pytest.MonkeyPatch) -> None:
    """Get past the network stage so the write is what fails."""

    class _Collector:
        def collect(self, _slug: str) -> list[Any]:
            return []

    monkeypatch.setattr(evidence_mod, "_build_evidence_collector", lambda *_a, **_k: (_Collector(), "org/repo"))


def test_collect_evidence_does_not_name_the_directory_it_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The destination is resolved to an absolute path before the write, so the raw
    exception named it even when the operator typed a relative one."""

    root = tmp_path / MARKER
    root.mkdir()
    (root / "notadir").write_text("x", encoding="utf-8")
    monkeypatch.chdir(root)
    _stub_collector(monkeypatch)

    result = runner.invoke(
        app, ["collect-evidence", "--target", ".", "--platform", "github", "--output-dir", "notadir/under"]
    )

    assert result.exit_code == 2, result.output
    assert MARKER not in result.output
    assert "Errno" not in result.output


def test_a_hand_built_oserror_still_reaches_the_operator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`collect-evidence` raises `OSError(<a sentence>)` when the token is missing.

    Redacting that handler to `strerror` alone would answer a missing token with
    "it could not be read (unreadable)". It has no `strerror`, and no filename either, so
    the idiom prints the sentence.
    """

    root = tmp_path / MARKER
    root.mkdir()
    monkeypatch.chdir(root)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    result = runner.invoke(app, ["collect-evidence", "--target", ".", "--platform", "github"])

    assert result.exit_code == 2, result.output
    assert "GITHUB_TOKEN" in result.output, result.output
    assert MARKER not in result.output


# --- the rule, derived from the source -------------------------------------------------

_REDACTORS = {"bad_input_detail"}


def _permitted(expr: ast.expr, name: str) -> set[int]:
    """Node ids of the bare mentions of *name* that one of the three safe shapes covers."""

    ok: set[int] = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or) and len(node.values) == 2:
            left, right = node.values
            if (
                isinstance(left, ast.Attribute)
                and left.attr == "strerror"
                and isinstance(left.value, ast.Name)
                and left.value.id == name
                and isinstance(right, ast.Name)
                and right.id == name
            ):
                ok.add(id(right))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _REDACTORS:
                ok.update(id(a) for a in node.args if isinstance(a, ast.Name) and a.id == name)
            elif node.func.id == "getattr" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Name) and first.id == name:
                    ok.add(id(first))
    return ok


def _renderings_of_a_whole_oserror() -> list[str]:
    src = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit"
    found: list[str] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for handler in ast.walk(tree):
            if not isinstance(handler, ast.ExceptHandler) or not handler.type or not handler.name:
                continue
            if "OSError" not in ast.unparse(handler.type):
                continue
            name = handler.name
            for node in ast.walk(handler):
                if not isinstance(node, ast.FormattedValue):
                    continue
                bases = {id(n.value) for n in ast.walk(node.value) if isinstance(n, ast.Attribute)}
                ok = _permitted(node.value, name)
                if any(
                    isinstance(n, ast.Name) and n.id == name and id(n) not in bases and id(n) not in ok
                    for n in ast.walk(node.value)
                ):
                    found.append(f"{path.relative_to(src).as_posix()}:{node.lineno}  {ast.unparse(node.value)[:80]}")
    return found


def test_the_sweep_reads_the_handlers_it_claims_to() -> None:
    """A sweep that inspects nothing would pass this file without checking anything."""

    src = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit"
    handlers = sum(
        1
        for path in src.rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ExceptHandler) and node.type and "OSError" in ast.unparse(node.type)
    )
    assert handlers >= 40, f"only {handlers} OSError handlers found; the sweep is not reaching the source"


def test_no_handler_renders_a_whole_oserror() -> None:
    """Six did before this. Derived, so a seventh is caught without editing this file."""

    leaking = _renderings_of_a_whole_oserror()
    assert not leaking, "these render str(OSError), which embeds the absolute path:\n  " + "\n  ".join(leaking)
