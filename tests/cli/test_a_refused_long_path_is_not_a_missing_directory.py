"""A write refused for its length is reported as a length, not as a missing directory.

Measured on Windows 11 on 2026-09-19 by creating directories at increasing lengths:

    total 247 and below                      created
    total 248..259, and any nested shape     winerror 206, "The filename or extension
                                             is too long" -- already correct
    total 260+, long final component         winerror 3, "The system cannot find the
                                             path specified" -- names the wrong thing

Only the third row is a defect, and it is the one an operator hits: ``--output-dir`` at
318 characters was answered with "cannot find the path specified" about a directory the
command had just been asked to create, which sends the reader hunting for a missing
parent that is not missing. Run against the parent commit the same invocation printed no
length at all; against this one it prints both the measured length and the limit.

Ten raisers report a failed write to an operator-supplied path and every one of them can be
handed winerror 3, so the sweep below is derived from the source rather than from a list.

It said eight, and it said "derived", and the second claim was only half true. It found a
raiser by the phrase "Cannot write" in its message, so two with the same defect and
different wording were invisible to it: `correlate-findings` says "cannot write --output",
lowercase, and `scaffold-evidence` says "Could not create --target directory". The sweep
now finds a raiser by what its `try` does, a write, and not by what its message says. That
finds exactly the eight it found before and exactly the two it missed, and nothing else.

What the clause deliberately does not do: assert a cause. ERROR_PATH_NOT_FOUND really is
also what a genuinely missing parent looks like, so the wording says the length "may be"
the reason and leaves the operating system's own sentence in front of it untouched. And
it names the length only, never the path, which would undo the M-002 redaction the same
messages go to some trouble to keep.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

from oss_policy_kit.application.input_limits import WINDOWS_LONG_PATH_FLOOR, long_path_note

#: ERROR_PATH_NOT_FOUND, "the system cannot find the path specified". What this Windows
#: 11 build returns for a long final component.
_PATH_NOT_FOUND = 3
#: ERROR_INVALID_NAME, "the filename, directory name, or volume label syntax is
#: incorrect". What the CI runner returns for the same shape. Found by the Windows leg
#: going red while both Linux legs passed, which is the whole reason that leg exists.
_INVALID_NAME = 123
#: ERROR_FILENAME_EXCED_RANGE, the code that already says the name is too long.
_FILENAME_TOO_LONG = 206
#: The two that name the wrong cause. Kept here as a literal rather than imported, so a
#: change to the product's set has to be made deliberately in both places.
_MISLEADING = (_PATH_NOT_FOUND, _INVALID_NAME)


class _RefusedForLength(OSError):
    """An ``OSError`` shaped like the Windows one, constructible on any platform.

    A real ``OSError`` carries ``winerror`` only on Windows, and there it is a read-only
    descriptor, so neither setting it nor raising the genuine article gives a test that
    runs on all three legs of the matrix. Shadowing the attribute on a subclass does:
    attribute lookup finds the subclass first on Windows and on Linux alike.
    """

    winerror = _PATH_NOT_FOUND
    strerror = "The system cannot find the path specified"

    def __init__(self, filename: str) -> None:
        super().__init__(_PATH_NOT_FOUND, self.strerror)
        self.filename = filename


# --- the clause itself --------------------------------------------------------------


@pytest.mark.parametrize("winerror", _MISLEADING)
def test_the_refused_length_is_named(winerror: int) -> None:
    note = long_path_note("x" * 318, winerror=winerror)
    assert "318 characters" in note
    assert f"{WINDOWS_LONG_PATH_FLOOR} characters" in note


def test_the_floor_is_the_measured_one() -> None:
    """248, the length at which this Windows build begins refusing directories."""

    assert WINDOWS_LONG_PATH_FLOOR == 248


@pytest.mark.parametrize("winerror", _MISLEADING)
@pytest.mark.parametrize("length", [WINDOWS_LONG_PATH_FLOOR, WINDOWS_LONG_PATH_FLOOR + 1, 400])
def test_at_or_past_the_floor_the_length_is_reported(length: int, winerror: int) -> None:
    assert f"{length} characters" in long_path_note("x" * length, winerror=winerror)


@pytest.mark.parametrize("winerror", _MISLEADING)
@pytest.mark.parametrize("length", [0, 1, 100, WINDOWS_LONG_PATH_FLOOR - 1])
def test_below_the_floor_nothing_is_added(length: int, winerror: int) -> None:
    """A short path that cannot be found is a missing path, and saying otherwise misleads."""

    assert long_path_note("x" * length, winerror=winerror) == ""


def test_the_code_that_already_explains_itself_is_left_alone() -> None:
    """Windows' own text for 206 names the length; repeating it in other words is noise."""

    assert long_path_note("x" * 400, winerror=_FILENAME_TOO_LONG) == ""


@pytest.mark.parametrize("winerror", [None, 0, 2, 13, 206, 5, 4, 32, 267])
def test_no_other_error_code_gets_the_clause(winerror: int | None) -> None:
    assert long_path_note("x" * 400, winerror=winerror) == ""


def test_no_winerror_is_every_other_platform() -> None:
    """On Linux and macOS ``OSError`` has no ``winerror``; the caller passes ``None``."""

    assert long_path_note("x" * 400, winerror=getattr(OSError(), "winerror", None)) == ""


def test_a_path_object_is_measured_the_same_as_its_string() -> None:
    p = Path("C:/") / ("d" * 300)
    assert long_path_note(p, winerror=_PATH_NOT_FOUND) == long_path_note(str(p), winerror=_PATH_NOT_FOUND)


def test_the_clause_never_carries_the_path() -> None:
    """M-002. The length is the missing fact; the path is the thing not to print."""

    secret = "usernameleakmarker"
    path = f"C:/{secret}/" + "z" * 400
    note = long_path_note(path, winerror=_PATH_NOT_FOUND)
    assert note, "the clause should fire for this length"
    assert secret not in note
    assert "z" * 8 not in note


# --- every raiser in the family, derived from the source ------------------------------


#: The calls that write to the filesystem. A `try` that makes one of them is guarding a
#: write, whatever its handler's message happens to say.
_WRITES = frozenset(
    {
        "write_text",
        "write_bytes",
        "mkdir",
        "makedirs",
        "touch",
        "replace",
        "rename",
        "copyfile",
        "copy2",
        "_atomic_write_text",
        "write_reports",
        "write_sarif_report",
        "write_markdown_report",
    }
)


def _open_modes(call: ast.Call) -> list[ast.expr]:
    """Where a mode can sit: second for ``open(path, mode)``, first for ``path.open(mode)``."""

    positional = call.args[1:2] if isinstance(call.func, ast.Name) else call.args[:2]
    return [*positional, *(kw.value for kw in call.keywords if kw.arg == "mode")]


def _is_a_write_mode(node: ast.expr) -> bool:
    # A mode string and nothing else: "tax.json" has an x in it and opens nothing for writing.
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and re.fullmatch(r"[rwaxbt+]+", node.value) is not None
        and bool(set(node.value) & set("wax"))
    )


def _performs_a_write(body: list[ast.stmt]) -> bool:
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in _WRITES:
            return True
        if name == "open" and any(_is_a_write_mode(mode) for mode in _open_modes(node)):
            return True
    return False


def _write_failure_raises() -> list[tuple[str, int, str]]:
    """Every ``raise InvalidInputError`` a failed write can reach, found by reading the source.

    A raise counts when it sits in a handler catching ``OSError`` on a ``try`` whose body
    writes. The message is deliberately not consulted: the first version of this matched
    "Cannot write" and could not see two raisers that phrase the same failure differently.
    """

    src = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit"
    found: list[tuple[str, int, str]] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for block in (n for n in ast.walk(tree) if isinstance(n, ast.Try)):
            if not _performs_a_write(block.body):
                continue
            for handler in block.handlers:
                if not handler.type or "OSError" not in ast.unparse(handler.type):
                    continue
                for node in ast.walk(handler):
                    if isinstance(node, ast.Raise) and node.exc is not None:
                        text = ast.unparse(node)
                        if "InvalidInputError" in text:
                            found.append((path.name, node.lineno, text))
    return found


@pytest.mark.parametrize(
    ("source", "writes"),
    [
        ("open(p, 'w')", True),
        ("open(p, mode='x')", True),
        ("p.open('a')", True),
        ("p.open(mode='wb')", True),
        ("io.open(p, 'w')", True),
        ("p.write_text(s)", True),
        ("open(p)", False),
        ("p.open('r')", False),
        ("open('tax.json')", False),
        ("io.open('tax.json')", False),
        ("p.open(encoding='utf-8')", False),
        ("p.read_text()", False),
    ],
)
def test_the_sweep_knows_a_write_when_it_sees_one(source: str, writes: bool) -> None:
    """``path.open("w")`` carries its mode first, and the first version only looked second."""

    assert _performs_a_write(ast.parse(source).body) is writes


def test_the_sweep_finds_the_family() -> None:
    """A sweep that matches nothing passes for the wrong reason."""

    assert len(_write_failure_raises()) >= 10


def test_the_sweep_does_not_depend_on_how_a_message_is_worded() -> None:
    """The two raisers the phrase-matching version missed are in the family by structure."""

    found = {name for name, _line, _text in _write_failure_raises()}

    assert {"correlate_findings.py", "evidence.py"} <= found, found


def test_every_write_failure_can_name_the_length() -> None:
    """Derived, not listed: a raiser added tomorrow is held to this without an edit here."""

    missing = [f"{name}:{line}" for name, line, text in _write_failure_raises() if "long_path_note" not in text]
    assert not missing, f"write failures that cannot name a refused length: {missing}"


# --- through the CLI ------------------------------------------------------------------


def test_the_message_an_operator_reads_names_the_length(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The end-to-end shape, driven by the error Windows actually returns.

    The real reproduction needs a 318-character path and so runs only on Windows; this
    hands the same error to the same handler on every platform, which is what keeps the
    clause from being a guard only one leg of the matrix can see.
    """

    from oss_policy_kit.cli import common
    from oss_policy_kit.domain.errors import InvalidInputError

    long_name = "C:/o/" + "a" * 313

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise _RefusedForLength(long_name)

    monkeypatch.setattr(common, "write_reports", _boom)

    class _Req:
        output_dir = Path("out")
        include_absolute_path = False

    with pytest.raises(InvalidInputError) as caught:
        common._write_eval_reports(object(), _Req(), tmp_path)  # type: ignore[arg-type]

    message = str(caught.value)
    assert "Cannot write to --output-dir" in message
    assert f"{len(long_name)} characters" in message
    assert f"{WINDOWS_LONG_PATH_FLOOR} characters" in message
    assert "a" * 8 not in message, "the path itself must not reach the operator (M-002)"


def test_correlate_findings_names_the_length_of_an_output_it_could_not_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One of the two the phrase-matching sweep missed: it says "cannot write", lowercase."""

    from oss_policy_kit.cli import correlate_findings
    from oss_policy_kit.domain.errors import InvalidInputError

    long_name = "C:/o/" + "b" * 313

    def _boom(*_args: object, **_kwargs: object) -> int:
        raise _RefusedForLength(long_name)

    monkeypatch.setattr(Path, "write_text", _boom)

    with pytest.raises(InvalidInputError) as caught:
        correlate_findings._write_artifact({}, tmp_path / "out.json")

    message = str(caught.value)
    assert "cannot write --output" in message
    assert f"{len(long_name)} characters" in message
    assert "b" * 8 not in message, "the path itself must not reach the operator (M-002)"


def test_scaffold_evidence_names_the_length_of_a_target_it_could_not_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other: it says "Could not create --target directory", and the sweep never read it."""

    from typer.testing import CliRunner

    from oss_policy_kit.cli.main import app

    missing = tmp_path / "not-there-yet"
    long_name = "C:/o/" + "c" * 313
    real_mkdir = Path.mkdir

    def _refuse_only_the_target(self: Path, *args: object, **kwargs: object) -> None:
        if self == missing:
            raise _RefusedForLength(long_name)
        real_mkdir(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "mkdir", _refuse_only_the_target)

    result = CliRunner().invoke(app, ["scaffold-evidence", "--target", str(missing), "--platform", "github"])

    output = " ".join(result.output.split())
    assert result.exit_code == 2, result.output
    assert "Could not create --target directory" in output
    assert f"{len(long_name)} characters" in output


# --- the premise the constant rests on ------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="the refusal being described is Windows'")
def test_windows_refuses_a_long_component_without_naming_the_length(tmp_path: Path) -> None:
    """The premise the clause rests on, asserted as a property rather than one code.

    An earlier version of this test pinned the code to 3, which is what this Windows 11
    build returns. The CI runner returns 123 for the same shape, so the test went red on
    one leg of the matrix and told me the product was too narrow as well: keyed to 3
    alone, the clause would never have appeared on that machine.

    What actually has to hold is weaker and more durable. Windows refuses the path, and
    the reason it gives does not mention the length. If a build ever starts saying so
    itself, this fails and the clause is stale for that code.
    """

    target = tmp_path / ("a" * 270)
    assert len(str(target)) >= 260

    with pytest.raises(OSError) as caught:
        target.mkdir(parents=True, exist_ok=True)

    reason = (caught.value.strerror or "").lower()
    assert "too long" not in reason, f"Windows now names the length itself: {reason!r}"
    assert caught.value.winerror in _MISLEADING, (
        f"winerror {caught.value.winerror} refuses a long path and is not in the set the "
        f"clause fires on, so an operator on this build gets {reason!r} and no length"
    )
    # The clause has to actually appear for this build's code, not merely be reachable.
    assert f"{len(str(target))} characters" in long_path_note(target, winerror=caught.value.winerror)
