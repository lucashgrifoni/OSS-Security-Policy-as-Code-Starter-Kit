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

Eight raisers report a failed write to an operator-supplied output path and every one of
them can be handed winerror 3, so the sweep below is derived from the source rather than
from a list -- a ninth raiser added later is held to the same rule without anyone
remembering to add it here.

What the clause deliberately does not do: assert a cause. ERROR_PATH_NOT_FOUND really is
also what a genuinely missing parent looks like, so the wording says the length "may be"
the reason and leaves the operating system's own sentence in front of it untouched. And
it names the length only, never the path, which would undo the M-002 redaction the same
messages go to some trouble to keep.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from oss_policy_kit.application.input_limits import WINDOWS_LONG_PATH_FLOOR, long_path_note

#: ERROR_PATH_NOT_FOUND, the code whose own message names the wrong cause.
_PATH_NOT_FOUND = 3
#: ERROR_FILENAME_EXCED_RANGE, the code that already says the name is too long.
_FILENAME_TOO_LONG = 206


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


def test_the_refused_length_is_named() -> None:
    note = long_path_note("x" * 318, winerror=_PATH_NOT_FOUND)
    assert "318 characters" in note
    assert f"{WINDOWS_LONG_PATH_FLOOR} characters" in note


def test_the_floor_is_the_measured_one() -> None:
    """248, the length at which this Windows build begins refusing directories."""

    assert WINDOWS_LONG_PATH_FLOOR == 248


@pytest.mark.parametrize("length", [WINDOWS_LONG_PATH_FLOOR, WINDOWS_LONG_PATH_FLOOR + 1, 400])
def test_at_or_past_the_floor_the_length_is_reported(length: int) -> None:
    assert f"{length} characters" in long_path_note("x" * length, winerror=_PATH_NOT_FOUND)


@pytest.mark.parametrize("length", [0, 1, 100, WINDOWS_LONG_PATH_FLOOR - 1])
def test_below_the_floor_nothing_is_added(length: int) -> None:
    """A short path that cannot be found is a missing path, and saying otherwise misleads."""

    assert long_path_note("x" * length, winerror=_PATH_NOT_FOUND) == ""


def test_the_code_that_already_explains_itself_is_left_alone() -> None:
    """Windows' own text for 206 names the length; repeating it in other words is noise."""

    assert long_path_note("x" * 400, winerror=_FILENAME_TOO_LONG) == ""


@pytest.mark.parametrize("winerror", [None, 0, 2, 13, 206, 5])
def test_only_one_error_code_gets_the_clause(winerror: int | None) -> None:
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


def _write_failure_raises() -> list[tuple[str, int, str]]:
    """Every ``raise InvalidInputError`` for a failed write, found by reading the source.

    Scoped to raises that sit inside a handler catching ``OSError``, which is what a
    failed write looks like everywhere in this package.
    """

    src = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit"
    found: list[tuple[str, int, str]] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)):
            caught = ast.unparse(handler.type) if handler.type else ""
            if "OSError" not in caught:
                continue
            for node in ast.walk(handler):
                if not isinstance(node, ast.Raise) or node.exc is None:
                    continue
                text = ast.unparse(node)
                if "InvalidInputError" in text and "Cannot write" in text:
                    found.append((path.name, node.lineno, text))
    return found


def test_the_sweep_finds_the_family() -> None:
    """A sweep that matches nothing passes for the wrong reason."""

    assert len(_write_failure_raises()) >= 8


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


# --- the premise the constant rests on ------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="the refusal being described is Windows'")
def test_windows_still_answers_a_long_component_with_the_misleading_code(tmp_path: Path) -> None:
    """If Windows ever starts naming the length itself, this fails and the clause is stale.

    Asserts the premise rather than the message: that a directory whose final component is
    long is refused with ERROR_PATH_NOT_FOUND, whose text talks about a path that cannot be
    found rather than one that is too long.
    """

    target = tmp_path / ("a" * 270)
    assert len(str(target)) >= 260

    with pytest.raises(OSError) as caught:
        target.mkdir(parents=True, exist_ok=True)

    assert caught.value.winerror == _PATH_NOT_FOUND, f"winerror was {caught.value.winerror}"
    assert "too long" not in (caught.value.strerror or "").lower()
