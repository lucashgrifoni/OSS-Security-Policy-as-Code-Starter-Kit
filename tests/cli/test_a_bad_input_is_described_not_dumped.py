"""Two messages an operator read as Python rather than as the kit.

Both were found by the clean-room validation of 10.0.25, from a venv holding only the wheel:

- a waivers file nested 600 levels deep answered ``Failed to read waivers file ...: maximum
  recursion depth exceeded``, the interpreter describing its own stack;
- the last-resort handler answered an unreadable input with ``input could not be read: it
  could not be read (Permission denied)``, the same verb twice.

The kit already had the words for both: ``bad_input_detail`` describes a bad input as a
clause about the input. The waivers loader now uses it, and the handler's prefix names the
class of failure instead of repeating the clause.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli.common import exit_for_unexpected
from oss_policy_kit.domain.errors import LoadError


def _failure(path: Path) -> str:
    with pytest.raises(LoadError) as caught:
        parse_waivers_file(path)
    return str(caught.value)


def test_a_waivers_file_nested_too_deeply_says_so(tmp_path: Path) -> None:
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text("a:\n" + "".join("  " * level + "- \n" for level in range(1, 600)), encoding="utf-8")

    message = _failure(waivers)

    assert "nested too deeply" in message, message
    assert "recursion" not in message, message


def test_a_malformed_waivers_file_is_called_invalid_yaml(tmp_path: Path) -> None:
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text("a: [unclosed\n", encoding="utf-8")

    assert "invalid YAML" in _failure(waivers)


def test_an_unreadable_waivers_file_names_its_path_once(tmp_path: Path) -> None:
    """A directory in the file's place. ``str(OSError)`` repeated the path the prefix prints."""

    waivers = tmp_path / "waivers.yaml"
    waivers.mkdir()

    message = _failure(waivers)

    assert "could not be read" in message, message
    assert message.count(waivers.name) == 1, message


def test_the_last_resort_handler_does_not_repeat_itself(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(typer.Exit) as caught:
        exit_for_unexpected(PermissionError(13, "Permission denied"))

    stderr = " ".join(capsys.readouterr().err.split())
    assert caught.value.exit_code == 2
    assert "could not be read (Permission denied)" in stderr, stderr
    assert stderr.count("could not be read") == 1, stderr
