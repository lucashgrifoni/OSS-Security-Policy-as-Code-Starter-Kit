"""Invalid ``--scorecard-json`` payloads are reported as user input errors.

Regression test for the validator finding where a malformed scorecard JSON exited
with code 3 ("Unexpected internal error") and a raw ``json.JSONDecodeError`` message,
instead of exit code 2 ("Invalid usage / validation error") with an actionable message.
"""

from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args


def _invoke_with_scorecard(scorecard: Path, out_dir: Path) -> object:
    runner = CliRunner()
    return runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(EXAMPLE_HARDENED),
                "--profile",
                "github-level-1",
                "--scorecard-json",
                str(scorecard),
                "--output-dir",
                str(out_dir),
            ]
        ),
    )


def _normalize(out: str) -> str:
    """Collapse rich-console line wraps so substring assertions survive long paths."""

    return " ".join(out.split())


def test_cli_invalid_scorecard_json_exits_2_with_friendly_message(tmp_path: Path) -> None:
    bad = tmp_path / "bad-scorecard.json"
    bad.write_text("{not json}", encoding="utf-8")
    out = tmp_path / "out"

    result = _invoke_with_scorecard(bad, out)
    flat = _normalize(result.output)

    assert result.exit_code == 2, result.output
    assert "Scorecard JSON could not be parsed" in flat
    assert bad.name in flat
    assert "OpenSSF Scorecard" in flat
    assert "Unexpected error" not in flat
    assert "Traceback" not in flat


def test_cli_invalid_scorecard_json_with_spaces_in_path_exits_2(tmp_path: Path) -> None:
    """The fix must also work when the scorecard path contains spaces (Windows-style)."""

    space_dir = tmp_path / "with space"
    space_dir.mkdir()
    bad = space_dir / "bad scorecard.json"
    bad.write_text("not json at all", encoding="utf-8")
    out = tmp_path / "out-spaces"

    result = _invoke_with_scorecard(bad, out)
    flat = _normalize(result.output)

    assert result.exit_code == 2, result.output
    assert "Scorecard JSON could not be parsed" in flat
    assert bad.name in flat
    assert "Unexpected error" not in flat


def test_cli_missing_scorecard_file_still_exits_2_with_existing_message(tmp_path: Path) -> None:
    """The pre-existing 'Scorecard file not found' path must keep its message and exit code."""

    missing = tmp_path / "does-not-exist.json"
    out = tmp_path / "out-missing"

    result = _invoke_with_scorecard(missing, out)

    assert result.exit_code == 2, result.output
    assert "Scorecard file not found" in result.output
    assert "Unexpected error" not in result.output
