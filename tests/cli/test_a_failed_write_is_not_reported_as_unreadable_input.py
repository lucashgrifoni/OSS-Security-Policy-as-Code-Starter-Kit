"""`evaluate-many` must not answer a blocked output directory by blaming its input.

The two consolidated artifacts were the last unguarded writes in the batch. An `OSError`
from either reached the CLI's last-resort handler, which classifies every `OSError` as
unreadable INPUT.

Measured with `evaluation-batch.json` occupied by a directory, so the write raises the way
a permission-denied or full output directory does:

    exit 2
    Error: input could not be read: it could not be read (Permission denied)

Nothing was wrong with the input. The repositories were read fine -- the run got as far as
producing a complete payload. The sentence sends the operator to check permissions on the
repositories being audited, and says "could not be read" twice about a write.

The kit already had the right sentence in two places: `_ensure_batch_dir` for the `mkdir`
a few lines earlier, and single `evaluate` for its own reports ("Cannot write to
--output-dir '...': Permission denied"). Only the step between them was missing it.

Both artifacts are covered, because they are written in sequence and either can be the one
that fails.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()

_ARTIFACTS = ("evaluation-batch.json", "evaluation-batch.md")


def _target_root(tmp_path: Path) -> Path:
    mono = tmp_path / "mono"
    for name in ("a-repo", "b-repo"):
        child = mono / name
        child.mkdir(parents=True)
        (child / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    return mono


def _run_with_blocked(tmp_path: Path, blocked: str) -> tuple[int, str]:
    """Run the batch with *blocked* occupied by a directory, so writing it raises."""

    out = tmp_path / "out"
    out.mkdir(parents=True)
    (out / blocked).mkdir()

    result = runner.invoke(
        app,
        [
            "evaluate-many",
            "--target-root",
            str(_target_root(tmp_path)),
            "--profiles",
            "github-level-1",
            "--output-dir",
            str(out),
            "--quiet",
        ],
    )
    return result.exit_code, " ".join(result.output.split())


@pytest.mark.parametrize("blocked", _ARTIFACTS)
def test_a_blocked_artifact_is_reported_as_a_write_failure(blocked: str, tmp_path: Path) -> None:
    exit_code, output = _run_with_blocked(tmp_path, blocked)

    assert exit_code == 2, f"exit {exit_code} for an output directory the kit cannot write to"
    assert f"Cannot write {blocked}" in output, (
        f"the run reported {output!r}. The input was read fine -- the batch got as far as a "
        "complete payload -- and this sentence sends the operator to the wrong place."
    )
    # The shape of a read failure, whatever prefix the handler puts in front of it. Asserting
    # the handler's exact wording would pass for any rewording of that prefix.
    assert "could not be read" not in output


@pytest.mark.parametrize("blocked", _ARTIFACTS)
def test_the_message_names_the_os_reason_and_not_the_path(blocked: str, tmp_path: Path) -> None:
    """`str(OSError)` embeds the absolute filename, which is the M-002 leak this avoids.

    The reason itself is whatever the platform says -- Windows answers "Permission denied"
    for a directory in the file's place and Linux answers "Is a directory". Asserting the
    Windows wording is what made the first version of this test pass here and fail in CI,
    so what is held is the shape: a real reason arrived, not the ``strerror or 'filesystem
    error'`` fallback, and no path came with it.
    """

    _exit_code, output = _run_with_blocked(tmp_path, blocked)

    reason = output.split("--output-dir: ", 1)[1].split(".", 1)[0]
    no_reason = (
        f"the message carries no OS reason for the failure: {output!r}. The fallback text "
        "tells the operator nothing they can act on."
    )
    assert reason, no_reason
    assert reason != "filesystem error", no_reason
    assert str(tmp_path) not in output
    assert tmp_path.name not in output


@pytest.mark.parametrize("blocked", _ARTIFACTS)
def test_the_operator_is_warned_the_two_files_may_disagree(blocked: str, tmp_path: Path) -> None:
    """They are written in sequence, so either failure leaves a mismatched pair.

    Which file is the stale one depends on which write failed, and nothing inside either
    says so. The warning therefore states what is true in both directions -- the pair
    describes different runs -- rather than naming one of them as the leftover. An earlier
    version said "left over from an earlier run", which is false when the SECOND write
    fails: the other file is this run's, freshly written.
    """

    _exit_code, output = _run_with_blocked(tmp_path, blocked)

    assert "different runs" in output
    assert "delete both" in output
    assert "earlier run" not in output, (
        "the message names one file as the leftover, which only holds when the first write is the one that failed."
    )


def test_a_writable_output_directory_still_produces_both_artifacts(tmp_path: Path) -> None:
    """The other half: the guard must not turn a working run into an error."""

    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "evaluate-many",
            "--target-root",
            str(_target_root(tmp_path)),
            "--profiles",
            "github-level-1",
            "--output-dir",
            str(out),
            "--quiet",
        ],
    )

    assert result.exit_code in (0, 1), f"exit {result.exit_code}: {result.output[-300:]!r}"
    for artifact in _ARTIFACTS:
        assert (out / artifact).is_file(), f"{artifact} was not written"
