"""The workflow ``init`` writes told the reader to copy it where it already was.

``init --with-workflow`` puts a file at ``.github/workflows/oss-policy-check.yml`` and the
file's second line read "Copy this file to .github/workflows/oss-policy-check.yml in your
repository". The adopter is handed a file, in the right place, instructing them to copy it to
the place it is in.

The line is correct where it was written. ``docs/adoption-guide.md`` tells adopters to browse
``templates/workflows/`` on GitHub and copy one by hand, and for that reader the destination
is the useful part of the sentence. It travelled into the generated copy because ``init``
wrote the template through unchanged apart from the gate arguments.

So the templates on disk keep the line and only the generated copy loses it, which is the
same split ``#277`` already used for the profile and fail-on substitution. The tests below
hold both halves of that split, because a fix that stripped the line from the packaged
templates would break the hand-copy path this project documents.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from click.testing import Result
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()

_TEMPLATE_PACKAGE = "oss_policy_kit.data.templates.workflows"

#: Every wording the bundled templates use to tell a reader where to put the file.
_COPY_INSTRUCTIONS = ("Copy this file to ", "Copy to ")


def _init(target: Path, *extra: str) -> Result:
    return runner.invoke(
        app,
        prepare_cli_args(
            ["init", "--target", str(target), "--platform", "github", "--with-workflow", *extra],
        ),
    )


def test_the_generated_workflow_does_not_tell_the_reader_to_copy_it(tmp_path: Path) -> None:
    """The defect, on the primary onboarding path and with no flags."""

    repo = tmp_path / "repo"
    repo.mkdir()

    result = _init(repo)
    assert result.exit_code == 0, result.output

    written = repo / ".github" / "workflows" / "oss-policy-check.yml"
    body = written.read_text(encoding="utf-8")

    offenders = [line for line in body.splitlines() if line.lstrip("# ").startswith(_COPY_INSTRUCTIONS)]
    assert not offenders, (
        f"{written.name} was written to its destination and still says to copy it there:\n  " + "\n  ".join(offenders)
    )


def test_the_packaged_templates_keep_the_instruction() -> None:
    """The other half of the split: the hand-copy path documented in the adoption guide.

    Without this, stripping the line at the source would pass the test above and quietly
    remove the destination from the file people are told to read on GitHub.
    """

    body = resources.files(_TEMPLATE_PACKAGE).joinpath("github-oss-policy-check.yml").read_text(encoding="utf-8")

    assert "# Copy this file to .github/workflows/oss-policy-check.yml" in body


def test_an_instruction_that_outlives_init_is_kept() -> None:
    """The waivers template folds two instructions into one sentence; only one expires.

    It reads "Copy to <path> and ensure waivers/waivers.yaml is committed". `init` satisfies
    the first half and not the second, so dropping the whole line would take a live
    instruction with it. This is the assertion that stops the fix from being a blunt delete.

    This one calls the transform rather than the CLI on purpose. `init` exposes
    `--with-workflow` and no way to pick which template it writes, so a test that asked the
    CLI for the waivers one would be asserting against a surface that does not exist.
    """

    from oss_policy_kit.application.init_writer import _drop_copy_instruction

    source = resources.files(_TEMPLATE_PACKAGE).joinpath("github-oss-policy-check-with-waivers.yml")
    body = _drop_copy_instruction(source.read_text(encoding="utf-8"))

    assert "Copy to " not in body
    assert "Ensure waivers/waivers.yaml is committed." in body


def test_a_template_with_no_such_instruction_is_untouched() -> None:
    """The transform must not edit a template it has nothing to do with.

    `github-oss-policy-check-level-2.yml` carries no copy instruction. If the line count or
    the header moved here, the matcher is too greedy.
    """

    from oss_policy_kit.application.init_writer import _drop_copy_instruction

    source = resources.files(_TEMPLATE_PACKAGE).joinpath("github-oss-policy-check-level-2.yml")
    body = source.read_text(encoding="utf-8")

    assert _drop_copy_instruction(body) == body


def test_the_generated_workflow_still_runs_the_gate(tmp_path: Path) -> None:
    """Removing a comment must not disturb the part of the file that does the work.

    A transform that dropped one line too many would still satisfy the first test here.
    """

    repo = tmp_path / "repo"
    repo.mkdir()

    result = _init(repo, "--profile", "github-level-1", "--fail-on", "fail")
    assert result.exit_code == 0, result.output

    body = (repo / ".github" / "workflows" / "oss-policy-check.yml").read_text(encoding="utf-8")

    assert "--profile github-level-1" in body
    assert "--fail-on fail" in body
    assert "name: OSS Policy Check" in body
    assert "uses: actions/checkout@" in body
