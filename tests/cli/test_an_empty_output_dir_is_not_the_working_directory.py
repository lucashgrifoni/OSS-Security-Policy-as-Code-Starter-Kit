"""`--output-dir ""` wrote the reports into the working directory and said nothing.

`Path("")` is `Path(".")`, so an empty value reached the filesystem as the current
directory. Run at a repository root, which is where CI runs, that dropped
`evaluation-report.json` and `evaluation-report.md` into the repository being scanned,
with exit 0 and no warning. The documented default is `out/`.

`scaffold-evidence` is absent from these cases on purpose: it has no `--output-dir` at
all. Passing it one made Click answer exit 2 for an unknown option, which is the code these
tests assert, so the case passed on both sides of the fix and proved nothing. Asking Click
which commands carry the flag is what settled it.

`init` had the worse version of it. Its `--output-dir` is a plain string, so the empty
value survived into the generated `oss-policy-kit.yaml` as `output_dir: ""`. The behaviour
then stopped being one mistaken run and became the project's configuration, in a file the
adopter keeps and versions.

Not passing the flag and passing it empty are different things, which is the whole point:
the first takes the default, the second was silently reinterpreted. `--output-dir .` still
asks for the working directory on purpose, and the last case here holds that open, because
a fix that rejected `.` as well would pass every rejection case above it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()


def _repo(root: Path) -> Path:
    """A target the commands accept, so the run reaches the option rather than the target."""

    repo = root / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    return repo


def _commands(repo: Path, root: Path) -> dict[str, list[str]]:
    return {
        "evaluate": ["evaluate", "--target", str(repo), "--profile", "github-level-1"],
        "evaluate-many": ["evaluate-many", "--target-root", str(root), "--profiles", "github-level-1"],
        "collect-evidence": ["collect-evidence", "--target", str(repo), "--platform", "github", "--dry-run"],
        "init": ["init", "--target", str(repo)],
    }


@pytest.mark.parametrize(
    "command",
    ["evaluate", "evaluate-many", "collect-evidence", "init"],
)
def test_an_empty_output_dir_is_refused(command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _repo(tmp_path)
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    result = runner.invoke(app, [*_commands(repo, tmp_path)[command], "--output-dir", ""])

    assert result.exit_code == 2, (
        f"`{command} --output-dir ''` exited {result.exit_code}. An empty value is not the "
        "documented default and is not `.`; it has to be refused, with the exit code this "
        f"CLI uses for bad input. Output was: {result.output!r}"
    )
    assert not list(workdir.iterdir()), (
        f"`{command} --output-dir ''` wrote {[p.name for p in workdir.iterdir()]} into the "
        "working directory. In CI that directory is the repository being scanned."
    )


@pytest.mark.parametrize(
    "command",
    ["evaluate", "evaluate-many", "collect-evidence", "init"],
)
def test_whitespace_is_not_a_directory_name_either(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A quoted space survives a shell that eats a truly empty argument."""

    repo = _repo(tmp_path)
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    result = runner.invoke(app, [*_commands(repo, tmp_path)[command], "--output-dir", "   "])

    assert result.exit_code == 2, f"`{command} --output-dir '   '` exited {result.exit_code}"


def test_init_does_not_persist_an_empty_output_dir(tmp_path: Path) -> None:
    """The half that outlives the run: the value would land in the config the adopter keeps."""

    repo = _repo(tmp_path)

    result = runner.invoke(app, ["init", "--target", str(repo), "--output-dir", ""])

    assert result.exit_code == 2
    assert not (repo / "oss-policy-kit.yaml").exists(), (
        'init wrote its config despite refusing the value, so the next run would read `output_dir: ""` back out of it'
    )


def test_a_single_dot_still_asks_for_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The preservation leg. Without it, refusing `.` too would satisfy every case above."""

    repo = _repo(tmp_path)
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    result = runner.invoke(app, ["evaluate", "--target", str(repo), "--profile", "github-level-1", "--output-dir", "."])

    assert result.exit_code in (0, 1), f"`--output-dir .` was refused: {result.output!r}"
    assert (workdir / "evaluation-report.json").exists(), (
        "`--output-dir .` no longer writes into the working directory, so the fix took away "
        "the one spelling that asked for it deliberately"
    )
