"""`emit-insights` named the file and not the place.

`emit-insights: wrote security-insights.yml` echoes the `--output` value back. The default is a
bare filename, so the operator is left to guess between the working directory, the `--target`,
and wherever the tool felt like writing. The two differ whenever `--target` is not `.`, which is
the case in every multi-repo workflow the kit documents.

`scan-sast` already answers this by putting the written path through `display_path`, which
resolves it, keeps it relative to the working directory and leaks no host layout.

The default is what carries the defect. An absolute `--output` already prints a full path, which
is why the first version of this file passed against the unfixed command.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _elsewhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """(working directory, target). Separate, because the defect is not seeing which one it means."""

    workdir = tmp_path / "workdir"
    target = tmp_path / "repo"
    workdir.mkdir()
    target.mkdir()
    monkeypatch.chdir(workdir)
    return workdir, target


def test_the_default_output_says_which_directory_it_landed_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workdir, target = _elsewhere(tmp_path, monkeypatch)

    res = runner.invoke(app, ["emit-insights", "--target", str(target)])

    assert res.exit_code == 0, res.output
    assert (workdir / "security-insights.yml").is_file(), "it lands beside the cwd, not the target"
    assert _flat(res.output) != "emit-insights: wrote security-insights.yml", (
        "a bare filename does not say which of the two directories it means"
    )


def test_the_merge_fragment_says_where_it_landed_too(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, target = _elsewhere(tmp_path, monkeypatch)

    res = runner.invoke(app, ["emit-insights", "--target", str(target), "--merge"])

    assert res.exit_code == 0, res.output
    assert _flat(res.output) != "emit-insights: wrote merge fragment security-insights.yml"


def test_the_message_does_not_leak_the_host_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The reason this goes through `display_path` rather than printing `output.resolve()`.

    A path under the working directory is shown relative to it, so the operator's home directory
    and account name stay out of a message that gets pasted into issues (M-002).
    """

    workdir, _ = _elsewhere(tmp_path, monkeypatch)

    res = runner.invoke(app, ["emit-insights", "--target", "."])

    assert res.exit_code == 0, res.output
    assert str(workdir) not in res.output, res.output
    assert "security-insights.yml" in _flat(res.output), res.output
