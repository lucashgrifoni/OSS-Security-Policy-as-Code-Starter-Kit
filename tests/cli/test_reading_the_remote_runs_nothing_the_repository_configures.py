"""`emit-insights` asks git for the remote of a repository it does not trust.

`git remote get-url origin` runs with the scanned repository's own `.git/config`, and that file
is written by whoever owns the repository. Git honours settings there that run a command: a
filesystem monitor (`core.fsmonitor`) when it reads the index, a hooks directory
(`core.hooksPath`) on commit and checkout. `remote get-url` reads config and prints a URL; it
does neither, so those settings have to stay inert here.

Each payload writes a marker file. The control runs a git command that DOES honour the setting
and requires the marker, so an absent marker after `_git_remote_url` means the command was not
run, not that the payload was broken. The URL itself is the repository's own text, so the
document it lands in must carry it as one value, whatever it contains.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from oss_policy_kit.cli import emit_insights as ei

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not on PATH")


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        check=False,
        timeout=30,
    )


def _repo(tmp_path: Path, url: str = "https://github.com/org/repo.git") -> Path:
    repo = tmp_path / "scanned"
    repo.mkdir()
    for args in (
        ("init", "-q"),
        ("config", "user.name", "t"),
        ("config", "user.email", "t@example.invalid"),
        ("config", "commit.gpgsign", "false"),
        ("remote", "add", "origin", url),
    ):
        assert _git(repo, *args).returncode == 0, args
    return repo


def _touch_command(marker: Path) -> str:
    """A shell command, as git runs it, that creates ``marker``."""

    python = Path(sys.executable).as_posix()
    return f'"{python}" -c "import pathlib; pathlib.Path(r\'{marker.as_posix()}\').touch()"'


def test_a_filesystem_monitor_in_the_config_is_not_run(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "fsmonitor-ran"
    assert _git(repo, "config", "core.fsmonitor", _touch_command(marker)).returncode == 0

    assert ei._git_remote_url(repo) == "https://github.com/org/repo"
    assert not marker.exists()

    _git(repo, "status")  # the control: status reads the index, so it asks the monitor
    assert marker.exists(), "the payload did not fire under `git status`; the test measures nothing"


def test_a_hooks_directory_in_the_config_is_not_run(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    marker = tmp_path / "hook-ran"
    hooks = tmp_path / "evil-hooks"
    hooks.mkdir()
    for name in ("pre-commit", "post-checkout", "post-merge", "reference-transaction", "pre-auto-gc"):
        hook = hooks / name
        hook.write_text(f"#!/bin/sh\n{_touch_command(marker)}\n", encoding="utf-8", newline="\n")
        hook.chmod(0o755)
    assert _git(repo, "config", "core.hooksPath", hooks.as_posix()).returncode == 0

    assert ei._git_remote_url(repo) == "https://github.com/org/repo"
    assert not marker.exists()

    _git(repo, "commit", "-q", "--allow-empty", "-m", "control")  # the control: commit runs pre-commit
    assert marker.exists(), "the hook did not fire under `git commit`; the test measures nothing"


def test_a_remote_url_that_looks_like_yaml_stays_one_value(tmp_path: Path) -> None:
    hostile = "https://github.com/org/repo\nheader:\n  url: https://evil.example/\n# end"
    repo = _repo(tmp_path, url=hostile)

    url = ei._git_remote_url(repo)
    assert url == hostile  # git hands the configured text back unchanged

    output = tmp_path / "security-insights.yml"
    ei._run_emit_insights(repo, output, validate=False, merge=False)
    doc = yaml.safe_load(output.read_text(encoding="utf-8"))

    assert doc["header"]["url"] == hostile
    assert doc["header"]["project-url"] == hostile
