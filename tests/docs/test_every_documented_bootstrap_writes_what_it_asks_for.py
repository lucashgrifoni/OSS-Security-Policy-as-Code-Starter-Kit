"""Every documented `init` that asks for an artifact writes it, on the repository it is aimed at.

The README quickstart ran `init --target . --with-evidence --with-workflow` and wrote neither.
Platform detection reads CI files in the clone, not the git remote, so a GitHub repository
that has no workflow yet -- the one a first gate is for -- is `unknown`, and `init` skips both
flags with exit 0. The first-PR tutorial had the same defect and was fixed with
`--platform github`, guarded by a test that executes that one page. The README and the CLI
reference's "full bootstrap" kept the broken form, because nothing read them.

So this guard does not name pages. It collects every `init` invocation from the fenced code
blocks of the README and every page under `docs/`, joins continuation lines, runs each one
against a GitHub repository without workflows, and checks that each `--with-*` flag in the
command produced its artifact.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app
from tests.conftest import ROOT

#: What each flag promises on disk. A command asks for exactly the flags it carries.
_ARTIFACT_FOR_FLAG = {
    "--with-workflow": ".github/workflows/oss-policy-check.yml",
    "--with-evidence": ".oss-policy-kit/evidence",
    "--with-waivers": "waivers.yaml",
}

_FENCE = re.compile(r"```[a-z]*\n(.*?)```", re.DOTALL)
_PREFIXES = ("python -P -m oss_policy_kit ", "python -m oss_policy_kit ", "oss-policy-kit ")


def _pages() -> list[Path]:
    return [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]


def _documented_bootstraps() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for page in _pages():
        for block in _FENCE.findall(page.read_text(encoding="utf-8")):
            for line in block.replace("\\\n", " ").splitlines():
                command = line.split("#", 1)[0].strip()
                if not any(command.startswith(p + "init") for p in _PREFIXES):
                    continue
                if any(flag in command for flag in _ARTIFACT_FOR_FLAG):
                    found.append((page.relative_to(ROOT).as_posix(), command))
    return found


def _argv(command: str) -> list[str]:
    for prefix in _PREFIXES:
        command = command.removeprefix(prefix)
    return shlex.split(command, posix=True)


def _github_repo_without_workflows(root: Path) -> Path:
    repo = root / "acme-widget"
    (repo / "src").mkdir(parents=True)
    (repo / "README.md").write_text("# Acme Widget\n", encoding="utf-8")
    (repo / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    return repo


def test_the_sweep_reaches_the_documented_bootstraps() -> None:
    """A sweep that finds nothing would pass whatever the pages said."""

    pages = {page for page, _ in _documented_bootstraps()}
    assert {"README.md", "docs/tutorial-first-pr-gate.md", "docs/cli-reference.md"} <= pages, pages


@pytest.mark.parametrize(("page", "command"), _documented_bootstraps(), ids=lambda value: value[:60])
def test_a_documented_bootstrap_writes_every_artifact_it_asks_for(page: str, command: str, tmp_path: Path) -> None:
    repo = _github_repo_without_workflows(tmp_path)
    argv = [str(repo) if arg == "." else arg for arg in _argv(command)]
    if "--dry-run" in argv:
        pytest.skip("a dry run writes nothing by design")

    result = CliRunner().invoke(app, argv, catch_exceptions=False)

    assert result.exit_code == 0, result.output
    missing = [path for flag, path in _ARTIFACT_FOR_FLAG.items() if flag in argv and not (repo / path).exists()]
    assert not missing, (
        f"{page} documents `{command}`. On a GitHub repository with no workflow yet it did not "
        f"write {missing}, and exited 0. Detection reads CI files, not the remote: name the "
        f"platform with `--platform github`. Output: {result.output}"
    )
