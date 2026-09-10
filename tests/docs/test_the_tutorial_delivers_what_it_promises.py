"""The first-PR-gate tutorial is executed, not read: its own commands, its own snippets.

Three of its steps were wrong at once, and each failed on the exact starting condition the
page describes -- "a GitHub repository", "from zero to PR gate":

* **Step 2** ran `init --target . --with-evidence --with-workflow` and promised three
  artifacts. Platform detection reads CI files in the clone, not the git remote, so a
  repository that has no `.github/workflows/` yet -- the repository this tutorial is for --
  is `unknown`, and `init` writes only `oss-policy-kit.yaml`. Step 2 then told the reader to
  `git diff` a workflow file that was never written.
* **Step 4** printed a waiver as a bare YAML list using `reason:`. The loader takes a mapping
  with `version` and `waivers`, and the field is `justification`; the snippet as printed exits
  2 with `Waivers file root must be a mapping`.
* **Step 3** claimed the weighted score is printed on stdout. It is in `evaluation-report.md`,
  and on stdout only under `--summary-only`.

So the guard runs the page instead of trusting it: the bootstrap command is lifted out of the
Markdown and executed, the promised paths are checked on disk, and the waiver snippet is
lifted out and fed to the real loader. A command edited in the page without being re-run fails
here.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli.main import app
from tests.conftest import ROOT

_TUTORIAL = ROOT / "docs" / "tutorial-first-pr-gate.md"

#: The bootstrap step: the first documented `init` invocation on the page.
_INIT_LINE = re.compile(r"^(?:python -m oss_policy_kit|oss-policy-kit)\s+init\b.*$", re.MULTILINE)

#: The artifacts Step 2 promises, exactly as the page lists them.
_PROMISED = ("oss-policy-kit.yaml", ".oss-policy-kit/evidence", ".github/workflows/oss-policy-check.yml")


def _tutorial_text() -> str:
    return _TUTORIAL.read_text(encoding="utf-8")


def _bootstrap_argv() -> list[str]:
    line = _INIT_LINE.search(_tutorial_text())
    assert line is not None, "the tutorial no longer contains an `init` command line"
    command = line.group(0).strip()
    for prefix in ("python -m oss_policy_kit ", "oss-policy-kit "):
        command = command.removeprefix(prefix)
    return shlex.split(command, posix=True)


def _waiver_snippet() -> str:
    """The YAML block that Step 4 tells the reader to save as `waivers/waivers.yaml`."""

    blocks = re.findall(r"```yaml\n(.*?)```", _tutorial_text(), flags=re.DOTALL)
    for block in blocks:
        if "waivers/waivers.yaml" in block:
            return block
    pytest.fail("the tutorial no longer contains the waivers/waivers.yaml snippet")


def _github_repo(root: Path) -> Path:
    """The repository the tutorial is addressed to: on GitHub, and not yet using Actions."""

    repo = root / "acme-widget"
    (repo / "src").mkdir(parents=True)
    (repo / "README.md").write_text("# Acme Widget\n", encoding="utf-8")
    (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (repo / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    return repo


def test_step_2_writes_every_artifact_it_lists(tmp_path: Path) -> None:
    repo = _github_repo(tmp_path)
    argv = _bootstrap_argv()
    # The page says "run this from your repository root"; `--target .` is aimed there.
    argv = [arg if arg != "." else str(repo) for arg in argv]

    result = CliRunner().invoke(app, argv, catch_exceptions=False)

    assert result.exit_code == 0, result.output
    missing = [name for name in _PROMISED if not (repo / name).exists()]
    assert not missing, (
        f"Step 2 of the tutorial lists {list(_PROMISED)} as what its command writes, and "
        f"{missing} were not written. Its next step tells the reader to `git diff` them. "
        f"Command run: {argv}. Output: {result.output}"
    )


def test_step_4_waiver_snippet_loads_through_the_real_loader(tmp_path: Path) -> None:
    snippet = _waiver_snippet()
    path = tmp_path / "waivers.yaml"
    path.write_text(snippet, encoding="utf-8")

    outcome = parse_waivers_file(path)

    assert outcome.by_control, (
        "the waiver snippet in Step 4 parsed to no waivers at all, so the reader who copies it "
        f"sees nothing change in the report the step promises. Snippet:\n{snippet}"
    )


def test_the_waived_control_is_one_the_documented_profile_evaluates() -> None:
    """A waiver for a control outside the profile is loaded and never applies -- a silent no-op.

    The step used to name `GH-PROV-023`, which `github-level-1` does not evaluate, so even a
    correctly shaped file would have changed nothing in the run the same step prints.
    """

    waived = set(yaml.safe_load(_waiver_snippet())["waivers"][0]["control_id"].split())
    profile = yaml.safe_load(
        (ROOT / "src" / "oss_policy_kit" / "data" / "profiles" / "github-level-1" / "profile.yaml").read_text(
            encoding="utf-8"
        )
    )
    evaluated = {str(entry.get("id") if isinstance(entry, dict) else entry) for entry in profile.get("controls", [])}

    assert waived <= evaluated, (
        f"Step 4 waives {sorted(waived)}, and the profile it runs on the next line evaluates "
        f"{len(evaluated)} controls that do not include it. The waiver would be loaded and never applied."
    )


def test_the_stdout_claim_names_the_flag_that_prints_the_score() -> None:
    """`evaluate` prints the weighted score under `--summary-only`; the default table does not.

    Asserted against the CLI, not against the prose, so the day the table starts carrying a
    score this test says the page may now make the simpler claim.
    """

    runner = CliRunner()
    hardened = str(ROOT / "examples" / "hardened-repo")
    default = runner.invoke(app, ["evaluate", "--target", hardened, "--profile", "github-level-1"])
    summary = runner.invoke(app, ["evaluate", "--target", hardened, "--profile", "github-level-1", "--summary-only"])

    assert "Weighted score" in summary.output, summary.output
    assert "Weighted score" not in default.output, (
        "the default `evaluate` stdout now carries the weighted score; the tutorial's evidence "
        "table was corrected to say it appears only under --summary-only and can be simplified."
    )
    claim = [line for line in _tutorial_text().splitlines() if line.startswith("| CLI stdout |")]
    assert claim and "--summary-only" in claim[0], (
        "the tutorial's `CLI stdout` evidence row no longer tells the reader that the weighted "
        f"score needs --summary-only: {claim}"
    )
