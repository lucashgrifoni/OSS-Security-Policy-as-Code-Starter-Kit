"""A `--include`/`--exclude` pattern must mean the same thing from any directory.

On Windows, Click expands globs in `argv` itself, to emulate a POSIX shell -- and it expands
them against the CURRENT WORKING DIRECTORY, which is not the directory being audited. Every
pattern-valued option in this CLI was rewritten by it: `evaluate-many --include/--exclude`
and the `--include/--exclude` of all five `scan-*` commands.

Measured with provably identical argv (`['--exclude', 'doc*']` both times), only the working
directory differing:

* from an empty directory, `evaluate-many --exclude 'doc*'` audited 1 of 2 repositories,
  as asked;
* from a directory that merely happened to contain an unrelated `docsomething`, the same
  command audited both and exited 0 with no warning.

A batch gate that reports green while it evaluated a set the operator excluded is worse
than one that fails, so this is pinned two ways: the flag that disables the expansion, and
the behaviour it protects.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_WORKFLOW = (
    "name: ci\non:\n  push:\npermissions:\n  contents: read\n"
    "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
)


def test_the_cli_disables_click_windows_argv_expansion() -> None:
    """The flag itself. Portable: it holds on every platform, and Windows is where it bites."""

    from oss_policy_kit.cli import main as cli_main

    source = Path(cli_main.__file__).read_text(encoding="utf-8")

    assert "windows_expand_args=False" in source, (
        "the CLI stopped disabling Click's Windows argv glob expansion, so pattern-valued "
        "options are again resolved against the caller's working directory"
    )


def _repo(root: Path, name: str) -> None:
    workflow = root / name / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(_WORKFLOW, encoding="utf-8")
    (root / name / "README.md").write_text("x\n", encoding="utf-8")


def test_an_unrelated_directory_beside_the_caller_cannot_widen_the_batch(tmp_path: Path) -> None:
    """The behaviour. Run from a directory holding a decoy that the pattern would match."""

    target_root = tmp_path / "root"
    _repo(target_root, "api")
    _repo(target_root, "docs-only")

    caller = tmp_path / "caller"
    (caller / "docsomething").mkdir(parents=True)

    out = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate-many",
            "--target-root",
            str(target_root),
            "--profiles",
            "github-level-1",
            "--output-dir",
            str(out),
            "--exclude",
            "doc*",
            "--skip-non-repos",
            "--quiet",
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        text=True,
        cwd=caller,
        env={**os.environ, "COLUMNS": "200"},
    )

    assert result.returncode == 0, f"batch failed: {result.stderr[-400:]}"
    batch = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    audited = sorted(_target_names(batch))

    assert audited == ["api"], (
        f"`--exclude doc*` should have left only 'api', but the batch audited {audited}. "
        f"An unrelated 'docsomething' next to the caller widened the scope."
    )


def _target_names(batch: dict[str, object]) -> list[str]:
    """The audited directory names, read from the batch contract's `runs` list."""

    runs = batch.get("runs")
    assert isinstance(runs, list), f"no `runs` list in the batch report; keys were {sorted(batch)}"

    return [str(r.get("target_name")) for r in runs if isinstance(r, dict) and r.get("target_name")]
