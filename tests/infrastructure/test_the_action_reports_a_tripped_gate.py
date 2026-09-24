"""A tripped gate must still produce the Action's outputs and its job summary.

A composite step with `shell: bash` runs as `bash --noprofile --norc -e -o pipefail`. The
evaluate step called the kit bare and read `rc=$?` on the next line, so under `-e` a non-zero
exit ended the script before any output was written. Measured on 10.0.26, on a GitHub-hosted
runner, with the published `@v10.0.26`:

    exit-code: ''    report-json: ''    report-markdown: ''

for a gate that tripped (exit 1) and for a profile that does not exist (exit 2), and no job
summary or per-finding annotations, because the summary script sits after the call. The gate
itself still failed, so no run passed that should not have. What an adopter reads after
`continue-on-error` was missing.

The step tests that existed ran the script with plain `bash` and a `python` that always exits
0, which is neither the runner's shell nor the case that breaks. These run it with the
runner's flags and a `python` that exits the way the kit does.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from tests.infrastructure.test_action_version_resolution import BASH, _step_script

pytestmark = pytest.mark.skipif(BASH is None, reason="needs a working bash to run the composite step")

#: What GitHub runs a composite step with `shell: bash` under, as a runner's log prints it.
RUNNER_SHELL = ["--noprofile", "--norc", "-e", "-o", "pipefail"]


def _bash_path(path: Path) -> str:
    """A path as bash spells it: Git Bash reads a Windows drive as `/c/...`."""

    posix = path.as_posix()
    if len(posix) > 1 and posix[1] == ":":
        return "/" + posix[0].lower() + posix[2:]
    return posix


def _run(tmp_path: Path, kit_exit: int) -> tuple[int, dict[str, str], list[str]]:
    """Run the shipped evaluate step under the runner's shell, with a kit that exits ``kit_exit``.

    The report is on disk before the kit exits, as it is for a real tripped gate: `evaluate`
    writes it and then returns 1.
    """

    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "evaluation-report.json").write_text("{}", encoding="utf-8")
    calls = tmp_path / "calls.log"
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "python"
    stub.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{_bash_path(calls)}"\n'
        'case "$*" in *action_summary.py*) exit 0 ;; esac\n'
        f"exit {kit_exit}\n",
        encoding="utf-8",
        newline="\n",
    )
    stub.chmod(0o755)
    script = tmp_path / "run.sh"
    script.write_text(_step_script("Run evaluate"), encoding="utf-8", newline="\n")
    gh_output = tmp_path / "gh_output"
    gh_output.write_text("", encoding="utf-8")

    assert BASH is not None  # guarded by pytestmark
    proc = subprocess.run(
        [BASH, *RUNNER_SHELL, str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={
            "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "INPUT_TARGET": ".",
            "INPUT_PROFILE": "github-level-1",
            "INPUT_FAIL_ON": "fail",
            "INPUT_OUTPUT_DIR": _bash_path(reports),
            "INPUT_WAIVERS": "",
            "INPUT_SCORECARD_JSON": "",
            "INPUT_SARIF_OUTPUT": "",
            "GITHUB_WORKSPACE": "/ws/repo",
            "GITHUB_OUTPUT": str(gh_output),
            "GITHUB_ACTION_PATH": _bash_path(tmp_path / "action"),
        },
        check=False,
    )
    written: dict[str, str] = {}
    for line in gh_output.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            written[key] = value
    invoked = calls.read_text(encoding="utf-8").splitlines() if calls.is_file() else []
    return proc.returncode, written, invoked


@pytest.mark.parametrize("kit_exit", [1, 2, 3])
def test_a_non_zero_exit_still_writes_every_output(tmp_path: Path, kit_exit: int) -> None:
    returncode, written, _ = _run(tmp_path, kit_exit)

    assert written.get("exit_code") == str(kit_exit), written
    assert written.get("report_json", "").endswith("/evaluation-report.json"), written
    assert written.get("report_md", "").endswith("/evaluation-report.md"), written
    assert returncode == kit_exit, "the step must still fail with the kit's own exit code"


def test_the_job_summary_is_written_when_the_gate_trips(tmp_path: Path) -> None:
    _, _, invoked = _run(tmp_path, 1)

    assert any("-m oss_policy_kit evaluate" in call for call in invoked), invoked
    assert any("action_summary.py" in call for call in invoked), (
        f"the summary and the per-finding annotations are what a reader of a failed run looks at; calls made: {invoked}"
    )


def test_a_passing_run_is_unchanged(tmp_path: Path) -> None:
    returncode, written, invoked = _run(tmp_path, 0)

    assert returncode == 0
    assert written.get("exit_code") == "0"
    assert any("action_summary.py" in call for call in invoked), invoked
