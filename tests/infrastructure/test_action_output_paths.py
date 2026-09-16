"""Where the Action says it put the report, against where the kit actually put it.

`output-dir` was joined onto `GITHUB_WORKSPACE` unconditionally. An adopter passing an
absolute path, which `${{ runner.temp }}/reports` is, got the workspace glued onto the front:
`<workspace>//tmp/reports/evaluation-report.json` in the `report-json` output, a path that does
not exist. Three of the four outputs point at nothing in that case, and the job summary is
guarded by `[ -f ]` on the same wrong path, so it disappears without a message.

The `sarif-output` branch two lines below already tested for a leading slash. The fix is that
same test, applied once to the directory both of them hang off.

Found by the Loop 05 release-readiness gate, campaign 4, which asks for absolute, relative and
spaced paths. It ran against `action.yml` at 10.0.23 and this is what it returned.

`python` is stubbed so the step's path arithmetic runs without an evaluation: the contract under
test is what reaches `GITHUB_OUTPUT`, not what the kit does when it gets there. The stand-in
workspace is `/ws/repo` rather than a runner's real one, because the public hygiene gate reads
the runner's layout as a POSIX home path. Only the shape matters here.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from tests.infrastructure.test_action_version_resolution import BASH, _step_script

pytestmark = pytest.mark.skipif(BASH is None, reason="needs a working bash to run the composite step")

RUN_STEP = "Run evaluate"
WORKSPACE = "/ws/repo"


def _run_step(tmp_path: Path, *, output_dir: str, sarif_output: str = "") -> dict[str, str]:
    """Run the shipped step with a stubbed `python` and return what it wrote to GITHUB_OUTPUT."""

    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "python"
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
    stub.chmod(0o755)

    script = tmp_path / "run.sh"
    script.write_text(_step_script(RUN_STEP), encoding="utf-8", newline="\n")
    gh_output = tmp_path / "gh_output"
    gh_output.write_text("", encoding="utf-8")

    assert BASH is not None  # guarded by pytestmark
    subprocess.run(
        [BASH, str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={
            "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "INPUT_TARGET": ".",
            "INPUT_PROFILE": "",
            "INPUT_FAIL_ON": "fail",
            "INPUT_OUTPUT_DIR": output_dir,
            "INPUT_WAIVERS": "",
            "INPUT_SCORECARD_JSON": "",
            "INPUT_SARIF_OUTPUT": sarif_output,
            "GITHUB_WORKSPACE": WORKSPACE,
            "GITHUB_OUTPUT": str(gh_output),
            "GITHUB_ACTION_PATH": str(tmp_path / "action"),
        },
        check=False,
    )
    written: dict[str, str] = {}
    for line in gh_output.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            written[key] = value
    return written


def test_a_relative_output_dir_still_resolves_under_the_workspace(tmp_path: Path) -> None:
    """The case that always worked, pinned so fixing the other one cannot break it."""

    written = _run_step(tmp_path, output_dir="oss-policy-reports")

    assert written["report_json"] == f"{WORKSPACE}/oss-policy-reports/evaluation-report.json"
    assert written["report_md"] == f"{WORKSPACE}/oss-policy-reports/evaluation-report.md"


def test_an_absolute_output_dir_is_not_glued_onto_the_workspace(tmp_path: Path) -> None:
    """`${{ runner.temp }}/reports` is absolute, and the kit writes exactly there."""

    written = _run_step(tmp_path, output_dir="/tmp/reports")

    assert written["report_json"] == "/tmp/reports/evaluation-report.json"
    assert written["report_md"] == "/tmp/reports/evaluation-report.md"
    assert WORKSPACE not in written["report_json"], "the workspace prefix is what made this path fictional"


def test_a_relative_sarif_follows_the_same_directory_the_reports_did(tmp_path: Path) -> None:
    """The compounding case: a relative SARIF under an absolute output-dir was doubly wrong."""

    written = _run_step(tmp_path, output_dir="/tmp/reports", sarif_output="out.sarif")

    assert written["sarif"] == "/tmp/reports/out.sarif"


def test_an_absolute_sarif_is_left_alone(tmp_path: Path) -> None:
    """The branch that was already right."""

    written = _run_step(tmp_path, output_dir="oss-policy-reports", sarif_output="/tmp/out.sarif")

    assert written["sarif"] == "/tmp/out.sarif"


def test_an_output_dir_with_a_space_survives(tmp_path: Path) -> None:
    written = _run_step(tmp_path, output_dir="reports with space")

    assert written["report_json"] == f"{WORKSPACE}/reports with space/evaluation-report.json"


def test_no_sarif_input_emits_no_sarif_output(tmp_path: Path) -> None:
    """The output is documented as only set when sarif-output was provided."""

    written = _run_step(tmp_path, output_dir="oss-policy-reports")

    assert "sarif" not in written


def test_the_exit_code_reaches_the_output(tmp_path: Path) -> None:
    """The gate the whole step exists to forward."""

    written = _run_step(tmp_path, output_dir="oss-policy-reports")

    assert written["exit_code"] == "0"
