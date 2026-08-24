"""The last arms: quiet summaries, an empty gap list, and the two ways stdout can be unusual.

`--quiet` suppresses the operational-warning summary, and there are three places that decide it
because there are three renderings of a report. Two of them were exercised; the summary-only one
was not, and a flag honoured by two paths out of three is worse than a flag honoured by none --
it works until the day someone uses it with the third.

The rest cover what `main()` does before the app runs and what it does when the reader has gone:
a stream with no `reconfigure` must be left alone rather than crashed on, and a closed pipe has
to unwind quietly instead of being reported as an internal error.
"""

from __future__ import annotations

import importlib
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from oss_policy_kit.application import osps_coverage as osps_module
from oss_policy_kit.application.evaluators import supply_chain
from oss_policy_kit.cli import main as cli_main
from oss_policy_kit.cli import osps_coverage as osps_cli
from oss_policy_kit.cli import profiles as pr
from oss_policy_kit.cli.main import app
from oss_policy_kit.infrastructure.iac.cfn.scanner import run_scan as run_cfn_scan

runner = CliRunner()


# --------------------------------------------------------------------------- #
# The module that only exists so `python -m` works
# --------------------------------------------------------------------------- #


def test_importing_the_entry_module_does_not_run_the_cli() -> None:
    """`import oss_policy_kit.__main__` must be inert; only `python -m` may start the app."""

    module = importlib.import_module("oss_policy_kit.__main__")

    assert callable(module.main)


# --------------------------------------------------------------------------- #
# Quiet report rendering
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("extra", [[], ["--summary-only"]])
def test_quiet_suppresses_the_operational_warning_summary(extra: list[str], tmp_path: Path) -> None:
    """Three renderings, one flag; a flag honoured by two of them is the harder bug to find."""

    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on:\n  push:\n    branches: [main]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  scan:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: semgrep --config p/ci\n",
        encoding="utf-8",
    )
    args = ["evaluate", "--target", str(tmp_path), "--profile", "github-level-1", "--output-dir", str(tmp_path / "out")]

    loud = runner.invoke(app, [*args, *extra])
    quiet = runner.invoke(app, [*args, *extra, "--quiet"])

    assert loud.exit_code in (0, 1), loud.output
    assert quiet.exit_code == loud.exit_code
    assert "-- see Markdown/JSON reports" in loud.output, loud.output
    assert "-- see Markdown/JSON reports" not in quiet.output


# --------------------------------------------------------------------------- #
# A coverage report with nothing left to admit
# --------------------------------------------------------------------------- #


def test_a_coverage_report_with_no_gaps_prints_no_gap_list(capsys: pytest.CaptureFixture[str]) -> None:
    """The gap list is the honest half; with nothing to list, the heading alone would mislead.

    `gap_criteria` is derived from the criteria themselves, so the fixture is a coverage report
    whose criteria all carry a signal -- the state the kit is working towards, not a stub.
    """

    real = osps_module.load_osps_coverage()
    covered = replace(real, criteria=tuple(c for c in real.criteria if c not in real.gap_criteria))

    osps_cli._render_human(covered)
    out = capsys.readouterr().out

    assert "Honest gaps: 0 of" in out


def test_the_real_coverage_report_still_lists_its_gaps(capsys: pytest.CaptureFixture[str]) -> None:
    """The counterpart, and the reason the branch exists at all: today there are gaps."""

    osps_cli._render_human(osps_module.load_osps_coverage())
    out = capsys.readouterr().out

    assert "Honest gaps:" in out
    assert "Honest gaps: 0 of" not in out


# --------------------------------------------------------------------------- #
# A control whose assurance class the kit does not know
# --------------------------------------------------------------------------- #


def test_an_unrecognised_assurance_class_is_counted_in_none_of_the_three() -> None:
    """Silently folding it into `signal` would misreport how a profile is actually verified."""

    from oss_policy_kit.application.loader import load_catalog, merge_kit_root

    root = merge_kit_root(None)
    catalog = dict(load_catalog(root / "controls" / "catalog.yaml"))
    known = next(iter(catalog.values()))
    catalog["ODD-001"] = replace(known, id="ODD-001", assurance="experimental")

    mix = pr._profile_assurance_mix(("ODD-001",), catalog)

    assert mix == {"deterministic": 0, "signal": 0, "evidence-backed": 0, "det": 0, "sig": 0, "evi": 0}


# --------------------------------------------------------------------------- #
# CloudFormation intrinsics on nodes the loader cannot re-encode
# --------------------------------------------------------------------------- #


def test_a_cloudformation_intrinsic_over_a_mapping_is_re_encoded(tmp_path: Path) -> None:
    """`!Fn::If` style tags can carry a mapping, and the long form has to survive the load."""

    template = (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  B:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      Tags: !Ref\n"
        "        Key: value\n"
    )
    (tmp_path / "template.yaml").write_text(template, encoding="utf-8")
    outcome = run_cfn_scan(tmp_path)

    assert outcome.parse_errors == [], outcome.parse_errors
    assert outcome.files_scanned


# --------------------------------------------------------------------------- #
# A bom.json that belongs to git, not to the project
# --------------------------------------------------------------------------- #


def test_a_document_inside_the_git_directory_is_not_the_projects_ml_bom(tmp_path: Path) -> None:
    """`.git` holds whatever a previous checkout left; it is not this repository's declaration."""

    path = tmp_path / ".git" / "bom.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"components": [{"type": "machine-learning-model"}]}', encoding="utf-8")

    assert supply_chain._is_ml_bom_marker_file(path, tmp_path) is False


def test_a_directory_named_like_an_ml_bom_is_not_one(tmp_path: Path) -> None:
    (tmp_path / "bom.json").mkdir()
    assert supply_chain._is_ml_bom_marker_file(tmp_path / "bom.json", tmp_path) is False


# --------------------------------------------------------------------------- #
# Streams that are not the ones `main` expects
# --------------------------------------------------------------------------- #


def test_a_stream_that_cannot_be_reconfigured_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirected output can be any file-like object; assuming `reconfigure` would crash on it."""

    class _PlainStream:
        def write(self, _text: str) -> int:
            return 0

        def flush(self) -> None:
            return None

    seen: list[bool] = []
    monkeypatch.setattr(sys, "stdout", _PlainStream())
    monkeypatch.setattr(sys, "stderr", _PlainStream())
    monkeypatch.setattr(sys, "argv", ["oss-policy-kit"])
    monkeypatch.setattr(cli_main, "app", lambda: seen.append(True))

    cli_main.main()

    assert seen == [True]


def test_a_pipe_closed_mid_write_exits_quietly(monkeypatch: pytest.MonkeyPatch) -> None:
    """`oss-policy-kit profiles | head` closes the pipe while the table is still printing."""

    def _write_into_a_closed_pipe() -> None:
        sys.stdout.write("a row that never arrives\n")
        sys.stdout.flush()

    class _ClosedPipe:
        def write(self, _text: str) -> int:
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self) -> None:
            raise BrokenPipeError(32, "Broken pipe")

        def fileno(self) -> int:
            return 1

    monkeypatch.setattr(sys, "stdout", _ClosedPipe())
    monkeypatch.setattr(sys, "argv", ["oss-policy-kit", "profiles"])
    monkeypatch.setattr(cli_main, "app", _write_into_a_closed_pipe)

    with pytest.raises(SystemExit) as excinfo:
        cli_main.main()

    assert excinfo.value.code == 0


def test_yaml_is_still_the_module_the_cfn_loader_subclasses() -> None:
    """Cheap guard so the intrinsic test above cannot rot into a no-op."""

    from oss_policy_kit.infrastructure.iac.cfn import scanner

    assert issubclass(scanner._CfnSafeLoader, yaml.SafeLoader)


def test_the_kit_still_exposes_the_helpers_these_tests_reach_for() -> None:
    """These are private names; a rename should fail here rather than silently skip coverage."""

    assert callable(getattr(osps_cli, "_render_human", None))
    assert callable(getattr(pr, "_profile_assurance_mix", None))
    assert isinstance(Any, object)
