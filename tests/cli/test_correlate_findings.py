"""A-S6 (ADR-030): the correlate-findings CLI command.

Functional coverage via CliRunner (artifact write, formats, --fail-on-* gates,
usage errors, path privacy) plus a subprocess --help check (flaky-help rule:
Rich help is never asserted in-process).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from click.testing import Result
from jsonschema import Draft202012Validator
from tests.conftest import ROOT
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()
_EVID = Path(".oss-policy-kit") / "evidence"
_SCHEMA = ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "findings" / "1.0.json"


def _invoke(args: list[str]) -> Result:
    return runner.invoke(app, prepare_cli_args(args))


def _write(repo: Path, rel: str | Path, payload: object) -> None:
    p = repo / _EVID / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload), encoding="utf-8")


def _iac_evidence(findings: list[dict]) -> dict:
    return {
        "schema_version": "oss-policy-kit/evidence/iac-terraform/v1",
        "tool": "oss-policy-kit-iac-parser",
        "status": "ok",
        "target": "x",
        "scanned_at": "t",
        "attested_at": "t",
        "attested_by": "t",
        "findings_total": len(findings),
        "findings": findings,
    }


def _osv_sarif(results: list[dict]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "osv-scanner", "version": "2.0.0"}}, "results": results}],
    }


def _crit(rule: str = "IAC-TF-001") -> dict:
    return {
        "rule_id": rule,
        "severity": "CRITICAL",
        "message": "public bucket",
        "file": "main.tf",
        "resource_type": "aws_s3_bucket",
        "resource_name": "logs",
    }


# --------------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------------- #


def test_empty_repo_writes_valid_empty_artifact(tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
    artifact = json.loads(out.read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(_SCHEMA.read_text(encoding="utf-8"))).validate(artifact)
    assert artifact["findings_total"] == 0
    assert "Wrote findings/1.0 artifact" in result.output


def test_with_evidence_correlates_and_writes_artifact(tmp_path: Path) -> None:
    _write(tmp_path, "iac-terraform.json", _iac_evidence([_crit()]))
    out = tmp_path / "findings.json"
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 0, result.output
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["findings_total"] == 1
    assert artifact["findings"][0]["severity"]["normalized"] == "critical"
    assert artifact["findings"][0]["id"].startswith("opk-fk/v1:")
    assert "CRITICAL" in result.output


def test_format_json_echoes_artifact_to_stdout(tmp_path: Path) -> None:
    _write(tmp_path, "iac-terraform.json", _iac_evidence([_crit()]))
    out = tmp_path / "findings.json"
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out), "--format", "json"])
    assert result.exit_code == 0, result.output
    echoed = json.loads(result.output)
    assert echoed["contract_version"] == "findings/1.0"
    assert echoed == json.loads(out.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# gates
# --------------------------------------------------------------------------- #


def test_fail_on_severity_trips_exit_1(tmp_path: Path) -> None:
    _write(tmp_path, "iac-terraform.json", _iac_evidence([_crit()]))
    out = tmp_path / "findings.json"
    result = _invoke(
        ["correlate-findings", "--target", str(tmp_path), "--output", str(out), "--fail-on-severity", "high"]
    )
    assert result.exit_code == 1, result.output
    assert out.is_file()  # artifact is still written before the gate trips
    assert "Gate:" in result.output


def test_fail_on_severity_does_not_trip_below_threshold(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "iac-terraform.json",
        _iac_evidence(
            [
                {
                    "rule_id": "IAC-TF-9",
                    "severity": "LOW",
                    "message": "m",
                    "file": "a.tf",
                    "resource_type": "t",
                    "resource_name": "n",
                }
            ]
        ),
    )
    out = tmp_path / "findings.json"
    result = _invoke(
        ["correlate-findings", "--target", str(tmp_path), "--output", str(out), "--fail-on-severity", "high"]
    )
    assert result.exit_code == 0, result.output


def test_fail_on_kev_trips_exit_1(tmp_path: Path) -> None:
    _write(
        tmp_path,
        Path("sast") / "osv-scanner.sarif.json",
        _osv_sarif(
            [
                {
                    "ruleId": "CVE-2026-1",
                    "level": "error",
                    "message": {"text": "v"},
                    "properties": {"kev": "true", "cve": "CVE-2026-1"},
                }
            ]
        ),
    )
    out = tmp_path / "findings.json"
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out), "--fail-on-kev"])
    assert result.exit_code == 1, result.output
    assert "KEV" in result.output


# --------------------------------------------------------------------------- #
# usage errors (exit 2)
# --------------------------------------------------------------------------- #


def test_bad_format_exits_2(tmp_path: Path) -> None:
    result = _invoke(
        ["correlate-findings", "--target", str(tmp_path), "--output", str(tmp_path / "f.json"), "--format", "xml"]
    )
    assert result.exit_code == 2, result.output
    assert "--format must be" in result.output


def test_bad_fail_on_severity_exits_2(tmp_path: Path) -> None:
    result = _invoke(
        [
            "correlate-findings",
            "--target",
            str(tmp_path),
            "--output",
            str(tmp_path / "f.json"),
            "--fail-on-severity",
            "spicy",
        ]
    )
    assert result.exit_code == 2, result.output
    assert "--fail-on-severity must be" in result.output


def test_nonexistent_target_exits_2(tmp_path: Path) -> None:
    result = _invoke(["correlate-findings", "--target", str(tmp_path / "nope"), "--output", str(tmp_path / "f.json")])
    assert result.exit_code == 2, result.output
    # Whitespace is collapsed before matching: Rich wraps to the console width, so an
    # asserted phrase can land across a line break. Home-directory redaction shortened
    # this message and moved the wrap point, which is exactly how a passing assertion
    # turns red without the behaviour changing at all.
    assert "is not a directory" in " ".join(result.output.split())


def test_unwritable_output_exits_2_without_path_leak(tmp_path: Path) -> None:
    blocker = tmp_path / "afile"
    blocker.write_text("x", encoding="utf-8")
    out = blocker / "sub" / "findings.json"  # parent is a regular file -> NotADirectoryError
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out)])
    assert result.exit_code == 2, result.output
    assert "cannot write --output" in result.output
    assert "Traceback" not in result.output
    assert str(tmp_path) not in result.output  # no absolute path / username leak


# --------------------------------------------------------------------------- #
# privacy + registration
# --------------------------------------------------------------------------- #


def test_target_path_basename_by_default_and_absolute_opt_in(tmp_path: Path) -> None:
    repo = tmp_path / "secret-repo"
    repo.mkdir()
    out = tmp_path / "f.json"
    _invoke(["correlate-findings", "--target", str(repo), "--output", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["target_path"] == "secret-repo"
    _invoke(["correlate-findings", "--target", str(repo), "--output", str(out), "--include-absolute-path"])
    assert json.loads(out.read_text(encoding="utf-8"))["target_path"] == str(repo.resolve())


def test_command_is_registered_in_order_and_dispatch() -> None:
    from oss_policy_kit.cli import common, main

    names = [c.name for c in main.app.registered_commands]
    assert "correlate-findings" in names
    # dispatched as a known subcommand (not stolen as an evaluate target path)
    assert common.prepare_cli_args(["correlate-findings", "--help"])[0] == "correlate-findings"


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def test_help_via_subprocess_exit_0() -> None:
    # Flaky-help rule: subprocess only, deterministic env (TERM=dumb strips the Rich
    # panel styling; ANSI stripped + text flattened so panel wraps cannot split tokens).
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "200"
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "correlate-findings", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    flat = " ".join(_ANSI_RE.sub("", proc.stdout).split())
    assert "correlate-findings" in flat
    assert "--fail-on-severity" in flat


def test_a_partial_scan_is_said_out_loud_not_only_written_to_the_artifact(tmp_path: Path) -> None:
    """`findings_total` reads as a total, and `--fail-on-severity` decides on that number.

    When a scanner could not read one of its sources, the count is of what it managed to look
    at. The artifact records that under `extensions.partial_scan_warnings`; an operator reading
    the terminal would never open the artifact to find out, so it is printed too.
    """

    evidence = _iac_evidence([_crit()])
    evidence["diagnostics"] = {"parse_errors": [{"file": "unreadable.tf", "error": "bad"}], "raw_message": ""}
    _write(tmp_path, "iac-terraform.json", evidence)

    result = _invoke(["correlate-findings", "--target", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "Partial scan" in result.output, f"the skipped file was never mentioned: {result.output}"
    assert "unreadable.tf" in result.output, f"the warning does not name the file: {result.output}"

    artifact = json.loads((tmp_path / ".oss-policy-kit" / "findings.json").read_text(encoding="utf-8"))
    assert artifact["extensions"]["partial_scan_warnings"], "the artifact lost the warning the CLI printed"
