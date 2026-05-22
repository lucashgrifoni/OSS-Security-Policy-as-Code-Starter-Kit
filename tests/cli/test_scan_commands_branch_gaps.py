"""Branch-coverage gaps for scan-pulumi/cfn/bicep/iac CLI commands.

Covers the bad-format guard, the scanner-error exit path, the empty-include
fallback, parse-error warnings, and the OssPolicyKitError / generic-exception
handlers that mirror across all four commands.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import scan_bicep, scan_cfn, scan_iac, scan_pulumi
from oss_policy_kit.cli.main import app
from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep_scanner
from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn_scanner
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi_scanner
from oss_policy_kit.infrastructure.iac import scanner as tf_scanner

runner = CliRunner()

# (command name, cli module, underlying scanner module)
_CMDS = [
    ("scan-pulumi", scan_pulumi, pulumi_scanner),
    ("scan-cfn", scan_cfn, cfn_scanner),
    ("scan-bicep", scan_bicep, bicep_scanner),
    ("scan-iac", scan_iac, tf_scanner),
]
_IDS = [c[0] for c in _CMDS]


@pytest.mark.parametrize("cmd,_cli_mod,_scanner_mod", _CMDS, ids=_IDS)
def test_scan_bad_format(tmp_path: Path, cmd, _cli_mod, _scanner_mod) -> None:
    res = runner.invoke(app, [cmd, "--target", str(tmp_path), "--format", "xml"])
    assert res.exit_code != 0


@pytest.mark.parametrize("cmd,_cli_mod,_scanner_mod", _CMDS, ids=_IDS)
def test_scan_empty_include_falls_back(tmp_path: Path, cmd, _cli_mod, _scanner_mod) -> None:
    res = runner.invoke(app, [cmd, "--target", str(tmp_path), "--include", " , ", "--format", "human"])
    assert res.exit_code == 0, res.output


@pytest.mark.parametrize("cmd,_cli_mod,scanner_mod", _CMDS, ids=_IDS)
def test_scan_scanner_error_exit2(tmp_path: Path, monkeypatch, cmd, _cli_mod, scanner_mod) -> None:
    # Force the rule engine to raise so run_scan returns status="error".
    def _boom(_repo, _data):
        raise RuntimeError("boom")

    # Drop one source file of each scanned type so the rule engine actually runs
    # (the Terraform scanner short-circuits to "ok" when no .tf files exist).
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    (tmp_path / "tpl.yaml").write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {}\n", encoding="utf-8"
    )
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'x'\n}\n", encoding="utf-8"
    )
    (tmp_path / "infra.py").write_text("import pulumi_aws as aws\naws.s3.Bucket('b')\n", encoding="utf-8")

    monkeypatch.setattr(scanner_mod, "_RULES", [("BAD", _boom)])
    res = runner.invoke(app, [cmd, "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 2
    assert "failed" in res.output.lower() or "error" in res.output.lower()


@pytest.mark.parametrize("cmd,cli_mod,_scanner_mod", _CMDS, ids=_IDS)
def test_scan_unexpected_error_exit3(tmp_path: Path, monkeypatch, cmd, cli_mod, _scanner_mod) -> None:
    def _explode(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli_mod, "run_scan", _explode)
    res = runner.invoke(app, [cmd, "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 3


@pytest.mark.parametrize("cmd,_cli_mod,_scanner_mod", _CMDS, ids=_IDS)
def test_scan_missing_target_exit2(tmp_path: Path, cmd, _cli_mod, _scanner_mod) -> None:
    res = runner.invoke(app, [cmd, "--target", str(tmp_path / "does-not-exist"), "--format", "human"])
    assert res.exit_code == 2


def test_scan_pulumi_parse_error_warning(tmp_path: Path) -> None:
    # A syntactically broken Python file produces a parse_errors entry.
    (tmp_path / "broken.py").write_text("def (:\n  pass\n", encoding="utf-8")
    res = runner.invoke(app, ["scan-pulumi", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "failed to parse" in res.output.lower()
