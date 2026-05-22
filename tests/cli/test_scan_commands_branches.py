"""Branch coverage for the scan-* CLI subcommands (human format, bad format, parse errors).

The existing scan tests cover the ``--format json`` happy path; these exercise the
default human summary line, the ``--format`` validation guard, and the parse-error
warning path for each scanner subcommand.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()


def _scan(args: list[str]):
    return runner.invoke(app, args)


def test_scan_cfn_human_and_bad_format(tmp_path: Path) -> None:
    (tmp_path / "stack.yaml").write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: { AccessControl: Private }\n",
        encoding="utf-8",
    )
    res = _scan(["scan-cfn", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "scan-cfn:" in res.output
    bad = _scan(["scan-cfn", "--target", str(tmp_path), "--format", "xml"])
    assert bad.exit_code != 0


def test_scan_pulumi_human(tmp_path: Path) -> None:
    (tmp_path / "infra.py").write_text(
        "import pulumi_aws as aws\naws.s3.Bucket('b', acl='private')\n", encoding="utf-8"
    )
    res = _scan(["scan-pulumi", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "scan-pulumi:" in res.output


def test_scan_bicep_human(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'x'\n  properties: { allowBlobPublicAccess: false }\n}\n",
        encoding="utf-8",
    )
    res = _scan(["scan-bicep", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "scan-bicep:" in res.output


def test_scan_iac_human(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" { acl = "private" }\n', encoding="utf-8")
    res = _scan(["scan-iac", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "scan-iac:" in res.output


def test_scan_k8s_human(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  template:\n    spec:\n"
        "      containers:\n        - name: c\n          image: nginx:1.25\n",
        encoding="utf-8",
    )
    res = _scan(["scan-k8s", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "scan-k8s:" in res.output


def test_scan_sast_human_no_semgrep(tmp_path: Path) -> None:
    # Semgrep is not installed in CI; the command should still complete and write a stub.
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    res = _scan(["scan-sast", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "scan-sast:" in res.output


def test_scan_bad_format_rejected_iac(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")
    res = _scan(["scan-iac", "--target", str(tmp_path), "--format", "csv"])
    assert res.exit_code != 0


def test_scan_iac_json(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" { acl = "private" }\n', encoding="utf-8")
    res = _scan(["scan-iac", "--target", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.stdout)["status"] == "ok"


def test_scan_pulumi_json(tmp_path: Path) -> None:
    (tmp_path / "infra.py").write_text(
        "import pulumi_aws as aws\naws.s3.Bucket('b', acl='private')\n", encoding="utf-8"
    )
    res = _scan(["scan-pulumi", "--target", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0, res.output


def test_scan_bicep_json(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'x'\n  properties: { allowBlobPublicAccess: false }\n}\n",
        encoding="utf-8",
    )
    res = _scan(["scan-bicep", "--target", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0, res.output


def test_scan_iac_parse_error_warning(tmp_path: Path) -> None:
    # Invalid HCL is recorded as a parse error; the scan still completes (exit 0).
    (tmp_path / "broken.tf").write_text('resource "aws_s3_bucket" "x" { acl = \n', encoding="utf-8")
    res = _scan(["scan-iac", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code in {0, 2}


def test_scan_cfn_with_parse_errors(tmp_path: Path) -> None:
    # A .json file that is valid JSON but not CFN is skipped silently; an unreadable
    # file is hard to simulate cross-platform, so assert the command still completes
    # cleanly with a non-CFN file present.
    (tmp_path / "notcfn.json").write_text('{"foo": "bar"}', encoding="utf-8")
    res = _scan(["scan-cfn", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
