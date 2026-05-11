"""CLI smoke tests for the v5.7.0 scan-cfn, scan-pulumi, scan-bicep subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()


def test_scan_cfn_writes_evidence(tmp_path: Path) -> None:
    (tmp_path / "stack.yaml").write_text(
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties: { AccessControl: Private }\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan-cfn", "--target", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["schema_version"].startswith("oss-policy-kit/evidence/iac-cfn/")
    assert (tmp_path / ".oss-policy-kit" / "evidence" / "iac-cfn.json").is_file()


def test_scan_pulumi_writes_evidence(tmp_path: Path) -> None:
    (tmp_path / "infra.py").write_text(
        "import pulumi_aws as aws\nb = aws.s3.Bucket('safe', acl='private')\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan-pulumi", "--target", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["schema_version"].startswith("oss-policy-kit/evidence/iac-pulumi/")
    assert (tmp_path / ".oss-policy-kit" / "evidence" / "iac-pulumi.json").is_file()


def test_scan_bicep_writes_evidence(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'safe'\n"
        "  location: 'eastus'\n"
        "  sku: { name: 'Standard_LRS' }\n"
        "  kind: 'StorageV2'\n"
        "  properties: { allowBlobPublicAccess: false }\n"
        "}\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan-bicep", "--target", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["schema_version"].startswith("oss-policy-kit/evidence/iac-bicep/")
    assert (tmp_path / ".oss-policy-kit" / "evidence" / "iac-bicep.json").is_file()
