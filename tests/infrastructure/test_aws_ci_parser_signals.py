"""Signal-detection coverage for ``infrastructure.aws_ci_parser`` (buildspec + CodePipeline export)."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.infrastructure import aws_ci_parser as acp


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


_BUILDSPEC = """\
version: 0.2
env:
  parameter-store:
    DB_PASS: /prod/db/pass
  secrets-manager:
    API_KEY: prod/api:key
  variables:
    PLAIN_TOKEN: "AKIAIOSFODNN7EXAMPLE"
    LONG_SECRET: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"
    my_password: "supersecretvalue123"
phases:
  build:
    commands:
      - trivy fs .
      - pip-audit
      - cyclonedx-py
      - cosign sign-blob artifact
"""


def test_analyze_aws_ci_all_signals(tmp_path: Path) -> None:
    _write(tmp_path, "buildspec.yml", _BUILDSPEC)
    a = acp.analyze_aws_ci(tmp_path)
    assert a.buildspec_paths
    assert a.parameter_store_signal_paths
    assert a.secrets_manager_signal_paths
    assert a.inline_secret_risk_paths  # AKIA / long secret / secretish key
    assert a.security_scan_signal_paths
    assert a.dependency_audit_signal_paths
    assert a.sbom_signal_paths
    assert a.provenance_signal_paths


def test_analyze_aws_ci_inline_key_material(tmp_path: Path) -> None:
    _write(tmp_path, "buildspec.yml", "version: 0.2\n# -----BEGIN RSA PRIVATE KEY-----\n")
    a = acp.analyze_aws_ci(tmp_path)
    assert a.inline_secret_risk_paths


def test_analyze_aws_ci_aws_dir_buildspec(tmp_path: Path) -> None:
    _write(tmp_path, ".aws/buildspec-ci.yml", "version: 0.2\nphases:\n  build:\n    commands:\n      - semgrep ci\n")
    a = acp.analyze_aws_ci(tmp_path)
    assert a.security_scan_signal_paths


def test_analyze_aws_ci_bad_yaml_falls_back(tmp_path: Path) -> None:
    # Invalid YAML -> parse error recorded + raw substring fallback for managed secrets.
    _write(tmp_path, "buildspec.yml", "version: 0.2\nenv: parameter-store: [\n: : :\n")
    a = acp.analyze_aws_ci(tmp_path)
    assert a.parse_errors
    assert a.parameter_store_signal_paths  # raw fallback matched "parameter-store"


def test_codepipeline_valid_export_with_iam_role(tmp_path: Path) -> None:
    doc = {
        "pipeline": {
            "name": "p",
            "roleArn": "arn:aws:iam::123456789012:role/pipeline",
            "stages": [{"name": "Source"}, {"name": "Build"}],
        }
    }
    _write(tmp_path, "pipelines/aws/codepipeline.json", json.dumps(doc))
    a = acp.analyze_aws_ci(tmp_path)
    assert a.codepipeline_paths
    assert a.codepipeline_valid_export_paths
    assert a.codepipeline_committed_iam_role_paths


def test_codepipeline_artifact_store_only(tmp_path: Path) -> None:
    doc = {"pipeline": {"name": "p", "artifactStore": {"type": "S3"}}}
    p = _write(tmp_path, "pipelines/aws/codepipeline.json", json.dumps(doc))
    ok, msg = acp.committed_codepipeline_export_is_minimal(p)
    assert ok and msg == ""


def test_codepipeline_name_only_stub_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, "pipelines/aws/codepipeline.json", json.dumps({"pipeline": {"name": "p"}}))
    ok, msg = acp.committed_codepipeline_export_is_minimal(p)
    assert not ok and "at least one stage" in msg


def test_codepipeline_bad_root(tmp_path: Path) -> None:
    p = _write(tmp_path, "pipelines/aws/codepipeline.json", json.dumps([1, 2]))
    assert acp.load_committed_codepipeline_document(p) is None
    ok, msg = acp.committed_codepipeline_export_is_minimal(p)
    assert not ok and "must be an object" in msg


def test_codepipeline_bad_json_recorded(tmp_path: Path) -> None:
    _write(tmp_path, "pipelines/aws/codepipeline.json", "{not json")
    a = acp.analyze_aws_ci(tmp_path)
    assert a.parse_errors
    assert a.codepipeline_valid_export_paths == []


def test_load_codepipeline_yaml(tmp_path: Path) -> None:
    p = _write(tmp_path, "pipelines/aws/codepipeline.yaml", "pipeline:\n  name: p\n  stages:\n    - name: S\n")
    doc = acp.load_committed_codepipeline_document(p)
    assert isinstance(doc, dict) and doc["name"] == "p"
