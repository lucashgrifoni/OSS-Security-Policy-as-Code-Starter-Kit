"""Tests for the v5.7.0 ``IAC-CFN-*`` CloudFormation controls.

Exercises the scanner (rules + evidence shape) and the evaluators (thin
readers of the evidence JSON).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_iac_cfn import IAC_CFN_RULES
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.iac.cfn.scanner import (
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
    all_rule_ids,
    render_evidence_payload,
    run_scan,
    write_evidence,
)


def test_all_iac_cfn_controls_present_in_catalog() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for rule_id, _ in IAC_CFN_RULES:
        assert rule_id in catalog, f"Catalog missing {rule_id}."
        spec = catalog[rule_id]
        assert spec.lifecycle == "experimental"
        assert spec.assurance == "evidence-backed"
        assert spec.category == "iac"


def test_all_iac_cfn_controls_have_evaluators() -> None:
    for rule_id, _ in IAC_CFN_RULES:
        assert rule_id in EVALUATOR_REGISTRY, f"EVALUATOR_REGISTRY missing {rule_id}."


def test_iac_cfn_baseline_1_profile_loads() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "iac-cfn-baseline-1")
    assert spec.id == "iac-cfn-baseline-1"
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for cid in spec.control_ids:
        assert cid in catalog
    cfn_in_profile = {c for c in spec.control_ids if c.startswith("IAC-CFN-")}
    assert cfn_in_profile == set(all_rule_ids())


def _scan_and_dump(tmp_path: Path, body: str, *, filename: str = "stack.yaml") -> dict:
    (tmp_path / filename).write_text(body, encoding="utf-8")
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    return payload


def test_scan_emits_versioned_evidence_with_attestation_fields(tmp_path: Path) -> None:
    body = (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      AccessControl: Private\n"
        "      BucketEncryption:\n"
        "        ServerSideEncryptionConfiguration:\n"
        "          - ServerSideEncryptionByDefault:\n"
        "              SSEAlgorithm: AES256\n"
    )
    payload = _scan_and_dump(tmp_path, body)
    assert payload["schema_version"] == EVIDENCE_SCHEMA_VERSION
    assert payload["status"] == "ok"
    assert payload["attested_by"] == "oss-policy-kit scan-cfn"
    assert payload["attested_at"] == payload["scanned_at"]
    for rid in all_rule_ids():
        assert rid in payload["findings_by_rule"]


@pytest.mark.parametrize("rule_id", [rid for rid, _ in IAC_CFN_RULES])
def test_vulnerable_fixture_triggers_rule(tmp_path: Path, rule_id: str) -> None:
    fixtures = {
        "IAC-CFN-001": (
            "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n"
        ),
        "IAC-CFN-002": (
            "Resources:\n"
            "  Sg:\n"
            "    Type: AWS::EC2::SecurityGroup\n"
            "    Properties:\n"
            "      GroupDescription: open ssh\n"
            "      SecurityGroupIngress:\n"
            "        - IpProtocol: tcp\n"
            "          FromPort: 22\n"
            "          ToPort: 22\n"
            "          CidrIp: 0.0.0.0/0\n"
        ),
        "IAC-CFN-003": (
            "Resources:\n"
            "  Role:\n"
            "    Type: AWS::IAM::Role\n"
            "    Properties:\n"
            "      AssumeRolePolicyDocument: {}\n"
            "      ManagedPolicyArns:\n"
            "        - arn:aws:iam::aws:policy/AdministratorAccess\n"
        ),
        "IAC-CFN-004": (
            "Resources:\n"
            "  Db:\n"
            "    Type: AWS::RDS::DBInstance\n"
            "    Properties:\n"
            "      Engine: postgres\n"
            "      StorageEncrypted: false\n"
        ),
        "IAC-CFN-005": (
            "Resources:\n"
            "  Trail:\n"
            "    Type: AWS::CloudTrail::Trail\n"
            "    Properties:\n"
            "      S3BucketName: logs\n"
            "      IsLogging: false\n"
        ),
        "IAC-CFN-006": (
            "Resources:\n"
            "  Sub:\n"
            "    Type: AWS::EC2::Subnet\n"
            "    Properties:\n"
            "      MapPublicIpOnLaunch: true\n"
            "      VpcId: vpc-1\n"
            "      CidrBlock: 10.0.0.0/24\n"
        ),
    }
    payload = _scan_and_dump(tmp_path, fixtures[rule_id])
    counts = payload["findings_by_rule"]
    assert counts[rule_id] >= 1, f"{rule_id} did not fire on its vulnerable fixture; got {counts}."


def test_cfn_short_form_intrinsics_do_not_crash(tmp_path: Path) -> None:
    """Short-form ``!Ref`` / ``!Sub`` must parse and not raise."""

    body = (
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: !Sub '${AWS::StackName}-data'\n"
        "      AccessControl: !Ref AccessControlParam\n"
    )
    payload = _scan_and_dump(tmp_path, body)
    assert payload["status"] == "ok"


def test_cfn_scanner_skips_non_cfn_yaml(tmp_path: Path) -> None:
    """A K8s manifest in YAML must not be treated as a CFN template."""

    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec: {}\n",
        encoding="utf-8",
    )
    outcome = run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.files_scanned == []  # nothing CFN-shaped


def test_cfn_evaluator_returns_manual_review_when_evidence_missing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")
    for rid in all_rule_ids():
        eval_fn = EVALUATOR_REGISTRY[rid]
        out = eval_fn(SimpleNamespace(repo_root=tmp_path))
        assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_cfn_evaluator_returns_not_applicable_when_no_templates(tmp_path: Path) -> None:
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    assert payload["files_scanned"] == []
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    for rid in all_rule_ids():
        eval_fn = EVALUATOR_REGISTRY[rid]
        out = eval_fn(SimpleNamespace(repo_root=tmp_path))
        assert out.status is ControlStatus.NOT_APPLICABLE
