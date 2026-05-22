"""Rule-detection coverage for the CloudFormation scanner.

Builds templates that trigger every IAC-CFN-00x rule so the positive-finding
branches (not just the clean-scan path) are exercised, plus the YAML
short-form intrinsic loader and the parse / shape guards.
"""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.infrastructure.iac.cfn import scanner as cfn

# A single template that trips all six rules.
_BAD_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "PublicBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "AccessControl": "PublicRead",
                "PublicAccessBlockConfiguration": {"BlockPublicAcls": False},
                # no BucketEncryption -> IAC-CFN-004; no LoggingConfiguration -> IAC-CFN-005
            },
        },
        "OpenSG": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "SecurityGroupIngress": {"CidrIp": "0.0.0.0/0", "FromPort": 20, "ToPort": 25},
            },
        },
        "AdminRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
                "Policies": [
                    {
                        "PolicyName": "wild",
                        "PolicyDocument": {
                            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                        },
                    }
                ],
            },
        },
        "WildManagedPolicy": {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
                "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}}
            },
        },
        "UnencryptedDb": {
            "Type": "AWS::RDS::DBInstance",
            "Properties": {"StorageEncrypted": False},
        },
        "QuietTrail": {
            "Type": "AWS::CloudTrail::Trail",
            "Properties": {"IsLogging": False},
        },
        "PublicSubnet": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {"MapPublicIpOnLaunch": True},
        },
        "PublicInstance": {
            "Type": "AWS::EC2::Instance",
            "Properties": {"NetworkInterfaces": {"AssociatePublicIpAddress": True}},
        },
    },
}


def _rule_ids(outcome: cfn.CfnScanOutcome) -> set[str]:
    return {f.rule_id for f in outcome.findings}


def test_all_rules_fire(tmp_path: Path) -> None:
    (tmp_path / "stack.json").write_text(json.dumps(_BAD_TEMPLATE), encoding="utf-8")
    outcome = cfn.run_scan(tmp_path)
    assert outcome.status == "ok"
    assert _rule_ids(outcome) == {
        "IAC-CFN-001",
        "IAC-CFN-002",
        "IAC-CFN-003",
        "IAC-CFN-004",
        "IAC-CFN-005",
        "IAC-CFN-006",
    }


def test_evidence_payload_counts(tmp_path: Path) -> None:
    (tmp_path / "stack.json").write_text(json.dumps(_BAD_TEMPLATE), encoding="utf-8")
    outcome = cfn.run_scan(tmp_path)
    payload = cfn.render_evidence_payload(outcome, target=tmp_path)
    assert payload["findings_total"] == len(outcome.findings)
    assert payload["findings_by_rule"]["IAC-CFN-003"] >= 3  # managed arn + inline + managed policy
    out = cfn.write_evidence(payload, repo_root=tmp_path)
    assert out.exists()


def test_yaml_short_form_intrinsics(tmp_path: Path) -> None:
    yaml_text = (
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: !Ref BucketNameParam\n"
        "      AccessControl: PublicReadWrite\n"
    )
    (tmp_path / "stack.yaml").write_text(yaml_text, encoding="utf-8")
    outcome = cfn.run_scan(tmp_path)
    assert "IAC-CFN-001" in _rule_ids(outcome)


def test_clean_template_no_findings(tmp_path: Path) -> None:
    good = {
        "Resources": {
            "B": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "AccessControl": "Private",
                    "BucketEncryption": {"x": 1},
                    "LoggingConfiguration": {"DestinationBucketName": "logs"},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    },
                },
            }
        }
    }
    (tmp_path / "stack.json").write_text(json.dumps(good), encoding="utf-8")
    outcome = cfn.run_scan(tmp_path)
    assert outcome.findings == []


def test_non_cfn_and_bad_json_skipped(tmp_path: Path) -> None:
    (tmp_path / "notcfn.json").write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "list.yaml").write_text("- a\n- b\n", encoding="utf-8")
    outcome = cfn.run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.findings == []
    assert outcome.files_scanned == []


def test_load_cfn_helpers(tmp_path: Path) -> None:
    assert cfn._looks_like_cfn({"Resources": {"R": {"Type": "AWS::S3::Bucket"}}})
    assert not cfn._looks_like_cfn({"Resources": {}})
    assert not cfn._looks_like_cfn([1, 2])
    assert not cfn._looks_like_cfn({"Resources": {"R": {"no": "type"}}})


def test_encryption_attr_per_type() -> None:
    assert cfn._encryption_attr("AWS::EC2::Volume", {"Encrypted": True}) is True
    assert cfn._encryption_attr("AWS::DynamoDB::Table", {"SSESpecification": {}}) == {}
    assert cfn._encryption_attr("AWS::SQS::Queue", {"SqsManagedSseEnabled": True}) is True
    assert cfn._encryption_attr("AWS::Unknown::Type", {}) is None


def test_is_unencrypted_variants() -> None:
    assert cfn._is_unencrypted(None)
    assert cfn._is_unencrypted(False)
    assert cfn._is_unencrypted("false")
    assert not cfn._is_unencrypted(True)


def test_open_mgmt_port_ipv6_and_no_match() -> None:
    assert cfn._open_mgmt_port({"CidrIpv6": "::/0", "FromPort": 22, "ToPort": 22}) == (22, 22, 22)
    assert cfn._open_mgmt_port({"CidrIp": "10.0.0.0/8", "FromPort": 22, "ToPort": 22}) is None
    assert cfn._open_mgmt_port({"CidrIp": "0.0.0.0/0", "FromPort": 80, "ToPort": 80}) is None
    assert cfn._open_mgmt_port({"CidrIp": "0.0.0.0/0", "FromPort": "x", "ToPort": 22}) is None


def test_all_rule_ids() -> None:
    assert cfn.all_rule_ids() == (
        "IAC-CFN-001",
        "IAC-CFN-002",
        "IAC-CFN-003",
        "IAC-CFN-004",
        "IAC-CFN-005",
        "IAC-CFN-006",
    )
