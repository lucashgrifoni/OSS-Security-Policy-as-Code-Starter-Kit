"""Rule-detection coverage for the Pulumi (Python AST) and Bicep (text) scanners.

Each fixture is crafted to trip all six IAC-PUL-00x / IAC-BICEP-00x rules so the
positive-finding branches are exercised, mirroring test_cfn_scanner_rules.py.
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.iac.bicep import scanner as bicep
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi

_PULUMI_SRC = '''\
import pulumi_aws as aws

bucket = aws.s3.Bucket("b", acl="public-read")
sg = aws.ec2.SecurityGroup(
    "sg", ingress=[{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22}]
)
attach = aws.iam.RolePolicyAttachment("a", policy_arn="arn:aws:iam::aws:policy/AdministratorAccess")
pol = aws.iam.Policy("p", policy='{"Action": "*", "Resource": "*"}')
db = aws.rds.Instance("db", storage_encrypted=False)
vpc = aws.ec2.DefaultVpc("d")
subnet = aws.ec2.Subnet("sub", map_public_ip_on_launch=True)
'''

_BICEP_SRC = """\
resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'sa1'
  properties: {
    allowBlobPublicAccess: true
    supportsHttpsTrafficOnly: false
  }
}

resource nsgRule 'Microsoft.Network/networkSecurityGroups/securityRules@2023-01-01' = {
  name: 'allow-ssh'
  properties: {
    access: 'Allow'
    direction: 'Inbound'
    sourceAddressPrefix: '*'
    destinationPortRange: '22'
  }
}

resource ra 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: 'owner-binding'
  properties: {
    roleDefinitionId: '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
  }
}

resource pip 'Microsoft.Network/publicIPAddresses@2023-01-01' = {
  name: 'pip1'
  properties: {
    publicIPAllocationMethod: 'Dynamic'
  }
}
"""


def _rule_ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- #
# Pulumi
# --------------------------------------------------------------------------- #


def test_pulumi_all_rules_fire(tmp_path: Path) -> None:
    (tmp_path / "infra.py").write_text(_PULUMI_SRC, encoding="utf-8")
    outcome = pulumi.run_scan(tmp_path)
    assert outcome.status == "ok"
    assert _rule_ids(outcome.findings) == {
        "IAC-PUL-001",
        "IAC-PUL-002",
        "IAC-PUL-003",
        "IAC-PUL-004",
        "IAC-PUL-005",
        "IAC-PUL-006",
    }


def test_pulumi_skips_non_pulumi_files(tmp_path: Path) -> None:
    (tmp_path / "plain.py").write_text("x = 1\nprint(x)\n", encoding="utf-8")
    outcome = pulumi.run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.findings == []
    assert outcome.files_scanned == []


def test_pulumi_syntax_error_recorded(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("import pulumi_aws as aws\ndef (:\n", encoding="utf-8")
    outcome = pulumi.run_scan(tmp_path)
    assert outcome.parse_errors


def test_pulumi_evidence_payload(tmp_path: Path) -> None:
    (tmp_path / "infra.py").write_text(_PULUMI_SRC, encoding="utf-8")
    outcome = pulumi.run_scan(tmp_path)
    payload = pulumi.render_evidence_payload(outcome, target=tmp_path)
    assert payload["findings_total"] == len(outcome.findings)
    out = pulumi.write_evidence(payload, repo_root=tmp_path)
    assert out.exists()


def test_pulumi_helpers() -> None:
    assert pulumi._pul_open_mgmt_port({"cidr_blocks": "0.0.0.0/0", "from_port": 22, "to_port": 22}) == (22, 22, 22)
    assert pulumi._pul_open_mgmt_port({"cidr_blocks": ["10.0.0.0/8"], "from_port": 22, "to_port": 22}) is None
    assert pulumi._pul_open_mgmt_port({"cidr_blocks": ["0.0.0.0/0"], "from_port": 80, "to_port": 80}) is None
    assert pulumi._inline_policy_grants_wildcard('{"Action": "*", "Resource": "*"}')
    assert not pulumi._inline_policy_grants_wildcard("not a policy")


def test_pulumi_ebs_dynamodb_unencrypted_and_instance_public_ip(tmp_path: Path) -> None:
    src = (
        "import pulumi_aws as aws\n"
        'vol = aws.ebs.Volume("v")\n'  # no encrypted -> 004
        'tbl = aws.dynamodb.Table("t")\n'  # no server_side_encryption -> 004
        'inst = aws.ec2.Instance("i", associate_public_ip_address=True)\n'  # 006
    )
    (tmp_path / "infra.py").write_text(src, encoding="utf-8")
    outcome = pulumi.run_scan(tmp_path)
    fired = _rule_ids(outcome.findings)
    assert "IAC-PUL-004" in fired and "IAC-PUL-006" in fired
    # Two distinct 004 findings (EBS + DynamoDB).
    assert sum(1 for f in outcome.findings if f.rule_id == "IAC-PUL-004") == 2


def test_pulumi_all_rule_ids() -> None:
    assert pulumi.all_rule_ids() == (
        "IAC-PUL-001",
        "IAC-PUL-002",
        "IAC-PUL-003",
        "IAC-PUL-004",
        "IAC-PUL-005",
        "IAC-PUL-006",
    )


# --------------------------------------------------------------------------- #
# Bicep
# --------------------------------------------------------------------------- #


def test_bicep_all_rules_fire(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(_BICEP_SRC, encoding="utf-8")
    outcome = bicep.run_scan(tmp_path)
    assert outcome.status == "ok"
    fired = _rule_ids(outcome.findings)
    assert {
        "IAC-BICEP-001",
        "IAC-BICEP-002",
        "IAC-BICEP-003",
        "IAC-BICEP-004",
        "IAC-BICEP-005",
        "IAC-BICEP-006",
    } <= fired


def test_bicep_clean_storage_no_findings(tmp_path: Path) -> None:
    src = (
        "resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'sa'\n"
        "  properties: {\n"
        "    allowBlobPublicAccess: false\n"
        "    supportsHttpsTrafficOnly: true\n"
        "  }\n"
        "}\n"
        "resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
        "  name: 'd'\n"
        "  scope: sa\n"
        "}\n"
    )
    (tmp_path / "main.bicep").write_text(src, encoding="utf-8")
    outcome = bicep.run_scan(tmp_path)
    # Storage is private + https-only + has paired diagnostics -> no 001/004/005.
    assert "IAC-BICEP-001" not in _rule_ids(outcome.findings)
    assert "IAC-BICEP-005" not in _rule_ids(outcome.findings)


def test_bicep_sql_and_disk_encryption(tmp_path: Path) -> None:
    src = (
        "resource db 'Microsoft.Sql/servers/databases@2022-05-01' = {\n"
        "  name: 'db'\n"
        "  properties: {}\n"
        "}\n"
        "resource disk 'Microsoft.Compute/disks@2023-01-02' = {\n"
        "  name: 'd'\n"
        "  properties: {}\n"
        "}\n"
    )
    (tmp_path / "main.bicep").write_text(src, encoding="utf-8")
    outcome = bicep.run_scan(tmp_path)
    # SQL db without state:'Enabled' and disk without encryptionSettings -> two 004s.
    assert sum(1 for f in outcome.findings if f.rule_id == "IAC-BICEP-004") == 2


def test_bicep_helpers() -> None:
    r = bicep.BicepResource(symbolic="x", type_full="Microsoft.Storage/storageAccounts@2023-01-01", body="", source=Path("x"))
    assert bicep._type_root(r) == "Microsoft.Storage/storageAccounts"
    r2 = bicep.BicepResource(symbolic="x", type_full="T@1", body="access: 'Allow'\nport: 22", source=Path("x"))
    assert bicep._body_has(r2, "access", "Allow")
    assert bicep._body_has_int_range(r2, "port") == (22, 22)
    r3 = bicep.BicepResource(symbolic="x", type_full="T@1", body="flag: true", source=Path("x"))
    assert bicep._body_has_bool(r3, "flag") is True
    assert bicep._body_has_bool(r3, "missing") is None


def test_bicep_evidence_payload(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(_BICEP_SRC, encoding="utf-8")
    outcome = bicep.run_scan(tmp_path)
    payload = bicep.render_evidence_payload(outcome, target=tmp_path)
    assert payload["findings_total"] == len(outcome.findings)
    out = bicep.write_evidence(payload, repo_root=tmp_path)
    assert out.exists()
