"""Rule-detection coverage for the Terraform (HCL) scanner — all 12 IAC-TF-0xx rules."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.iac import scanner as tf

_TF_SRC = """\
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

resource "aws_s3_bucket" "prod_data" {
  acl = "public-read"
}

resource "aws_s3_bucket_public_access_block" "pab" {
  bucket            = aws_s3_bucket.prod_data.id
  block_public_acls = false
}

resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role_policy_attachment" "admin" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_db_instance" "prod_db" {
  identifier = "prod-db"
}

resource "aws_cloudtrail" "trail" {
  enable_logging = false
}

resource "aws_default_vpc" "def" {
}

resource "aws_subnet" "sub" {
  map_public_ip_on_launch = true
}

data "aws_iam_policy_document" "doc" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}
"""


def _rule_ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def test_tf_all_rules_fire(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(_TF_SRC, encoding="utf-8")
    outcome = tf.run_scan(tmp_path)
    assert outcome.status == "ok"
    fired = _rule_ids(outcome.findings)
    expected = {f"IAC-TF-{n:03d}" for n in range(1, 13)}
    missing = expected - fired
    assert not missing, f"rules that did not fire: {sorted(missing)}"


def test_tf_evidence_payload(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(_TF_SRC, encoding="utf-8")
    outcome = tf.run_scan(tmp_path)
    payload = tf.render_evidence_payload(outcome, target=tmp_path)
    assert payload["findings_total"] == len(outcome.findings)
    out = tf.write_evidence(payload, repo_root=tmp_path)
    assert out.exists()


def test_tf_clean_repo_no_findings(tmp_path: Path) -> None:
    src = (
        "terraform {\n"
        "  required_providers {\n"
        "    aws = {\n"
        '      source  = "hashicorp/aws"\n'
        '      version = "5.0.0"\n'
        "    }\n"
        "  }\n"
        '  backend "s3" {\n'
        '    bucket = "state"\n'
        "  }\n"
        "}\n"
    )
    (tmp_path / "main.tf").write_text(src, encoding="utf-8")
    outcome = tf.run_scan(tmp_path)
    # No resources -> only terraform-block rules evaluated; pinned providers + remote backend = clean.
    assert "IAC-TF-009" not in _rule_ids(outcome.findings)
    assert "IAC-TF-010" not in _rule_ids(outcome.findings)


def test_tf_no_files(tmp_path: Path) -> None:
    outcome = tf.run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.findings == []


_TF_EDGE = """\
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

resource "google_storage_bucket" "gcs" {
  public_access_prevention = "inherited"
}

resource "aws_iam_policy" "inline" {
  policy = "{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}]}"
}

resource "aws_iam_role" "admin" {
  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}

resource "aws_launch_template" "lt" {
  network_interfaces {
    associate_public_ip_address = true
  }
}

resource "aws_instance" "inst" {
  associate_public_ip_address = true
  tags = {
    owner = "team"
  }
}

resource "aws_db_instance" "prod_db" {
  identifier = "production-db"
  storage_encrypted = true
}
"""


def test_tf_edge_branches(tmp_path: Path) -> None:
    (tmp_path / "edge.tf").write_text(_TF_EDGE, encoding="utf-8")
    outcome = tf.run_scan(tmp_path)
    fired = _rule_ids(outcome.findings)
    # GCS public-access + IAM wildcard/admin + launch-template/instance public IP + unpinned provider + prevent_destroy.
    assert "IAC-TF-001" in fired  # GCS inherited
    assert "IAC-TF-003" in fired  # iam inline wildcard + admin managed policy
    assert "IAC-TF-007" in fired  # launch template / instance public IP
    assert "IAC-TF-009" in fired  # provider without pinned version
    assert "IAC-TF-011" in fired  # prod data store without prevent_destroy


def test_tf_helpers() -> None:
    assert tf._is_truthy(True)
    assert tf._is_truthy("yes")
    assert tf._is_truthy(1)
    assert not tf._is_truthy("no")
    assert not tf._is_truthy(None)
    assert tf._tf_ingress_open_mgmt_port({"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22}) == (22, 22, 22)
    assert tf._tf_ingress_open_mgmt_port({"cidr_blocks": ["10.0.0.0/8"], "from_port": 22, "to_port": 22}) is None


def test_tf_all_rule_ids() -> None:
    assert tf.all_rule_ids() == tuple(f"IAC-TF-{n:03d}" for n in range(1, 13))
