"""Tests for the v5.7.0 ``IAC-PUL-*`` Pulumi controls (Python flavor)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_iac_pulumi import IAC_PUL_RULES
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.iac.pulumi.scanner import (
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
    all_rule_ids,
    render_evidence_payload,
    run_scan,
    write_evidence,
)


def test_all_iac_pul_controls_present_in_catalog() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for rule_id, _ in IAC_PUL_RULES:
        assert rule_id in catalog, f"Catalog missing {rule_id}."
        spec = catalog[rule_id]
        assert spec.lifecycle == "experimental"
        assert spec.assurance == "evidence-backed"
        assert spec.category == "iac"


def test_all_iac_pul_controls_have_evaluators() -> None:
    for rule_id, _ in IAC_PUL_RULES:
        assert rule_id in EVALUATOR_REGISTRY


def test_iac_pulumi_baseline_1_profile_loads() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "iac-pulumi-baseline-1")
    assert spec.id == "iac-pulumi-baseline-1"
    pul_in_profile = {c for c in spec.control_ids if c.startswith("IAC-PUL-")}
    assert pul_in_profile == set(all_rule_ids())


def _scan_and_dump(tmp_path: Path, body: str, *, filename: str = "infra.py") -> dict:
    (tmp_path / filename).write_text(body, encoding="utf-8")
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    return payload


def test_scan_emits_versioned_evidence(tmp_path: Path) -> None:
    body = "import pulumi_aws as aws\nbucket = aws.s3.Bucket('hardened', acl='private')\n"
    payload = _scan_and_dump(tmp_path, body)
    assert payload["schema_version"] == EVIDENCE_SCHEMA_VERSION
    assert payload["status"] == "ok"
    assert payload["attested_by"] == "oss-policy-kit scan-pulumi"
    for rid in all_rule_ids():
        assert rid in payload["findings_by_rule"]


@pytest.mark.parametrize("rule_id", [rid for rid, _ in IAC_PUL_RULES])
def test_vulnerable_fixture_triggers_rule(tmp_path: Path, rule_id: str) -> None:
    fixtures = {
        "IAC-PUL-001": ("import pulumi_aws as aws\nb = aws.s3.Bucket('leaky', acl='public-read')\n"),
        "IAC-PUL-002": (
            "import pulumi_aws as aws\n"
            "sg = aws.ec2.SecurityGroup('open-ssh', ingress=[{"
            "'from_port': 22, 'to_port': 22, 'cidr_blocks': ['0.0.0.0/0']}])\n"
        ),
        "IAC-PUL-003": (
            "import pulumi_aws as aws\n"
            "att = aws.iam.RolePolicyAttachment('admin', role='r', "
            "policy_arn='arn:aws:iam::aws:policy/AdministratorAccess')\n"
        ),
        "IAC-PUL-004": (
            "import pulumi_aws as aws\ndb = aws.rds.Instance('db', engine='postgres', storage_encrypted=False)\n"
        ),
        "IAC-PUL-005": ("import pulumi_aws as aws\nvpc = aws.ec2.DefaultVpc('default')\n"),
        "IAC-PUL-006": (
            "import pulumi_aws as aws\n"
            "inst = aws.ec2.Instance(\n"
            "    'exposed', associate_public_ip_address=True,\n"
            "    ami='ami-1', instance_type='t3.micro',\n"
            ")\n"
        ),
    }
    payload = _scan_and_dump(tmp_path, fixtures[rule_id])
    counts = payload["findings_by_rule"]
    assert counts[rule_id] >= 1, f"{rule_id} did not fire on its vulnerable fixture; got {counts}."


def test_pulumi_scanner_skips_non_pulumi_python_files(tmp_path: Path) -> None:
    """A regular Python file without Pulumi imports must not be scanned."""

    (tmp_path / "app.py").write_text(
        "import json\nprint(json.dumps({'hello': 'world'}))\n",
        encoding="utf-8",
    )
    outcome = run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.files_scanned == []


def test_pulumi_scanner_does_not_crash_on_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("import pulumi\nthis is :: not python\n", encoding="utf-8")
    outcome = run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.parse_errors  # diagnostic captured, no crash


def test_pulumi_evaluator_returns_manual_review_when_evidence_missing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")
    for rid in all_rule_ids():
        eval_fn = EVALUATOR_REGISTRY[rid]
        out = eval_fn(SimpleNamespace(repo_root=tmp_path))
        assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_pulumi_evaluator_returns_not_applicable_when_no_pulumi_program(tmp_path: Path) -> None:
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    assert payload["files_scanned"] == []
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    for rid in all_rule_ids():
        eval_fn = EVALUATOR_REGISTRY[rid]
        out = eval_fn(SimpleNamespace(repo_root=tmp_path))
        assert out.status is ControlStatus.NOT_APPLICABLE
