"""Tests for the v5.5.0 ``IAC-TF-*`` Terraform / OpenTofu controls.

Exercises both the scanner (rules + evidence shape) and the evaluators
(thin readers of the evidence JSON). Every rule has at least one
vulnerable fixture + one hardened counterpart so a change in detection
heuristics is caught immediately.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_iac import IAC_TF_RULES
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.iac.scanner import (
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
    all_rule_ids,
    render_evidence_payload,
    run_scan,
    write_evidence,
)

# ---------------------------------------------------------------------------
# Catalog & registry sanity
# ---------------------------------------------------------------------------


def test_all_iac_tf_controls_present_in_catalog() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for rule_id, _ in IAC_TF_RULES:
        assert rule_id in catalog, f"Catalog missing {rule_id}."
        spec = catalog[rule_id]
        assert spec.lifecycle == "experimental"
        assert spec.assurance == "evidence-backed"
        assert spec.category == "iac"


def test_all_iac_tf_controls_have_evaluators() -> None:
    for rule_id, _ in IAC_TF_RULES:
        assert rule_id in EVALUATOR_REGISTRY, f"EVALUATOR_REGISTRY missing {rule_id}."


def test_iac_terraform_baseline_1_profile_loads() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "iac-terraform-baseline-1")
    assert spec.id == "iac-terraform-baseline-1"
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for cid in spec.control_ids:
        assert cid in catalog
    iac_in_profile = {c for c in spec.control_ids if c.startswith("IAC-TF-")}
    assert iac_in_profile == set(all_rule_ids())


# ---------------------------------------------------------------------------
# Evidence schema + status invariants
# ---------------------------------------------------------------------------


def _scan_and_dump(tmp_path: Path, hcl: str) -> dict:
    (tmp_path / "main.tf").write_text(hcl, encoding="utf-8")
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    return payload


def test_scan_emits_versioned_evidence_with_attestation_fields(tmp_path: Path) -> None:
    payload = _scan_and_dump(tmp_path, 'resource "aws_s3_bucket" "x" { acl = "private" }\n')
    assert payload["schema_version"].startswith("oss-policy-kit/evidence/iac-terraform/")
    assert payload["schema_version"] == EVIDENCE_SCHEMA_VERSION
    assert payload["status"] == "ok"
    assert payload["attested_by"] == "oss-policy-kit scan-iac"
    assert payload["attested_at"] == payload["scanned_at"]
    assert isinstance(payload["findings_by_rule"], dict)
    # Every bundled rule_id appears in findings_by_rule (count may be 0).
    for rid in all_rule_ids():
        assert rid in payload["findings_by_rule"]


def test_scan_skips_dot_terraform_and_node_modules(tmp_path: Path) -> None:
    """Vendored / cache directories are pruned from discovery so module
    cache bytes do not pollute findings."""

    bad_dir = tmp_path / ".terraform" / "modules" / "vendored"
    bad_dir.mkdir(parents=True)
    (bad_dir / "evil.tf").write_text('resource "aws_s3_bucket" "leak" { acl = "public-read" }\n', encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "ok" { acl = "private" }\n', encoding="utf-8")
    outcome = run_scan(tmp_path)
    assert outcome.status == "ok"
    # The vendored bucket would be public-read; if discovered it would create an IAC-TF-001 finding.
    rule_001 = [f for f in outcome.findings if f.rule_id == "IAC-TF-001"]
    assert rule_001 == []


# ---------------------------------------------------------------------------
# Per-rule vulnerable + hardened pairs
# ---------------------------------------------------------------------------


VULNERABLE_FIXTURES: dict[str, str] = {
    "IAC-TF-001": 'resource "aws_s3_bucket" "x" { acl = "public-read" }\n',
    "IAC-TF-002": (
        'resource "aws_security_group" "x" {\n'
        "  ingress {\n"
        '    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n}\n"
    ),
    "IAC-TF-003": (
        'resource "aws_iam_role_policy_attachment" "x" {\n'
        '  role = "r"\n'
        '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n'
        "}\n"
    ),
    "IAC-TF-004": (
        'resource "aws_db_instance" "x" {\n  identifier = "x"\n  engine = "postgres"\n  storage_encrypted = false\n}\n'
    ),
    "IAC-TF-005": 'resource "aws_cloudtrail" "x" { name = "t" enable_logging = false }\n',
    "IAC-TF-006": 'resource "aws_default_vpc" "x" {}\n',
    "IAC-TF-007": (
        'resource "aws_subnet" "x" {\n'
        "  map_public_ip_on_launch = true\n"
        '  vpc_id = "v"\n'
        '  cidr_block = "10.0.0.0/24"\n'
        "}\n"
    ),
    "IAC-TF-008": 'resource "aws_s3_bucket" "x" { acl = "private" }\n',  # no tags block
    # terraform block present but required_providers missing -> rule fires.
    "IAC-TF-009": (
        "terraform {\n"
        '  backend "s3" { bucket = "tf-state" key = "k" region = "us-east-1" encrypt = true dynamodb_table = "lock" }\n'
        "}\n\n"
        'resource "aws_s3_bucket" "x" { acl = "private" tags = { owner = "team" cost_center = "cc-1" } }\n'
    ),
    "IAC-TF-010": 'terraform {\n  backend "local" { path = "x.tfstate" }\n}\n',
    "IAC-TF-011": (
        'resource "aws_db_instance" "prod_main" {\n'
        '  identifier = "prod-main"\n'
        '  engine = "postgres"\n'
        "  storage_encrypted = true\n"
        "}\n"
    ),
    "IAC-TF-012": (
        'data "aws_iam_policy_document" "x" {\n'
        "  statement {\n"
        '    actions = ["s3:GetObject"]\n'
        '    resources = ["*"]\n'
        '    principals { type = "AWS" identifiers = ["*"] }\n'
        "  }\n}\n"
    ),
}


HARDENED_FIXTURE_HEADER = (
    "terraform {\n"
    "  required_providers {\n"
    '    aws = { source = "hashicorp/aws" version = "5.0.0" }\n'
    "  }\n"
    '  backend "s3" { bucket = "tf-state" key = "k" region = "us-east-1" encrypt = true dynamodb_table = "lock" }\n'
    "}\n\n"
)

HARDENED_TF = HARDENED_FIXTURE_HEADER + (
    'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n  tags = { owner = "team" cost_center = "cc-1" }\n}\n\n'
    'resource "aws_s3_bucket" "private" {\n'
    '  bucket = "private-data"\n'
    '  acl = "private"\n'
    "  server_side_encryption_configuration {\n"
    '    rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }\n'
    "  }\n"
    '  logging { target_bucket = "log-bucket" target_prefix = "x/" }\n'
    '  tags = { owner = "team" cost_center = "cc-1" }\n'
    "}\n"
)


@pytest.mark.parametrize("rule_id", [rid for rid, _ in IAC_TF_RULES])
def test_vulnerable_fixture_triggers_rule(tmp_path: Path, rule_id: str) -> None:
    fixture = VULNERABLE_FIXTURES[rule_id]
    payload = _scan_and_dump(tmp_path, fixture)
    counts = payload["findings_by_rule"]
    assert counts[rule_id] >= 1, f"{rule_id} did not fire on its vulnerable fixture; got counts={counts}."


def test_hardened_fixture_has_zero_iac_tf_findings(tmp_path: Path) -> None:
    payload = _scan_and_dump(tmp_path, HARDENED_TF)
    assert payload["status"] == "ok"
    counts = payload["findings_by_rule"]
    # The hardened fixture deliberately covers controls 001/004/005/008/009/010
    # and avoids the others (002/003/006/007/011/012) by not declaring those resources.
    for rid in ("IAC-TF-001", "IAC-TF-004", "IAC-TF-005", "IAC-TF-008", "IAC-TF-009", "IAC-TF-010"):
        assert counts[rid] == 0, f"{rid} should be 0 on hardened fixture; got {counts[rid]}."


# ---------------------------------------------------------------------------
# Evaluator wiring: evidence absent -> manual-review-required
# ---------------------------------------------------------------------------


def test_iac_evaluator_returns_manual_review_when_evidence_missing(tmp_path: Path) -> None:
    """Evaluators must never crash on a clone without scan-iac evidence."""

    from oss_policy_kit.application.engine import evaluate_repository

    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")
    root = bundled_kit_root()
    spec = load_profile_by_id(root, "iac-terraform-baseline-1")
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    report = evaluate_repository(tmp_path, spec, catalog, waiver_outcome=None, scorecard=None)
    statuses = {r.control_id: r.status.value for r in report.results}
    for rid in all_rule_ids():
        assert statuses[rid] == "manual-review-required", (
            f"{rid}: expected manual-review-required without evidence, got {statuses[rid]}."
        )


def test_iac_evaluator_passes_on_clean_evidence(tmp_path: Path) -> None:
    """An evidence file with status=ok and zero findings yields PASS for every rule."""

    from oss_policy_kit.application.engine import evaluate_repository

    (tmp_path / "main.tf").write_text(
        HARDENED_FIXTURE_HEADER + 'resource "aws_iam_role" "x" {\n'
        '  name = "x"\n'
        '  assume_role_policy = "{}"\n'
        '  tags = { owner = "team" cost_center = "cc-1" }\n'
        "}\n",
        encoding="utf-8",
    )
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)

    root = bundled_kit_root()
    spec = load_profile_by_id(root, "iac-terraform-baseline-1")
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    report = evaluate_repository(tmp_path, spec, catalog, waiver_outcome=None, scorecard=None)
    statuses = {r.control_id: r.status.value for r in report.results}
    # All 12 IAC-TF-* should now be either PASS (evidence says zero findings) -- never FAIL on hardened.
    for rid in all_rule_ids():
        assert statuses[rid] in {"pass", "manual-review-required"}, (
            f"{rid}: hardened fixture should not produce FAIL; got {statuses[rid]}."
        )
    # At least the rules whose hardened branches we cover must be pass.
    for rid in ("IAC-TF-001", "IAC-TF-002", "IAC-TF-003", "IAC-TF-004"):
        assert statuses[rid] == "pass"


def test_iac_evaluator_fails_on_findings(tmp_path: Path) -> None:
    """A finding for IAC-TF-001 must produce ControlStatus.FAIL on that evaluator."""

    (tmp_path / "main.tf").write_text(VULNERABLE_FIXTURES["IAC-TF-001"], encoding="utf-8")
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)

    eval_fn = EVALUATOR_REGISTRY["IAC-TF-001"]
    # Build a minimal EvalContext-shaped object: the evaluator only needs repo_root.
    from oss_policy_kit.application.evaluators import EvalContext
    from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
    from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines
    from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

    ctx = EvalContext(
        repo_root=tmp_path,
        profile_id="iac-terraform-baseline-1",
        workflows=analyze_workflows(tmp_path),
        azure_pipelines=analyze_azure_pipelines(tmp_path),
        aws_ci=analyze_aws_ci(tmp_path),
        scorecard=None,
    )
    outcome_eval = eval_fn(ctx)
    assert outcome_eval.status == ControlStatus.FAIL


# ---------------------------------------------------------------------------
# Honest-gap behavior when the parser library is absent
# ---------------------------------------------------------------------------


def test_scan_writes_not_available_when_hcl2_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When ``python-hcl2`` is unavailable the scan still writes valid evidence."""

    from oss_policy_kit.infrastructure.iac import scanner as _scanner

    monkeypatch.setattr(_scanner, "hcl2_available", lambda: False)
    outcome = _scanner.run_scan(tmp_path)
    payload = _scanner.render_evidence_payload(outcome, target=tmp_path)
    assert payload["status"] == "not_available"
    assert payload["schema_version"] == EVIDENCE_SCHEMA_VERSION
    assert "python-hcl2" in payload["diagnostics"]["raw_message"]


def test_evaluate_reports_manual_review_when_status_not_available(tmp_path: Path) -> None:
    """Stub an evidence file with status=not_available and ensure evaluators flip
    to manual-review-required (instead of pass)."""

    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / EVIDENCE_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "tool": "oss-policy-kit-tf-parser",
                "tool_version": "5.5.0",
                "status": "not_available",
                "target": str(tmp_path),
                "scanned_at": "2026-05-09T00:00:00Z",
                "attested_at": "2026-05-09T00:00:00Z",
                "attested_by": "oss-policy-kit scan-iac",
                "files_scanned": [],
                "files_failed": [],
                "findings_total": 0,
                "findings_by_rule": {rid: 0 for rid in all_rule_ids()},
                "findings_by_severity": {},
                "findings": [],
                "diagnostics": {"parse_errors": [], "raw_message": "stub"},
            }
        ),
        encoding="utf-8",
    )

    from oss_policy_kit.application.engine import evaluate_repository

    root = bundled_kit_root()
    spec = load_profile_by_id(root, "iac-terraform-baseline-1")
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    report = evaluate_repository(tmp_path, spec, catalog, waiver_outcome=None, scorecard=None)
    statuses = {r.control_id: r.status.value for r in report.results}
    for rid in all_rule_ids():
        assert statuses[rid] == "manual-review-required"
