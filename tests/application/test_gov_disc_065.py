"""GOV-DISC-065: disclosure-channel-SLA evidence-backed coverage.

Validates the signal fallback (SECURITY.md SLA keyword), evidence-backed PASS,
schema-error MANUAL_REVIEW_REQUIRED, and missing-required-field FAIL paths.
"""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_gov_disc_065
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, profile_id: str = "cra-eu-reporting-1") -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_evidence(tmp_path: Path, payload: dict) -> Path:
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / "disclosure-policy.json"
    evidence_file.write_text(json.dumps(payload), encoding="utf-8")
    return evidence_file


def _valid_payload(**overrides) -> dict:
    base = {
        "schema_version": "disclosure-policy/v1",
        "attested_at": "2026-05-01",
        "attested_by": "security-team",
        "contact": {"method": "email", "value": "security@example.org"},
        "acknowledgement_sla_hours": 72,
        "triage_sla_hours": 168,
        "public_disclosure_policy": {"default_window_days": 90, "negotiable": True},
    }
    base.update(overrides)
    return base


def test_gov_disc_065_manual_review_when_no_evidence_and_no_signal(tmp_path: Path) -> None:
    out = eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "disclosure" in out.reason.lower() or "sla" in out.reason.lower()


def test_gov_disc_065_signal_pass_when_security_md_mentions_sla(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text(
        "# Security Policy\n\n## Reporting\nPlease email security@example.org. We will respond within 72 hours.\n",
        encoding="utf-8",
    )
    out = eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "low"
    assert any("keyword match" in w.lower() for w in out.operational_warnings)


def test_gov_disc_065_signal_pass_via_github_security_md(tmp_path: Path) -> None:
    (tmp_path / ".github").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "SECURITY.md").write_text(
        "# Security\n\nWe aim to respond within 5 business days.\n", encoding="utf-8"
    )
    out = eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_gov_disc_065_security_md_without_sla_does_not_pass(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text(
        "# Security Policy\n\nReport issues to security@example.org.\n", encoding="utf-8"
    )
    out = eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_gov_disc_065_evidence_pass_when_complete(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _valid_payload())
    out = eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "high"
    assert "acknowledgement_sla_hours=72" in out.reason


def test_gov_disc_065_fails_when_ack_sla_missing(tmp_path: Path) -> None:
    payload = _valid_payload()
    del payload["acknowledgement_sla_hours"]
    _write_evidence(tmp_path, payload)
    out = eval_gov_disc_065(_ctx(tmp_path))
    # Missing required field → schema validation rejects → MANUAL_REVIEW_REQUIRED.
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_gov_disc_065_manual_review_when_schema_invalid(tmp_path: Path) -> None:
    _write_evidence(tmp_path, {"schema_version": "disclosure-policy/v1", "garbage": "value"})
    out = eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_gov_disc_065_marks_live_collection_method(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["collection"] = {
        "evidence_collection_method": "live",
        "collected_at": "2026-05-01T12:00:00Z",
        "source_url": "https://example.org/security/policy",
        "mode": "api",
    }
    _write_evidence(tmp_path, payload)
    out = eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method == EvidenceCollectionMethod.LIVE


def test_gov_disc_065_pgp_contact_method_accepted(tmp_path: Path) -> None:
    payload = _valid_payload(
        contact={
            "method": "pgp",
            "value": "0xDEADBEEF12345678",
            "pgp_fingerprint": "AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333",
        }
    )
    _write_evidence(tmp_path, payload)
    out = eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
