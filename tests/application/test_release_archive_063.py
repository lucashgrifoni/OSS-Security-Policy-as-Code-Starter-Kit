"""RELEASE-ARCHIVE-063: signal + evidence-backed release archival policy."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_release_archive_063
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, profile_id: str = "github-release-hardening-3") -> EvalContext:
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
    p = evidence_dir / "release-archival-policy.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _valid_payload(*, retention: int = 10) -> dict:
    return {
        "schema_version": "release-archival-policy/v1",
        "attested_at": "2026-04-21",
        "attested_by": "release-eng",
        "retention_years": retention,
        "archive_destination": "github-releases",
        "vulnerability_handling_doc": "SECURITY.md",
    }


def test_release_archive_063_manual_review_when_no_evidence_and_no_signal(tmp_path: Path) -> None:
    out = eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_release_archive_063_signal_pass_when_policy_md_present(tmp_path: Path) -> None:
    (tmp_path / "RELEASE_ARCHIVAL.md").write_text(
        "# Release archival\n\nWe retain release artifacts for 10 years.\n", encoding="utf-8"
    )
    out = eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "low"


def test_release_archive_063_signal_pass_when_yaml_present(tmp_path: Path) -> None:
    (tmp_path / ".github").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "release-archival.yml").write_text(
        "retention_years: 10\narchive: github-releases\n", encoding="utf-8"
    )
    out = eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_release_archive_063_evidence_pass_with_10y(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _valid_payload(retention=10))
    out = eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "10" in out.reason


def test_release_archive_063_manual_review_when_retention_below_10(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _valid_payload(retention=3))
    out = eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "10" in out.reason or "cra" in out.reason.lower()


def test_release_archive_063_fail_when_archive_destination_empty(tmp_path: Path) -> None:
    p = _valid_payload()
    p["archive_destination"] = ""
    _write_evidence(tmp_path, p)
    out = eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


def test_release_archive_063_fail_when_no_vuln_handling_doc(tmp_path: Path) -> None:
    p = _valid_payload()
    p["vulnerability_handling_doc"] = ""
    _write_evidence(tmp_path, p)
    out = eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


def test_release_archive_063_manual_review_on_invalid_schema(tmp_path: Path) -> None:
    _write_evidence(tmp_path, {"schema_version": "release-archival-policy/v1", "invalid": "data"})
    out = eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
