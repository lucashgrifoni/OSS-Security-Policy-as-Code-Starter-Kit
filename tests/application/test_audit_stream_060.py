"""AUDIT-STREAM-060: signal fallback + evidence-backed paths."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_audit_stream_060
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, profile_id: str = "github-level-3") -> EvalContext:
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
    evidence_file = evidence_dir / "audit-log-streaming.json"
    evidence_file.write_text(json.dumps(payload), encoding="utf-8")
    return evidence_file


def _valid_payload(*, enabled: bool = True, destinations: list[dict] | None = None) -> dict:
    return {
        "schema_version": "audit-log-streaming/v1",
        "attested_at": "2026-05-01",
        "attested_by": "security-team",
        "platform": "github",
        "streaming_enabled": enabled,
        "destinations": destinations
        if destinations is not None
        else [{"kind": "s3", "uri": "s3://example-org-audit-logs"}],
    }


def test_audit_stream_060_manual_review_when_no_evidence_and_no_signal(tmp_path: Path) -> None:
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "audit log streaming" in out.reason.lower() or "owasp cicd-sec-10" in out.reason.lower()


def test_audit_stream_060_signal_pass_when_yaml_marker_present(tmp_path: Path) -> None:
    (tmp_path / ".github").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".github" / "audit-log-streaming.yml").write_text(
        "destination: s3://example-org-audit-logs\nenabled: true\n", encoding="utf-8"
    )
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "low"
    # Signal-grade PASS includes the keyword warning
    assert any("keyword match" in w.lower() for w in out.operational_warnings)


def test_audit_stream_060_signal_pass_when_doc_keyword_present(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs" / "release-readiness.md").write_text(
        "# Release readiness\n\n## Audit log streaming\nLogs are streamed to s3.\n", encoding="utf-8"
    )
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "low"


def test_audit_stream_060_doc_without_keyword_does_not_pass(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs" / "release-readiness.md").write_text(
        "# Release readiness\n\nNo mention of streaming here.\n", encoding="utf-8"
    )
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_audit_stream_060_evidence_pass_when_streaming_enabled(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _valid_payload(enabled=True))
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "high"


def test_audit_stream_060_fails_when_streaming_disabled(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _valid_payload(enabled=False))
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "streaming_enabled" in out.reason or "destinations" in out.reason


def test_audit_stream_060_fails_when_destinations_empty(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _valid_payload(enabled=True, destinations=[]))
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


def test_audit_stream_060_manual_review_when_invalid_schema(tmp_path: Path) -> None:
    _write_evidence(tmp_path, {"schema_version": "audit-log-streaming/v1", "invalid": "data"})
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_audit_stream_060_marks_live_collection_method(tmp_path: Path) -> None:
    payload = _valid_payload(enabled=True)
    payload["collection"] = {
        "evidence_collection_method": "live",
        "collected_at": "2026-05-01T12:00:00Z",
        "source_url": "https://api.github.com/orgs/example-org/audit-log/stream-key",
        "mode": "api",
    }
    _write_evidence(tmp_path, payload)
    out = eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method == EvidenceCollectionMethod.LIVE
