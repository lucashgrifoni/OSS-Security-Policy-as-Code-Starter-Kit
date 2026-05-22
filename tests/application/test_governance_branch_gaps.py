"""Branch-coverage gaps for governance evaluators and their private helpers.

Mixes integration tests (evidence files on disk) with direct unit tests for
defensive branches that a schema-valid evidence file can never reach.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from oss_policy_kit.application.evaluators import governance as gov
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, profile_id: str = "github-level-3", max_age: int = 90) -> gov.EvalContext:
    return gov.EvalContext(
        repo_root=tmp_path,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        evidence_max_age_days=max_age,
    )


def _evid(tmp_path: Path, name: str, payload: dict) -> Path:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# eval_rel_change_012 — workflows README present, no changelog (line 150)
# --------------------------------------------------------------------------- #


def test_rel_change_012_manual_when_ci_readme_only(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "README.md").write_text("# Workflows\n", encoding="utf-8")
    out = gov.eval_rel_change_012(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# eval_gov_evidfresh_054
# --------------------------------------------------------------------------- #


def test_evidfresh_054_na_when_only_sarif(tmp_path: Path) -> None:
    """Evidence dir exists but every JSON is a skipped SARIF file -> NOT_APPLICABLE (line 340)."""
    sast = tmp_path / ".oss-policy-kit" / "evidence" / "sast"
    sast.mkdir(parents=True, exist_ok=True)
    (sast / "semgrep.sarif.json").write_text("{}", encoding="utf-8")
    out = gov.eval_gov_evidfresh_054(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_APPLICABLE


def test_evidfresh_054_manual_on_invalid_json(tmp_path: Path) -> None:
    """Unreadable/invalid JSON short-circuits to MANUAL (lines 285-286, 354)."""
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / "broken.json").write_text("{not valid json", encoding="utf-8")
    out = gov.eval_gov_evidfresh_054(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_evidfresh_054_undated_when_json_is_list(tmp_path: Path) -> None:
    """Non-dict JSON root counts as undated (lines 299-300)."""
    _evid(tmp_path, "list.json", [])  # type: ignore[arg-type]
    out = gov.eval_gov_evidfresh_054(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "date" in out.reason.lower()


def test_evidfresh_054_zero_max_age_falls_back(tmp_path: Path) -> None:
    """Negative max_age resets to the default window, so a fresh file PASSes (line 351)."""
    _evid(tmp_path, "fresh.json", {"collected_at": date.today().isoformat()})
    out = gov.eval_gov_evidfresh_054(_ctx(tmp_path, max_age=-1))
    assert out.status == ControlStatus.PASS


# --------------------------------------------------------------------------- #
# _classify_evidence_files (direct)
# --------------------------------------------------------------------------- #


def test_classify_evidence_files_error_path(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    stale, undated, warns, err = gov._classify_evidence_files([bad], date.today(), 90)
    assert err is not None
    assert err.status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# _mfa_enforcement_failure (direct) — lines 541, 568
# --------------------------------------------------------------------------- #


def test_mfa_failure_none_all_members(tmp_path: Path) -> None:
    out = gov._mfa_enforcement_failure(None, True, tmp_path / "x.json")
    assert out is not None and out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_mfa_failure_admins_off_only(tmp_path: Path) -> None:
    out = gov._mfa_enforcement_failure(True, False, tmp_path / "x.json")
    assert out is not None and out.status == ControlStatus.FAIL


def test_mfa_failure_clean_returns_none(tmp_path: Path) -> None:
    assert gov._mfa_enforcement_failure(True, True, tmp_path / "x.json") is None


def test_org_mfa_placeholder_blocked(tmp_path: Path) -> None:
    """Schema-valid evidence with a scaffold token -> NOT_EVALUATED (line 607)."""
    _evid(
        tmp_path,
        "org-mfa-posture.json",
        {
            "schema_version": "org-mfa-posture/v1",
            "attested_at": "2026-05-01",
            "attested_by": "REPLACE_ME",
            "org_name": "acme",
            "platform": "github",
            "mfa_required_for_all_members": True,
            "mfa_required_for_admins": True,
            "sso_enforced": True,
            "enforcement_scope": "all_members",
        },
    )
    out = gov.eval_org_mfa_001(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_EVALUATED


# --------------------------------------------------------------------------- #
# SBOM helpers (direct) — lines 677, 708, 720, 736, 749
# --------------------------------------------------------------------------- #


def test_evidence_sbom_format_none_when_no_block(tmp_path: Path) -> None:
    p = tmp_path / "azure-sbom-artifact.json"
    p.write_text(json.dumps({"unrelated": True}), encoding="utf-8")
    assert gov._evidence_sbom_format(p) is None


def test_evidence_sbom_format_none_when_missing(tmp_path: Path) -> None:
    assert gov._evidence_sbom_format(tmp_path / "missing.json") is None


def test_classify_sbom_file_unconfirmed(tmp_path: Path) -> None:
    p = tmp_path / "not-an-sbom.json"
    p.write_text("just some text, not an sbom", encoding="utf-8")
    label, note, unconfirmed = gov._classify_sbom_file(p)
    assert label is None and note is None and unconfirmed == p.name


def test_classify_sbom_file_unreadable_returns_all_none(tmp_path: Path) -> None:
    # A directory path makes read_text raise OSError, exercising the suppressed branch.
    d = tmp_path / "sbom_dir"
    d.mkdir()
    assert gov._classify_sbom_file(d) == (None, None, None)


def test_scan_repo_sbom_files_manual_when_all_invalid(tmp_path: Path) -> None:
    p = tmp_path / "maybe-sbom.json"
    p.write_text("nope", encoding="utf-8")
    out = gov._scan_repo_sbom_files([p])
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# AUDIT-STREAM-060 — lines 861, 881
# --------------------------------------------------------------------------- #


def _audit_payload(*, method: str | None = None, attested_by: str = "platform-team") -> dict:
    payload: dict = {
        "schema_version": "audit-log-streaming/v1",
        "attested_at": "2026-05-01",
        "attested_by": attested_by,
        "platform": "github",
        "streaming_enabled": True,
        "destinations": [{"kind": "splunk", "uri": "https://splunk.example/ingest"}],
    }
    if method is not None:
        payload["collection"] = {"evidence_collection_method": method, "collected_at": "2026-05-01"}
    return payload


def test_audit_stream_060_placeholder_blocked(tmp_path: Path) -> None:
    _evid(tmp_path, "audit-log-streaming.json", _audit_payload(attested_by="TODO fill in"))
    out = gov.eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_EVALUATED


def test_audit_stream_060_manual_collection_method(tmp_path: Path) -> None:
    _evid(tmp_path, "audit-log-streaming.json", _audit_payload(method="manual"))
    out = gov.eval_audit_stream_060(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method == EvidenceCollectionMethod.MANUAL


# --------------------------------------------------------------------------- #
# _collection_method (direct) — lines 903-904
# --------------------------------------------------------------------------- #


def test_collection_method_manual() -> None:
    assert (
        gov._collection_method({"collection": {"evidence_collection_method": "manual"}})
        == EvidenceCollectionMethod.MANUAL
    )


def test_collection_method_default_static() -> None:
    assert gov._collection_method({}) == EvidenceCollectionMethod.STATIC


# --------------------------------------------------------------------------- #
# _disclosure_missing_fields (direct) — lines 957-963
# --------------------------------------------------------------------------- #


def test_disclosure_missing_fields_all_missing() -> None:
    missing = gov._disclosure_missing_fields({}, None, None, {})
    assert "contact.method / contact.value" in missing
    assert "acknowledgement_sla_hours" in missing
    assert "triage_sla_hours" in missing
    assert any("public_disclosure_policy" in m for m in missing)


def test_disclosure_missing_fields_none_when_complete() -> None:
    assert (
        gov._disclosure_missing_fields(
            {"method": "email", "value": "sec@example.com"},
            72,
            48,
            {"default_window_days": 90, "negotiable": True},
        )
        == []
    )


# --------------------------------------------------------------------------- #
# GOV-DISC-065 placeholder blocked — line 995
# --------------------------------------------------------------------------- #


def _disclosure_payload(*, attested_by: str = "sec-team") -> dict:
    return {
        "schema_version": "disclosure-policy/v1",
        "attested_at": "2026-05-01",
        "attested_by": attested_by,
        "contact": {"method": "email", "value": "security@example.com"},
        "acknowledgement_sla_hours": 72,
        "triage_sla_hours": 48,
        "public_disclosure_policy": {"default_window_days": 90, "negotiable": True},
    }


def test_disc_065_placeholder_blocked(tmp_path: Path) -> None:
    _evid(tmp_path, "disclosure-policy.json", _disclosure_payload(attested_by="YOUR_NAME"))
    out = gov.eval_gov_disc_065(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_EVALUATED


# --------------------------------------------------------------------------- #
# PROV-VERIFY-061 — lines 1078, 1112
# --------------------------------------------------------------------------- #


def _prov_payload(*, verified_at: str = "2026-05-01T12:00:00Z", attested_by: str = "release-bot") -> dict:
    return {
        "schema_version": "github-provenance-artifact/v1",
        "attested_at": "2026-04-21",
        "attested_by": attested_by,
        "artifact": {
            "uri": "https://github.com/example-org/example-repo/releases/download/v1/x.tgz",
            "digest_sha256": "e7c2a4d8f1b6c9d2e5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6f9a2b5c8d1e4",
        },
        "attestation": {
            "kind": "github-artifact-attestation",
            "digest_sha256": "b3a6c9d2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b6",
        },
        "posture": {
            "attestation_covers_release_artifact": True,
            "attestation_digest_recorded": True,
            "artifact_digest_recorded": True,
        },
        "verification": {
            "method": "gh-attestation-verify",
            "verified_at": verified_at,
            "transparency_log_inclusion": True,
        },
    }


def test_prov_verify_061_placeholder_blocked(tmp_path: Path) -> None:
    _evid(tmp_path, "github-provenance-artifact.json", _prov_payload(attested_by="REPLACE-ME"))
    out = gov.eval_prov_verify_061(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_EVALUATED


def test_prov_verify_061_manual_when_verified_at_blank(tmp_path: Path) -> None:
    _evid(tmp_path, "github-provenance-artifact.json", _prov_payload(verified_at="   "))
    out = gov.eval_prov_verify_061(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "verified_at" in out.reason


# --------------------------------------------------------------------------- #
# RELEASE-ARCHIVE-063 placeholder blocked — line 1208
# --------------------------------------------------------------------------- #


def test_release_archive_063_placeholder_blocked(tmp_path: Path) -> None:
    _evid(
        tmp_path,
        "release-archival-policy.json",
        {
            "schema_version": "release-archival-policy/v1",
            "attested_at": "2026-04-21",
            "attested_by": "release-eng",
            "retention_years": 10,
            "archive_destination": "github-releases",
            "vulnerability_handling_doc": "SECURITY.md",
            "notes": "TODO: confirm with legal",
        },
    )
    out = gov.eval_release_archive_063(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_EVALUATED


# --------------------------------------------------------------------------- #
# OSPS-SCORECARD-V6-001 — lines 1465-1466, 1474
# --------------------------------------------------------------------------- #


def test_osps_scorecard_v6_fail_verdict(tmp_path: Path) -> None:
    _evid(tmp_path, "scorecard-osps.json", {"conformance": "fail"})
    out = gov.eval_osps_scorecard_v6_001(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


def test_osps_scorecard_v6_unrecognized_verdict(tmp_path: Path) -> None:
    _evid(tmp_path, "scorecard-osps.json", {"conformance": "maybe"})
    out = gov.eval_osps_scorecard_v6_001(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
