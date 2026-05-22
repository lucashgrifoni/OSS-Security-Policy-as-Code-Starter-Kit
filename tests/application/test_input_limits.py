"""Input-size-limit hardening: oversize SARIF / evidence / scorecard / waiver inputs.

Backlog: 'v6 input size limits for SARIF and evidence files'. Evaluator paths must
degrade (manual-review), CLI paths must reject with InvalidInputError (exit 2).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application import input_limits as il
from oss_policy_kit.domain.errors import InvalidInputError

# --------------------------------------------------------------------------- #
# Helper unit tests
# --------------------------------------------------------------------------- #


def test_oversize_reason_under_and_over(tmp_path: Path) -> None:
    p = tmp_path / "f.json"
    p.write_text("x" * 100, encoding="utf-8")
    assert il.oversize_reason(p, 1000, label="Evidence") is None
    msg = il.oversize_reason(p, 10, label="Evidence")
    assert msg is not None and "exceeding" in msg and "Evidence" in msg


def test_oversize_reason_missing_file(tmp_path: Path) -> None:
    assert il.oversize_reason(tmp_path / "nope.json", 10, label="X") is None


def test_read_text_capped_ok_and_reject(tmp_path: Path) -> None:
    p = tmp_path / "f.txt"
    p.write_text("hello", encoding="utf-8")
    assert il.read_text_capped(p, 1000, label="X") == "hello"
    with pytest.raises(InvalidInputError):
        il.read_text_capped(p, 2, label="X")


def test_default_limits_are_sane() -> None:
    assert il.MAX_EVIDENCE_BYTES == 5 * 1024 * 1024
    assert il.MAX_SARIF_BYTES == 20 * 1024 * 1024
    assert il.MAX_SARIF_BYTES > il.MAX_EVIDENCE_BYTES


# --------------------------------------------------------------------------- #
# Evaluator path: oversize evidence JSON degrades, never crashes
# --------------------------------------------------------------------------- #


def test_validate_json_evidence_oversize_returns_error(tmp_path: Path, monkeypatch) -> None:
    from oss_policy_kit.application import evaluators_common as ec

    monkeypatch.setattr(ec, "MAX_EVIDENCE_BYTES", 10)
    ev = tmp_path / "evidence.json"
    ev.write_text(json.dumps({"schema_version": "x", "padding": "y" * 100}), encoding="utf-8")
    data, error, ph = ec.validate_json_evidence(ev, schema_loader=lambda: {}, evidence_name="Test")
    assert data is None and ph == []
    assert error is not None and "exceeding" in error


def test_org_mfa_oversize_evidence_degrades_to_manual(tmp_path: Path, monkeypatch) -> None:
    from oss_policy_kit.application import evaluators_common as ec
    from oss_policy_kit.application.evaluators import governance as gov
    from oss_policy_kit.domain.models import ControlStatus
    from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
    from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
    from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

    monkeypatch.setattr(ec, "MAX_EVIDENCE_BYTES", 10)
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / "org-mfa-posture.json").write_text(
        json.dumps({"schema_version": "org-mfa-posture/v1", "x": "y" * 200}), encoding="utf-8"
    )
    ctx = gov.EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )
    out = gov.eval_org_mfa_001(ctx)
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# SARIF loader path: oversize returns error tuple
# --------------------------------------------------------------------------- #


def test_load_sarif_runs_oversize(tmp_path: Path, monkeypatch) -> None:
    from oss_policy_kit.application.evaluators import _shared

    monkeypatch.setattr(_shared, "MAX_SARIF_BYTES", 10)
    sf = tmp_path / "x.sarif.json"
    sf.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
    runs, err = _shared._load_sarif_runs(sf)
    assert runs is None and err is not None and "exceeding" in err


# --------------------------------------------------------------------------- #
# CLI paths: oversize raises InvalidInputError
# --------------------------------------------------------------------------- #


def test_load_eval_scorecard_oversize(tmp_path: Path, monkeypatch) -> None:
    from oss_policy_kit.cli import common as cc

    monkeypatch.setattr(cc, "MAX_EVIDENCE_BYTES", 10)
    sp = tmp_path / "scorecard.json"
    sp.write_text(json.dumps({"score": 7.0, "checks": [], "pad": "z" * 100}), encoding="utf-8")
    with pytest.raises(InvalidInputError):
        cc._load_eval_scorecard(sp)


def test_load_eval_waivers_oversize(tmp_path: Path, monkeypatch) -> None:
    from oss_policy_kit.cli import common as cc

    monkeypatch.setattr(cc, "MAX_EVIDENCE_BYTES", 10)
    wp = tmp_path / "waivers.yaml"
    wp.write_text("version: 1\nwaivers: []\n# padding " + "x" * 100 + "\n", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        cc._load_eval_waivers(wp)


def test_emit_vex_sarif_oversize(tmp_path: Path, monkeypatch) -> None:
    from oss_policy_kit.cli import emit_vex as ev

    monkeypatch.setattr(ev, "MAX_SARIF_BYTES", 10)
    sf = tmp_path / "osv.sarif.json"
    sf.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": []}]}),
        encoding="utf-8",
    )
    _ids, _refs, err = ev._extract_sarif_data(sf)
    assert err is not None and "exceeding" in err
