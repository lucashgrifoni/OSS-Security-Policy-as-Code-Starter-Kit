"""SARIF-ingest SAST adapters (Fase 4): zizmor, poutine, OSV-Scanner, gitleaks.

Validates the shared `_parse_sarif_findings` helper plus the four concrete
adapters introduced in v5.9.0. Each adapter reads a raw SARIF 2.1.0 file
dropped at `.oss-policy-kit/evidence/sast/<tool>.sarif.json`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import (
    EvalContext,
    _parse_sarif_findings,
    eval_sast_gitleaks_069,
    eval_sast_osv_068,
    eval_sast_poutine_067,
    eval_sast_zizmor_066,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, profile_id: str = "appsec-sast-sca-1") -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_sarif(tmp_path: Path, tool_filename: str, payload: dict) -> Path:
    sast_dir = tmp_path / ".oss-policy-kit" / "evidence" / "sast"
    sast_dir.mkdir(parents=True, exist_ok=True)
    p = sast_dir / tool_filename
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _sarif(*, errors: int = 0, warnings: int = 0, notes: int = 0) -> dict:
    """Build a minimal SARIF 2.1.0 doc with explicit-level results."""

    results = []
    for _ in range(errors):
        results.append({"level": "error", "message": {"text": "x"}})
    for _ in range(warnings):
        results.append({"level": "warning", "message": {"text": "x"}})
    for _ in range(notes):
        results.append({"level": "note", "message": {"text": "x"}})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "test", "rules": []}}, "results": results}],
    }


# --- Helper unit tests ------------------------------------------------------


def test_parse_sarif_counts_explicit_levels(tmp_path: Path) -> None:
    p = tmp_path / "x.sarif.json"
    p.write_text(json.dumps(_sarif(errors=2, warnings=3, notes=1)), encoding="utf-8")
    counts, err = _parse_sarif_findings(p)
    assert err is None
    assert counts == {"error": 2, "warning": 3, "note": 1, "none": 0}


def test_parse_sarif_uses_rule_default_level_when_result_omits(tmp_path: Path) -> None:
    p = tmp_path / "x.sarif.json"
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "R1", "defaultConfiguration": {"level": "error"}},
                            {"id": "R2", "defaultConfiguration": {"level": "note"}},
                        ]
                    }
                },
                "results": [{"ruleId": "R1"}, {"ruleId": "R2"}, {"ruleId": "R-missing"}],
            }
        ]
    }
    p.write_text(json.dumps(payload), encoding="utf-8")
    counts, err = _parse_sarif_findings(p)
    assert err is None
    # R-missing falls back to "warning" per SARIF spec.
    assert counts == {"error": 1, "warning": 1, "note": 1, "none": 0}


def test_parse_sarif_rejects_malformed_json(tmp_path: Path) -> None:
    p = tmp_path / "x.sarif.json"
    p.write_text("{ not json", encoding="utf-8")
    counts, err = _parse_sarif_findings(p)
    assert counts is None
    assert err is not None
    assert "parse" in err.lower() or "json" in err.lower()


def test_parse_sarif_rejects_missing_runs(tmp_path: Path) -> None:
    p = tmp_path / "x.sarif.json"
    p.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    counts, err = _parse_sarif_findings(p)
    assert counts is None
    assert err is not None


# --- Adapter tests: shared shape parametrized over the four adapters --------


_ADAPTERS = [
    (eval_sast_zizmor_066, "zizmor.sarif.json", "zizmor"),
    (eval_sast_poutine_067, "poutine.sarif.json", "poutine"),
    (eval_sast_osv_068, "osv-scanner.sarif.json", "osv-scanner"),
    (eval_sast_gitleaks_069, "gitleaks.sarif.json", "gitleaks"),
]


@pytest.mark.parametrize("fn, filename, name", _ADAPTERS, ids=lambda x: getattr(x, "__name__", str(x)))
def test_adapter_manual_review_when_no_evidence(fn, filename, name, tmp_path: Path) -> None:
    out = fn(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert filename in out.reason


@pytest.mark.parametrize("fn, filename, name", _ADAPTERS, ids=lambda x: getattr(x, "__name__", str(x)))
def test_adapter_pass_when_sarif_has_no_findings(fn, filename, name, tmp_path: Path) -> None:
    _write_sarif(tmp_path, filename, _sarif())
    out = fn(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert "error=0" in out.reason


@pytest.mark.parametrize("fn, filename, name", _ADAPTERS, ids=lambda x: getattr(x, "__name__", str(x)))
def test_adapter_fail_on_error_finding(fn, filename, name, tmp_path: Path) -> None:
    _write_sarif(tmp_path, filename, _sarif(errors=1))
    out = fn(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


@pytest.mark.parametrize(
    "fn, filename, name",
    [a for a in _ADAPTERS if a[0] is not eval_sast_gitleaks_069],
    ids=lambda x: getattr(x, "__name__", str(x)),
)
def test_non_gitleaks_adapters_pass_on_warnings_only(fn, filename, name, tmp_path: Path) -> None:
    """zizmor / poutine / OSV pass on warning-only output (fail_on_warning=False)."""
    _write_sarif(tmp_path, filename, _sarif(warnings=3))
    out = fn(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_gitleaks_fails_on_warning_only(tmp_path: Path) -> None:
    """Gitleaks treats any finding (even warning) as block — secrets are zero-tolerance."""
    _write_sarif(tmp_path, "gitleaks.sarif.json", _sarif(warnings=1))
    out = eval_sast_gitleaks_069(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


@pytest.mark.parametrize("fn, filename, name", _ADAPTERS, ids=lambda x: getattr(x, "__name__", str(x)))
def test_adapter_manual_review_on_malformed_sarif(fn, filename, name, tmp_path: Path) -> None:
    sast_dir = tmp_path / ".oss-policy-kit" / "evidence" / "sast"
    sast_dir.mkdir(parents=True, exist_ok=True)
    (sast_dir / filename).write_text("{not valid", encoding="utf-8")
    out = fn(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
