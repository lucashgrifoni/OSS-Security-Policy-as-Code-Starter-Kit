"""export-evidence subcommand: format registry + Chainloop renderer (PR-17, ADR-012)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.cli.export_evidence import (
    _RENDERERS,
    _SUPPORTED_FORMATS,
    _load_evaluation_report,
    _render_chainloop,
    _render_sarif,
    _validate,
)
from oss_policy_kit.domain.errors import InvalidInputError


def _sample_report() -> dict:
    return {
        "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/1.0",
        "target": "examples/hardened-repo",
        "profile": {"id": "github-level-1"},
        "summary_by_status": {"pass": 8, "fail": 1, "manual-review-required": 2},
        "controls": [
            {"id": "GOV-SEC-001", "status": "pass", "reason": "SECURITY.md present."},
            {"id": "GH-PROV-023", "status": "manual-review-required", "reason": "No evidence file."},
        ],
        "waivers": [],
    }


def test_supported_formats_present() -> None:
    assert set(_RENDERERS.keys()) == set(_SUPPORTED_FORMATS)


def test_render_chainloop_envelope_shape() -> None:
    out = _render_chainloop(_sample_report())
    assert out["attestation_type"].startswith("https://chainloop.dev/")
    assert out["subject"]["kit"] == "oss-policy-kit"
    assert out["subject"]["profile"] == "github-level-1"
    assert out["experimental"] is True
    assert "predicate" in out and "evaluatedAt" in out["predicate"]


def test_render_chainloop_passes_validation() -> None:
    out = _render_chainloop(_sample_report())
    assert _validate(out, "chainloop") == []


def test_render_chainloop_validation_catches_missing_fields() -> None:
    errs = _validate({"attestation_type": "x"}, "chainloop")
    assert any("subject" in e for e in errs)
    assert any("predicate" in e for e in errs)


def test_render_sarif_synthesises_from_controls() -> None:
    out = _render_sarif(_sample_report())
    assert out["version"] == "2.1.0"
    assert isinstance(out["runs"], list) and len(out["runs"]) == 1
    results = out["runs"][0]["results"]
    assert len(results) == 2
    assert any(r["ruleId"] == "GOV-SEC-001" for r in results)
    assert _validate(out, "sarif") == []


def test_render_sarif_uses_existing_runs_when_present() -> None:
    report = _sample_report()
    report["sarif_runs"] = [{"tool": {"driver": {"name": "existing"}}, "results": []}]
    out = _render_sarif(report)
    assert out["runs"][0]["tool"]["driver"]["name"] == "existing"


def test_load_evaluation_report_finds_explicit_path(tmp_path: Path) -> None:
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(_sample_report()), encoding="utf-8")
    data = _load_evaluation_report(tmp_path, report_file)
    assert data["target"] == "examples/hardened-repo"


def test_load_evaluation_report_falls_back_to_target_out(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "evaluation-report.json").write_text(json.dumps(_sample_report()), encoding="utf-8")
    data = _load_evaluation_report(tmp_path, None)
    assert data["profile"]["id"] == "github-level-1"


def test_load_evaluation_report_raises_when_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Chdir into the empty tmp_path so the cwd fallback also misses.
    monkeypatch.chdir(tmp_path)
    with pytest.raises(InvalidInputError, match="No evaluation report found"):
        _load_evaluation_report(tmp_path, None)


def test_chainloop_format_is_marked_experimental() -> None:
    """The output must self-declare as experimental so downstream consumers can branch."""
    out = _render_chainloop(_sample_report())
    assert out.get("experimental") is True
    assert "experimental_note" in out
