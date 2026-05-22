"""Coverage for the ``export-evidence`` command (chainloop + sarif renderers, validate, errors)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli import export_evidence as ee
from oss_policy_kit.cli.main import app

runner = CliRunner()

_REPORT = {
    "schema_version": "https://example/reports/1.0",
    "target": "C:/tmp/repo",
    "profile": {"id": "github-level-1"},
    "summary_by_status": {"pass": 2, "fail": 1},
    "controls": [
        {"id": "GOV-SEC-001", "status": "pass", "reason": "ok"},
        {"id": "CI-PIN-008", "status": "fail", "reason": "mutable refs"},
    ],
    "waivers": [],
}


def _report_at(target: Path, *, report: dict | None = None) -> None:
    out = target / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / "evaluation-report.json").write_text(json.dumps(report or _REPORT), encoding="utf-8")


def test_export_chainloop(tmp_path: Path) -> None:
    _report_at(tmp_path)
    out = tmp_path / "evidence.json"
    res = runner.invoke(
        app, ["export-evidence", "--target", str(tmp_path), "--format", "chainloop", "--output", str(out)]
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["attestation_type"].startswith("https://chainloop.dev/")
    assert doc["subject"]["profile"] == "github-level-1"


def test_export_sarif_synthesized(tmp_path: Path) -> None:
    _report_at(tmp_path)
    out = tmp_path / "ev.sarif.json"
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--output", str(out)])
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]  # synthesized from controls


def test_export_sarif_passthrough_runs(tmp_path: Path) -> None:
    report = dict(_REPORT)
    report["sarif_runs"] = [{"tool": {"driver": {"name": "x"}}, "results": []}]
    _report_at(tmp_path, report=report)
    out = tmp_path / "ev.sarif.json"
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--output", str(out)])
    assert res.exit_code == 0, res.output


def test_export_validate_ok(tmp_path: Path) -> None:
    _report_at(tmp_path)
    out = tmp_path / "ev.json"
    res = runner.invoke(
        app, ["export-evidence", "--target", str(tmp_path), "--format", "chainloop", "--output", str(out), "--validate"]
    )
    assert res.exit_code == 0, res.output


def test_export_with_explicit_report(tmp_path: Path) -> None:
    rep = tmp_path / "custom-report.json"
    rep.write_text(json.dumps(_REPORT), encoding="utf-8")
    out = tmp_path / "ev.json"
    res = runner.invoke(
        app,
        ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--report", str(rep), "--output", str(out)],
    )
    assert res.exit_code == 0, res.output


def test_export_bad_format(tmp_path: Path) -> None:
    _report_at(tmp_path)
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "spdx"])
    assert res.exit_code != 0


def test_export_bad_target(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    res = runner.invoke(app, ["export-evidence", "--target", str(missing), "--format", "sarif"])
    assert res.exit_code != 0


def test_export_unparseable_report(tmp_path: Path) -> None:
    rep = tmp_path / "broken.json"
    rep.write_text("{not json", encoding="utf-8")
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--report", str(rep)])
    assert res.exit_code != 0


def test_render_helpers_directly() -> None:
    chain = ee._render_chainloop(_REPORT)
    assert chain["subject"]["profile"] == "github-level-1"
    assert ee._validate(chain, "chainloop") == []
    sarif = ee._render_sarif(_REPORT)
    assert ee._validate(sarif, "sarif") == []
    # validation catches malformed docs
    assert ee._validate({}, "chainloop")
    assert ee._validate({"version": "1.0"}, "sarif")
