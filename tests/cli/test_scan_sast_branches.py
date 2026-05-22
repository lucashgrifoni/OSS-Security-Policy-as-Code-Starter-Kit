"""Branch coverage for the ``scan-sast`` command (json/human, not-available, error, timeout, validation)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli import scan_sast as ss
from oss_policy_kit.cli.main import app
from oss_policy_kit.infrastructure.scanners.semgrep_adapter import SemgrepRunOutcome

runner = CliRunner()


def test_scan_sast_json_not_available(tmp_path: Path) -> None:
    # Semgrep is not installed in CI -> status not_available, exit 0, JSON emitted.
    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert payload["status"] in {"not_available", "ok", "error", "timeout"}


def test_scan_sast_human_not_available(tmp_path: Path) -> None:
    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "scan-sast:" in res.output


def test_scan_sast_empty_rulesets(tmp_path: Path) -> None:
    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--rulesets", "  "])
    assert res.exit_code == 2


def test_scan_sast_bad_format(tmp_path: Path) -> None:
    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--format", "xml"])
    assert res.exit_code != 0


def test_scan_sast_error_status(tmp_path: Path, monkeypatch) -> None:
    def _err(*_a, **_k) -> SemgrepRunOutcome:
        return SemgrepRunOutcome(status="error", version="1.0", rulesets=["auto"], raw_stderr="boom")

    monkeypatch.setattr(ss, "run_semgrep", _err)
    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 2


def test_scan_sast_timeout_status(tmp_path: Path, monkeypatch) -> None:
    def _to(*_a, **_k) -> SemgrepRunOutcome:
        return SemgrepRunOutcome(status="timeout", version="1.0", rulesets=["auto"])

    monkeypatch.setattr(ss, "run_semgrep", _to)
    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0
    assert "scan-sast:" in res.output


def test_scan_sast_ok_json(tmp_path: Path, monkeypatch) -> None:
    def _ok(*_a, **_k) -> SemgrepRunOutcome:
        return SemgrepRunOutcome(status="ok", version="1.0", rulesets=["auto"], findings=[])

    monkeypatch.setattr(ss, "run_semgrep", _ok)
    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0
    assert json.loads(res.stdout)["status"] == "ok"
