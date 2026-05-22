"""Branch-coverage gaps for application.cli_output summary helpers."""

from __future__ import annotations

from oss_policy_kit.application import cli_output as co
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, WeightedScore


def _cr(cid: str, status: ControlStatus, *, reason: str = "needs work", category: str = "governance") -> ControlResult:
    return ControlResult(
        control_id=cid,
        title="t",
        category=category,
        status=status,
        profile="github-level-3",
        evidence_sources=[],
        confidence="medium",
        reason=reason,
        remediation="fix it",
    )


def _report(
    results: list[ControlResult], *, summary: dict[str, int], external_waiver: str | None = None
) -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://x/reports/0.3",
        generated_at="2026-05-22T00:00:00Z",
        kit_version="6.1.0",
        target_path="C:/tmp/repo",
        profile_id="github-level-3",
        profile_title="Title",
        summary_by_status=summary,
        results=results,
        operational_warnings=[],
        external_waiver_path=external_waiver,
        weighted_score=WeightedScore(earned=5, possible=10, percent=50.0),
    )


# --------------------------------------------------------------------------- #
# _ordered_summary forward-compat key (line 43)
# --------------------------------------------------------------------------- #


def test_ordered_summary_preserves_unknown_status() -> None:
    out = co._ordered_summary({"pass": 1, "future-status": 2})
    assert out["future-status"] == 2


# --------------------------------------------------------------------------- #
# _collect_gap_lines duplicate skip (line 80)
# --------------------------------------------------------------------------- #


def test_collect_gap_lines_dedupes_identical_reasons() -> None:
    rep = _report(
        [_cr("A", ControlStatus.FAIL, reason="same gap"), _cr("B", ControlStatus.FAIL, reason="same gap")],
        summary={"fail": 2},
    )
    gaps = co._collect_gap_lines(rep, gap_max=80)
    assert gaps == ["same gap"]


# --------------------------------------------------------------------------- #
# print_stdout_summary human-tty + external waiver block (lines 194-209)
# --------------------------------------------------------------------------- #


def test_print_stdout_summary_human_external_waiver(monkeypatch, capsys) -> None:
    monkeypatch.setattr(co, "human_tty_stdout", lambda: True)
    monkeypatch.setattr(co, "print_interactive_stdout_summary", lambda *a, **k: None)
    rep = _report([_cr("A", ControlStatus.FAIL)], summary={"fail": 1}, external_waiver="waivers/ext.yaml")
    co.print_stdout_summary(rep, output_format="human")
    out = capsys.readouterr().out
    assert "Waiver note" in out and "ext.yaml" in out


def test_print_stdout_summary_human_external_waiver_long_path(monkeypatch, capsys) -> None:
    monkeypatch.setattr(co, "human_tty_stdout", lambda: True)
    monkeypatch.setattr(co, "print_interactive_stdout_summary", lambda *a, **k: None)
    monkeypatch.setattr(co, "terminal_width", lambda _stream: 20)
    long_path = "a/" * 40 + "external-waivers.yaml"
    rep = _report([_cr("A", ControlStatus.FAIL)], summary={"fail": 1}, external_waiver=long_path)
    co.print_stdout_summary(rep, output_format="human")
    out = capsys.readouterr().out
    assert "Path:" in out
