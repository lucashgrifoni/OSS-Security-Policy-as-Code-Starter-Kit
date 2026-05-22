"""Coverage for the Rich print helpers in ``cli.terminal_ui``.

Renders each interactive panel into an in-memory Console so the executive
preface, interactive summary, recommend-profile layout, banners, and their
private helpers are all exercised across compact / wide and unicode / ascii
variants. Output is asserted structurally (key labels present), not pixel-exact.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from oss_policy_kit.cli import terminal_ui as tui
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, WeightedScore


def _console(width: int = 100) -> tuple[Console, StringIO]:
    buf = StringIO()
    return Console(file=buf, width=width, force_terminal=False, color_system=None), buf


def _report(profile_id: str = "github-level-1", *, with_score: bool = True) -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://example/reports/0.2",
        generated_at="2026-04-18T00:00:00Z",
        kit_version="6.1.0",
        target_path="C:/tmp/repo",
        profile_id=profile_id,
        profile_title="Title",
        summary_by_status={"pass": 2, "fail": 1, "manual-review-required": 1},
        results=[
            ControlResult(
                control_id="GOV-SEC-001", title="SECURITY.md present", category="governance",
                status=ControlStatus.PASS, profile=profile_id, evidence_sources=[],
                confidence="high", reason="Found.", remediation="Keep.",
            ),
            ControlResult(
                control_id="CI-PIN-008", title="Pin actions", category="supply_chain",
                status=ControlStatus.FAIL, profile=profile_id, evidence_sources=[],
                confidence="medium",
                reason="A very long reason " * 10, remediation="Pin SHAs.",
            ),
            ControlResult(
                control_id="GOV-MR-002", title="Manual thing", category="governance",
                status=ControlStatus.MANUAL_REVIEW_REQUIRED, profile=profile_id,
                evidence_sources=[], confidence="low", reason="Check it.", remediation="Do.",
            ),
        ],
        operational_warnings=[],
        weighted_score=WeightedScore(earned=7, possible=10, percent=70.0) if with_score else None,
    )


# --------------------------------------------------------------------------- #
# Small pure helpers
# --------------------------------------------------------------------------- #


def test_profile_platform_key() -> None:
    assert tui._profile_platform_key("github-level-1") == "github"
    assert tui._profile_platform_key("azure-level-2") == "azure"
    assert tui._profile_platform_key("aws-level-3") == "aws"
    assert tui._profile_platform_key("custom") is None


def test_forward_journey_ids() -> None:
    cands = {"github-level-1", "github-level-2", "github-level-3"}
    out = tui._forward_journey_ids("github-level-1", cands)
    assert out[0] == "github-level-1" and len(out) <= 3
    # Non-platform profile.
    assert tui._forward_journey_ids("custom", {"custom"}) == ["custom"]
    assert tui._forward_journey_ids("custom", set()) == []
    # Platform id not in order -> filter by platform.
    assert tui._forward_journey_ids("github-unknown", {"github-level-2"}) == ["github-level-2"]


def test_signal_ids_and_strength() -> None:
    assert tui._signal_ids([{"id": "a"}, {"id": "b"}, {}]) == {"a", "b", ""}
    assert tui._signal_strength(True, True) == "strong"
    assert tui._signal_strength(True, False) == "partial"
    assert tui._signal_strength(False, False) == "none"


def test_status_glyph_and_bar_fill() -> None:
    assert tui._status_glyph("pass", unicode_icons=True) == "✓"
    assert tui._status_glyph("pass", unicode_icons=False) == "+"
    assert tui._status_glyph("unknown-name", unicode_icons=False) == "."
    assert tui._bar_fill(0, 0, 10, unicode_icons=True) == ""
    assert tui._bar_fill(5, 10, 10, unicode_icons=False).count("#") == 5


def test_numbered_next_steps() -> None:
    out = tui._numbered_next_steps(["a", "a", "b", "c", "d"], "final", limit=4)
    assert out == ["a", "b", "c", "final"]
    assert tui._numbered_next_steps([], "only", limit=4) == ["only"]


def test_primary_panel_width_and_section_heading() -> None:
    assert tui.primary_panel_width(120) > 0
    c, buf = _console(100)
    tui._section_heading(c, "Section", width=100)
    assert "Section" in buf.getvalue()


# --------------------------------------------------------------------------- #
# Executive preface + interactive summary
# --------------------------------------------------------------------------- #


def test_executive_preface_wide() -> None:
    c, buf = _console(100)
    tui.print_evaluate_executive_preface(_report(), unicode_icons=True, console=c)
    out = buf.getvalue()
    assert "OSS Policy Evaluation" in out
    assert "Health" in out  # health strip rendered at width 100


def test_executive_preface_advisory_banner() -> None:
    c, buf = _console(100)
    tui.print_evaluate_executive_preface(_report("iac-cfn-baseline-1"), unicode_icons=True, console=c)
    assert "advisory profile" in buf.getvalue()


def test_executive_preface_no_score_narrow() -> None:
    c, buf = _console(50)  # below health-strip threshold (cw < 48 path)
    tui.print_evaluate_executive_preface(_report(with_score=False), unicode_icons=False, console=c)
    assert "OSS Policy Evaluation" in buf.getvalue()


def test_interactive_summary_full() -> None:
    c, buf = _console(100)
    tui.print_interactive_stdout_summary(
        _report(),
        gap_lines=["Fix CI-PIN-008", "Add SECURITY.md"],
        next_step="Re-run evaluate",
        console=c,
    )
    out = buf.getvalue()
    assert "OSS Policy Evaluation" in out
    assert "Triage" in out
    assert "Next actions" in out
    assert "Fail" in out and "Manual review" in out


def test_interactive_summary_advisory_and_no_triage() -> None:
    clean = ExecutionReport(
        schema_version="x", generated_at="t", kit_version="6.1.0", target_path="C:/r",
        profile_id="iac-cfn-baseline-1", profile_title="T",
        summary_by_status={"pass": 1}, results=[], operational_warnings=[],
    )
    c, buf = _console(100)
    tui.print_interactive_stdout_summary(clean, gap_lines=[], next_step="", console=c)
    out = buf.getvalue()
    assert "advisory profile" in out
    assert "Triage" not in out  # no fails/mrr/highlights


def test_truncate_reason() -> None:
    assert tui._truncate_reason("short", 100) == "short"
    long = "x" * 200
    assert tui._truncate_reason(long, 60).endswith("...")


# --------------------------------------------------------------------------- #
# recommend-profile layout
# --------------------------------------------------------------------------- #


def _rec(**over: object) -> SimpleNamespace:
    base = {
        "signals_detected": [
            {"id": "github_actions_workflows", "detail": "12 workflows"},
            {"id": "github_evidence_json_files", "detail": "evidence present"},
        ],
        "suggestions": [
            {"profile_id": "github-level-1", "rationale": "Start here for GitHub repos."},
            {"profile_id": "github-level-2", "rationale": "Next step."},
        ],
        "notes": ["Heuristic only.", "Re-run after adding evidence."],
    }
    base.update(over)
    return SimpleNamespace(**base)


def test_recommend_profile_rich_full(tmp_path: Path) -> None:
    c, buf = _console(100)
    tui.print_recommend_profile_human_rich(_rec(), repo_root=tmp_path, console=c)
    out = buf.getvalue()
    assert "Decision" in out
    assert "Recommended now" in out
    assert "Repository signals" in out
    assert "Observed signals" in out
    assert "Notes" in out


def test_recommend_profile_rich_no_suggestions(tmp_path: Path) -> None:
    c, buf = _console(100)
    tui.print_recommend_profile_human_rich(_rec(suggestions=[], signals_detected=[], notes=[]),
                                           repo_root=tmp_path, console=c)
    assert "Decision" in buf.getvalue()


def test_recommend_profile_rich_compact(tmp_path: Path) -> None:
    c, buf = _console(60)  # compact path (< 72)
    tui.print_recommend_profile_human_rich(_rec(), repo_root=tmp_path, console=c)
    assert "Decision" in buf.getvalue()


def test_compute_rec_signals_and_context() -> None:
    sig = tui._compute_rec_signals(_rec(), unicode_icons=False)
    assert sig.gh_sig and sig.gh_ev and sig.rel_label == "strong"
    assert tui._recommend_context_line(sig).startswith("Primary context: GitHub")
    # Azure-only context.
    az = tui._compute_rec_signals(_rec(signals_detected=[{"id": "azure_pipelines_yaml"}]), unicode_icons=False)
    assert "Azure" in tui._recommend_context_line(az)
    # Mixed.
    mixed = tui._compute_rec_signals(
        _rec(signals_detected=[{"id": "github_actions_workflows"}, {"id": "azure_pipelines_yaml"}]),
        unicode_icons=False,
    )
    assert "Mixed CI" in tui._recommend_context_line(mixed)
    # No CI definitions.
    none = tui._compute_rec_signals(_rec(signals_detected=[]), unicode_icons=False)
    assert "conservative" in tui._recommend_context_line(none)


def test_build_recommend_scope_compact_vs_wide() -> None:
    sig = tui._compute_rec_signals(_rec(), unicode_icons=False)
    wide = tui._build_recommend_scope(sig, compact=False)
    compact = tui._build_recommend_scope(sig, compact=True)
    assert "Signal board" in wide.plain
    assert "Signal board" not in compact.plain


# --------------------------------------------------------------------------- #
# Banners
# --------------------------------------------------------------------------- #


def test_cli_banner_plain() -> None:
    assert isinstance(tui.cli_banner_plain(), str) and tui.cli_banner_plain()


def test_write_cli_banner_to_formatter(monkeypatch) -> None:
    monkeypatch.setattr(tui, "should_show_cli_banner", lambda **_k: True)
    written: list[str] = []
    fmt = SimpleNamespace(
        write_paragraph=lambda: written.append("\n"),
        write_text=lambda t: written.append(t),
    )
    tui.write_cli_banner_to_formatter(fmt)
    assert written  # banner lines written


def test_write_cli_banner_to_formatter_suppressed(monkeypatch) -> None:
    monkeypatch.setattr(tui, "should_show_cli_banner", lambda **_k: False)
    fmt = SimpleNamespace(write_paragraph=lambda: None, write_text=lambda _t: None)
    tui.write_cli_banner_to_formatter(fmt)  # returns early, no error


def test_should_show_cli_banner_explicit_stream() -> None:
    class _NotTTY:
        encoding = "utf-8"

        def isatty(self) -> bool:
            return False

    assert tui.should_show_cli_banner(stream=_NotTTY()) is False


def test_print_cli_banner_before_typer_rich_help(monkeypatch) -> None:
    monkeypatch.setattr(tui, "should_show_cli_banner", lambda **_k: False)
    tui.print_cli_banner_before_typer_rich_help()  # returns early, no error
    monkeypatch.setattr(tui, "should_show_cli_banner", lambda **_k: True)
    tui.print_cli_banner_before_typer_rich_help()  # prints via typer rich console


# --------------------------------------------------------------------------- #
# build_console / stream helpers / text helpers
# --------------------------------------------------------------------------- #


def test_build_console_no_color_env() -> None:
    buf = StringIO()
    c = tui.build_console(file=buf, width=100, _environ={"NO_COLOR": "1", "TERM": "dumb"})
    assert c.width >= 80


def test_build_console_derives_width() -> None:
    buf = StringIO()
    c = tui.build_console(file=buf, _environ={})
    assert c.width >= 1


def test_build_stdout_and_stderr_console() -> None:
    assert tui.build_stdout_console(width=90).width >= 80
    assert tui.build_stderr_console(width=70).width >= 40


def test_stream_supports_unicode_no_encoding() -> None:
    class _S:
        encoding = None

    assert tui.stream_supports_unicode(_S()) is True


def test_sanitize_cli_display_text() -> None:
    assert tui.sanitize_cli_display_text("a—b… → c") == "a-b... -> c"
    assert tui.sanitize_cli_display_text("") == ""


def test_human_fill_and_wrap() -> None:
    out = tui.human_fill("word " * 50, stream=StringIO(), fallback_width=40)
    assert "\n" in out
    lines = tui.human_wrap_lines("word " * 50, stream=StringIO(), fallback_width=40)
    assert isinstance(lines, str)


def test_max_gap_line_chars_and_layout() -> None:
    assert tui.max_gap_line_chars(stream=StringIO(), cap=120) > 0
    layout = tui.profile_table_layout_for_width(terminal_columns=120, detailed=True, longest_profile_id_chars=24)
    assert layout
    layout2 = tui.profile_table_layout_for_width(terminal_columns=60, detailed=False, longest_profile_id_chars=18)
    assert layout2


def test_render_eval_results_table_unicode() -> None:
    table = tui.render_eval_results_table(_report(), unicode_icons=True)
    assert table.columns


# --------------------------------------------------------------------------- #
# print_profiles_catalog_panel
# --------------------------------------------------------------------------- #


def _prow(platform: str, pid: str, *, legacy: bool = False) -> SimpleNamespace:
    return SimpleNamespace(platform=platform, profile_id=pid, level="L1", summary="s", is_legacy_alias=legacy)


def test_print_profiles_catalog_panel_wide() -> None:
    c, buf = _console(100)
    rows = [_prow("GitHub", "github-level-1"), _prow("Azure", "azure-level-1"), _prow("AWS", "aws-level-1")]
    tui.print_profiles_catalog_panel(rows, console=c, subtitle="bundled")
    out = buf.getvalue()
    assert "Bundled profiles" in out and "github-level-1" in out


def test_print_profiles_catalog_panel_narrow_and_legacy() -> None:
    c, buf = _console(60)
    rows = [_prow("GitHub", "github-release-hardening", legacy=True)]
    tui.print_profiles_catalog_panel(rows, console=c)
    assert "Bundled profiles" in buf.getvalue()


def test_print_profiles_catalog_panel_empty() -> None:
    c, buf = _console(100)
    tui.print_profiles_catalog_panel([], console=c)
    assert buf.getvalue() == ""  # no chunks -> early return, nothing printed
