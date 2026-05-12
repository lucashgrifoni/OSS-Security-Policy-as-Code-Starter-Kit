"""Central terminal width and Rich console helpers for human-facing CLI output.

All human-readable Rich rendering and width-sensitive formatting in this package
should derive effective width from here so behavior stays consistent under TTY,
redirection, ``CliRunner``, and subprocess capture.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from oss_policy_kit.application.loader import PROFILE_DIRECTORY_ALIASES

if TYPE_CHECKING:
    from oss_policy_kit.domain.models import ExecutionReport

# When ``stdout``/``stderr`` is not a TTY (pipes, tests, CI), use a stable width so
# layout and snapshots stay deterministic.
DEFAULT_FALLBACK_COLUMNS = 120
TTY_MIN_COLUMNS = 20
MAX_COLUMNS = 512
# Rich borders/separators for the six-column profiles table (conservative).
PROFILE_TABLE_OVERHEAD_COLUMNS = 21
_PROFILE_PLATFORM_COL_WIDTH = 8
_PROFILE_LEVEL_COL_WIDTH = 5
_PROFILE_GATE_COL_WIDTH = 14
_PROFILE_COL_MIN_PROFILE = 12
_PROFILE_COL_MIN_TITLE = 8
_PROFILE_COL_MIN_AUDIENCE = 8
_PROFILE_COL_MIN_DESCRIPTION = 8
_UNICODE_STATUS_SAMPLE = "✓✗—"

# Human TTY visual language (single palette; avoid competing decoration styles).
STYLE_BORDER_PRIMARY = "cyan"
STYLE_BORDER_SOFT = "dim"
STYLE_SECTION_TITLE = "bold cyan"
STYLE_EMPHASIS = "cyan"
STYLE_MUTED = "dim"
STYLE_OK = "green"
STYLE_WARN = "yellow"
STYLE_ERR = "red"
# Primary Rich panels: cap width so ultra-wide terminals do not stretch content edge-to-edge.
CLI_PRIMARY_PANEL_MAX_WIDTH = 70


def primary_panel_width(terminal_columns: int) -> int:
    """Comfortable max width for main CLI panels (composition over full-width stretch)."""

    return max(42, min(CLI_PRIMARY_PANEL_MAX_WIDTH, max(TTY_MIN_COLUMNS, terminal_columns)))


def _section_heading(c: Console, label: str, *, width: int) -> None:
    """Short section separator (avoids full-terminal Rich rules)."""

    span = primary_panel_width(width)
    c.print(Align(Text(label, style="bold dim"), align="left", width=span))
    c.print(Text("─" * min(span, 52), style="dim"))


_PROFILE_JOURNEY_ORDER: dict[str, list[str]] = {
    "github": [
        "github-level-1",
        "github-release-hardening-1",
        "github-level-2",
        "github-release-hardening-2",
        "github-level-3",
        "github-release-hardening-3",
    ],
    "azure": [
        "azure-level-1",
        "azure-release-hardening-1",
        "azure-level-2",
        "azure-release-hardening-2",
        "azure-level-3",
        "azure-release-hardening-3",
    ],
    "aws": [
        "aws-level-1",
        "aws-release-hardening-1",
        "aws-level-2",
        "aws-release-hardening-2",
        "aws-level-3",
        "aws-release-hardening-3",
    ],
}


def _profile_platform_key(profile_id: str) -> str | None:
    if profile_id.startswith("github-"):
        return "github"
    if profile_id.startswith("azure-"):
        return "azure"
    if profile_id.startswith("aws-"):
        return "aws"
    return None


def _forward_journey_ids(now_id: str, candidate_ids: set[str]) -> list[str]:
    """Return up to three profile IDs along the bundled maturity path, never stepping backward."""

    pk = _profile_platform_key(now_id)
    if pk is None:
        return [now_id] if now_id in candidate_ids else []
    order = _PROFILE_JOURNEY_ORDER.get(pk, [])
    if not order or now_id not in order:
        return [x for x in candidate_ids if _profile_platform_key(x) == pk][:3] or [now_id]
    start = order.index(now_id)
    out: list[str] = []
    for pid in order[start:]:
        if pid in candidate_ids:
            out.append(pid)
        if len(out) >= 3:
            break
    return out if out else [now_id]


def is_interactive_stream(stream: Any) -> bool:
    """Return True when ``stream`` looks like an interactive terminal."""

    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def _get_terminal_size(*, fallback: tuple[int, int]) -> os.terminal_size:
    """Delegate to :func:`shutil.get_terminal_size` without binding tests to global ``shutil``."""

    return shutil.get_terminal_size(fallback=fallback)


def terminal_width(stream: Any, *, fallback: int = DEFAULT_FALLBACK_COLUMNS) -> int:
    """Effective column width for layout when rendering to ``stream``.

    Uses the OS terminal size when ``stream`` is a TTY; otherwise returns ``fallback``.
    """

    if not is_interactive_stream(stream):
        return fallback
    try:
        cols = _get_terminal_size(fallback=(fallback, 24)).columns
    except OSError:
        return fallback
    if cols < 1:
        return fallback
    return max(TTY_MIN_COLUMNS, min(cols, MAX_COLUMNS))


def _enriched_columns_env(width: int) -> dict[str, str]:
    """Environment Rich consults so ``Console.width`` matches our layout width."""

    enriched = dict(os.environ)
    enriched["COLUMNS"] = str(width)
    enriched.setdefault("LINES", "40")
    return enriched


def build_console(
    *,
    file: TextIO | None = None,
    stderr: bool = False,
    width: int | None = None,
    _environ: dict[str, str] | None = None,
) -> Console:
    """Build a Rich :class:`~rich.console.Console` for human output.

    When ``width`` is omitted, it is derived from ``terminal_width`` on the target stream
    (``sys.stderr`` if ``stderr=True``, else ``sys.stdout``). ``_environ`` carries a
    matching ``COLUMNS`` so nested Rich layout matches even when the shell exports a
    different ``COLUMNS`` (common on Windows and in CI).

    Respects ``NO_COLOR`` (https://no-color.org/) and ``TERM=dumb``. Color is disabled when
    the target stream is not a TTY (pipes, redirects) so escape codes do not pollute logs.
    """

    target: TextIO = file if file is not None else (sys.stderr if stderr else sys.stdout)
    base_env = _environ if _environ is not None else os.environ
    no_color = "NO_COLOR" in base_env or base_env.get("TERM", "").lower() == "dumb"
    try:
        is_tty = bool(target.isatty())
    except (AttributeError, OSError):
        is_tty = False
    w = terminal_width(target) if width is None else width
    w = max(TTY_MIN_COLUMNS, min(w, MAX_COLUMNS))
    merged_env = dict(_enriched_columns_env(w))
    for k, v in base_env.items():
        if k not in merged_env:
            merged_env[k] = v
    force_color = is_tty and not no_color
    return Console(
        file=target,
        width=w,
        force_terminal=force_color,
        no_color=no_color or not is_tty,
        _environ=merged_env,
    )


def build_stdout_console(*, width: int | None = None) -> Console:
    """Rich console bound to ``sys.stdout`` for tables and other stdout human output."""

    return build_console(file=sys.stdout, width=width)


def stream_supports_unicode(stream: Any) -> bool:
    """Return True when ``stream`` can encode the status glyphs used in Rich tables."""

    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return True
    try:
        _UNICODE_STATUS_SAMPLE.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def render_eval_results_table(report: ExecutionReport, *, unicode_icons: bool = True) -> Table:
    """Build a Rich :class:`~rich.table.Table` summarizing all control results for stdout display.

    One row per evaluated control, colored by status (pass / self-attested green, fail red,
    not-applicable dim, manual-review-required yellow, waived cyan, others neutral).
    """

    status_colors: dict[str, str] = {
        "pass": "green",
        "self-attested": "green",
        "fail": "red",
        "not-applicable": "dim",
        "not-evaluated": "yellow",
        "not-observable": "dim",
        "manual-review-required": "yellow",
        "waived": "cyan",
    }
    status_icons: dict[str, str]
    if unicode_icons:
        status_icons = {
            "pass": "✓",
            "self-attested": "✓",
            "fail": "✗",
            "not-applicable": "—",
            "not-evaluated": "?",
            "not-observable": "—",
            "manual-review-required": "!",
            "waived": "W",
        }
    else:
        status_icons = {
            "pass": "+",
            "self-attested": "+",
            "fail": "x",
            "not-applicable": "-",
            "not-evaluated": "?",
            "not-observable": "-",
            "manual-review-required": "!",
            "waived": "W",
        }
    target_name = Path(report.target_path).name
    table = Table(
        title=f"[bold cyan]Profile: {report.profile_id}[/bold cyan]  [dim]|[/dim]  Target: [dim]{target_name}[/dim]",
        show_lines=False,
        expand=False,
    )
    table.add_column("ID", style="cyan", no_wrap=True, min_width=14)
    table.add_column("Status", no_wrap=True, min_width=18)
    table.add_column("Confidence", no_wrap=True, min_width=10)
    table.add_column("Reason", overflow="fold", max_width=70)

    for result in report.results:
        status = str(result.status.value)
        color = status_colors.get(status, "white")
        icon = status_icons.get(status, " ")
        reason = result.reason or ""
        if len(reason) > 90:
            reason = reason[:87] + "..."
        table.add_row(
            result.control_id,
            f"[{color}]{icon} {status}[/{color}]",
            result.confidence or "",
            reason,
        )
    return table


def build_stderr_console(*, width: int | None = None) -> Console:
    """Rich console bound to ``sys.stderr`` for errors, warnings, and status lines."""

    return build_console(file=sys.stderr, width=width)


def human_fill(
    text: str,
    *,
    stream: Any,
    fallback_width: int = DEFAULT_FALLBACK_COLUMNS,
    subtract: int = 0,
) -> str:
    """Wrap ``text`` to fit ``terminal_width(stream)`` minus ``subtract`` (indent margins)."""

    w = max(TTY_MIN_COLUMNS, terminal_width(stream, fallback=fallback_width) - max(0, subtract))
    return textwrap.fill(
        " ".join(text.split()),
        width=w,
        break_long_words=True,
        break_on_hyphens=False,
    )


def human_wrap_lines(
    text: str,
    *,
    stream: Any,
    fallback_width: int = DEFAULT_FALLBACK_COLUMNS,
    subtract: int = 0,
) -> str:
    """Like :func:`human_fill` but preserves intentional newlines between paragraphs."""

    w = max(TTY_MIN_COLUMNS, terminal_width(stream, fallback=fallback_width) - max(0, subtract))
    blocks: list[str] = []
    for para in text.split("\n"):
        p = para.strip()
        if not p:
            blocks.append("")
            continue
        blocks.append(
            textwrap.fill(
                p,
                width=w,
                break_long_words=True,
                break_on_hyphens=False,
            )
        )
    return "\n".join(blocks)


@dataclass(frozen=True, slots=True)
class ProfileTableLayout:
    """Max column widths for the bundled profiles Rich table."""

    profile: int
    title: int
    platform: int
    level: int
    gate: int
    audience: int
    description: int


def profile_table_layout_for_width(
    *,
    terminal_columns: int,
    detailed: bool,
    longest_profile_id_chars: int,
) -> ProfileTableLayout:
    """Split usable width between fixed-ish and flexible profile table columns."""

    tc = max(40, min(terminal_columns, MAX_COLUMNS))
    usable = max(40, tc - PROFILE_TABLE_OVERHEAD_COLUMNS)
    platform_w = _PROFILE_PLATFORM_COL_WIDTH
    level_w = _PROFILE_LEVEL_COL_WIDTH
    gate_w = _PROFILE_GATE_COL_WIDTH

    min_flex = _PROFILE_COL_MIN_TITLE + _PROFILE_COL_MIN_AUDIENCE + _PROFILE_COL_MIN_DESCRIPTION
    max_profile = usable - platform_w - level_w - gate_w - min_flex
    ideal_profile = max(_PROFILE_COL_MIN_PROFILE, min(36, longest_profile_id_chars + 1))
    profile_w = min(ideal_profile, max(_PROFILE_COL_MIN_PROFILE, max_profile))
    flex = usable - profile_w - platform_w - level_w - gate_w
    flex = max(min_flex, flex)

    if detailed:
        title_pct, aud_pct, desc_pct = 22, 28, 50
    else:
        # Non-detailed layout reserves extra slack for the Audience column so that
        # single-word labels like "Maintainers" do not wrap mid-word once the new
        # fixed "Recommended gate" column is rendered.
        title_pct, aud_pct, desc_pct = 22, 42, 36
    denom = title_pct + aud_pct + desc_pct

    title_w = max(_PROFILE_COL_MIN_TITLE, (flex * title_pct) // denom)
    aud_w = max(_PROFILE_COL_MIN_AUDIENCE, (flex * aud_pct) // denom)
    desc_w = flex - title_w - aud_w
    if desc_w < _PROFILE_COL_MIN_DESCRIPTION:
        deficit = _PROFILE_COL_MIN_DESCRIPTION - desc_w
        shave = min(deficit, max(0, aud_w - _PROFILE_COL_MIN_AUDIENCE))
        aud_w -= shave
        deficit -= shave
        if deficit > 0:
            title_w = max(_PROFILE_COL_MIN_TITLE, title_w - deficit)
        desc_w = flex - title_w - aud_w

    remainder = usable - (profile_w + title_w + platform_w + level_w + gate_w + aud_w + desc_w)
    if remainder > 0:
        desc_w += remainder
    elif remainder < 0:
        need = -remainder
        take = min(need, max(0, desc_w - _PROFILE_COL_MIN_DESCRIPTION))
        desc_w -= take
        need -= take
        if need > 0:
            take_a = min(need, max(0, aud_w - _PROFILE_COL_MIN_AUDIENCE))
            aud_w -= take_a
            need -= take_a
        if need > 0:
            title_w = max(_PROFILE_COL_MIN_TITLE, title_w - need)

    return ProfileTableLayout(
        profile=profile_w,
        title=title_w,
        platform=platform_w,
        level=level_w,
        gate=gate_w,
        audience=aud_w,
        description=desc_w,
    )


def max_gap_line_chars(*, stream: Any = None, cap: int = 200, fallback_width: int = DEFAULT_FALLBACK_COLUMNS) -> int:
    """Max characters for a single-line primary gap hint in human summaries."""

    s = sys.stdout if stream is None else stream
    base = max(60, terminal_width(s, fallback=fallback_width) - 8)
    return min(cap, base)


CLI_BANNER_MIN_COLUMNS = 52
_CLI_BANNER_FULL = """       /\\
      /  \\      OSS Policy Kit
     /_/\\_\\     clone-visible security posture
     \\ \\/ /     GitHub | Azure | AWS
      \\  /
       \\/

  Evaluate governance, CI hygiene, and release evidence"""


def sanitize_cli_display_text(text: str) -> str:
    """Replace common Unicode punctuation with ASCII so Windows/consoles legacy stay readable."""

    if not text:
        return text
    return (
        text.replace("\u2014", "-")  # em dash
        .replace("\u2013", "-")  # en dash
        .replace("\u2026", "...")  # ellipsis
        .replace("\u2192", "->")  # arrow
    )


def human_tty_stdout() -> bool:
    """True when stdout is an interactive TTY (human Rich layers may render)."""

    return is_interactive_stream(sys.stdout)


def should_show_cli_banner(*, stream: Any | None = None) -> bool:
    """Whether to prepend the branded ASCII banner (help, demos).

    When *stream* is omitted, accept either stdout or stderr as interactive: Typer/Click
    renders ``--help`` to stderr on many platforms while stdout may still be a TTY in
    PowerShell and other consoles.
    """

    if stream is not None:
        if not is_interactive_stream(stream):
            return False
        return terminal_width(stream) >= CLI_BANNER_MIN_COLUMNS
    streams = [s for s in (sys.stdout, sys.stderr) if is_interactive_stream(s)]
    if not streams:
        return False
    return max(terminal_width(s) for s in streams) >= CLI_BANNER_MIN_COLUMNS


def cli_banner_plain() -> str:
    """ASCII banner and tagline for Click help formatters (no Rich markup)."""

    return _CLI_BANNER_FULL


def write_cli_banner_to_formatter(formatter: Any) -> None:
    """Prepend the kit banner to a Click ``HelpFormatter`` (plain text, no ANSI)."""

    if not should_show_cli_banner():
        return
    formatter.write_paragraph()
    for raw_line in _CLI_BANNER_FULL.splitlines():
        line = raw_line.rstrip("\n")
        formatter.write_text(f"{line}\n")
    formatter.write_paragraph()


def print_cli_banner_before_typer_rich_help() -> None:
    """Emit the ASCII banner on Typer's Rich help console (stdout) when TTY/width gates pass.

    Typer's Rich help path does not use a Click ``HelpFormatter``; it prints via
    ``typer.rich_utils.rich_format_help``. This helper uses the same Rich console Typer
    uses so the banner appears immediately above the styled help.
    """

    if not should_show_cli_banner():
        return
    try:
        from typer import rich_utils as typer_rich_utils
    except ImportError:
        return
    console = typer_rich_utils._get_rich_console(stderr=False)
    for raw_line in cli_banner_plain().splitlines():
        console.print(raw_line, highlight=False, markup=False, emoji=False)
    console.print()


def _status_glyph(name: str, *, unicode_icons: bool) -> str:
    icons_u = {"pass": "✓", "fail": "✗", "manual-review-required": "!", "other": "·"}
    icons_a = {"pass": "+", "fail": "x", "manual-review-required": "!", "other": "."}
    m = icons_u if unicode_icons else icons_a
    return m.get(name, m["other"])


def _bar_fill(done: int, total: int, width: int, *, unicode_icons: bool) -> str:
    if total <= 0 or width <= 0:
        return ""
    filled = min(width, max(0, round(width * done / total)))
    empty = width - filled
    full_c, empty_c = ("█", "░") if unicode_icons else ("#", ".")
    return full_c * filled + empty_c * empty


def _print_health_strip(
    c: Console,
    *,
    pass_n: int,
    fail_n: int,
    manual_n: int,
    unicode_icons: bool,
    w: int,
) -> None:
    """Single-line status bars (compact; avoids stacking three rows)."""

    cw = primary_panel_width(w)
    if cw < 48:
        return
    total_vis = max(1, pass_n + fail_n + manual_n)
    bar_w = min(12, max(5, cw // 12))
    hp = _bar_fill(pass_n, total_vis, bar_w, unicode_icons=unicode_icons)
    hf = _bar_fill(fail_n, total_vis, bar_w, unicode_icons=unicode_icons)
    hm = _bar_fill(manual_n, total_vis, bar_w, unicode_icons=unicode_icons)
    gp = _status_glyph("pass", unicode_icons=unicode_icons)
    gf = _status_glyph("fail", unicode_icons=unicode_icons)
    gm = _status_glyph("manual-review-required", unicode_icons=unicode_icons)
    line = Text()
    line.append("Health  ", style=STYLE_MUTED)
    line.append(f"{gp} ", style=STYLE_OK)
    line.append(hp + f" {pass_n}", style=STYLE_OK)
    line.append("   ")
    line.append(f"{gf} ", style=STYLE_ERR)
    line.append(hf + f" {fail_n}", style=STYLE_ERR)
    line.append("   ")
    line.append(f"{gm} ", style=STYLE_WARN)
    line.append(hm + f" {manual_n}", style=STYLE_WARN)
    c.print(line)


#: Profiles that are advisory-only by design. They surface posture but must
#: not be wired as release gates. The banner below makes that constraint
#: visible at the top of every interactive evaluate run.
_ADVISORY_ONLY_PROFILE_IDS: frozenset[str] = frozenset(
    {
        "container-baseline-1",
        "cra-eu-ready-1",
        "github-aws-level-2",
        "github-azure-level-2",
        "iac-bicep-baseline-1",
        "iac-cfn-baseline-1",
        "iac-pulumi-baseline-1",
        "iac-terraform-baseline-1",
        "kubernetes-baseline-1",
        "webhook-security-1",
    }
)


def _print_advisory_profile_banner(
    console: Console,
    *,
    profile_id: str,
    width: int,
) -> None:
    """Print a yellow banner above the executive panel for advisory-only profiles."""

    pw = primary_panel_width(width)
    msg = Text()
    msg.append("[advisory profile] ", style="bold yellow")
    msg.append(
        "This profile is advisory-only by design. Do not use as a release gate. "
        "Recommended --fail-on degraded; --fail-on fail defeats the design.",
        style="yellow",
    )
    panel = Panel(
        msg,
        border_style="yellow",
        box=box.ROUNDED,
        width=pw,
    )
    console.print(Align(panel, align="left"))


def print_evaluate_executive_preface(
    report: ExecutionReport,
    *,
    unicode_icons: bool,
    console: Console | None = None,
) -> None:
    """Optional executive strip before the per-control table (interactive human runs only)."""

    c = console or build_stdout_console()
    w = c.width
    if report.profile_id in _ADVISORY_ONLY_PROFILE_IDS:
        _print_advisory_profile_banner(c, profile_id=report.profile_id, width=w)
    target_name = Path(report.target_path).name
    summary = report.summary_by_status
    pass_n = int(summary.get("pass", 0)) + int(summary.get("self-attested", 0))
    fail_n = int(summary.get("fail", 0))
    manual_n = int(summary.get("manual-review-required", 0))
    blockers = fail_n + manual_n
    status_word = "healthy"
    if fail_n:
        status_word = "degraded"
    elif manual_n:
        status_word = "attention"
    score_txt = "—" if stream_supports_unicode(sys.stdout) else "-"
    if report.weighted_score is not None:
        ws = report.weighted_score
        score_txt = f"{ws.percent}% ({ws.earned}/{ws.possible})"
    inner = Text()
    inner.append(f"{target_name}\n", style="bold default")
    inner.append(f"{report.profile_id}\n", style=STYLE_EMPHASIS)
    inner.append(f"{pass_n} pass  ·  {fail_n} fail  ·  {manual_n} manual\n", style="default")
    inner.append(f"Score  {score_txt}\n", style=STYLE_MUTED)
    inner.append(f"Overall  {status_word}", style="default")
    if blockers:
        inner.append(f"  ·  {blockers} blocker(s)", style=STYLE_WARN)
    inner.append("\n", style="default")
    pw = primary_panel_width(w)
    panel = Panel(
        inner,
        title=Text("OSS Policy Evaluation", style="bold cyan"),
        border_style=STYLE_BORDER_PRIMARY,
        box=box.ROUNDED,
        width=pw,
    )
    c.print(Align(panel, align="left"))
    _print_health_strip(
        c,
        pass_n=pass_n,
        fail_n=fail_n,
        manual_n=manual_n,
        unicode_icons=unicode_icons,
        w=w,
    )


def print_interactive_stdout_summary(
    report: Any,
    *,
    gap_lines: list[str],
    next_step: str,
    console: Console | None = None,
) -> None:
    """Rich evaluation summary for interactive ``--summary-only`` / human stdout (TTY only)."""

    from oss_policy_kit.domain.models import ControlStatus

    c = console or build_stdout_console()
    unicode_icons = stream_supports_unicode(sys.stdout)
    w = c.width
    if getattr(report, "profile_id", None) in _ADVISORY_ONLY_PROFILE_IDS:
        _print_advisory_profile_banner(c, profile_id=report.profile_id, width=w)
    target_name = Path(report.target_path).name
    ordered_summary = {k: report.summary_by_status[k] for k in report.summary_by_status}
    pass_n = int(ordered_summary.get("pass", 0)) + int(ordered_summary.get("self-attested", 0))
    fail_n = int(ordered_summary.get("fail", 0))
    manual_n = int(ordered_summary.get("manual-review-required", 0))
    blockers = fail_n + manual_n

    status_word = "healthy"
    if fail_n:
        status_word = "degraded"
    elif manual_n:
        status_word = "attention"

    score_line = ""
    if report.weighted_score is not None:
        ws = report.weighted_score
        score_line = f"{ws.percent}% ({ws.earned}/{ws.possible})"
    inner = Text()
    inner.append(f"{target_name}\n", style="bold default")
    inner.append(f"{report.profile_id}\n", style=STYLE_EMPHASIS)
    inner.append(f"{pass_n} pass  ·  {fail_n} fail  ·  {manual_n} manual\n", style="default")
    if score_line:
        inner.append(f"Score  {score_line}\n", style=STYLE_MUTED)
    inner.append(f"Overall  {status_word}", style="default")
    inner.append(f"  ·  priority gaps surfaced: {len(gap_lines)}", style=STYLE_MUTED)
    if blockers:
        inner.append(f"  ·  blockers: {blockers}", style=STYLE_WARN)
    inner.append("\n", style="default")
    pw = primary_panel_width(w)
    panel = Panel(
        inner,
        title=Text("OSS Policy Evaluation", style="bold cyan"),
        border_style=STYLE_BORDER_PRIMARY,
        box=box.ROUNDED,
        width=pw,
    )
    c.print(Align(panel, align="left"))

    _print_health_strip(
        c,
        pass_n=pass_n,
        fail_n=fail_n,
        manual_n=manual_n,
        unicode_icons=unicode_icons,
        w=w,
    )

    fails = [r for r in report.results if r.status == ControlStatus.FAIL]
    mrr = [r for r in report.results if r.status == ControlStatus.MANUAL_REVIEW_REQUIRED]
    healthy_candidates = [
        r for r in report.results if r.status == ControlStatus.PASS and str(r.control_id).startswith("GOV-")
    ][:5]

    body = Text()
    show_triage = bool(fails or mrr or healthy_candidates)
    if fails:
        body.append("Fail\n", style=f"bold {STYLE_ERR}")
        for r in fails[:4]:
            reason = (r.reason or r.control_id).strip().replace("\n", " ")
            if len(reason) > max(40, w - 10):
                reason = reason[: max(36, w - 14)].rstrip() + "..."
            body.append(f"  {_status_glyph('fail', unicode_icons=unicode_icons)} {reason}\n", style=STYLE_ERR)
    if mrr:
        body.append("Manual review\n", style=f"bold {STYLE_WARN}")
        for r in mrr[:4]:
            reason = (r.reason or r.control_id).strip().replace("\n", " ")
            if len(reason) > max(40, w - 10):
                reason = reason[: max(36, w - 14)].rstrip() + "..."
            body.append(
                f"  {_status_glyph('manual-review-required', unicode_icons=unicode_icons)} {reason}\n",
                style=STYLE_WARN,
            )
    if healthy_candidates:
        body.append("Highlights\n", style=f"bold {STYLE_OK}")
        for r in healthy_candidates[:3]:
            hint = (r.title or r.control_id).strip()
            if len(hint) > max(36, w - 12):
                hint = hint[: max(32, w - 16)].rstrip() + "..."
            body.append(f"  {_status_glyph('pass', unicode_icons=unicode_icons)} {hint}\n", style=STYLE_OK)

    if show_triage:
        _section_heading(c, "Triage", width=w)
        c.print(Align(body, align="left", width=primary_panel_width(w)))

    _section_heading(c, "Next actions", width=w)
    steps = _numbered_next_steps(gap_lines, next_step, limit=4)
    for i, step in enumerate(steps, start=1):
        wrapped_lines = human_wrap_lines(step, stream=sys.stdout, subtract=6).split("\n")
        for j, ln in enumerate(wrapped_lines):
            prefix = f"  {i}. " if j == 0 else "     "
            c.print(prefix + ln)


def _numbered_next_steps(gap_lines: list[str], next_step: str, *, limit: int) -> list[str]:
    steps: list[str] = []
    seen: set[str] = set()
    for g in gap_lines:
        t = g.strip()
        if t and t not in seen:
            steps.append(t)
            seen.add(t)
        if len(steps) >= max(1, limit - 1):
            break
    ns = next_step.strip()
    if ns and ns not in seen:
        steps.append(ns)
    return steps[:limit]


def _signal_ids(signals: list[dict[str, str]]) -> set[str]:
    return {str(s.get("id", "")) for s in signals}


def print_recommend_profile_human_rich(
    rec: Any,
    *,
    repo_root: Path,
    console: Console | None = None,
) -> None:
    """Rich layout for ``recommend-profile`` (TTY stdout only)."""

    c = console or build_stdout_console()
    unicode_icons = stream_supports_unicode(sys.stdout)
    w = c.width
    compact = w < 72
    chk = "✓" if unicode_icons else "+"
    dash = "—" if unicode_icons else "-"
    sig_ids = _signal_ids(list(rec.signals_detected))
    gh = chk if "github_actions_workflows" in sig_ids else dash
    az = chk if "azure_pipelines_yaml" in sig_ids else dash
    aws = chk if "aws_codebuild_buildspec" in sig_ids else dash

    def strength(_label: str, present: bool, evidence: bool) -> str:
        if evidence:
            return "strong"
        if present:
            return "partial"
        return "none"

    gh_sig = "github_actions_workflows" in sig_ids
    az_sig = "azure_pipelines_yaml" in sig_ids
    aws_sig = "aws_codebuild_buildspec" in sig_ids
    gh_ev = "github_evidence_json_files" in sig_ids
    az_ev = "azure_evidence_json_files" in sig_ids
    aws_ev = "aws_evidence_json_files" in sig_ids
    rel_partial = any(
        x in sig_ids
        for x in (
            "github_evidence_json_files",
            "azure_evidence_json_files",
            "aws_evidence_json_files",
            "evidence_dir_empty",
        )
    )

    suggestions: list[dict[str, Any]] = list(rec.suggestions)
    now_id = str(suggestions[0]["profile_id"]) if suggestions else ""
    cand_ids = {str(s["profile_id"]) for s in suggestions}
    journey_ids = _forward_journey_ids(now_id, cand_ids) if suggestions else []
    journey_next = journey_ids[1] if len(journey_ids) > 1 else None
    raw_second = str(suggestions[1]["profile_id"]) if len(suggestions) > 1 else None

    ci_definitions = gh_sig or az_sig or aws_sig
    if gh_ev or az_ev or aws_ev:
        rel_label = "strong"
    elif rel_partial or ci_definitions:
        rel_label = "partial"
    else:
        rel_label = "none"

    scope_lines = Text()
    scope_lines.append("Repository signals\n", style=f"bold {STYLE_EMPHASIS}")
    scope_lines.append(f"  .github/workflows      {gh}\n", style="default")
    scope_lines.append(f"  Azure pipeline YAML    {az}\n", style="default")
    scope_lines.append(f"  buildspec.yml          {aws}\n", style="default")
    if not compact:
        scope_lines.append("\nSignal board\n", style=f"bold {STYLE_EMPHASIS}")
        scope_lines.append(f"  GitHub workflows    {strength('gh', gh_sig, gh_ev)}\n", style="default")
        scope_lines.append(f"  Azure pipelines     {strength('az', az_sig, az_ev)}\n", style="default")
        scope_lines.append(f"  AWS buildspec       {strength('aws', aws_sig, aws_ev)}\n", style="default")
        scope_lines.append(f"  Release evidence    {rel_label}\n", style="default")
        if rel_label == "partial" and ci_definitions and not (gh_ev or az_ev or aws_ev):
            scope_lines.append(
                "  (partial: CI definitions visible; add .oss-policy-kit/evidence JSON for strong.)\n",
                style=STYLE_MUTED,
            )

    ctx_line = ""
    if gh_sig and not az_sig and not aws_sig:
        ctx_line = "Primary context: GitHub Actions material visible in this clone."
    elif az_sig and not gh_sig and not aws_sig:
        ctx_line = "Primary context: Azure Pipelines material visible in this clone."
    elif aws_sig and not gh_sig and not az_sig:
        ctx_line = "Primary context: AWS CodeBuild/buildspec material visible in this clone."
    elif sum(bool(x) for x in (gh_sig, az_sig, aws_sig)) > 1:
        ctx_line = (
            "Mixed CI definitions in clone; ranking follows strongest platform evidence "
            "(see JSON notes when multiple platforms tie)."
        )
    elif not ci_definitions:
        ctx_line = "Limited CI definitions in clone; recommendation leans conservative."

    decision = Text()
    if suggestions:
        decision.append("Recommended now\n", style=f"bold {STYLE_OK}")
        decision.append(f"  {now_id}\n\n", style=f"{STYLE_OK}")
        if why := str(suggestions[0].get("rationale", "")).strip():
            decision.append("Why now\n", style=f"bold {STYLE_EMPHASIS}")
            for ln in human_wrap_lines(why, stream=sys.stdout, subtract=4).split("\n"):
                decision.append(f"  {ln}\n", style="default")
            decision.append("\n", style="default")
        if ctx_line:
            decision.append("Recommendation path\n", style=f"bold {STYLE_EMPHASIS}")
            decision.append(f"{ctx_line}\n\n", style=STYLE_MUTED)
        if journey_ids:
            decision.append("Suggested journey\n", style=f"bold {STYLE_EMPHASIS}")
            labels = ("Now", "Next", "Later")
            for i, jid in enumerate(journey_ids[:3]):
                decision.append(f"  [{labels[i]}]  {jid}\n", style="default")
            decision.append("\n", style="default")
        if raw_second and (journey_next is None or raw_second != journey_next):
            decision.append("Also consider\n", style=f"bold {STYLE_WARN}")
            decision.append(Text.from_markup(f"  {raw_second}  [dim](parallel heuristic pick)[/dim]\n\n"))

    main_body = Text.assemble(
        Text(f"{repo_root.resolve()}\n\n", style=STYLE_MUTED),
        scope_lines,
        Text("\n") if suggestions else Text(),
        decision,
        Text("\nHeuristic only - not a compliance decision.", style="italic dim"),
    )

    pw = primary_panel_width(w)
    c.print(
        Align(
            Panel(
                Align(main_body, align="left"),
                title=Text("Decision", style="bold cyan"),
                border_style=STYLE_BORDER_PRIMARY,
                box=box.ROUNDED,
                width=pw,
            ),
            align="left",
        )
    )

    if rec.signals_detected and not compact:
        _section_heading(c, "Observed signals", width=w)
        for sig in rec.signals_detected[:8]:
            sid = sig.get("id", "")
            detail = str(sig.get("detail", ""))
            c.print(Text(f"  {sid}", style=STYLE_EMPHASIS))
            for ln in human_wrap_lines(detail, stream=sys.stdout, subtract=6).split("\n"):
                c.print(Text(f"    {ln}", style=STYLE_MUTED))
        if len(rec.signals_detected) > 8:
            more = "…" if unicode_icons else "..."
            c.print(Text(f"  {more} {len(rec.signals_detected) - 8} more", style=STYLE_MUTED))

    if rec.notes:
        _section_heading(c, "Notes", width=w)
        for note in rec.notes:
            for ln in human_wrap_lines(str(note), stream=sys.stdout, subtract=4).split("\n"):
                c.print(Text(f"  {ln}", style=STYLE_MUTED))


def print_profiles_catalog_panel(
    rows: list[Any],
    *,
    console: Console | None = None,
    subtitle: str | None = None,
) -> None:
    """Single primary surface: bundled profiles grouped by platform (TTY human)."""

    c = console or build_stdout_console()
    w = c.width
    by_plat: dict[str, list[Any]] = {}
    for r in rows:
        by_plat.setdefault(r.platform, []).append(r)

    order = ("GitHub", "Azure", "AWS", "Custom")
    catalog_chunks: list[str] = []
    for plat in order:
        rs = by_plat.get(plat)
        if not rs:
            continue
        lines = [f"[bold]{plat}[/bold]"]
        for row in rs:
            pid = row.profile_id
            if getattr(row, "is_legacy_alias", False):
                canon = PROFILE_DIRECTORY_ALIASES.get(row.profile_id, row.profile_id)
                pid = f"{row.profile_id} [dim](legacy -> {canon})[/dim]"
            lines.append(f"  [cyan]{pid}[/cyan]  [dim]{row.level}[/dim]  [dim]{row.summary}[/dim]")
        catalog_chunks.append("\n".join(lines))
    if not catalog_chunks:
        return
    body = "\n\n".join(catalog_chunks) if w >= 80 else "\n".join(catalog_chunks)
    sub = Text(subtitle, style="dim") if subtitle else None
    pw = primary_panel_width(w)
    c.print(
        Align(
            Panel(
                Align(Text.from_markup(body), align="left"),
                title=Text("Bundled profiles", style="bold cyan"),
                subtitle=sub,
                border_style=STYLE_BORDER_PRIMARY,
                box=box.ROUNDED,
                width=pw,
            ),
            align="left",
        )
    )
