"""``oss-policy-kit osps-coverage`` subcommand (ADR-037).

Prints the kit's **advisory** coverage of the OpenSSF OSPS Baseline v2026.02.19:
honest per-level (L1/L2/L3) counts of criteria with at least one clone-visible
signal from a bundled ``osps-baseline-2026-1`` control, plus the real gaps. The
computation lives in :mod:`oss_policy_kit.application.osps_coverage` (the single
source of truth, shared with ``scripts/generate-osps-coverage.py``); this module
only shapes and renders it.

Read-only and informational. This is **not** a conformance certification: a kit
control provides a signal *toward* a criterion, never a guarantee of an OSPS
maturity level. The command does not change any ``evaluate`` verdict. The
Scorecard v6 ``--format=osps`` conformance *verdict* renderer is intentionally
deferred until that format reaches GA (see ADR-018 / ADR-037).
"""

from __future__ import annotations

import json

import typer

from oss_policy_kit.application.osps_coverage import OspsCoverage, load_osps_coverage
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_DISCOVER
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


def _render_human(cov: OspsCoverage) -> None:
    lines = [
        f"OSPS Baseline {cov.version} coverage (advisory; NOT a conformance certification)",
        f"  Profile:  {cov.profile}",
        f"  Snapshot: {cov.source_tag} (ossf/security-baseline, signed tag)",
        "",
        "Coverage by maturity level (criteria with >=1 clone-visible kit signal):",
    ]
    for lc in cov.levels:
        lines.append(f"  L{lc.level}   {lc.covered:>2} / {lc.total:<2}   ({lc.gaps} not yet expressed)")
    gaps = cov.gap_criteria
    total = len(cov.criteria)
    lines.append("")
    lines.append(f"Honest gaps: {len(gaps)} of {total} criteria have no clone-visible kit signal.")
    if gaps:
        by_family: dict[str, list[str]] = {}
        for crit in gaps:
            by_family.setdefault(crit.family, []).append(crit.id)
        for family in sorted(by_family):
            lines.append(f"  {family}: {', '.join(by_family[family])}")
    lines.append("")
    lines.append("Coverage is a clone-visible signal toward each criterion, never a guarantee of OSPS level")
    lines.append("conformance. Full per-criterion map: --format json or docs/osps-baseline-2026-coverage.md.")
    write_stdout_text("\n".join(lines) + "\n")


#: A format the kit deliberately does not emit, and the reason, so asking for it gets an
#: answer instead of a list of two. The conformance renderer is deferred until the Scorecard
#: v6 wire shape it would have to match reaches GA -- ADR-018 and
#: docs/osps-baseline-2026-coverage.md both record that, and until this constant existed the
#: only way to learn it was to read the second half of a documentation page. Emitting a shape
#: guessed at before the upstream one is stable would be a conformance claim the kit cannot
#: keep.
#:
#: The CONSUMING half is already shipped: OSPS-SCORECARD-V6-001 reads a
#: `scorecard --format=osps` report from .oss-policy-kit/evidence/scorecard-osps.json when
#: one is present, and answers manual review when it is not.
_DEFERRED_FORMATS = {
    "osps": (
        "--format osps is not implemented yet, deliberately. It would have to match the "
        "Scorecard v6 OSPS conformance wire shape, which is still a proposal rather than a "
        "released format, and emitting a guess at it would be a conformance claim this kit "
        "cannot keep. See ADR-018 and docs/osps-baseline-2026-coverage.md. The kit already "
        "CONSUMES that format: put a scorecard --format=osps report at "
        ".oss-policy-kit/evidence/scorecard-osps.json and OSPS-SCORECARD-V6-001 reads it. "
        "For the coverage map itself, use --format json."
    )
}


def _run_osps_coverage(output_format: str) -> None:
    fmt = output_format.lower().strip()
    if fmt in _DEFERRED_FORMATS:
        raise InvalidInputError(_DEFERRED_FORMATS[fmt])
    if fmt not in {"human", "json"}:
        raise InvalidInputError("--format must be human or json.")
    cov = load_osps_coverage()
    if fmt == "json":
        write_stdout_text(json.dumps(cov.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        _render_human(cov)


@app.command("osps-coverage", rich_help_panel=CMD_PANEL_DISCOVER)
def osps_coverage_cmd(
    output_format: str = typer.Option(
        "human",
        "--format",
        help="Output format: human (default) or json.",
    ),
) -> None:
    """Show advisory OSPS Baseline v2026.02.19 coverage (per-level + honest gaps).

    Reports how the bundled ``osps-baseline-2026-1`` controls map to the OpenSSF
    OSPS Baseline criteria, with honest per-level (L1/L2/L3) counts and the real
    gaps. Read-only and advisory; see ADR-037 and docs/osps-baseline-2026-coverage.md.
    This is not a conformance certification and changes no ``evaluate`` verdict.

    Exit codes: 0 success (informational); 2 usage error; 3 unexpected internal error.
    """

    try:
        _run_osps_coverage(output_format)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    # Last-resort user message, no traceback leak.
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)
