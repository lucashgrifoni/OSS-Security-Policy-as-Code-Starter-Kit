"""`profiles` subcommand: discovery, filtering, and JSON/table rendering."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any

import typer
from rich.table import Table

from oss_policy_kit import __version__ as kit_version
from oss_policy_kit.application.loader import (
    BUNDLED_PROFILE_LEGACY_IDS,
    PROFILE_DIRECTORY_ALIASES,
    ControlSpec,
    load_catalog,
    load_profile_by_id,
    merge_kit_root,
)
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.common import (
    app,
    normalize_profiles_format,
    stderr_console,
)
from oss_policy_kit.domain.errors import InvalidInputError, LoadError, OssPolicyKitError

_PROFILE_DISPLAY_ALIAS_TARGETS = dict(PROFILE_DIRECTORY_ALIASES)
_REGULATORY_PROFILE_IDS: frozenset[str] = frozenset({"cra-eu-ready-1", "cra-eu-strict-1"})

_FRAMEWORK_PROFILE_LABELS: dict[str, str] = {
    "osps-baseline-1": "framework-aligned advisory (OSPS Baseline)",
    "slsa-build-l2-1": "framework-aligned hard-gate-capable (SLSA Build L2)",
    "ssdf-baseline-1": "framework-aligned advisory (NIST SSDF)",
    "cis-supply-chain-1": "framework-aligned advisory (CIS Supply Chain)",
    "owasp-cicd-top10-1": "framework-aligned advisory (OWASP CICD Top 10)",
    "s2c2f-l1-1": "framework-aligned advisory (Microsoft S2C2F L1)",
    "appsec-sast-sca-1": "AppSec native bundle (hard-gate-capable with scan-sast)",
    "iac-terraform-baseline-1": "IaC Terraform posture (advisory, paired with scan-iac)",
    "kubernetes-baseline-1": "Kubernetes manifest posture (advisory, paired with scan-k8s)",
    "container-baseline-1": "container hardening posture (advisory)",
}

_PROFILE_COMPACT_AUDIENCES = {
    "aws-level-1": "AWS teams starting honest checks.",
    "aws-level-2": "AWS teams with mature pipelines.",
    "aws-level-3": "AWS teams needing deterministic + evidence-backed hard gates.",
    "aws-release-hardening-1": "AWS teams preparing releases.",
    "aws-release-hardening-2": "AWS teams using evidence files.",
    "aws-release-hardening-3": "High-assurance AWS release teams.",
    "azure-level-1": "Azure teams starting OSS hygiene.",
    "azure-level-2": "Azure teams with stronger CI/CD.",
    "azure-level-3": "Security-focused Azure maintainers.",
    "azure-release-hardening-1": "Azure teams preparing releases.",
    "azure-release-hardening-2": "Azure teams with release governance.",
    "azure-release-hardening-3": "High-assurance Azure release teams.",
    "github-level-1": "GitHub maintainers starting a baseline.",
    "github-level-2": "GitHub maintainers with disciplined CI/CD.",
    "github-level-3": "Security-focused GitHub maintainers.",
    "github-aws-level-2": "Teams with GitHub SCM and AWS CI/CD.",
    "github-azure-level-2": "Teams with GitHub SCM and Azure Pipelines.",
    "github-release-hardening": "GitHub teams preparing releases.",
    "github-release-hardening-1": "GitHub teams preparing releases.",
    "github-release-hardening-2": "GitHub teams enforcing release posture.",
    "github-release-hardening-3": "High-assurance GitHub release teams.",
    "cra-eu-ready-1": "EU manufacturers preparing for CRA reporting (advisory, multi-platform).",
}
_PROFILE_COMPACT_DESCRIPTIONS = {
    "aws-level-1": "Starter AWS buildspec/pipeline signals (honest clone checks).",
    "aws-level-2": "Advisory AWS profile with validated pipeline exports + signals.",
    "aws-level-3": "Hard-gate AWS profile (evidence-backed posture, IAM, artifact SBOM/prov).",
    "aws-release-hardening-1": "AWS baseline plus pipeline/project evidence.",
    "aws-release-hardening-2": "Stricter AWS release posture with evidence.",
    "aws-release-hardening-3": "Level-3 hard gate plus release-time signal controls.",
    "azure-level-1": "Starter Azure DevOps baseline from repo signals.",
    "azure-level-2": "Stricter Azure pipeline governance baseline.",
    "azure-level-3": "High-assurance Azure DevOps governance baseline.",
    "azure-release-hardening-1": "Azure baseline plus branch/pipeline evidence.",
    "azure-release-hardening-2": "Stricter Azure release governance with evidence.",
    "azure-release-hardening-3": "Highest Azure release governance with evidence.",
    "github-level-1": "Starter GitHub baseline for clone-visible checks.",
    "github-level-2": "Stricter GitHub workflow hardening baseline.",
    "github-level-3": "High-assurance GitHub supply-chain baseline.",
    "github-aws-level-2": "Multi-platform advisory-only profile (GitHub + AWS signals).",
    "github-azure-level-2": "Multi-platform advisory-only profile (GitHub + Azure signals).",
    "github-release-hardening": "Legacy id — same as github-release-hardening-1 (prefer -1).",
    "github-release-hardening-1": "GitHub baseline plus release settings evidence.",
    "github-release-hardening-2": "Stricter GitHub release posture with evidence.",
    "github-release-hardening-3": "Highest GitHub release governance with evidence.",
    "cra-eu-ready-1": "EU CRA preparation (advisory) — multi-platform mapping, not certification.",
}


@dataclass(frozen=True, slots=True)
class _ProfileDisplayRow:
    """Compact CLI metadata for a bundled profile."""

    profile_id: str
    title: str
    platform: str
    level: str
    controls: int
    track: str
    summary: str
    description: str
    audience: str
    is_legacy_alias: bool = False


def _profile_maturity_label(profile_id: str, *, is_legacy_alias: bool) -> str:
    """Human-oriented ladder label derived from bundled profile ids (no new profile schema)."""

    if is_legacy_alias:
        return "legacy bundled id (non-canonical)"
    if profile_id in _REGULATORY_PROFILE_IDS:
        return "framework-aligned advisory (regulatory)"
    if profile_id in _FRAMEWORK_PROFILE_LABELS:
        return _FRAMEWORK_PROFILE_LABELS[profile_id]
    if profile_id in {"github-aws-level-2", "github-azure-level-2"}:
        return "advisory hybrid (multi-platform)"
    if profile_id.endswith("release-hardening-3"):
        return "release hard-gate (extreme)"
    if "-level-3" in profile_id and "release-hardening" not in profile_id:
        return "hard-gate ladder (extreme)"
    if "release-hardening" in profile_id:
        return "release ladder"
    if "-level-2" in profile_id:
        return "advisory ladder"
    return "starter ladder"


def _profile_row_is_extreme(row: _ProfileDisplayRow) -> bool:
    """Return True for profiles that default to extreme / hard-gate posture.

    The catalog has two such tiers: ``*-level-3`` and ``*release-hardening-3``.
    Both produce a maturity label containing ``(extreme)``; the pid patterns are
    redundant but kept as a belt-and-suspenders. Labels that merely describe a
    profile as ``hard-gate-capable`` (e.g. ``appsec-sast-sca-1``,
    ``slsa-build-l2-1``) are intentionally NOT extreme — they ship as advisory
    by default and graduate only when paired with the appropriate ``scan-*``
    evidence.
    """

    m = _profile_maturity_label(row.profile_id, is_legacy_alias=row.is_legacy_alias).lower()
    pid = row.profile_id
    return "(extreme)" in m or ("-level-3" in pid and "release-hardening" not in pid) or ("release-hardening-3" in pid)


def _profile_row_is_advisory(row: _ProfileDisplayRow) -> bool:
    m = _profile_maturity_label(row.profile_id, is_legacy_alias=row.is_legacy_alias).lower()
    return "advisory" in m or "-level-2" in row.profile_id


def _profile_family_key(platform: str) -> str:
    return {"GitHub": "github", "Azure": "azure", "AWS": "aws", "Multi": "multi", "Custom": "custom"}.get(
        platform, "custom"
    )


def _profile_posture_descriptor(profile_id: str, maturity: str) -> str:
    ml = maturity.lower()
    if "legacy" in ml:
        return "legacy_alias"
    if "regulatory" in ml or profile_id in _REGULATORY_PROFILE_IDS:
        return "framework_aligned_advisory"
    if "hybrid" in ml:
        return "multi_platform_advisory_hybrid"
    if "hard-gate" in ml or ("extreme" in ml and "advisory" not in ml):
        return "hard_gate_or_extreme"
    if "advisory" in ml:
        return "advisory"
    if "starter" in ml:
        return "starter"
    if "release" in ml:
        return "release_track"
    return "general"


def _profile_live_signal_posture(profile_id: str, posture_descriptor: str) -> str:
    if posture_descriptor == "multi_platform_advisory_hybrid":
        return "clone_visible_github_plus_platform_ci_signals_advisory"
    if posture_descriptor == "framework_aligned_advisory":
        return "regulatory_mapping_no_release_gate"
    if posture_descriptor == "hard_gate_or_extreme":
        return "evidence_heavy_or_high_assurance_expectations"
    if "release-hardening" in profile_id:
        return "release_evidence_expectations"
    return "clone_visible_primary"


def _profile_recommended_gate(posture_descriptor: str) -> str:
    """Derived, rendering-only column. JSON profile-list schema is not affected."""

    return {
        "starter": "--fail-on fail",
        "advisory": "--fail-on none",
        "hard_gate_or_extreme": "--fail-on fail",
        "release_track": "--fail-on fail",
        "multi_platform_advisory_hybrid": "--fail-on none",
        "framework_aligned_advisory": "--fail-on degraded",
        "legacy_alias": "(migrate)",
    }.get(posture_descriptor, "--fail-on none")


def _filter_profile_display_rows(
    rows: list[_ProfileDisplayRow],
    *,
    family: str | None,
    only_extreme: bool,
    advisory_only: bool,
) -> list[_ProfileDisplayRow]:
    fam = family.strip().lower() if family else None
    if fam and fam not in {"github", "azure", "aws", "multi"}:
        raise InvalidInputError("--family must be one of: github, azure, aws, multi.")
    want_platform = {"github": "GitHub", "azure": "Azure", "aws": "AWS", "multi": "Multi"}.get(fam) if fam else None
    out: list[_ProfileDisplayRow] = []
    for row in rows:
        if want_platform is not None and row.platform != want_platform:
            continue
        if only_extreme and not _profile_row_is_extreme(row):
            continue
        if advisory_only and not _profile_row_is_advisory(row):
            continue
        out.append(row)
    return out


def _profile_assurance_mix(control_ids: tuple[str, ...], catalog: dict[str, ControlSpec]) -> dict[str, int]:
    """Count catalog assurance classes for controls listed in a bundled profile."""

    det = sig = evi = 0
    for cid in control_ids:
        spec = catalog.get(cid)
        if spec is None:
            continue
        if spec.assurance == "deterministic":
            det += 1
        elif spec.assurance == "signal":
            sig += 1
        elif spec.assurance == "evidence-backed":
            evi += 1
    return {"deterministic": det, "signal": sig, "evidence-backed": evi, "det": det, "sig": sig, "evi": evi}


def _profile_platform(profile_id: str) -> str:
    """Return the platform family for a profile id."""

    if profile_id in _REGULATORY_PROFILE_IDS:
        return "Multi"
    if profile_id.startswith("github-"):
        return "GitHub"
    if profile_id.startswith("azure-"):
        return "Azure"
    if profile_id.startswith("aws-"):
        return "AWS"
    return "Custom"


def _profile_level(profile_id: str) -> str:
    """Return the maturity level label for a profile id."""

    if "-level-" in profile_id:
        return f"L{profile_id.rsplit('-', 1)[-1]}"
    if profile_id.endswith("release-hardening"):
        return "L1"
    if "-release-hardening-" in profile_id:
        return f"L{profile_id.rsplit('-', 1)[-1]}"
    return "-"


def _profile_track(profile_id: str) -> str:
    """Return whether the profile is a baseline or release-hardening track."""

    return "rel" if "release-hardening" in profile_id else "base"


def _profile_summary(profile_id: str, description: str, title: str) -> str:
    """Return a short, scan-friendly CLI summary for a bundled profile."""

    level = _profile_level(profile_id)
    track = _profile_track(profile_id)
    summaries = {
        ("base", "L1"): "Core clone",
        ("base", "L2"): "Strict posture",
        ("base", "L3"): "High assurance",
        ("rel", "L1"): "Base + evidence",
        ("rel", "L2"): "Strict + evidence",
        ("rel", "L3"): "Assur. + evidence",
    }
    if (track, level) in summaries:
        return summaries[(track, level)]
    normalized = " ".join((description or title).split())
    if len(normalized) <= 48:
        return normalized
    return f"{normalized[:45].rstrip()}..."


def _compact_profile_description(profile_id: str, description: str) -> str:
    """Return a fixed executive description for the compact profiles table."""

    if profile_id in _PROFILE_COMPACT_DESCRIPTIONS:
        return _PROFILE_COMPACT_DESCRIPTIONS[profile_id]
    normalized = " ".join(description.split())
    return normalized if len(normalized) <= 48 else f"{normalized[:45].rstrip()}..."


def _compact_profile_audience(profile_id: str, audience: str) -> str:
    """Return a fixed executive audience for the compact profiles table."""

    if profile_id in _PROFILE_COMPACT_AUDIENCES:
        return _PROFILE_COMPACT_AUDIENCES[profile_id]
    normalized = " ".join(audience.split())
    return normalized if len(normalized) <= 40 else f"{normalized[:37].rstrip()}..."


def _iter_bundled_profiles() -> list[_ProfileDisplayRow]:
    """Return bundled profile metadata for display in the CLI."""

    root = merge_kit_root(None)
    profiles_dir = root / "profiles"
    available_profile_ids = {profile_yaml.parent.name for profile_yaml in profiles_dir.glob("*/profile.yaml")}
    rows: list[_ProfileDisplayRow] = []
    for profile_yaml in sorted(profiles_dir.glob("*/profile.yaml")):
        legacy_alias_target = _PROFILE_DISPLAY_ALIAS_TARGETS.get(profile_yaml.parent.name)
        if legacy_alias_target is not None and legacy_alias_target in available_profile_ids:
            continue
        profile = load_profile_by_id(root, profile_yaml.parent.name)
        title_clean = terminal_ui.sanitize_cli_display_text(profile.title)
        desc_clean = terminal_ui.sanitize_cli_display_text(" ".join(profile.description.split()))
        aud_clean = terminal_ui.sanitize_cli_display_text(" ".join(profile.audience.split()))
        rows.append(
            _ProfileDisplayRow(
                profile_id=profile.id,
                title=title_clean,
                platform=_profile_platform(profile.id),
                level=_profile_level(profile.id),
                controls=len(profile.control_ids),
                track=_profile_track(profile.id),
                summary=_profile_summary(profile.id, desc_clean, title_clean),
                description=desc_clean,
                audience=aud_clean,
                is_legacy_alias=False,
            )
        )
    seen = {r.profile_id for r in rows}
    for legacy_id in sorted(BUNDLED_PROFILE_LEGACY_IDS):
        if legacy_id in seen:
            continue
        profile = load_profile_by_id(root, legacy_id)
        title_clean = terminal_ui.sanitize_cli_display_text(profile.title)
        desc_clean = terminal_ui.sanitize_cli_display_text(" ".join(profile.description.split()))
        aud_clean = terminal_ui.sanitize_cli_display_text(" ".join(profile.audience.split()))
        rows.append(
            _ProfileDisplayRow(
                profile_id=profile.id,
                title=title_clean,
                platform=_profile_platform(profile.id),
                level=_profile_level(profile.id),
                controls=len(profile.control_ids),
                track=_profile_track(profile.id),
                summary=_profile_summary(profile.id, desc_clean, title_clean),
                description=desc_clean,
                audience=aud_clean,
                is_legacy_alias=True,
            )
        )
    plat_order = {"GitHub": 0, "Azure": 1, "AWS": 2, "Multi": 3, "Custom": 4}
    rows.sort(key=lambda r: (plat_order.get(r.platform, 9), int(r.is_legacy_alias), r.profile_id))
    return rows


def _print_profiles_table(
    *,
    detailed: bool,
    compact_layout: bool,
    rows: list[_ProfileDisplayRow] | None = None,
) -> None:
    """Render bundled profiles as a compact or detailed table on stdout."""

    plat_order = {"GitHub": 0, "Azure": 1, "AWS": 2, "Multi": 3, "Custom": 4}
    if rows is None:
        rows = _iter_bundled_profiles()
    rows = sorted(
        rows,
        key=lambda r: (plat_order.get(r.platform, 9), int(r.is_legacy_alias), r.profile_id),
    )
    longest_pid = max(
        (
            len(r.profile_id)
            + (len(" (legacy -> )") + len(PROFILE_DIRECTORY_ALIASES.get(r.profile_id, "")) if r.is_legacy_alias else 0)
            for r in rows
        ),
        default=16,
    )
    term_w = terminal_ui.terminal_width(sys.stdout)
    compact_default = compact_layout and not detailed
    if terminal_ui.human_tty_stdout():
        sub = "Six-column table follows" if not compact_default else None
        terminal_ui.print_profiles_catalog_panel(rows, subtitle=sub)
        if compact_default:
            oc = terminal_ui.build_stdout_console(width=term_w)
            oc.print(
                "[dim]Full table:[/dim] [cyan]profiles --format table[/cyan]  [dim]|[/dim]  "
                "[cyan]profiles --format detailed[/cyan]"
            )
            return
    layout = terminal_ui.profile_table_layout_for_width(
        terminal_columns=term_w,
        detailed=detailed,
        longest_profile_id_chars=longest_pid,
    )
    tbl_title = None if terminal_ui.human_tty_stdout() else "Bundled profiles"
    table = Table(title=tbl_title, show_lines=not (compact_layout and not detailed))
    table.add_column("Profile", style="cyan", no_wrap=True, max_width=layout.profile)
    table.add_column("Title", style="dim", max_width=layout.title, overflow="fold")
    table.add_column("Platform", style="dim", no_wrap=True, max_width=layout.platform)
    table.add_column("Level", style="dim", no_wrap=True, max_width=layout.level)
    table.add_column(
        "Recommended gate",
        style="default",
        header_style="dim",
        no_wrap=True,
        max_width=layout.gate,
    )
    table.add_column(
        "Audience",
        style="default",
        header_style="dim",
        max_width=layout.audience,
        overflow="fold",
    )
    table.add_column(
        "Description",
        style="default",
        header_style="dim",
        max_width=layout.description,
        overflow="fold",
    )

    for row in rows:
        pid = row.profile_id
        if row.is_legacy_alias:
            canon = PROFILE_DIRECTORY_ALIASES.get(row.profile_id, row.profile_id)
            pid = f"{row.profile_id} (legacy -> {canon})"
        maturity = _profile_maturity_label(row.profile_id, is_legacy_alias=row.is_legacy_alias)
        posture = _profile_posture_descriptor(row.profile_id, maturity)
        gate = _profile_recommended_gate(posture)
        table.add_row(
            pid,
            row.title,
            row.platform,
            row.level,
            gate,
            row.audience if detailed else _compact_profile_audience(row.profile_id, row.audience),
            row.description if detailed else _compact_profile_description(row.profile_id, row.description),
        )

    terminal_ui.build_stdout_console(width=term_w).print(table)


def _print_profiles_json(rows: list[_ProfileDisplayRow] | None = None) -> None:
    """Emit bundled profile metadata as JSON on stdout."""

    root = merge_kit_root(None)
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    if rows is None:
        rows = _iter_bundled_profiles()
    profiles_out: list[dict[str, Any]] = []
    for r in rows:
        spec = load_profile_by_id(root, r.profile_id)
        mix = _profile_assurance_mix(spec.control_ids, catalog)
        maturity = _profile_maturity_label(r.profile_id, is_legacy_alias=r.is_legacy_alias)
        posture = _profile_posture_descriptor(r.profile_id, maturity)
        profiles_out.append(
            {
                "profile_id": r.profile_id,
                "canonical_profile_id": PROFILE_DIRECTORY_ALIASES.get(r.profile_id, r.profile_id),
                "is_legacy_alias": r.is_legacy_alias,
                "maturity_label": maturity,
                "family": _profile_family_key(r.platform),
                "posture": posture,
                "live_signal_posture": _profile_live_signal_posture(r.profile_id, posture),
                "assurance_mix": mix,
                "platform": r.platform,
                "level": r.level,
                "controls": r.controls,
                "track": r.track,
                "summary": r.summary,
            }
        )
    payload = {
        "schema_version": "oss-policy-kit/profile-list/v2",
        "kit_version": kit_version,
        "profiles": profiles_out,
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


@app.command("profiles")
def profiles_cmd(
    output_format: str = typer.Option(
        "compact",
        "--format",
        "-f",
        help=(
            "compact (default): dense table; table: full grid lines; detailed: full YAML audience/description; "
            "json. Aliases: human -> compact, verbose -> detailed."
        ),
        case_sensitive=False,
    ),
    family: str | None = typer.Option(
        None,
        "--family",
        help="Restrict listing to one platform family: github, azure, or aws.",
    ),
    only_extreme: bool = typer.Option(
        False,
        "--only-extreme",
        help="Only profiles with extreme / hard-gate posture (level-3 or release-hardening-3).",
    ),
    advisory_only: bool = typer.Option(
        False,
        "--advisory-only",
        help="Only advisory-tier profiles (includes level-2 ladders and hybrid advisories).",
    ),
) -> None:
    """List bundled profiles available in this kit build."""

    try:
        fmt = normalize_profiles_format(output_format)
        filtered = _filter_profile_display_rows(
            _iter_bundled_profiles(),
            family=family,
            only_extreme=only_extreme,
            advisory_only=advisory_only,
        )
        if fmt == "json":
            _print_profiles_json(filtered)
        else:
            if fmt == "detailed":
                _print_profiles_table(detailed=True, compact_layout=False, rows=filtered)
            elif fmt == "compact":
                _print_profiles_table(detailed=False, compact_layout=True, rows=filtered)
            else:
                # fmt == "table": full grid lines, default column balance (not density-compact).
                _print_profiles_table(detailed=False, compact_layout=False, rows=filtered)
    except LoadError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
