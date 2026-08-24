"""Orchestrate loading, evaluation, waivers, and report assembly."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.markup import escape as _markup_escape

import oss_policy_kit
from oss_policy_kit.adapters.scorecard_json import ScorecardBundle
from oss_policy_kit.application.applicability import resolve_applicability
from oss_policy_kit.application.clock import report_generated_at
from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY, EvalContext
from oss_policy_kit.application.evidence_placeholders import has_placeholder_values
from oss_policy_kit.application.insights_evidence import InsightsEvidence
from oss_policy_kit.application.loader import ControlSpec, ProfileSpec
from oss_policy_kit.application.waivers import WaiverParseOutcome
from oss_policy_kit.domain.errors import LoadError
from oss_policy_kit.domain.models import (
    ControlResult,
    ControlStatus,
    EvalOutcome,
    ExecutionReport,
    LiveCollectionMetadata,
    WaiverRecord,
    WeightedScore,
)
from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines
from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

# Diagnostic logger. Silent unless the caller raises the "oss_policy_kit" logger to
# DEBUG (e.g. via the CLI `--debug` flag); default output is therefore unchanged.
logger = logging.getLogger(__name__)

_HARD_GATE_EVIDENCE_PROFILES = frozenset(
    {
        "github-level-3",
        "aws-level-3",
        "azure-level-3",
        "github-release-hardening-3",
        "aws-release-hardening-3",
        "azure-release-hardening-3",
    }
)


def _has_real_evidence(evidence_dir: Path) -> bool:
    """True when the evidence dir holds at least one JSON file free of placeholder values."""

    if not evidence_dir.is_dir():
        return False
    for path in sorted(evidence_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not has_placeholder_values(data):
            return True
    return False


def _hard_gate_evidence_warning(profile_id: str, repo_root: Path) -> str | None:
    """Build an operational warning when a hard-gate profile runs without real evidence.

    Returns a single warning string when ``profile_id`` is one of the L3 /
    release-hardening-3 profiles AND the target has no populated evidence
    (either ``.oss-policy-kit/evidence/`` is missing, has no JSON files, or
    every JSON file contains placeholder tokens). Returns ``None`` otherwise.
    """

    if profile_id not in _HARD_GATE_EVIDENCE_PROFILES:
        return None
    if _has_real_evidence(repo_root / ".oss-policy-kit" / "evidence"):
        return None

    return (
        f"Profile '{profile_id}' expects .oss-policy-kit/evidence/ to be populated by "
        "scaffold-evidence (then edited) or by collect-evidence. "
        "See docs/release-hardening-workflow.md."
    )


REPORT_JSON_SCHEMA_URL_V2_0 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0"


# v6.0.0 (V6-05, ADR-013): reports/2.0 contract maps the v5.x seven-state
# vocabulary into the Scorecard-v6 five-state vocabulary. The mapping is
# documented in docs/reports-contract-v2.0.md.
#
# v5.x status -> (v2.0 STATE, optional reason sub-field)
REPORTS_V2_STATUS_MAP: dict[str, tuple[str, str | None]] = {
    "pass": ("PASS", None),
    "fail": ("FAIL", None),
    # Kept so a v5.x report still maps, but `ControlStatus` has had no `degraded` member
    # since the 2.0 flip: no evaluator produces it and nothing writes a per-control
    # `degraded` flag. `--fail-on degraded` is a separate, still-live policy value.
    "degraded": ("FAIL", None),
    "manual-review-required": ("UNKNOWN", "manual-review-required"),
    "not-applicable": ("NOT_APPLICABLE", None),
    "skipped": ("UNKNOWN", "skipped-by-flag"),
    "error": ("UNKNOWN", "evaluator-error"),
    "attested": ("ATTESTED", None),  # ADR-028: verified-attestation pass (in-toto+cosign); distinct from PASS
    "self-attested": ("SELF_ATTESTED", None),  # ADR-033: opt-in Insights self-reported evidence
    "waived": ("UNKNOWN", "waived"),  # parity with reporting.REPORTS_V2_STATUS_MAP (v9.0.3 drift fix)
    # Both were ControlStatus members with no entry here, so they fell through to the
    # "we do not recognise this" fallback below and reached adopters as
    # `unmapped-source-status` -- a discriminator documented nowhere. NOT_EVALUATED is
    # returned by evaluators across five modules, notably OSS-SCORECARD-001 when no
    # Scorecard JSON is supplied, so the fallback was reachable on an ordinary run.
    "not-evaluated": ("UNKNOWN", "not-evaluated"),
    "not-observable": ("UNKNOWN", "not-observable-in-clone"),
}


def map_status_to_reports_v2(status: str) -> tuple[str, str | None]:
    """Map an internal status string to the (state, reason) pair of reports/2.0.

    See docs/reports-contract-v2.0.md for the full mapping table. Since v9.0.0
    (ADR-043) ``reports/2.0`` is the only report contract; this map is the single
    source of truth for the state vocabulary and must stay in sync with
    ``reporting.REPORTS_V2_STATUS_MAP``.
    """
    key = status.strip().lower()
    if key in REPORTS_V2_STATUS_MAP:
        return REPORTS_V2_STATUS_MAP[key]
    return ("UNKNOWN", "unmapped-source-status")


#: The report contracts that really existed and were really removed in v9.0.0 (ADR-043),
#: in both the bare and ``reports/``-prefixed spellings a user might type.
#:
#: Only these may be told they "were removed": ``--report-json-contract 3.0`` or ``two``
#: or ``2.0.0`` never named a contract of this kit, and sending that user to a migration
#: guide for a version they never used is a false statement about the kit's own history.
_REMOVED_REPORT_JSON_CONTRACTS = frozenset(
    {
        "0.1",
        "0.2",
        "0.3",
        "1.0",
        "reports/0.1",
        "reports/0.2",
        "reports/0.3",
        "reports/1.0",
    }
)


def report_json_schema_url(contract: str) -> str:
    """Return the full ``schema_version`` URL for an evaluation JSON report contract.

    v9.0.0 (ADR-043, BREAKING): ``reports/2.0`` is the **only** contract. The legacy
    selectable contracts (``0.1``/``0.2``/``0.3``/``1.0``) were removed; only ``2.0``
    is accepted and any other value — including an empty or whitespace-only value —
    is a hard error (no silent fallback to the default).

    Rejection is uniform; the *explanation* is not. A removed contract gets the
    migration pointer; anything else is simply not a contract this kit ever wrote.
    """

    c = contract.strip().lower().removeprefix("v")
    if c == "2.0":
        return REPORT_JSON_SCHEMA_URL_V2_0
    if c == "":
        raise LoadError(
            "Report JSON contract is empty; 'reports/2.0' is the only contract in v9.0.0 (ADR-043). "
            "Drop --report-json-contract (2.0 is the default) or pass '2.0'. "
            "See docs/v9.0.0-migration-guide.md."
        )
    if c in _REMOVED_REPORT_JSON_CONTRACTS:
        raise LoadError(
            f"Report JSON contract {contract!r} was removed in v9.0.0 (ADR-043); 'reports/2.0' is the only "
            "contract. Drop --report-json-contract (2.0 is the default) or pass '2.0'. "
            "See docs/v9.0.0-migration-guide.md."
        )
    raise LoadError(
        f"Report JSON contract {contract!r} is not a recognised contract; 'reports/2.0' is the only "
        "contract this kit writes. Drop --report-json-contract (2.0 is the default) or pass '2.0'."
    )


def _apply_waiver(
    base_status: ControlStatus,
    waiver: WaiverRecord | None,
) -> tuple[ControlStatus, WaiverRecord | None]:
    """Attach waiver only when it legitimately mitigates a non-pass outcome."""

    if waiver is None:
        return base_status, None
    st = waiver.status.lower()
    if st not in {"approved", "active"}:
        return base_status, None
    if base_status in {
        ControlStatus.FAIL,
        ControlStatus.MANUAL_REVIEW_REQUIRED,
    }:
        return ControlStatus.WAIVED, waiver
    return base_status, None


def _summarize(results: list[ControlResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        key = r.status.value
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


_PASSING_STATUSES = frozenset(
    {ControlStatus.PASS, ControlStatus.ATTESTED, ControlStatus.SELF_ATTESTED, ControlStatus.WAIVED}
)
_SCORING_EXCLUDED = frozenset({ControlStatus.NOT_APPLICABLE, ControlStatus.NOT_EVALUATED})


def _compute_weighted_score(results: list[ControlResult]) -> WeightedScore:
    """Compute risk-adjusted posture score based on per-control weights."""
    earned = 0
    possible = 0
    for r in results:
        if r.status in _SCORING_EXCLUDED:
            continue
        possible += r.weight
        if r.status in _PASSING_STATUSES:
            earned += r.weight
    pct = round((earned / possible * 100), 1) if possible > 0 else 0.0
    return WeightedScore(earned=earned, possible=possible, percent=pct)


def _build_scorecard_supplemental(
    scorecard: ScorecardBundle | None,
    results: list[ControlResult],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Explain whether a scorecard file was loaded and whether it changed any control outcomes."""

    if scorecard is None:
        return None, []

    extra_warnings: list[str] = []
    workflows_satisfied = False
    codeql_row = next((r for r in results if r.control_id == "SEC-CODEQL-010"), None)
    if codeql_row is not None and codeql_row.status == ControlStatus.PASS:
        workflows_satisfied = "scorecard" not in codeql_row.reason.lower()

    influenced = [
        r.control_id for r in results if r.control_id == "SEC-CODEQL-010" and "Scorecard export references" in r.reason
    ]

    n = len(scorecard.checks)
    if n == 0:
        extra_warnings.append(
            "Scorecard JSON was read but contains zero recognizable check entries; "
            "supplemental influence on controls is unlikely until valid check objects are present."
        )

    parts: list[str] = [
        f"Loaded {n} scorecard check entr(y/ies) from {scorecard.raw_path or 'the provided path'}.",
    ]
    if influenced:
        parts.append(f"Supplemental data changed outcomes for: {', '.join(influenced)}.")
    elif workflows_satisfied:
        parts.append(
            "No supplemental influence in this run: SEC-CODEQL-010 was already satisfied from in-repo workflows; "
            "the scorecard file did not change results."
        )
    else:
        if codeql_row is not None and codeql_row.status == ControlStatus.FAIL:
            parts.append(
                "Scorecard did not provide a matching supplemental signal for SEC-CODEQL-010; "
                "add CodeQL or equivalent SAST in CI for a pass."
            )
        else:
            parts.append("Scorecard did not influence any control outcomes for this profile.")

    blob: dict[str, Any] = {
        "loaded": True,
        "path": scorecard.raw_path,
        "check_count": n,
        "influenced_control_ids": influenced,
        "workflows_satisfied_codeql_signal": workflows_satisfied,
        "explanation": " ".join(parts),
    }
    return blob, extra_warnings


def _collect_parse_warnings(workflows: Any, azure_pipelines: Any, aws_ci: Any, gitlab_ci: Any) -> list[str]:
    """Flatten the four CI parsers' parse errors into operational-warning strings."""

    out: list[str] = []
    out.extend(f"Workflow parse issue {p.name}: {m}" for p, m in workflows.parse_errors)
    out.extend(f"Azure pipeline parse issue {p.name}: {m}" for p, m in azure_pipelines.parse_errors)
    out.extend(f"AWS CI parse issue {p.name}: {m}" for p, m in aws_ci.parse_errors)
    out.extend(f"GitLab CI parse issue {p.name}: {m}" for p, m in gitlab_ci.parse_errors)
    return out


def _not_applicable_result(cid: str, spec: ControlSpec, profile: ProfileSpec, reason: str) -> ControlResult:
    """Build a NOT_APPLICABLE result for a control whose declared precondition is unmet (ADR-028)."""

    return ControlResult(
        control_id=cid,
        title=spec.title,
        category=spec.category,
        status=ControlStatus.NOT_APPLICABLE,
        profile=profile.id,
        evidence_sources=[],
        confidence="high",
        reason=reason,
        remediation="No action required while the declared precondition is unmet.",
        lifecycle=spec.lifecycle,
        assurance=spec.assurance,
        deprecation_note=spec.deprecation_note,
        weight=spec.weight,
    )


def _resolve_inapplicable(
    cid: str,
    ctx: EvalContext,
    profile: ProfileSpec,
    spec: ControlSpec,
) -> ControlResult | None:
    """Return the NOT_APPLICABLE result when *spec*'s precondition is unmet, else None."""

    if spec.applicability is None:
        return None
    applicable, na_reason = resolve_applicability(spec.applicability, ctx.repo_root)
    if applicable:
        return None
    if ctx.verbose_emit is not None:
        ctx.verbose_emit(
            f"[dim]→ {_markup_escape(cid)} ({_markup_escape(spec.title)}) — not applicable (precondition unmet)[/dim]"
        )
    return _not_applicable_result(cid, spec, profile, na_reason or "Not applicable.")


def _emit_verbose_outcome(ctx: EvalContext, outcome: EvalOutcome) -> None:
    """Echo one evaluator's verdict on the verbose channel, truncated and escaped."""

    if ctx.verbose_emit is None:
        return
    reason_one = outcome.reason.replace("\n", " ").strip()
    if len(reason_one) > 220:
        reason_one = reason_one[:217].rstrip() + "..."
    # Truncate first, escape second, so the cut never lands inside a ``\[`` we added.
    ctx.verbose_emit(f"[dim]  Result: {_markup_escape(outcome.status.value)} — {_markup_escape(reason_one)}[/dim]")


def _evaluate_control(
    cid: str,
    ctx: EvalContext,
    profile: ProfileSpec,
    catalog: dict[str, ControlSpec],
    waivers: dict[str, Any],
    operational_warnings: list[str],
    *,
    applicability_engine: bool = False,
) -> ControlResult:
    """Run one control's evaluator, apply any waiver, and build its :class:`ControlResult`.

    When *applicability_engine* is enabled (ADR-028, opt-in) and the control declares a
    precondition, an unmet precondition resolves to ``NOT_APPLICABLE`` consistently and the
    evaluator is not run. Default off → unchanged behavior.

    ``verbose_emit`` receives Rich markup, so every value interpolated into one of those
    lines is escaped: a reason naming ``[bold]unsafe.yml`` otherwise reached the operator
    as ``unsafe.yml``, silently, while the JSON report held the real name.
    """

    if cid not in catalog:
        raise LoadError(f"Profile references unknown control '{cid}'")
    spec = catalog[cid]
    if applicability_engine:
        inapplicable = _resolve_inapplicable(cid, ctx, profile, spec)
        if inapplicable is not None:
            return inapplicable
    evaluator = EVALUATOR_REGISTRY.get(cid)
    if evaluator is None:
        raise LoadError(f"No evaluator implemented for control '{cid}'")
    if ctx.verbose_emit is not None:
        ctx.verbose_emit(f"[dim]→ {_markup_escape(cid)} ({_markup_escape(spec.title)})[/dim]")
    logger.debug("evaluating %s (%s)", cid, spec.title)
    outcome = evaluator(ctx)
    operational_warnings.extend(outcome.operational_warnings)
    logger.debug(
        "%s -> %s [%s] sources=%d%s",
        cid,
        outcome.status.value,
        outcome.evidence_collection_method.value,
        len(outcome.evidence_sources),
        f" reason={outcome.reason.splitlines()[0]!r}" if outcome.status.value != "pass" and outcome.reason else "",
    )
    _emit_verbose_outcome(ctx, outcome)
    final_status, applied_waiver = _apply_waiver(outcome.status, waivers.get(cid))
    return ControlResult(
        control_id=cid,
        title=spec.title,
        category=spec.category,
        status=final_status,
        profile=profile.id,
        evidence_sources=list(outcome.evidence_sources),
        confidence=outcome.confidence,
        reason=outcome.reason,
        remediation=outcome.remediation,
        lifecycle=spec.lifecycle,
        assurance=spec.assurance,
        owner=applied_waiver.owner if applied_waiver else None,
        waiver=applied_waiver,
        expires_at=applied_waiver.expires_at if applied_waiver else None,
        evidence_collection_method=outcome.evidence_collection_method.value,
        deprecation_note=spec.deprecation_note,
        weight=spec.weight,
        extra=dict(outcome.extra),
    )


def evaluate_repository(
    repo_root: Path,
    profile: ProfileSpec,
    catalog: dict[str, ControlSpec],
    waiver_outcome: WaiverParseOutcome | None,
    scorecard: ScorecardBundle | None,
    *,
    external_waiver_path: str | None = None,
    verbose_emit: Callable[[str], None] | None = None,
    # v9.0.0 (ADR-043): ``reports/2.0`` is the only contract; the programmatic default
    # matches the CLI / config / init default. Any other value is a hard error.
    report_json_contract: str = "2.0",
    live_collection: LiveCollectionMetadata | None = None,
    insights_evidence: InsightsEvidence | None = None,
    applicability_engine: bool = False,
    enable_attested: bool = False,
) -> ExecutionReport:
    """Run all profile controls against a local repository clone.

    ``insights_evidence`` (ADR-033) is the opt-in, self-reported Security Insights
    contribution. It is ``None`` unless the caller passed ``--use-insights-evidence``;
    when ``None`` no control consumes self-reported signals (clone-only verdicts stand).
    """

    workflows = analyze_workflows(repo_root)
    azure_pipelines = analyze_azure_pipelines(repo_root)
    aws_ci = analyze_aws_ci(repo_root)
    gitlab_ci = analyze_gitlab_ci(repo_root)
    ctx = EvalContext(
        repo_root=repo_root,
        profile_id=profile.id,
        workflows=workflows,
        azure_pipelines=azure_pipelines,
        aws_ci=aws_ci,
        scorecard=scorecard,
        verbose_emit=verbose_emit,
        gitlab_ci=gitlab_ci,
        insights_evidence=insights_evidence,
        enable_attested=enable_attested,
    )

    waivers = waiver_outcome.by_control if waiver_outcome else {}
    operational_warnings: list[str] = list(waiver_outcome.warnings if waiver_outcome else [])
    operational_warnings.extend(_collect_parse_warnings(workflows, azure_pipelines, aws_ci, gitlab_ci))

    results = [
        _evaluate_control(
            cid, ctx, profile, catalog, waivers, operational_warnings, applicability_engine=applicability_engine
        )
        for cid in profile.control_ids
    ]

    generated_at = report_generated_at()

    supplemental, scorecard_warnings = _build_scorecard_supplemental(scorecard, results)
    operational_warnings.extend(scorecard_warnings)

    hard_gate_warning = _hard_gate_evidence_warning(profile.id, repo_root)
    if hard_gate_warning is not None:
        operational_warnings.append(hard_gate_warning)

    weighted = _compute_weighted_score(results)

    # Evaluation JSON contract version (reports/schema/*.json); not the same as kit/package semver.
    return ExecutionReport(
        schema_version=report_json_schema_url(report_json_contract),
        generated_at=generated_at,
        kit_version=oss_policy_kit.__version__,
        target_path=str(repo_root.resolve()),
        profile_id=profile.id,
        profile_title=profile.title,
        summary_by_status=_summarize(results),
        results=results,
        operational_warnings=operational_warnings,
        scorecard_path=scorecard.raw_path if scorecard else None,
        scorecard_supplemental=supplemental,
        external_waiver_path=external_waiver_path,
        live_collection=live_collection,
        weighted_score=weighted,
    )
