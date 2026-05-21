"""Orchestrate loading, evaluation, waivers, and report assembly."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import oss_policy_kit
from oss_policy_kit.adapters.scorecard_json import ScorecardBundle
from oss_policy_kit.application.clock import report_generated_at
from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY, EvalContext
from oss_policy_kit.application.evidence_placeholders import has_placeholder_values
from oss_policy_kit.application.loader import ControlSpec, ProfileSpec
from oss_policy_kit.application.waivers import WaiverParseOutcome
from oss_policy_kit.domain.errors import LoadError
from oss_policy_kit.domain.models import (
    ControlResult,
    ControlStatus,
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


def _hard_gate_evidence_warning(profile_id: str, repo_root: Path) -> str | None:
    """Build an operational warning when a hard-gate profile runs without real evidence.

    Returns a single warning string when ``profile_id`` is one of the L3 /
    release-hardening-3 profiles AND the target has no populated evidence
    (either ``.oss-policy-kit/evidence/`` is missing, has no JSON files, or
    every JSON file contains placeholder tokens). Returns ``None`` otherwise.
    """

    if profile_id not in _HARD_GATE_EVIDENCE_PROFILES:
        return None

    evidence_dir = repo_root / ".oss-policy-kit" / "evidence"
    if not evidence_dir.is_dir():
        has_real = False
    else:
        json_files = sorted(evidence_dir.glob("*.json"))
        if not json_files:
            has_real = False
        else:
            has_real = False
            for path in json_files:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if not has_placeholder_values(data):
                    has_real = True
                    break
    if has_real:
        return None

    return (
        f"Profile '{profile_id}' expects .oss-policy-kit/evidence/ to be populated by "
        "scaffold-evidence (then edited) or by collect-evidence. "
        "See docs/release-hardening-workflow.md."
    )


REPORT_JSON_SCHEMA_URL_V0_1 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/0.1"
REPORT_JSON_SCHEMA_URL_V0_2 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/0.2"
REPORT_JSON_SCHEMA_URL_V0_3 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/0.3"
REPORT_JSON_SCHEMA_URL_V1_0 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/1.0"
REPORT_JSON_SCHEMA_URL_V2_0 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0"


# v6.0.0 (V6-05, ADR-013): reports/2.0 contract maps the v5.x seven-state
# vocabulary into the Scorecard-v6 five-state vocabulary. The mapping is
# documented in docs/reports-contract-v2.0.md.
#
# v5.x status -> (v2.0 STATE, optional reason sub-field)
REPORTS_V2_STATUS_MAP: dict[str, tuple[str, str | None]] = {
    "pass": ("PASS", None),
    "fail": ("FAIL", None),
    "degraded": ("FAIL", None),  # consumers also read per-control 'degraded' flag
    "manual-review-required": ("UNKNOWN", "manual-review-required"),
    "not-applicable": ("NOT_APPLICABLE", None),
    "skipped": ("UNKNOWN", "skipped-by-flag"),
    "error": ("UNKNOWN", "evaluator-error"),
    "attested": ("ATTESTED", None),  # reserved for evidence-backed PROV-VERIFY-061 PASS in v6.0.0
}


def map_status_to_reports_v2(status: str) -> tuple[str, str | None]:
    """Map a v5.x status string to the (state, reason) pair of reports/2.0.

    See docs/reports-contract-v2.0.md for the full mapping table and the
    deprecation timeline (reports/1.0 is selectable in v6.0.x, removed in v6.1.0).
    """
    key = status.strip().lower()
    if key in REPORTS_V2_STATUS_MAP:
        return REPORTS_V2_STATUS_MAP[key]
    return ("UNKNOWN", "unmapped-source-status")


def report_json_schema_url(contract: str) -> str:
    """Return the full ``schema_version`` URL for an evaluation JSON report contract.

    v5.0.0 default: ``1.0``. Selectable: ``1.0``, ``0.3``, ``0.2``. Removed: ``0.1``.
    v6.0.0 (PR-16, V6-05): ``2.0`` selectable; planned default in a future v6.x.
    """

    c = contract.strip().lower().removeprefix("v")
    if c in {"", "1.0"}:
        return REPORT_JSON_SCHEMA_URL_V1_0
    if c == "2.0":
        return REPORT_JSON_SCHEMA_URL_V2_0
    if c == "0.3":
        return REPORT_JSON_SCHEMA_URL_V0_3
    if c == "0.2":
        return REPORT_JSON_SCHEMA_URL_V0_2
    if c == "0.1":
        raise LoadError(
            "Report JSON contract '0.1' was removed in v5.0.0. Use '1.0' (default), '2.0', '0.3', or '0.2'. "
            "See docs/v5.0.0-migration-guide.md."
        )
    raise LoadError(f"Unknown report JSON contract {contract!r}; expected '1.0', '2.0', '0.3', or '0.2'.")


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


_PASSING_STATUSES = frozenset({ControlStatus.PASS, ControlStatus.SELF_ATTESTED, ControlStatus.WAIVED})
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


def evaluate_repository(
    repo_root: Path,
    profile: ProfileSpec,
    catalog: dict[str, ControlSpec],
    waiver_outcome: WaiverParseOutcome | None,
    scorecard: ScorecardBundle | None,
    *,
    external_waiver_path: str | None = None,
    verbose_emit: Callable[[str], None] | None = None,
    # Programmatic default is kept at "0.3" for ExecutionReport callers that
    # were written against the v4.x report shape. The CLI, ``oss-policy-kit.yaml``
    # config loader, and ``init`` template all default to "1.0" — pass
    # ``report_json_contract="1.0"`` explicitly when invoking this engine
    # function from new code paths.
    report_json_contract: str = "0.3",
    live_collection: LiveCollectionMetadata | None = None,
) -> ExecutionReport:
    """Run all profile controls against a local repository clone."""

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
    )

    waivers = waiver_outcome.by_control if waiver_outcome else {}
    operational_warnings: list[str] = list(waiver_outcome.warnings if waiver_outcome else [])

    for wf_path, msg in workflows.parse_errors:
        operational_warnings.append(f"Workflow parse issue {wf_path.name}: {msg}")
    for az_path, msg in azure_pipelines.parse_errors:
        operational_warnings.append(f"Azure pipeline parse issue {az_path.name}: {msg}")
    for aws_path, msg in aws_ci.parse_errors:
        operational_warnings.append(f"AWS CI parse issue {aws_path.name}: {msg}")
    for gl_path, msg in gitlab_ci.parse_errors:
        operational_warnings.append(f"GitLab CI parse issue {gl_path.name}: {msg}")

    results: list[ControlResult] = []

    for cid in profile.control_ids:
        if cid not in catalog:
            raise LoadError(f"Profile references unknown control '{cid}'")
        spec = catalog[cid]
        evaluator = EVALUATOR_REGISTRY.get(cid)
        if evaluator is None:
            raise LoadError(f"No evaluator implemented for control '{cid}'")

        if ctx.verbose_emit is not None:
            ctx.verbose_emit(f"[dim]→ {cid} ({spec.title})[/dim]")
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
        if ctx.verbose_emit is not None:
            reason_one = outcome.reason.replace("\n", " ").strip()
            if len(reason_one) > 220:
                reason_one = reason_one[:217].rstrip() + "..."
            ctx.verbose_emit(f"[dim]  Result: {outcome.status.value} — {reason_one}[/dim]")
        waiver = waivers.get(cid)
        final_status, applied_waiver = _apply_waiver(outcome.status, waiver)

        expires_display = applied_waiver.expires_at if applied_waiver else None

        results.append(
            ControlResult(
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
                expires_at=expires_display,
                evidence_collection_method=outcome.evidence_collection_method.value,
                deprecation_note=spec.deprecation_note,
                weight=spec.weight,
            )
        )

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
