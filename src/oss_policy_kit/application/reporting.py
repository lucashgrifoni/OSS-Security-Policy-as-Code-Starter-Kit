"""Markdown and JSON report emission."""

from __future__ import annotations

import hashlib
import json
from io import StringIO
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from oss_policy_kit.application.drift import ControlDelta, DriftReport
from oss_policy_kit.application.evidence_projection import (
    EVIDENCE_PROVENANCE_VERSION,
    gate_role_for,
    normalize_confidence,
    project_evidence,
)
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, LiveCollectionMetadata

REPORT_JSON_SCHEMA_URL_V0_1 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/0.1"
REPORT_JSON_SCHEMA_URL_V0_2 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/0.2"
REPORT_JSON_SCHEMA_URL_V0_3 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/0.3"
REPORT_JSON_SCHEMA_URL_V1_0 = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/1.0"


def _effective_schema_version(report: ExecutionReport, schema_version_override: str | None) -> str:
    if schema_version_override is None:
        return report.schema_version
    o = schema_version_override.strip()
    if "reports/0.1" in o or o.rstrip("/").endswith("0.1"):
        return REPORT_JSON_SCHEMA_URL_V0_1
    if "reports/0.2" in o or o.rstrip("/").endswith("0.2"):
        return REPORT_JSON_SCHEMA_URL_V0_2
    if "reports/0.3" in o or o.rstrip("/").endswith("0.3"):
        return REPORT_JSON_SCHEMA_URL_V0_3
    if "reports/1.0" in o or o.rstrip("/").endswith("1.0"):
        return REPORT_JSON_SCHEMA_URL_V1_0
    return report.schema_version


def _emit_contract_v2(schema_version_effective: str) -> bool:
    # v0.2 and v0.3 share the same per-control extension fields (assurance, etc.).
    return "reports/0.2" in schema_version_effective or "reports/0.3" in schema_version_effective


def _emit_contract_v3(schema_version_effective: str) -> bool:
    return "reports/0.3" in schema_version_effective


def _emit_contract_v1_0(schema_version_effective: str) -> bool:
    return "reports/1.0" in schema_version_effective


def compute_summary_by_gate_role(summary_by_status: dict[str, int]) -> dict[str, int]:
    """Aggregate status counts under explicit CI-gate-focused roles (reports/0.3 extension)."""

    def _n(key: str) -> int:
        return int(summary_by_status.get(key, 0))

    out = {
        "ci_blocking_fail": _n("fail"),
        "human_review_gate": _n("manual-review-required"),
        "passed_observation": _n("pass"),
        "self_attested_declarative": _n("self-attested"),
        "not_evaluated_limit": _n("not-evaluated"),
        "waived": _n("waived"),
        "not_applicable": _n("not-applicable"),
        "not_observable": _n("not-observable"),
    }
    return {k: v for k, v in out.items() if v}


GATE_EXECUTION_MODEL_V1: dict[str, Any] = {
    "model_version": 1,
    "report_contract": "reports/0.3",
    "fail_on_semantics": {
        "none": {"exit_1_from_results": False},
        "fail": {
            "exit_1_when": "ci_blocking_fail > 0",
            "maps_to_summary_status": "fail",
        },
        "degraded": {
            "exit_1_when": "ci_blocking_fail > 0 OR human_review_gate > 0",
            "maps_to_summary_statuses": ["fail", "manual-review-required"],
        },
    },
    "trust_boundary_notes": [
        "`not-evaluated` never triggers fail-on by itself - it signals evaluation limits or missing evidence.",
        "`self-attested` is declarative and is not the same as verifier-backed pass.",
        "Waivers may convert `fail` to `waived` before summaries are computed.",
    ],
}


GATE_EXECUTION_MODEL_V2: dict[str, Any] = {
    "model_version": 2,
    "report_contract": "reports/1.0",
    "fail_on_semantics": {
        "none": {"exit_1_from_results": False},
        "fail": {
            "exit_1_when": "ci_blocking_fail > 0",
            "maps_to_summary_status": "fail",
        },
        "degraded": {
            "exit_1_when": "ci_blocking_fail > 0 OR human_review_gate > 0",
            "maps_to_summary_statuses": ["fail", "manual-review-required"],
        },
    },
    "trust_boundary_notes": [
        "`not-evaluated` never triggers fail-on by itself - it signals evaluation limits or missing evidence.",
        "`self-attested` is declarative and is not the same as verifier-backed pass.",
        "Waivers may convert `fail` to `waived` before summaries are computed.",
        "`assurance: signal` controls cannot project to `trust_level: verified` in the v1 evidence model.",
        "`evidence.freshness_status: stale` reduces trust to `declared` even when collection method is live.",
    ],
}


_GITHUB_PROFILE_PREFIX = "github-"
_AZURE_PROFILE_PREFIX = "azure-"
_AWS_PROFILE_PREFIX = "aws-"


def derive_profile_metadata(profile_id: str) -> dict[str, Any]:
    """Derive lightweight profile metadata from a profile id for reports/1.0.

    Falls back to ``None`` for fields that cannot be inferred from the id alone.
    Centralizing this in the reporting layer avoids coupling reports to the CLI
    profile-listing helpers.
    """

    pid = profile_id.strip()
    family: str | None = None
    if pid.startswith(_GITHUB_PROFILE_PREFIX):
        family = "github"
    elif pid.startswith(_AZURE_PROFILE_PREFIX):
        family = "azure"
    elif pid.startswith(_AWS_PROFILE_PREFIX):
        family = "aws"

    level: str | None = None
    for token in ("level-1", "level-2", "level-3"):
        if token in pid:
            level = "L" + token.split("-", 1)[1]
            break

    is_release_track = "release-hardening" in pid

    posture: str | None = None
    is_hybrid = pid.startswith(("github-aws-", "github-azure-"))
    if is_hybrid:
        posture = "multi_platform_advisory_hybrid"
    elif pid.endswith("-level-1") or pid.endswith("release-hardening-1"):
        posture = "starter"
    elif pid.endswith("-level-2"):
        posture = "advisory"
    elif pid.endswith("-level-3") or pid.endswith("release-hardening-3"):
        posture = "hard_gate"
    elif pid.endswith("release-hardening-2"):
        posture = "release_track"

    recommended_gate: str | None = None
    if posture in {"starter", "release_track", "hard_gate"} or is_release_track:
        recommended_gate = "--fail-on fail"
    elif posture in {"advisory", "multi_platform_advisory_hybrid"}:
        recommended_gate = "--fail-on none"

    return {
        "family": family,
        "level": level,
        "posture": posture,
        "is_release_track": is_release_track,
        "recommended_gate": recommended_gate,
    }


def compute_results_digest(results: list[ControlResult]) -> str:
    """Stable sha256 digest over canonical control-result fields.

    Covers the deterministic columns: ``control_id``, ``profile``, ``status``,
    ``lifecycle``, ``assurance``, ``weight``. Excludes free-form text (reason,
    remediation), evidence references, and timestamps so the digest is robust to
    cosmetic refactors and to evidence freshness changes.
    """

    canonical = []
    for r in sorted(results, key=lambda x: (x.profile, x.control_id)):
        canonical.append(
            {
                "control_id": r.control_id,
                "profile": r.profile,
                "status": r.status.value,
                "lifecycle": r.lifecycle,
                "assurance": r.assurance,
                "weight": r.weight,
            }
        )
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _live_collection_dict(lc: LiveCollectionMetadata | None) -> dict[str, Any] | None:
    if lc is None:
        return None
    return {
        "performed": lc.performed,
        "platform": lc.platform,
        "collected_at": lc.collected_at,
        "api_evidence_sources": list(lc.api_evidence_sources),
    }


def _structural_bucket(control_id: str) -> str:
    if control_id.startswith("GOV-") or control_id.startswith("REL-"):
        return "Governance and release artifacts (README, LICENSE, SECURITY, changelog)"
    if control_id.startswith("CI-") or control_id.startswith("GH-"):
        return "GitHub Actions CI/CD (workflows, permissions, pins)"
    if control_id.startswith("SEC-"):
        return "Security scanning and vulnerability management in CI"
    if control_id.startswith("PLAT-"):
        return "Platform settings (branch protection, .oss-policy-kit evidence)"
    if control_id.startswith("AZ-"):
        return "Azure Pipelines and related governance"
    if control_id.startswith("AWS-"):
        return "AWS CI/CD (buildspec, CodePipeline) and related governance"
    return "Other profile controls"


def compute_priority_insights(report: ExecutionReport) -> dict[str, Any]:
    """Derive grouped non-pass signals for Markdown / JSON consumers."""

    from collections import Counter

    actionable = [r for r in report.results if r.status in (ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED)]
    bucket_counts = Counter(_structural_bucket(r.control_id) for r in actionable)
    top_causes = [{"bucket": b, "count": n} for b, n in bucket_counts.most_common(5)]

    fails = [r for r in report.results if r.status in (ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED)]
    control_ids = {r.control_id for r in fails}
    actions: list[str] = []
    if "GOV-SEC-001" in control_ids:
        actions.append("Add SECURITY.md at the repo root with a monitored private reporting channel.")
    if "GOV-LIC-004" in control_ids:
        actions.append("Add a recognizable LICENSE file at the repository root.")
    if "GOV-CON-002" in control_ids:
        actions.append("Add CONTRIBUTING.md aligned with security expectations.")
    if "CI-WF-005" in control_ids:
        actions.append("Add workflows under .github/workflows for reproducible CI.")
    if "SEC-CODEQL-010" in control_ids:
        actions.append("Add SAST or code scanning in CI (CodeQL, Semgrep, Bandit, etc.).")
    if "CI-PERM-006" in control_ids:
        actions.append("Declare explicit permissions at the top of workflows.")
    if "CI-PIN-008" in control_ids:
        actions.append("Pin third-party actions to immutable SHAs or safe version tags.")
    if not actions and fails:
        actions.append("Address fail and manual-review-required controls in the detailed table below.")
    elif not fails:
        actions.append("Keep the repository aligned with the profile; review self-attested or not-observable items.")

    by_category: dict[str, list[str]] = {}
    for r in fails:
        by_category.setdefault(r.category, []).append(r.control_id)
    for k in by_category:
        by_category[k] = sorted(set(by_category[k]))

    return {
        "top_structural_causes": top_causes,
        "recommended_actions": actions[:5],
        "failing_controls_by_category": by_category,
    }


def _result_to_dict(r: ControlResult, *, contract_v2: bool) -> dict[str, Any]:
    d: dict[str, Any] = {
        "control_id": r.control_id,
        "title": r.title,
        "category": r.category,
        "status": r.status.value,
        "lifecycle": r.lifecycle,
        "profile": r.profile,
        "evidence_sources": r.evidence_sources,
        "confidence": r.confidence,
        "reason": r.reason,
        "remediation": r.remediation,
        "owner": r.owner,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        "extra": r.extra,
    }
    if r.waiver:
        d["waiver"] = {
            "control_id": r.waiver.control_id,
            "justification": r.waiver.justification,
            "owner": r.waiver.owner,
            "status": r.waiver.status,
            "expires_at": r.waiver.expires_at.isoformat() if r.waiver.expires_at else None,
            "applies_to": r.waiver.applies_to,
        }
    else:
        d["waiver"] = None
    if contract_v2:
        d["evidence_collection_method"] = r.evidence_collection_method
        d["assurance"] = r.assurance
        d["weight"] = r.weight
        if r.deprecation_note is not None:
            d["deprecation_note"] = r.deprecation_note
    return d


def _result_to_dict_v1(r: ControlResult) -> dict[str, Any]:
    """Project a ControlResult into the reports/1.0 control_result_v1 shape."""

    waiver_dict: dict[str, Any] | None = None
    if r.waiver:
        waiver_dict = {
            "control_id": r.waiver.control_id,
            "justification": r.waiver.justification,
            "owner": r.waiver.owner,
            "status": r.waiver.status,
            "expires_at": r.waiver.expires_at.isoformat() if r.waiver.expires_at else None,
            "applies_to": r.waiver.applies_to,
        }

    payload: dict[str, Any] = {
        "control_id": r.control_id,
        "title": r.title,
        "category": r.category,
        "lifecycle": r.lifecycle,
        "profile": r.profile,
        "status": r.status.value,
        "gate_role": gate_role_for(r.status),
        "assurance": r.assurance,
        "confidence": normalize_confidence(r.confidence),
        "weight": r.weight,
        "reason": r.reason,
        "remediation": r.remediation,
        "evidence": project_evidence(r),
        "owner": r.owner,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        "waiver": waiver_dict,
        "extra": dict(r.extra) if isinstance(r.extra, dict) else {},
    }
    if r.deprecation_note is not None:
        payload["deprecation_note"] = r.deprecation_note
    payload["finding_id"] = f"{r.control_id}@{r.profile}"
    return payload


def report_to_dict_v1(report: ExecutionReport) -> dict[str, Any]:
    """Serialize execution report under the reports/1.0 contract."""

    profile_meta = derive_profile_metadata(report.profile_id)
    profile_block = {
        "id": report.profile_id,
        "title": report.profile_title,
        "family": profile_meta["family"],
        "level": profile_meta["level"],
        "posture": profile_meta["posture"],
        "is_release_track": profile_meta["is_release_track"],
        "recommended_gate": profile_meta["recommended_gate"],
    }

    scorecard_block = {
        "path": report.scorecard_path,
        "supplemental": report.scorecard_supplemental,
    }

    weighted_score_block: dict[str, Any] | None = None
    if report.weighted_score is not None:
        weighted_score_block = {
            "earned": report.weighted_score.earned,
            "possible": report.weighted_score.possible,
            "percent": report.weighted_score.percent,
        }

    results_v1 = [_result_to_dict_v1(r) for r in report.results]

    payload: dict[str, Any] = {
        "schema_version": REPORT_JSON_SCHEMA_URL_V1_0,
        "evidence_provenance_version": EVIDENCE_PROVENANCE_VERSION,
        "generated_at": report.generated_at,
        "kit_version": report.kit_version,
        "target_path": report.target_path,
        "profile": profile_block,
        "summary_by_status": report.summary_by_status,
        "controls_total": sum(report.summary_by_status.values()),
        "summary_by_gate_role": compute_summary_by_gate_role(report.summary_by_status),
        "gate_execution_model": GATE_EXECUTION_MODEL_V2,
        "results": results_v1,
        "results_digest": compute_results_digest(report.results),
        "operational_warnings": report.operational_warnings,
        "scorecard": scorecard_block,
        "external_waiver_path": report.external_waiver_path,
        "action_insights": compute_priority_insights(report),
        "live_collection": _live_collection_dict(report.live_collection),
        "weighted_score": weighted_score_block,
        "migration": None,
        "extensions": {},
    }
    return payload


def report_to_dict(
    report: ExecutionReport,
    *,
    schema_version_override: str | None = None,
) -> dict[str, Any]:
    """Serialize execution report to a JSON-compatible dict.

    When *schema_version_override* is a string containing ``reports/0.1`` (or ends
    with ``0.1``), emit the legacy ``reports/0.1`` payload shape without v0.2-only keys,
    even if the in-memory report object targets ``reports/0.2``.

    When *schema_version_override* targets ``reports/1.0``, dispatch to the v1
    projection which uses a structured ``evidence`` object per result.
    """

    effective = _effective_schema_version(report, schema_version_override)
    if _emit_contract_v1_0(effective):
        return report_to_dict_v1(report)
    contract_v2 = _emit_contract_v2(effective)
    payload: dict[str, Any] = {
        "schema_version": effective,
        "generated_at": report.generated_at,
        "kit_version": report.kit_version,
        "target_path": report.target_path,
        "profile_id": report.profile_id,
        "profile_title": report.profile_title,
        "summary_by_status": report.summary_by_status,
        "results": [_result_to_dict(r, contract_v2=contract_v2) for r in report.results],
        "operational_warnings": report.operational_warnings,
        "scorecard_path": report.scorecard_path,
        "scorecard_supplemental": report.scorecard_supplemental,
        "external_waiver_path": report.external_waiver_path,
        "action_insights": compute_priority_insights(report),
    }
    if contract_v2:
        payload["live_collection"] = _live_collection_dict(report.live_collection)
        if report.weighted_score is not None:
            ws = report.weighted_score
            payload["weighted_score"] = {
                "earned": ws.earned,
                "possible": ws.possible,
                "percent": ws.percent,
            }
    if _emit_contract_v3(effective):
        payload["summary_by_gate_role"] = compute_summary_by_gate_role(report.summary_by_status)
        payload["gate_execution_model"] = GATE_EXECUTION_MODEL_V1
    return payload


def write_json_report(
    report: ExecutionReport,
    path: Path,
    *,
    schema_version_override: str | None = None,
) -> None:
    """Write evaluation-report.json."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = report_to_dict(report, schema_version_override=schema_version_override)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_markdown_report(report: ExecutionReport, path: Path) -> None:
    """Write evaluation-report.md."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# OSS Policy Kit - evaluation report")
    lines.append("")
    lines.append(f"- **Generated (UTC)**: `{report.generated_at}`")
    lines.append(f"- **Kit version**: `{report.kit_version}`")
    lines.append(f"- **Target**: `{report.target_path}`")
    lines.append(f"- **Profile**: `{report.profile_id}` - {report.profile_title}")
    if report.scorecard_path:
        lines.append(f"- **Scorecard file**: `{report.scorecard_path}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("| --- | ---: |")
    for k, v in report.summary_by_status.items():
        lines.append(f"| `{k}` | {v} |")
    lines.append("")
    if _emit_contract_v3(report.schema_version):
        lines.append("### Gate-oriented summary (reports/0.3)")
        lines.append("")
        lines.append(
            "Explicit gate roles complement `summary_by_status`. "
            "`ci_blocking_fail` aligns with `--fail-on fail`; "
            "`human_review_gate` contributes only when `--fail-on degraded`."
        )
        lines.append("")
        lines.append("| Gate role | Count |")
        lines.append("| --- | ---: |")
        for k, v in compute_summary_by_gate_role(report.summary_by_status).items():
            lines.append(f"| `{k}` | {v} |")
        lines.append("")
    if report.weighted_score is not None:
        ws = report.weighted_score
        lines.append("## Weighted posture score")
        lines.append("")
        lines.append(
            f"**{ws.earned} / {ws.possible} points ({ws.percent}%)** — risk-adjusted score based on control weights "
            f"(critical=3, high=2, medium=1). Controls with status `not-applicable` or `not-evaluated` are excluded."
        )
        lines.append("")
    insights = compute_priority_insights(report)
    lines.append("## Prioritization (structural causes)")
    lines.append("")
    lines.append("### Top structural buckets")
    lines.append("")
    for row in insights["top_structural_causes"][:5]:
        b, n = row["bucket"], row["count"]
        lines.append(f"- **{b}** — {n} control(s) failing or requiring manual review in this bucket.")
    if not insights["top_structural_causes"]:
        lines.append("- (no aggregated structural findings in this run)")
    lines.append("")
    lines.append("### Recommended next actions")
    lines.append("")
    for item in insights["recommended_actions"][:5]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Failing controls by category")
    lines.append("")
    if insights["failing_controls_by_category"]:
        for cat, ids in sorted(insights["failing_controls_by_category"].items()):
            lines.append(f"- **{cat}**: {', '.join(f'`{i}`' for i in ids)}")
    else:
        lines.append("- (no controls in `fail` or `manual-review-required`)")
    lines.append("")
    lines.append("## Waivers and trust boundary")
    lines.append("")
    lines.append(
        "This evaluation only observes what is visible in a local clone (plus optional evidence under "
        "`.oss-policy-kit/evidence/`). It **does not** replace human audit or prove absence of risk."
    )
    lines.append("")
    if report.external_waiver_path:
        lines.append(
            f"- **External waiver file loaded for this run** (`--waivers`): `{report.external_waiver_path}`. "
            "That file is **not** the same as **versioned in-repo** waiver policy."
        )
        lines.append(
            "- Control `GOV-WAIV-014` specifically checks for a waiver policy file **inside the clone** "
            "(for example `waivers/waivers.yaml`). It may therefore stay `not-evaluated` when no in-repo "
            "waiver file exists even when `--waivers` waives other controls."
        )
    else:
        lines.append(
            "- No external waiver file was passed via `--waivers` in this run. "
            "`GOV-WAIV-014` continues to evaluate **versioned in-repo** waivers only."
        )
    lines.append("")
    if report.operational_warnings:
        lines.append("## Operational warnings")
        lines.append("")
        for w in report.operational_warnings:
            lines.append(f"- {w}")
        lines.append("")
    if report.scorecard_supplemental:
        lines.append("## Scorecard supplemental")
        lines.append("")
        ss = report.scorecard_supplemental
        lines.append(f"- **Loaded**: `{ss.get('loaded')}`")
        lines.append(f"- **Check count**: {ss.get('check_count')}")
        influenced = ss.get("influenced_control_ids") or []
        if influenced:
            lines.append(f"- **Influenced controls**: {', '.join(f'`{c}`' for c in influenced)}")
        else:
            lines.append("- **Influenced controls**: (none in this run)")
        lines.append(f"- **Workflows satisfied CodeQL signal**: `{ss.get('workflows_satisfied_codeql_signal')}`")
        lines.append(f"- **Explanation**: {ss.get('explanation', '')}")
        lines.append("")
    lines.append("## Controls")
    lines.append("")
    lines.append("| ID | Category | Lifecycle | Assurance | Status | Confidence | Reason | Remediation | Waiver |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in report.results:
        w = ""
        if r.waiver:
            w = f"yes ({r.waiver.owner})"
        reason = r.reason.replace("|", "\\|")
        rem = r.remediation.replace("|", "\\|")
        row = (
            f"| `{r.control_id}` | {r.category} | {r.lifecycle} | `{r.assurance}` |"
            f" `{r.status.value}` | {r.confidence} | {reason} | {rem} | {w} |"
        )
        lines.append(row)
    lines.append("")
    lines.append("## Detail")
    lines.append("")
    for r in report.results:
        lines.append(f"### `{r.control_id}` - {r.title}")
        lines.append("")
        lines.append(f"- **Status**: `{r.status.value}`")
        lines.append(f"- **Lifecycle**: {r.lifecycle}")
        lines.append(f"- **Assurance**: `{r.assurance}`")
        lines.append(f"- **Evidence collection method**: `{r.evidence_collection_method}`")
        lines.append(f"- **Confidence**: {r.confidence}")
        lines.append(f"- **Reason**: {r.reason}")
        lines.append(f"- **Remediation**: {r.remediation}")
        if r.evidence_sources:
            lines.append("- **Evidence**:")
            for e in r.evidence_sources:
                lines.append(f"  - `{e}`")
        if r.waiver:
            lines.append("- **Waiver**:")
            lines.append(f"  - **Owner**: {r.waiver.owner}")
            lines.append(f"  - **Justification**: {r.waiver.justification}")
            if r.waiver.expires_at:
                lines.append(f"  - **Expires**: {r.waiver.expires_at.isoformat()}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_reports(
    report: ExecutionReport,
    output_dir: Path,
    *,
    schema_version_override: str | None = None,
) -> tuple[Path, Path]:
    """Write JSON and Markdown reports; return paths."""

    json_path = output_dir / "evaluation-report.json"
    md_path = output_dir / "evaluation-report.md"
    write_json_report(report, json_path, schema_version_override=schema_version_override)
    write_markdown_report(report, md_path)
    return json_path, md_path


def _control_delta_dict(d: ControlDelta) -> dict[str, Any]:
    return {
        "control_id": d.control_id,
        "title": d.title,
        "before_status": d.before_status,
        "after_status": d.after_status,
        "is_regression": d.is_regression,
    }


def _drift_report_dict(report: DriftReport) -> dict[str, Any]:
    return {
        "before_path": report.before_path,
        "after_path": report.after_path,
        "before_kit_version": report.before_kit_version,
        "after_kit_version": report.after_kit_version,
        "regressions": [_control_delta_dict(x) for x in report.regressions],
        "improvements": [_control_delta_dict(x) for x in report.improvements],
        "new_controls": list(report.new_controls),
        "removed_controls": list(report.removed_controls),
        "expired_waivers": list(report.expired_waivers),
        "has_regressions": report.has_regressions,
        "profile_mismatch": report.profile_mismatch,
        "before_profile_id": report.before_profile_id,
        "after_profile_id": report.after_profile_id,
    }


def render_drift_report(report: DriftReport, fmt: str, *, color: bool = True) -> str:
    """Render a :class:`~oss_policy_kit.application.drift.DriftReport` for stdout or files.

    Args:
        report: Drift summary from :func:`~oss_policy_kit.application.drift.compute_drift`.
        fmt: ``table`` (default Rich layout), ``json``, or ``markdown`` / ``md``.
        color: Whether ANSI colors should be emitted for ``table`` format.

    Returns:
        Serialized representation as a single string (UTF-8 text).
    """

    f = fmt.strip().lower()
    if f == "json":
        return json.dumps(_drift_report_dict(report), indent=2, ensure_ascii=False) + "\n"
    if f in {"markdown", "md"}:
        lines = [
            "# Drift report",
            "",
        ]
        if report.profile_mismatch:
            lines.extend(
                [
                    "> **Note:** Before profile "
                    f"(`{report.before_profile_id}`) differs from after profile (`{report.after_profile_id}`). "
                    "New or removed controls may reflect profile scope change, not posture change.",
                    "",
                ]
            )
        lines.extend(
            [
                f"- **Before**: `{report.before_path}`",
                f"- **After**: `{report.after_path}`",
                f"- **Kit versions**: {report.before_kit_version} → {report.after_kit_version}",
                f"- **Regressions**: {len(report.regressions)}",
                f"- **Improvements**: {len(report.improvements)}",
                "",
                "## Regressions",
                "",
                "| Control | Before | After |",
                "| --- | --- | --- |",
            ]
        )
        for d in report.regressions:
            lines.append(f"| `{d.control_id}` | `{d.before_status}` | `{d.after_status}` |")
        lines.extend(["", "## Improvements", "", "| Control | Before | After |", "| --- | --- | --- |"])
        for d in report.improvements:
            lines.append(f"| `{d.control_id}` | `{d.before_status}` | `{d.after_status}` |")
        if report.new_controls:
            lines.extend(["", "## New controls in after", ""])
            lines.extend(f"- `{c}`" for c in report.new_controls)
        if report.removed_controls:
            lines.extend(["", "## Removed controls (present only in before)", ""])
            lines.extend(f"- `{c}`" for c in report.removed_controls)
        if report.expired_waivers:
            lines.extend(["", "## Expired waivers", ""])
            lines.extend(f"- `{c}`" for c in report.expired_waivers)
        return "\n".join(lines) + "\n"

    buf = StringIO()
    console = Console(file=buf, width=120, force_terminal=color, color_system=("standard" if color else None))
    table = Table(title="Posture drift — regressions (red) and improvements (green)")
    table.add_column("Kind", style="bold")
    table.add_column("Control")
    table.add_column("Before")
    table.add_column("After")
    for d in report.regressions:
        table.add_row("[red]regression[/red]", d.control_id, d.before_status, d.after_status)
    for d in report.improvements:
        table.add_row("[green]improve[/green]", d.control_id, d.before_status, d.after_status)
    if not report.regressions and not report.improvements:
        table.add_row("—", "(no status changes on shared controls)", "", "")
    console.print(table)
    if report.new_controls:
        console.print(f"[cyan]New in after:[/cyan] {', '.join(report.new_controls)}")
    if report.removed_controls:
        console.print(f"[yellow]Removed:[/yellow] {', '.join(report.removed_controls)}")
    if report.expired_waivers:
        console.print(f"[magenta]Expired waivers:[/magenta] {', '.join(report.expired_waivers)}")
    return buf.getvalue()
