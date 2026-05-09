"""Per-control local evaluators (filesystem + workflow static analysis)."""

from __future__ import annotations

import contextlib
import importlib.metadata
import importlib.resources as ir
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from oss_policy_kit.adapters.scorecard_json import ScorecardBundle, checks_as_map
from oss_policy_kit.application.evidence_placeholders import has_placeholder_values, is_placeholder_digest
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

NO_AZURE_PIPELINES_REASON = "No Azure pipeline files present."
NO_AWS_BUILDSPEC_REASON = "No AWS buildspec files present in supported paths."

_STRICT_AWS_SECRET_PROFILE_IDS = frozenset(
    {
        "aws-level-2",
        "aws-release-hardening-2",
        "aws-level-3",
        "aws-release-hardening-3",
    }
)

_STRICT_AWS_CODEBUILD_PROJECT_PROFILE_IDS = frozenset({"aws-level-3", "aws-release-hardening-3"})

# Evidence older than this many days is treated as stale for GOV-EVIDFRESH-054.
_EVIDENCE_MAX_AGE_DAYS: int = 90
# When remaining freshness drops below this window, emit an operational warning (still PASS if under max age).
_EVIDENCE_EXPIRY_WARN_DAYS: int = 14

_KEYWORD_CI_SIGNAL_WARN = (
    "Signal detected via keyword match; verify in CI execution logs or add platform evidence for hard-gate use."
)
_SUPPLEMENTAL_SIGNAL_WARN = (
    "Signal came from supplemental evidence only; "
    "prefer in-repo workflow evidence or API-backed collection for hard gates."
)

# Required protection flags (must be true) after JSON Schema validation of the evidence file.
_REQUIRED_BRANCH_PROTECTION_FLAGS = (
    "require_pull_request_reviews",
    "dismiss_stale_reviews",
    "require_status_checks",
    "enforce_admins",
    "restrict_force_push",
)


def _branch_protection_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-branch-protection.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _rulesets_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-github-rulesets.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _environment_protection_schema() -> dict[str, Any]:
    raw = (
        ir.files("oss_policy_kit.data.schema")
        .joinpath("evidence-github-environment-protection.schema.json")
        .read_bytes()
    )
    return cast(dict[str, Any], json.loads(raw))


def _secret_scanning_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-github-secret-scanning.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _azure_branch_policies_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-azure-branch-policies.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _azure_pipeline_governance_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-azure-pipeline-governance.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _azure_sbom_artifact_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-azure-sbom-artifact.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _azure_provenance_artifact_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-azure-provenance-artifact.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


_AZURE_BP_SUPPORT_KEYS = frozenset({"policies_api_reachable"})
_AZURE_GOV_SUPPORT_KEYS = frozenset(
    {
        "pipelines_api_reachable",
        "environments_api_reachable",
        "service_endpoints_api_verified",
        "environment_approval_checks_observable",
    }
)


def _azure_branch_policies_api_support_complete(data: dict[str, Any]) -> bool:
    sup = data.get("posture_support")
    if not isinstance(sup, dict):
        return False
    return _AZURE_BP_SUPPORT_KEYS.issubset(sup.keys()) and all(sup.get(k) is True for k in _AZURE_BP_SUPPORT_KEYS)


def _azure_pipeline_governance_api_support_complete(data: dict[str, Any]) -> bool:
    sup = data.get("posture_support")
    if not isinstance(sup, dict):
        return False
    return _AZURE_GOV_SUPPORT_KEYS.issubset(sup.keys()) and all(sup.get(k) is True for k in _AZURE_GOV_SUPPORT_KEYS)


def _aws_codebuild_project_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-aws-codebuild-project.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _aws_codepipeline_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-aws-codepipeline.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _aws_codecommit_review_schema() -> dict[str, Any]:
    raw = (
        ir.files("oss_policy_kit.data.schema")
        .joinpath("evidence-aws-codecommit-review-posture.schema.json")
        .read_bytes()
    )
    return cast(dict[str, Any], json.loads(raw))


def _aws_sbom_artifact_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-aws-sbom-artifact.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _aws_provenance_artifact_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-aws-provenance-artifact.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _github_provenance_artifact_schema() -> dict[str, Any]:
    raw = (
        ir.files("oss_policy_kit.data.schema").joinpath("evidence-github-provenance-artifact.schema.json").read_bytes()
    )
    return cast(dict[str, Any], json.loads(raw))


def _audit_log_streaming_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-audit-log-streaming.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _runner_groups_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-runner-groups.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _release_archival_policy_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-release-archival-policy.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _evidence_is_api_backed(data: dict[str, Any]) -> bool:
    """True when JSON was produced by ``collect-evidence`` / cloud API collection (not manual scaffold)."""

    att = str(data.get("attested_by", "")).strip().lower()
    if att in ("aws-api-collection", "azure-devops-api-collection", "github-api-collection"):
        return True
    coll = data.get("collection")
    if isinstance(coll, dict):
        if str(coll.get("evidence_collection_method", "")).strip().lower() == "live":
            return True
        if str(coll.get("mode", "")).strip().lower() == "api":
            return True
    return False


@dataclass(slots=True)
class EvalContext:
    """Inputs for a single control evaluation."""

    repo_root: Path
    profile_id: str
    workflows: WorkflowAnalysis
    azure_pipelines: AzurePipelineAnalysis
    aws_ci: AwsCiAnalysis
    scorecard: ScorecardBundle | None
    verbose_emit: Callable[[str], None] | None = None
    #: Max age (days) before evidence JSON under .oss-policy-kit/evidence is considered stale
    #: by GOV-EVIDFRESH-054. Override per invocation to tighten or relax freshness requirements.
    evidence_max_age_days: int = 90


def _exists_ci_readme(repo: Path) -> bool:
    p = repo / ".github" / "workflows" / "README.md"
    return p.is_file()


def _has_changelog(repo: Path) -> bool:
    names = [
        repo / "CHANGELOG.md",
        repo / "CHANGES.md",
        repo / "docs" / "CHANGELOG.md",
        repo / ".github" / "RELEASE.md",
    ]
    return any(p.is_file() for p in names)


def _has_license(repo: Path) -> bool:
    for p in repo.iterdir():
        if not p.is_file():
            continue
        n = p.name.lower()
        if n.startswith("license") or n == "copying":
            return True
    return False


def _has_codeowners(repo: Path) -> bool:
    return (repo / "CODEOWNERS").is_file() or (repo / ".github" / "CODEOWNERS").is_file()


def _read_security(repo: Path) -> str | None:
    for name in ("SECURITY.md", "security.md"):
        p = repo / name
        if p.is_file():
            return p.read_text(encoding="utf-8", errors="replace")
    return None


def _has_placeholder_security_contact(text: str) -> bool:
    lower = text.lower()
    markers = (
        "update this file with a working contact",
        "placeholder",
        "todo",
        "tbd",
    )
    return any(marker in lower for marker in markers)


def eval_gov_sec_001(ctx: EvalContext) -> EvalOutcome:
    text = _read_security(ctx.repo_root)
    if text is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="SECURITY.md present.",
            remediation="Keep SECURITY.md current and linked from the repository README.",
            evidence_sources=[str((ctx.repo_root / "SECURITY.md").resolve())],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="SECURITY.md not found at repository root.",
        remediation="Add SECURITY.md describing supported versions and how to report vulnerabilities.",
        evidence_sources=[],
        confidence="high",
    )


def eval_gov_con_002(ctx: EvalContext) -> EvalOutcome:
    for name in ("CONTRIBUTING.md", "CONTRIBUTING", "docs/CONTRIBUTING.md"):
        p = ctx.repo_root / name
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Contributing guide present.",
                remediation="Keep contribution expectations and security expectations aligned.",
                evidence_sources=[str(p.resolve())],
                confidence="high",
            )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="CONTRIBUTING guide not found.",
        remediation="Add CONTRIBUTING.md with workflow, review expectations, and security notes.",
        evidence_sources=[],
        confidence="high",
    )


def eval_gov_cown_003(ctx: EvalContext) -> EvalOutcome:
    if _has_codeowners(ctx.repo_root):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="CODEOWNERS file present.",
            remediation="Review CODEOWNERS coverage for critical paths.",
            evidence_sources=[],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="CODEOWNERS not found at .github/CODEOWNERS or repository root.",
        remediation="Add CODEOWNERS to route reviews for sensitive areas.",
        evidence_sources=[],
        confidence="high",
    )


def eval_gov_lic_004(ctx: EvalContext) -> EvalOutcome:
    if _has_license(ctx.repo_root):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="LICENSE (or COPYING) file detected.",
            remediation="Ensure LICENSE matches declared SPDX and distribution intent.",
            evidence_sources=[],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No LICENSE file detected at repository root.",
        remediation="Add a LICENSE file consistent with your SPDX identifier.",
        evidence_sources=[],
        confidence="high",
    )


def eval_ci_wf_005(ctx: EvalContext) -> EvalOutcome:
    if ctx.workflows.workflow_paths:
        srcs = [str(p.resolve()) for p in ctx.workflows.workflow_paths]
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Found {len(srcs)} workflow file(s).",
            remediation="Keep CI workflows minimal, pinned, and least-privilege.",
            evidence_sources=srcs,
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No workflows under .github/workflows.",
        remediation="Add a CI workflow for build/test on pull requests.",
        evidence_sources=[],
        confidence="high",
    )


def eval_ci_perm_006(ctx: EvalContext) -> EvalOutcome:
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows to evaluate.",
            remediation="Add workflows with explicit top-level permissions.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.missing_top_level_permissions:
        names = ", ".join(p.name for p in ctx.workflows.missing_top_level_permissions)
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Workflows missing top-level permissions: {names}",
            remediation="Declare top-level `permissions:` with the narrowest scope required.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.missing_top_level_permissions],
            confidence="medium",
        )
    if ctx.workflows.parse_errors:
        pe_names = ", ".join(sorted({p.name for p, _ in ctx.workflows.parse_errors}))
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"One or more workflow files could not be parsed ({pe_names}); "
                "top-level permissions could not be confirmed for all workflows."
            ),
            remediation="Fix YAML syntax errors, then re-run evaluation for structured permissions analysis.",
            evidence_sources=[str(p.resolve()) for p, _ in ctx.workflows.parse_errors],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="All workflows declare top-level permissions.",
        remediation="Re-audit permissions when adding new jobs.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_ci_danger_007(ctx: EvalContext) -> EvalOutcome:
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Avoid pull_request_target unless strictly required and reviewed.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.uses_pull_request_target:
        names = ", ".join(p.name for p in ctx.workflows.uses_pull_request_target)
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"pull_request_target detected in: {names}",
            remediation="Remove pull_request_target or restrict to audited, minimal patterns; prefer pull_request.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.uses_pull_request_target],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No pull_request_target detected in workflows.",
        remediation="Continue avoiding pull_request_target unless necessary.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_ci_pin_008(ctx: EvalContext) -> EvalOutcome:
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Pin third-party actions to full commit SHAs.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.mutable_action_refs:
        sample = ctx.workflows.mutable_action_refs[0]
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Mutable action references (tags/branches) detected.",
            remediation="Pin actions to immutable SHAs (40-char commit) from trusted repos.",
            evidence_sources=[f"{sample[0].name}: {sample[1]}"],
            confidence="medium",
        )
    if ctx.workflows.parse_errors:
        pe_names = ", ".join(sorted({p.name for p, _ in ctx.workflows.parse_errors}))
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "No obvious mutable third-party action pins detected in a raw `uses:` scan. "
                f"YAML parse errors limited structural validation ({pe_names}); "
                "treat pinning posture as lower confidence."
            ),
            remediation="Fix YAML parse errors, then re-check action pins with structured workflow analysis.",
            evidence_sources=[str(p.resolve()) for p, _ in ctx.workflows.parse_errors],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No obvious mutable third-party action pins detected.",
        remediation="Re-check when editing workflows; verify transitive action versions.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_ci_least_009(ctx: EvalContext) -> EvalOutcome:
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Avoid workflow-wide contents:write unless required.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.suspicious_permissions:
        item = ctx.workflows.suspicious_permissions[0]
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Broad workflow permissions in {item[0].name}: {item[1]}",
            remediation="Narrow permissions; prefer job-level permissions scoped to the minimum.",
            evidence_sources=[str(item[0].resolve())],
            confidence="medium",
        )
    if ctx.workflows.implicit_permission_risks:
        wf, job, detail = ctx.workflows.implicit_permission_risks[0]
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Implicit broad-permissions risk in {wf.name} ({job}): {detail}",
            remediation=(
                "Add explicit `permissions:` on the affected job (or narrow workflow-level defaults) "
                "when using checkout tokens, image pushes, releases, or cloud deploy steps."
            ),
            evidence_sources=[str(wf.resolve())],
            confidence="medium",
        )
    if ctx.workflows.parse_errors:
        pe_names = ", ".join(sorted({p.name for p, _ in ctx.workflows.parse_errors}))
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"One or more workflow files could not be parsed ({pe_names}); "
                "workflow-wide permission posture could not be confirmed for all files."
            ),
            remediation="Fix YAML syntax errors, then re-run evaluation for structured permissions analysis.",
            evidence_sources=[str(p.resolve()) for p, _ in ctx.workflows.parse_errors],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No obviously over-broad workflow permissions detected.",
        remediation="Review permissions when adding publishing or release jobs.",
        evidence_sources=[],
        confidence="medium",
    )


_CODEQL_ACTION_PATTERNS = (
    "github/codeql-action/analyze",
    "github/codeql-action/autobuild",
    "github/codeql-action/init",
)


def eval_sec_codeql_010(ctx: EvalContext) -> EvalOutcome:
    # Check for a dedicated CodeQL workflow file — highest confidence signal.
    codeql_dedicated: list[Path] = []
    for p in ctx.workflows.workflow_paths:
        name_lower = p.name.lower()
        if "codeql" in name_lower or "code-scanning" in name_lower:
            codeql_dedicated.append(p)
    if codeql_dedicated:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Dedicated CodeQL / code-scanning workflow detected: {', '.join(p.name for p in codeql_dedicated)}.",  # noqa: E501
            remediation="Keep CodeQL workflow pinned and ensure it runs on PRs and default-branch pushes.",
            evidence_sources=[str(p.resolve()) for p in codeql_dedicated],
            confidence="high",
        )
    # Check for explicit github/codeql-action/analyze usage in any workflow.
    for p in ctx.workflows.workflow_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace")
            if any(pat in text for pat in _CODEQL_ACTION_PATTERNS):
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=f"github/codeql-action usage detected in {p.name}.",
                    remediation="Keep the CodeQL action pinned to an immutable SHA.",
                    evidence_sources=[str(p.resolve())],
                    confidence="high",
                )
    # Broader SAST signal (any tool keyword).
    if ctx.workflows.sast_ci_signals:
        joined = ", ".join(ctx.workflows.sast_ci_signals)
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"SAST or security scanning signal in CI workflows: {joined}.",
            remediation="Keep scanning jobs pinned, scoped, and aligned with org AppSec policy.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.workflow_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    # Scorecard supplemental fallback.
    scm = checks_as_map(ctx.scorecard)
    for name in scm:
        n = name.lower()
        if "codeql" in n or "code-ql" in n or "sast" in n:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Scorecard export references static analysis related checks (supplemental).",
                remediation="Prefer an explicit CodeQL workflow in-repo for deterministic CI evidence.",
                evidence_sources=[ctx.scorecard.raw_path or "scorecard"] if ctx.scorecard else [],
                confidence="low",
                operational_warnings=(_SUPPLEMENTAL_SIGNAL_WARN,),
            )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No CodeQL (or equivalent) signal in local workflows.",
        remediation="Add GitHub CodeQL workflow or equivalent SAST in CI.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_sec_deprev_011(ctx: EvalContext) -> EvalOutcome:
    if ctx.workflows.has_dependency_review:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="dependency-review-action detected in workflows.",
            remediation="Keep dependency review enabled for pull requests.",
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No dependency-review-action detected in workflows.",
        remediation="Add GitHub Dependency Review to pull request workflows.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_rel_change_012(ctx: EvalContext) -> EvalOutcome:
    if _has_changelog(ctx.repo_root):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Changelog or release notes file detected.",
            remediation="Keep changelog entries aligned with semver and releases.",
            evidence_sources=[],
            confidence="high",
        )
    if _exists_ci_readme(ctx.repo_root):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No changelog file; workflows README present - verify release notes process.",
            remediation="Add CHANGELOG.md or document release notes process in docs/.",
            evidence_sources=[str((ctx.repo_root / ".github/workflows/README.md").resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No CHANGELOG-style file detected.",
        remediation="Add CHANGELOG.md and reference it from releases.",
        evidence_sources=[],
        confidence="high",
    )


def _gov_disc_013_private_reporting_signals(lower: str) -> bool:
    """Return True when SECURITY.md text strongly suggests a private reporting path."""

    if any(
        k in lower
        for k in (
            "security@",
            "mailto:",
            "private vulnerability reporting",
            "report a vulnerability",
            "private report via github",
            "hackerone",
            "bugcrowd",
            "huntr",
        )
    ):
        return True
    # GitHub Security Advisories wording alone is not a private channel; require explicit private-reporting context.
    ghsa = "github security advis" in lower
    if ghsa and any(
        p in lower
        for p in (
            "private report",
            "report privately",
            "privately report",
            "private vulnerability",
            "do not open a public issue",
            "before public disclosure",
            "security@",
            "mailto:",
        )
    ):
        return True
    disclosure_en = "responsible disclosure" in lower or "coordinated disclosure" in lower
    if disclosure_en and any(x in lower for x in ("privat", "privad", "mailto:", "security@", "canal")):
        return True
    # Portuguese: inequivocal private / coordinated reporting phrasing
    if any(
        phrase in lower
        for phrase in (
            "canal privado",
            "relatorio privado",
            "relatório privado",
            "reporte privado",
            "relato privado",
            "reporte responsável",
            "reporte responsavel",
        )
    ):
        return True
    div_pt = "divulgacao responsavel" in lower or "divulgação responsável" in lower
    return div_pt and any(x in lower for x in ("privad", "privat", "canal", "email", "mailto:", "security@"))


def eval_gov_disc_013(ctx: EvalContext) -> EvalOutcome:
    text = _read_security(ctx.repo_root)
    if text is None:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="SECURITY.md missing; cannot evaluate disclosure reporting mechanism.",
            remediation="Add SECURITY.md with a clear reporting channel (email or form).",
            evidence_sources=[],
            confidence="high",
        )
    lower = text.lower()
    if _has_placeholder_security_contact(text):
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="SECURITY.md contains placeholder disclosure guidance instead of a real private reporting channel.",
            remediation=(
                "Replace placeholder text with a monitored private reporting channel "
                "such as security email or GitHub private vulnerability reporting."
            ),
            evidence_sources=[],
            confidence="high",
        )
    if _gov_disc_013_private_reporting_signals(lower):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "SECURITY.md includes private disclosure/reporting cues "
                "(heuristic text signal; channel monitoring is not validated from clone-only evidence)."
            ),
            remediation="Ensure the reporting channel is monitored and SLA-aligned.",
            evidence_sources=[],
            confidence="low",
            operational_warnings=(_SUPPLEMENTAL_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="SECURITY.md present but no explicit private reporting channel detected by heuristics.",
        remediation="Document how researchers should report issues privately before public disclosure.",
        evidence_sources=[],
        confidence="low",
    )


def _github_workflow_raw_suggests_release_or_deploy(raw: str) -> bool:
    lower = raw.lower()
    if re.search(r"(^|\n)\s*release\s*:", raw) or re.search(r"\bon\s*:\s*\n?\s*release\b", lower):
        return True
    push_main = "push" in lower and ("branches:" in lower or "branches :" in lower)
    push_main = push_main and ("main" in lower or "master" in lower)
    deploy_keywords = (
        "publish",
        "deploy",
        "upload-release-asset",
        "gh release",
        "npm publish",
        "pypa/gh-action-pypi-publish",
        "actions/create-release",
    )
    return push_main and any(k in lower for k in deploy_keywords)


def _any_github_workflow_suggests_release_or_deploy(ctx: EvalContext) -> bool:
    for p in ctx.workflows.workflow_paths:
        with contextlib.suppress(OSError):
            if _github_workflow_raw_suggests_release_or_deploy(p.read_text(encoding="utf-8", errors="replace")):
                return True
    return False


_LONG_LIVED_CLOUD_SECRET_SNIPPETS: tuple[str, ...] = (
    "${{ secrets.AWS_SECRET_ACCESS_KEY }}",
    "${{ secrets.AWS_ACCESS_KEY_ID }}",
    "${{ secrets.AZURE_CLIENT_SECRET }}",
    "${{ secrets.GCP_SA_KEY }}",
)


def _workflow_text_has_long_lived_cloud_secret(text: str) -> bool:
    lower = text.lower()
    for snippet in _LONG_LIVED_CLOUD_SECRET_SNIPPETS:
        if snippet.lower() in lower:
            return True
    for m in re.finditer(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", text):
        name_u = m.group(1).upper()
        for frag in ("SECRET_KEY", "CLIENT_SECRET", "SA_KEY", "ACCESS_KEY"):
            if frag in name_u:
                return True
    return False


_REUSABLE_WORKFLOW_USES_LINE = re.compile(
    r"^\s*uses:\s*([^\s#]+)",
    re.MULTILINE | re.IGNORECASE,
)


def _reusable_workflow_ref_has_full_sha(ref: str) -> bool:
    r = ref.strip().strip("'\"")
    if ".github/workflows" not in r.lower():
        return True
    if "@" not in r:
        return False
    _prefix, pin = r.rsplit("@", 1)
    return bool(re.fullmatch(r"[0-9a-f]{40}", pin.strip().lower()))


def _iter_structured_workflow_uses_strings(doc: dict[str, Any]) -> list[str]:
    out: list[str] = []
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return out
    for _job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        ju = job.get("uses")
        if isinstance(ju, str):
            out.append(ju.strip())
        steps = job.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict):
                    su = step.get("uses")
                    if isinstance(su, str):
                        out.append(su.strip())
    return out


def _iter_structured_workflow_uses_with_location(
    doc: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """Yield ``(job_name, step_label, uses)`` for every structural ``uses:`` string.

    ``step_label`` is ``job`` when the ``uses`` is at the job level, or the step ``name``/``uses``
    identifier when at the step level. This lets evaluators report exact workflow locations
    without re-parsing raw text.
    """

    out: list[tuple[str, str, str]] = []
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return out
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        ju = job.get("uses")
        if isinstance(ju, str):
            out.append((str(job_name), "job", ju.strip()))
        steps = job.get("steps")
        if isinstance(steps, list):
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                su = step.get("uses")
                if not isinstance(su, str):
                    continue
                label = step.get("name") if isinstance(step.get("name"), str) else None
                if not label:
                    label = f"step[{idx}]"
                out.append((str(job_name), label, su.strip()))
    return out


def _reusable_workflow_uses_from_strings(uses_values: list[str]) -> list[str]:
    return [u for u in uses_values if ".github/workflows" in u.lower()]


def eval_gov_waiv_014(ctx: EvalContext) -> EvalOutcome:
    candidates = [
        ctx.repo_root / "waivers.yaml",
        ctx.repo_root / "waivers.yml",
        ctx.repo_root / "waivers" / "waivers.yaml",
        ctx.repo_root / ".oss-policy-kit" / "waivers.yaml",
    ]
    for p in candidates:
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Versioned waiver file detected in repository.",
                remediation="Keep waivers justified, owned, time-bounded, and reviewed.",
                evidence_sources=[str(p.resolve())],
                confidence="high",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            "No versioned waiver policy file found in repository. If waivers are not applicable, create a waivers/ "
            "directory with a documented policy statement or use an empty waivers file."
        ),
        remediation="Create waivers/policy.yaml or waivers/README.md documenting the waiver governance approach.",
        evidence_sources=[],
        confidence="medium",
    )


def _parse_branch_protection_evidence(evidence: Path) -> EvalOutcome:
    """Validate and interpret a branch-protection evidence file."""
    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Branch protection evidence file is unreadable or invalid JSON: {exc}",
            remediation="Fix or regenerate .oss-policy-kit/evidence/branch-protection.json per the evidence schema.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    if not isinstance(data, dict):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Branch protection evidence file root must be a JSON object.",
            remediation="Regenerate the file following reports/schema/evidence-branch-protection.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    try:
        Draft202012Validator(_branch_protection_schema()).validate(data)
    except ValidationError as exc:
        loc = "/".join(str(p) for p in exc.absolute_path) if exc.absolute_path else "root"
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Branch protection evidence does not match evidence-branch-protection.schema.json: {exc.message} "
                f"(at {loc})"
            ),
            remediation=(
                "Regenerate the file using reports/schema/evidence-branch-protection.schema.json "
                "or the packaged copy under src/oss_policy_kit/data/schema/."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    ph_bp = has_placeholder_values(data)
    blocked_bp = _evidence_placeholder_outcome(evidence, ph_bp)
    if blocked_bp is not None:
        return blocked_bp

    protections = data["protections"]
    assert isinstance(protections, dict)
    ecm = EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
    evidence_origin = "confirmed via live collection metadata" if ecm is EvidenceCollectionMethod.LIVE else "attested"

    missing = [k for k in _REQUIRED_BRANCH_PROTECTION_FLAGS if protections.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Evidence file present but required protection(s) not enabled: {', '.join(sorted(missing))}. "
                f"Branch: {data.get('branch', 'unknown')}, attested: {data.get('attested_at', 'unknown')}."
            ),
            remediation="Enable the missing protections in GitHub Settings (Branches) and update the evidence file.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=ecm,
        )

    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Branch protection evidence present and required protections {evidence_origin} as enabled. "
            f"Branch: {data.get('branch', 'unknown')}, attested: {data.get('attested_at', 'unknown')} "
            f"by {data.get('attested_by', 'unknown')}."
        ),
        remediation=(
            "Keep evidence file updated when GitHub settings change; re-attest after each configuration review."
        ),
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=ecm,
    )


def eval_plat_brprot_015(ctx: EvalContext) -> EvalOutcome:
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    if evidence.is_file():
        return _parse_branch_protection_evidence(evidence)
    return EvalOutcome(
        status=ControlStatus.NOT_EVALUATED,
        reason=(
            "Branch protection posture cannot be determined: no evidence file found at "
            "`.oss-policy-kit/evidence/branch-protection.json`. "
            "Collect evidence using the GitHub platform collector or create the file manually "
            "following the schema at `src/oss_policy_kit/data/schema/evidence-branch-protection.schema.json`."
        ),
        remediation=(
            "Run `oss-policy-kit collect-evidence --platform github` to generate the evidence file, "
            "or manually create `.oss-policy-kit/evidence/branch-protection.json` "
            "and attest branch protection settings."
        ),
        evidence_sources=[],
        confidence="high",
    )


_SECRET_SCAN_TOKENS = (
    "gitleaks",
    "trufflehog",
    "detect-secrets",
    "git-secrets",
    "secretlint",
    "noseyparker",
    "gitguardian",
    "ggshield",
    "truffle security",
    "checkov",
    "ckv_secret",
)


_SECRET_SCAN_EXTRA_PATTERNS = (
    re.compile(r"trivy[^\n]{0,120}--scanners[^\n]{0,40}secret", re.I),
    re.compile(r"semgrep[^\n]{0,120}p/secrets", re.I),
    re.compile(r"checkov[^\n]{0,120}ckv_secret", re.I),
)


def eval_sec_secrets_050(ctx: EvalContext) -> EvalOutcome:
    """SEC-SECRETS-050: secret scanning referenced in CI workflows."""
    paths: list[Path] = list(ctx.workflows.workflow_paths)
    texts: list[tuple[Path, str]] = []
    for p in paths:
        with contextlib.suppress(OSError):
            texts.append((p, p.read_text(encoding="utf-8", errors="replace")))
    hits: list[Path] = []
    for path, text in texts:
        lower = text.lower()
        if any(tok in lower for tok in _SECRET_SCAN_TOKENS):
            hits.append(path)
            continue
        if any(rx.search(text) for rx in _SECRET_SCAN_EXTRA_PATTERNS):
            hits.append(path)
    if hits:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"Secret scanning tool signal detected in {len(hits)} workflow file(s). "
                "(keyword signal in workflow YAML — execution and blocking behavior not validated)"
            ),
            remediation="Keep secret scanning enabled on default branches and pull requests.",
            evidence_sources=[str(p.resolve()) for p in hits],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    if not paths:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="No GitHub Actions workflows found; cannot detect an in-repo secret scanning step.",
            remediation=(
                "Add a secret scanning step to CI (for example gitleaks, trufflehog, detect-secrets, or secretlint)."
            ),
            evidence_sources=[],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No secret scanning tool keyword found in workflow YAML (gitleaks, trufflehog, detect-secrets, etc.).",
        remediation=(
            "Add a secret scanning step to your CI workflow. Example: uses: gitleaks/gitleaks-action@v2 "
            "(pin to a commit SHA in production)."
        ),
        evidence_sources=[],
        confidence="medium",
    )


_GITIGNORE_SECRET_FRAGMENTS = (".env", "*.pem", "*.key", "secrets.", "credentials")


def eval_sec_gitignore_051(ctx: EvalContext) -> EvalOutcome:
    """SEC-GITIGNORE-051: root .gitignore with basic secret-related patterns."""
    gi = ctx.repo_root / ".gitignore"
    if not gi.is_file():
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="No `.gitignore` file at repository root.",
            remediation=(
                "Add `.gitignore` with patterns such as `.env`, `*.pem`, `*.key`, `secrets.*`, `credentials.json`."
            ),
            evidence_sources=[],
            confidence="high",
        )
    try:
        raw = gi.read_text(encoding="utf-8", errors="replace")
    except OSError:
        raw = ""
    low = raw.lower()
    matched = [frag for frag in _GITIGNORE_SECRET_FRAGMENTS if frag.lower() in low]
    if matched:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"`.gitignore` includes basic secret-protection patterns ({', '.join(matched)}).",
            remediation="Review periodically so new sensitive artifact types remain ignored.",
            evidence_sources=[str(gi.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="`.gitignore` exists but no common secret-protection patterns were detected.",
        remediation="Expand `.gitignore` with `.env`, `*.pem`, `*.key`, `secrets.*`, or `credentials.json` patterns.",
        evidence_sources=[str(gi.resolve())],
        confidence="low",
    )


_PIN_REQ_PIN = re.compile(r"==\s*[0-9A-Za-z._-]+")


def _python_lock_or_pins(repo: Path) -> bool:
    if (repo / "poetry.lock").is_file() or (repo / "Pipfile.lock").is_file() or (repo / "uv.lock").is_file():
        return True
    if (repo / "requirements.lock").is_file() or (repo / "requirements-lock.txt").is_file():
        return True
    req = repo / "requirements.txt"
    if req.is_file():
        with contextlib.suppress(OSError):
            body = req.read_text(encoding="utf-8", errors="replace")
        return bool(_PIN_REQ_PIN.search(body))
    return False


def eval_sec_pinlock_052(ctx: EvalContext) -> EvalOutcome:
    """SEC-PINLOCK-052: dependency lockfile or pinned requirements when a stack is detected."""
    repo = ctx.repo_root
    stacks: list[str] = []
    if (repo / "package.json").is_file():
        stacks.append("node")
    if (repo / "requirements.txt").is_file() or (repo / "pyproject.toml").is_file():
        stacks.append("python")
    if (repo / "go.mod").is_file():
        stacks.append("go")
    if not stacks:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Node.js, Python, or Go manifest detected at repository root.",
            remediation="Not applicable until a supported dependency manifest is present.",
            evidence_sources=[],
            confidence="high",
        )

    missing: list[str] = []
    node_lock_names = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")
    if "node" in stacks and not any((repo / name).is_file() for name in node_lock_names):
        missing.append("Node.js lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml)")
    if "python" in stacks and not _python_lock_or_pins(repo):
        missing.append("Python lockfile or pinned requirements (== in requirements.txt, poetry.lock, etc.)")
    if "go" in stacks and not (repo / "go.sum").is_file():
        missing.append("go.sum")

    if not missing:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Dependency lockfile or pinned requirements detected for the observed stack(s).",
            remediation="Keep lockfiles committed and refresh them when dependencies change.",
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="Missing lockfile or pins: " + "; ".join(missing) + ".",
        remediation=(
            "For Python use pinned versions (==) or pip-compile; for Node commit package-lock.json or yarn.lock; "
            "for Go commit go.sum."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def eval_gh_mergeq_053(ctx: EvalContext) -> EvalOutcome:
    """GH-MERGEQ-053: GitHub merge queue / merge_group signal in workflow configuration."""

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="If you use merge queues, declare merge_group triggers in protected workflows.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.merge_queue_signal_paths:
        names = ", ".join(sorted({p.name for p in ctx.workflows.merge_queue_signal_paths}))
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Merge queue / merge_group signal detected in workflow(s): {names}.",
            remediation="Keep merge queue configuration aligned with branch protection and required checks.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.merge_queue_signal_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No merge queue (merge_group) or merge-queue documentation signal detected in workflows.",
        remediation=("Enable GitHub merge queue for protected branches or document an equivalent gated merge policy."),
        evidence_sources=[],
        confidence="low",
    )


def _parse_evidence_date(value: str) -> date | None:
    s = value.strip()
    if len(s) >= 10:
        with contextlib.suppress(ValueError):
            return date.fromisoformat(s[:10])
    with contextlib.suppress(ValueError):
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    return None


def eval_gov_evidfresh_054(ctx: EvalContext) -> EvalOutcome:
    """GOV-EVIDFRESH-054: evidence JSON under .oss-policy-kit/evidence is not older than policy."""

    evid_root = ctx.repo_root / ".oss-policy-kit" / "evidence"
    if not evid_root.is_dir():
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No .oss-policy-kit/evidence directory present.",
            remediation="Run collect-evidence for your platform(s) or add validated evidence JSON when required.",
            evidence_sources=[],
            confidence="high",
        )
    json_files = sorted(evid_root.rglob("*.json"))
    if not json_files:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="Evidence directory exists but contains no JSON files.",
            remediation="Populate evidence JSON via collect-evidence or controlled exports.",
            evidence_sources=[str(evid_root.resolve())],
            confidence="high",
        )

    today = datetime.now(UTC).date()
    max_age = int(ctx.evidence_max_age_days) if ctx.evidence_max_age_days else _EVIDENCE_MAX_AGE_DAYS
    if max_age <= 0:
        max_age = _EVIDENCE_MAX_AGE_DAYS
    stale: list[str] = []
    undated: list[str] = []
    expiry_warns: list[str] = []
    for path in json_files:
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            return EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=f"Evidence file {path.name} is unreadable or invalid JSON: {exc}.",
                remediation="Repair or regenerate the evidence JSON file.",
                evidence_sources=[str(path.resolve())],
                confidence="low",
            )
        if not isinstance(data, dict):
            undated.append(path.name)
            continue
        stamp: str | None = None
        coll = data.get("collection")
        if isinstance(coll, dict):
            v0 = coll.get("collected_at")
            if isinstance(v0, str) and v0.strip():
                stamp = v0.strip()
        if stamp is None:
            for key in ("collected_at", "attested_at", "generated_at"):
                v = data.get(key)
                if isinstance(v, str) and v.strip():
                    stamp = v.strip()
                    break
        parsed = _parse_evidence_date(stamp) if stamp else None
        if parsed is None:
            undated.append(path.name)
            continue
        age_days = (today - parsed).days
        if age_days > max_age:
            stale.append(f"{path.name} ({parsed.isoformat()})")
        elif age_days > max_age - _EVIDENCE_EXPIRY_WARN_DAYS:
            days_left = max_age - age_days
            expiry_warns.append(
                f"Evidence file '{path.name}' is {age_days} days old and will expire in "
                f"{days_left} day(s). Refresh before it becomes stale."
            )

    if stale:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Stale evidence JSON (older than "
            f"{max_age} days by attested_at/collected_at): "
            + "; ".join(stale[:6])
            + ("; …" if len(stale) > 6 else "")
            + ".",
            remediation="Re-run collect-evidence or refresh manual exports so dates stay current.",
            evidence_sources=[str(evid_root.resolve())],
            confidence="medium",
        )
    if undated:
        preview = ", ".join(sorted(undated)[:5])
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "Some evidence JSON files lack a usable collected_at/attested_at date: "
                f"{preview}{'…' if len(undated) > 5 else ''}."
            ),
            remediation="Ensure each evidence file includes attested_at or collected_at (ISO-8601 date or datetime).",
            evidence_sources=[str(evid_root.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"All {len(json_files)} evidence JSON file(s) carry recent dates (≤ {max_age} days).",
        remediation="Refresh evidence after material platform or pipeline changes.",
        evidence_sources=[str(evid_root.resolve())],
        confidence="medium",
        operational_warnings=tuple(expiry_warns),
    )


def eval_ci_wfcallsha_055(ctx: EvalContext) -> EvalOutcome:
    """CI-WFCALLSHA-055: reusable workflow calls use full 40-character commit SHAs."""

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Pin reusable workflows with immutable commit SHAs when using workflow_call.",
            evidence_sources=[],
            confidence="high",
        )

    parse_warns: list[str] = []
    call_paths: list[Path] = []
    bad_paths: list[Path] = []
    bad_evidence_sources: list[str] = []

    for path in ctx.workflows.workflow_paths:
        raw = path.read_text(encoding="utf-8", errors="replace")
        structured_failed = False
        try:
            doc = load_yaml_file(path)
        except Exception:
            structured_failed = True
            doc = None
        if structured_failed or not isinstance(doc, dict):
            parse_warns.append(f"{path.name}: YAML parse failed; reusable workflow SHA pins not verified structurally.")
            for m in _REUSABLE_WORKFLOW_USES_LINE.finditer(raw):
                ref = m.group(1).strip()
                if not ref or ref.startswith("${{"):
                    continue
                if ".github/workflows" not in ref.lower():
                    continue
                if path not in call_paths:
                    call_paths.append(path)
                if not _reusable_workflow_ref_has_full_sha(ref):
                    if path not in bad_paths:
                        bad_paths.append(path)
                    bad_evidence_sources.append(f"{path.resolve()} (regex-fallback: `{ref}`)")
            continue

        located = _iter_structured_workflow_uses_with_location(doc)
        reusable_located = [(job, step, u) for (job, step, u) in located if ".github/workflows" in u.lower()]
        if not reusable_located:
            continue
        if path not in call_paths:
            call_paths.append(path)
        for job_name, step_label, ref in reusable_located:
            if not _reusable_workflow_ref_has_full_sha(ref):
                if path not in bad_paths:
                    bad_paths.append(path)
                bad_evidence_sources.append(f"{path.resolve()} :: jobs.{job_name}.{step_label} uses=`{ref}`")

    if not call_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No reusable workflow references under .github/workflows were detected.",
            remediation="Not applicable until you call reusable workflows from another workflow.",
            evidence_sources=[],
            confidence="high",
        )
    if bad_paths:
        names = ", ".join(sorted({p.name for p in bad_paths}))
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Reusable workflow call(s) without a full 40-character SHA pin detected: {names}. "
                "Use org/repo/.github/workflows/file.yml@<40-hex-sha>."
            ),
            remediation="Pin reusable workflow entrypoints to immutable commit SHAs, not tags or branches.",
            evidence_sources=bad_evidence_sources or [str(p.resolve()) for p in bad_paths],
            confidence="medium",
            operational_warnings=tuple(parse_warns) if parse_warns else (),
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="Reusable workflow calls under .github/workflows use full commit SHA pins (parsed from workflow YAML).",
        remediation="Keep pins immutable when updating reusable workflow targets.",
        evidence_sources=[str(p.resolve()) for p in call_paths],
        confidence="medium",
        operational_warnings=tuple(parse_warns) if parse_warns else (),
    )


def eval_gh_wf_018(ctx: EvalContext) -> EvalOutcome:
    """GH-WF-018: Reusable workflow calls should avoid `secrets: inherit`."""

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Avoid reusable workflow calls with `secrets: inherit` in strict profiles.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.reusable_secrets_inherit_paths:
        names = ", ".join(sorted({p.name for p in ctx.workflows.reusable_secrets_inherit_paths}))
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Reusable workflow call(s) with `secrets: inherit` detected: {names}.",
            remediation="Pass only explicit required secrets to reusable workflows and keep permissions minimal.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.reusable_secrets_inherit_paths],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No reusable workflow calls using `secrets: inherit` were detected.",
        remediation="Keep secret flow explicit when reusing workflows.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_gh_wf_019(ctx: EvalContext) -> EvalOutcome:
    """GH-WF-019: pull_request/pull_request_target workflows should avoid self-hosted runners."""

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Use GitHub-hosted runners for pull request triggered workflows unless isolation is proven.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.pr_self_hosted_runner_paths:
        names = ", ".join(sorted({p.name for p in ctx.workflows.pr_self_hosted_runner_paths}))
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"PR-exposed workflow(s) use self-hosted runner labels: {names}.",
            remediation=(
                "Prefer GitHub-hosted runners for PR events, or isolate self-hosted runners "
                "with strict trust boundaries."
            ),
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.pr_self_hosted_runner_paths],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No self-hosted runner usage detected in pull-request-triggered workflows.",
        remediation="Keep self-hosted runners out of untrusted PR execution paths.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_gh_wf_020(ctx: EvalContext) -> EvalOutcome:
    """GH-WF-020: avoid broad job-level write scopes."""

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Declare minimal job-level permissions for privileged scopes.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.broad_job_permissions:
        sample = ctx.workflows.broad_job_permissions[0]
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Broad job-level write permission detected ({sample[1]}) in {sample[0].name}.",
            remediation="Reduce job-level scopes to read-only unless write is strictly required for that job.",
            evidence_sources=[str(sample[0].resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No obvious broad job-level write scopes were detected.",
        remediation="Re-audit job permissions whenever release/deploy jobs change.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_gh_rel_021(ctx: EvalContext) -> EvalOutcome:
    """GH-REL-021: release/deploy workflows should declare concurrency to avoid duplicate runs."""

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Define release/package workflows with explicit concurrency groups.",
            evidence_sources=[],
            confidence="high",
        )
    if not ctx.workflows.release_workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No release or deploy workflow detected; concurrency posture not applicable.",
            remediation="If you publish artifacts, add explicit release workflow signals with concurrency controls.",
            evidence_sources=[],
            confidence="medium",
        )
    if ctx.workflows.release_workflows_missing_concurrency:
        sorted_names = sorted({p.name for p in ctx.workflows.release_workflows_missing_concurrency})
        if len(sorted_names) == 1:
            reason = (
                f"Release/deploy workflow `{sorted_names[0]}` does not declare "
                "`concurrency:` at the workflow or job level. Concurrent runs can cause "
                "race conditions in deployment state."
            )
        else:
            joined = ", ".join(f"`{n}`" for n in sorted_names)
            reason = (
                f"Release/deploy workflows {joined} do not declare "
                "`concurrency:` at the workflow or job level. Concurrent runs can cause "
                "race conditions in deployment state."
            )
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=reason,
            remediation=(
                "Add top-level `concurrency` (for example "
                "`concurrency: { group: release-${{ github.ref }}, cancel-in-progress: false }`) "
                "to release/deploy workflows to prevent duplicate artifact publication."
            ),
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.release_workflows_missing_concurrency],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="Release/deploy workflow signals include top-level concurrency controls.",
        remediation="Keep concurrency groups stable across release workflow edits.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_gh_dep_022(ctx: EvalContext) -> EvalOutcome:
    """GH-DEPLOY-022: triage cloud deployment OIDC posture with 3 explicit branches.

    Priority order (evaluated top-down):

    1. ``has_oidc`` → :class:`ControlStatus.PASS`
    2. ``has_long_lived_secrets`` → :class:`ControlStatus.FAIL`
    3. ``not has_cloud_deploy`` → :class:`ControlStatus.NOT_APPLICABLE`
    4. Cloud deploy detected but OIDC posture cannot be confirmed →
       :class:`ControlStatus.MANUAL_REVIEW_REQUIRED`
    """

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="For cloud deployments, prefer OIDC federation over long-lived cloud credentials.",
            evidence_sources=[],
            confidence="high",
        )

    cloud_deploy_paths = list(ctx.workflows.cloud_deploy_workflow_paths)
    oidc_paths = list(ctx.workflows.cloud_deploy_with_oidc_paths)
    has_cloud_deploy = bool(cloud_deploy_paths)
    has_oidc = bool(oidc_paths) and len(oidc_paths) >= len(cloud_deploy_paths)

    long_lived_hits: list[Path] = []
    for p in cloud_deploy_paths or ctx.workflows.workflow_paths:
        with contextlib.suppress(OSError):
            raw = p.read_text(encoding="utf-8", errors="replace")
            if _workflow_text_has_long_lived_cloud_secret(raw):
                long_lived_hits.append(p)
    has_long_lived_secrets = bool(long_lived_hits)

    if has_oidc and not has_long_lived_secrets:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Cloud deployment workflow signal detected with explicit OIDC posture "
                "(YAML signal only; cloud-side trust policy and role bindings are not validated here)."
            ),
            remediation="Keep cloud identity federation configured; avoid static long-lived cloud secrets.",
            evidence_sources=[str(p.resolve()) for p in oidc_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    if has_long_lived_secrets:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Long-lived cloud credentials detected (e.g., AWS_SECRET_ACCESS_KEY). Use OIDC federation instead."
            ),
            remediation=("Replace static cloud secrets with workload identity federation (OIDC) to GitHub Actions."),
            evidence_sources=[str(p.resolve()) for p in long_lived_hits],
            confidence="high",
        )
    if not has_cloud_deploy:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No cloud deployment workflow detected.",
            remediation="If cloud deploy workflows exist elsewhere, add explicit OIDC posture evidence.",
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Cloud deployment detected but OIDC posture could not be confirmed.",
        remediation=(
            "Add explicit `id-token: write` and cloud OIDC auth steps, or document and attest credential model."
        ),
        evidence_sources=[str(p.resolve()) for p in cloud_deploy_paths],
        confidence="low",
    )


def eval_gh_prov_023(ctx: EvalContext) -> EvalOutcome:
    """GH-PROV-023: provenance/attestation signal should exist for strict release posture."""

    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No workflows present.",
            remediation="Add build provenance or artifact attestation to release/package workflows.",
            evidence_sources=[],
            confidence="high",
        )
    has_release_intent = bool(ctx.workflows.release_workflow_paths or ctx.workflows.cloud_deploy_workflow_paths)
    if not has_release_intent and _any_github_workflow_suggests_release_or_deploy(ctx):
        has_release_intent = True
    if not has_release_intent:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=(
                "No release, deploy, or artifact publication workflow detected. "
                "Provenance/attestation controls apply only to repositories that "
                "produce and publish artifacts."
            ),
            remediation=(
                "If this repository publishes artifacts, add a release workflow with "
                "build provenance or artifact attestation (for example `actions/attest-build-provenance`)."
            ),
            evidence_sources=[],
            confidence="high",
        )
    if ctx.workflows.has_artifact_attestation:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Provenance/attestation signal detected in workflow configuration "
                "(workflow signal only; artifact-level verification is not confirmed from clone-only evidence)."
            ),
            remediation="Keep provenance artifacts linked to release outputs.",
            evidence_sources=[str(p.resolve()) for p in ctx.workflows.workflow_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No provenance/attestation signal detected in workflows.",
        remediation=(
            "Add GitHub build provenance attestation (for example actions/attest-build-provenance) "
            "or equivalent signed provenance workflow."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def _evidence_placeholder_outcome(evidence: Path, placeholders: list[str]) -> EvalOutcome | None:
    """Return a :class:`EvalOutcome` when scaffold-style placeholders remain in evidence JSON."""

    if not placeholders:
        return None
    preview = ", ".join(placeholders[:5])
    return EvalOutcome(
        status=ControlStatus.NOT_EVALUATED,
        reason=(
            f"Evidence file {evidence.name} contains unfilled placeholder tokens ({preview}). "
            "Replace template values before relying on this control."
        ),
        remediation="Edit the evidence JSON and remove REPLACE_ME-style placeholders and template dates.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        operational_warnings=(f"Evidence {evidence.name}: placeholder tokens ({preview}).",),
    )


def _validate_json_evidence(
    evidence: Path,
    *,
    schema_loader: Callable[[], dict[str, Any]],
    evidence_name: str,
) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"{evidence_name} evidence is unreadable or invalid JSON: {exc}", []
    if not isinstance(data, dict):
        return None, f"{evidence_name} evidence root must be a JSON object.", []
    try:
        Draft202012Validator(schema_loader()).validate(data)
    except ValidationError as exc:
        loc = "/".join(str(p) for p in exc.absolute_path) if exc.absolute_path else "root"
        return None, f"{evidence_name} evidence does not match schema: {exc.message} (at {loc})", []
    return data, None, has_placeholder_values(data)


_DIGEST_PLACEHOLDER_REASON = (
    "Evidence file digest fields contain template/placeholder values. Replace with real SHA256 digests "
    "from the actual release artifacts."
)


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_WEAK_DIGEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^(.)\1{63}$"),
    re.compile(r"^(..)\1{31}$"),
    re.compile(r"^0{64}$"),
)


def _is_valid_sha256_digest(value: object) -> bool:
    """Return True only when *value* is a plausible, non-placeholder SHA-256 hex digest.

    A digest is rejected when any of the following is true:

    - value is not a string
    - value is not 64 lowercase hexadecimal characters
    - value matches a low-entropy placeholder pattern (``0..0``, ``aa..aa``, ``ab ab ...``)
    """

    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    if not _SHA256_PATTERN.match(normalized):
        return False
    return not any(pat.match(normalized) for pat in _WEAK_DIGEST_PATTERNS)


_INVALID_DIGEST_REASON = (
    "Artifact digest is a placeholder or invalid SHA-256 value. Replace with the actual artifact digest."
)


def _digest_invalid_not_evaluated(evidence: Path) -> EvalOutcome:
    return EvalOutcome(
        status=ControlStatus.NOT_EVALUATED,
        reason=_INVALID_DIGEST_REASON,
        remediation=("Populate digest_sha256 with the real 64-character hex SHA-256 of the artifact/SBOM/attestation."),
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def _sbom_artifact_digest_strings(data: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("artifact", "sbom"):
        block = data.get(key)
        if isinstance(block, dict):
            d = block.get("digest_sha256")
            if isinstance(d, str):
                out.append(d)
    return out


def _provenance_artifact_digest_strings(data: dict[str, Any]) -> list[str]:
    out: list[str] = []
    art = data.get("artifact")
    if isinstance(art, dict):
        d = art.get("digest_sha256")
        if isinstance(d, str):
            out.append(d)
    att = data.get("attestation")
    if isinstance(att, dict):
        d2 = att.get("digest_sha256")
        if isinstance(d2, str):
            out.append(d2)
    return out


def _digest_placeholder_manual_review(evidence: Path) -> EvalOutcome:
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=_DIGEST_PLACEHOLDER_REASON,
        remediation="Replace digest_sha256 values with hashes from your real release artifact and SBOM/provenance.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def _azure_governance_evidence_dict(ctx: EvalContext) -> dict[str, Any] | None:
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "azure-pipeline-governance.json"
    if not evidence.is_file():
        return None
    data, error, _ph = _validate_json_evidence(
        evidence,
        schema_loader=_azure_pipeline_governance_schema,
        evidence_name="Azure pipeline governance",
    )
    if error or data is None:
        return None
    return data


def eval_gh_plat_024(ctx: EvalContext) -> EvalOutcome:
    """GH-PLAT-024: repository rulesets posture via explicit evidence."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "github-rulesets.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.NOT_EVALUATED,
            reason=(
                "GitHub rulesets posture cannot be evaluated without evidence JSON. "
                "Run `oss-policy-kit collect-evidence --platform github` or add "
                "`.oss-policy-kit/evidence/github-rulesets.json`."
            ),
            remediation=(
                "Verify GitHub rulesets in repository settings and optionally add "
                ".oss-policy-kit/evidence/github-rulesets.json."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_rulesets_schema,
        evidence_name="GitHub rulesets",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=error,
            remediation=(
                "Regenerate github-rulesets evidence using reports/schema/evidence-github-rulesets.schema.json."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture = data["posture"]
    assert isinstance(posture, dict)
    ecm = EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
    checks = ("require_pull_request", "require_status_checks", "restrict_force_push", "require_code_owner_review")
    missing = [k for k in checks if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Rulesets evidence present but required posture flag(s) are not enabled: {', '.join(sorted(missing))}."
            ),
            remediation="Enable missing ruleset controls in GitHub and refresh evidence file.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
            evidence_collection_method=ecm,
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Rulesets evidence valid and required posture flags are enabled "
            f"({'live API collection' if ecm is EvidenceCollectionMethod.LIVE else 'self-attested file'}) "
            f"(repository {data.get('repository', 'unknown')}, attested {data.get('attested_at', 'unknown')})."
        ),
        remediation="Re-collect or re-attest rulesets evidence after policy changes in GitHub settings.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=ecm,
    )


def eval_gh_plat_025(ctx: EvalContext) -> EvalOutcome:
    """GH-PLAT-025: deployment environment protections via explicit evidence."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "github-environment-protection.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.NOT_EVALUATED,
            reason=(
                "GitHub deployment environment protection cannot be evaluated without evidence JSON. "
                "Run `oss-policy-kit collect-evidence --platform github` or add "
                "`.oss-policy-kit/evidence/github-environment-protection.json`."
            ),
            remediation=(
                "Verify GitHub deployment environment approvals/reviewers and optionally add "
                ".oss-policy-kit/evidence/github-environment-protection.json."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_environment_protection_schema,
        evidence_name="GitHub environment protection",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=error,
            remediation=(
                "Regenerate environment protection evidence using "
                "reports/schema/evidence-github-environment-protection.schema.json."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    envs = data["environments"]
    assert isinstance(envs, list)
    ecm = EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
    weak = [
        str(env.get("name", "unknown"))
        for env in envs
        if isinstance(env, dict)
        and (
            env.get("requires_reviewers") is not True
            or env.get("prevent_self_review") is not True
            or env.get("wait_timer_minutes", 0) == 0
        )
    ]
    if weak:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Environment protection evidence present but required reviewer controls are missing or weak for: "
                f"{', '.join(weak)}."
            ),
            remediation=(
                "Require reviewers, prevent self-review, and use non-zero wait timers for production-like environments."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
            evidence_collection_method=ecm,
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="Environment protection evidence valid with strict reviewer posture for all listed environments.",
        remediation="Keep environment protection evidence current when deployment policy changes.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=ecm,
    )


def eval_gh_plat_026(ctx: EvalContext) -> EvalOutcome:
    """GH-PLAT-026: secret scanning / push protection posture via evidence."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "github-secret-scanning.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.NOT_EVALUATED,
            reason=(
                "GitHub secret scanning / push protection cannot be evaluated without evidence JSON. "
                "Run `oss-policy-kit collect-evidence --platform github` or add "
                "`.oss-policy-kit/evidence/github-secret-scanning.json`."
            ),
            remediation=(
                "Verify secret scanning and push protection in GitHub security settings and optionally add "
                ".oss-policy-kit/evidence/github-secret-scanning.json."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_secret_scanning_schema,
        evidence_name="GitHub secret scanning",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=error,
            remediation=(
                "Regenerate secret scanning evidence using reports/schema/evidence-github-secret-scanning.schema.json."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture = data["posture"]
    assert isinstance(posture, dict)
    ecm = EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
    checks = ("secret_scanning_enabled", "push_protection_enabled", "validity_checks_enabled")
    missing = [k for k in checks if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Secret scanning evidence present but required setting(s) are not enabled: "
                f"{', '.join(sorted(missing))}."
            ),
            remediation="Enable secret scanning, push protection, and validity checks in GitHub settings.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
            evidence_collection_method=ecm,
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="Secret scanning evidence valid and strict posture flags are enabled.",
        remediation="Refresh evidence file after changing security settings.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=ecm,
    )


def eval_az_pipe_027(ctx: EvalContext) -> EvalOutcome:
    """AZ-PIPE-027: Azure Pipelines definitions exist in supported paths."""

    if ctx.azure_pipelines.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Found {len(ctx.azure_pipelines.pipeline_paths)} Azure pipeline definition file(s).",
            remediation="Keep Azure pipeline definitions minimal and policy-aligned.",
            evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.pipeline_paths],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No Azure pipeline definition found in supported paths.",
        remediation="Add azure-pipelines.yml or supported pipelines/azure/* layout.",
        evidence_sources=[],
        confidence="high",
    )


def eval_az_pipe_028(ctx: EvalContext) -> EvalOutcome:
    """AZ-PIPE-028: PR validation trigger posture exists in Azure Pipelines."""

    if not ctx.azure_pipelines.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AZURE_PIPELINES_REASON,
            remediation="Add Azure pipeline definition before enforcing PR validation posture.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.azure_pipelines.pr_validation_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="PR validation trigger signal detected in Azure pipeline YAML.",
            remediation="Keep PR validation enabled for protected branches.",
            evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.pr_validation_paths],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No PR validation trigger signal detected in Azure pipelines.",
        remediation="Add `pr:` trigger posture for pull request validation in Azure Pipelines.",
        evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.pipeline_paths],
        confidence="medium",
    )


def eval_az_pipe_029(ctx: EvalContext) -> EvalOutcome:
    """AZ-PIPE-029: Avoid checkout credential persistence in pipelines."""

    if not ctx.azure_pipelines.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AZURE_PIPELINES_REASON,
            remediation="Adopt explicit checkout posture with persistCredentials disabled.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.azure_pipelines.persist_credentials_true_paths:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="checkout steps with persistCredentials: true detected.",
            remediation="Set `persistCredentials: false` for checkout steps unless strictly required.",
            evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.persist_credentials_true_paths],
            confidence="medium",
        )
    # Check whether any pipeline explicitly sets persistCredentials: false (stronger confirmation).
    explicit_false: list[Path] = []
    for p in ctx.azure_pipelines.pipeline_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if "persistcredentials" in text and "false" in text:
                explicit_false.append(p)
    if explicit_false:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "No checkout step with persistCredentials: true detected; "
                f"explicit persistCredentials: false confirmed in {len(explicit_false)} pipeline file(s)."
            ),
            remediation="Continue setting persistCredentials: false explicitly for clarity.",
            evidence_sources=[str(p.resolve()) for p in explicit_false],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            "No checkout step with persistCredentials: true detected. "
            "The Azure Checkout task defaults to false; explicitly setting it is recommended for clarity."
        ),
        remediation="Set `persistCredentials: false` explicitly in all checkout steps to remove ambiguity.",
        evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.pipeline_paths],
        confidence="low",
    )


def eval_az_pipe_030(ctx: EvalContext) -> EvalOutcome:
    """AZ-PIPE-030: Encourage secure template extension posture (extends)."""

    if not ctx.azure_pipelines.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AZURE_PIPELINES_REASON,
            remediation="Use extends templates for stronger policy reuse in Azure Pipelines.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.azure_pipelines.extends_template_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Azure pipeline template extension signal (`extends`) detected.",
            remediation="Keep secure template baseline reviewed and versioned.",
            evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.extends_template_paths],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No `extends` template posture detected in Azure pipelines.",
        remediation="Adopt secure template extension (`extends`) for stricter Azure pipeline governance.",
        evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.pipeline_paths],
        confidence="medium",
    )


def eval_az_sec_031(ctx: EvalContext) -> EvalOutcome:
    """AZ-SEC-031: Security scanning signal in Azure Pipelines."""

    if not ctx.azure_pipelines.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AZURE_PIPELINES_REASON,
            remediation="Add security scanning stage or tasks to Azure Pipelines.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.azure_pipelines.security_scan_signal_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Security scanning signal detected in Azure pipeline YAML."
                " (keyword signal in pipeline YAML — not verified as executed)"
            ),
            remediation="Keep security scanning on PR and default-branch execution paths.",
            evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.security_scan_signal_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No security scanning signal detected in Azure pipelines.",
        remediation=(
            "Add security scanning tasks (for example Microsoft Security DevOps, Semgrep, Trivy, or equivalent)."
        ),
        evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.pipeline_paths],
        confidence="medium",
    )


def eval_az_sca_032(ctx: EvalContext) -> EvalOutcome:
    """AZ-SCA-032: Dependency audit/SCA signal in Azure Pipelines."""

    if not ctx.azure_pipelines.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AZURE_PIPELINES_REASON,
            remediation="Add dependency audit/SCA checks to Azure Pipelines.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.azure_pipelines.dependency_audit_signal_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Dependency audit/SCA signal detected in Azure pipeline YAML."
                " (keyword signal in pipeline YAML — not verified as executed)"
            ),
            remediation="Keep dependency audit/SCA checks on PR and scheduled pathways.",
            evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.dependency_audit_signal_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No dependency audit/SCA signal detected in Azure pipelines.",
        remediation="Add dependency audit or SCA tooling (pip-audit, npm audit, osv-scanner, or equivalent).",
        evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.pipeline_paths],
        confidence="medium",
    )


def eval_az_sbom_033(ctx: EvalContext) -> EvalOutcome:
    """AZ-SBOM-033: SBOM generation or publication signal in Azure Pipelines."""

    if not ctx.azure_pipelines.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AZURE_PIPELINES_REASON,
            remediation="Add SBOM generation/publishing to Azure Pipelines.",
            evidence_sources=[],
            confidence="high",
        )
    if ctx.azure_pipelines.sbom_signal_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "SBOM generation/publishing signal detected in Azure pipeline YAML."
                " (keyword signal in pipeline YAML — not verified as executed)"
            ),
            remediation="Keep SBOM artifacts linked to build/release outputs.",
            evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.sbom_signal_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No SBOM generation/publishing signal detected in Azure pipelines.",
        remediation="Add CycloneDX, SPDX, Syft, or equivalent SBOM generation in pipeline stages.",
        evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.pipeline_paths],
        confidence="medium",
    )


def eval_az_plat_034(ctx: EvalContext) -> EvalOutcome:
    """AZ-PLAT-034: Azure Repos branch policies posture from evidence."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "azure-branch-policies.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Azure branch policy posture cannot be proven from clone-only evidence.",
            remediation=(
                "Verify Azure Repos branch policies in project settings and optionally add "
                ".oss-policy-kit/evidence/azure-branch-policies.json."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_azure_branch_policies_schema,
        evidence_name="Azure branch policies",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-azure-branch-policies.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture = data["posture"]
    assert isinstance(posture, dict)
    required = (
        "minimum_reviewers_enabled",
        "build_validation_enabled",
        "comment_resolution_required",
        "reset_votes_on_push",
        "block_last_pusher_approval",
        "bypass_policy_restricted",
    )
    missing = [key for key in required if posture.get(key) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"Branch policy evidence present, but required setting(s) are not enabled: {', '.join(missing)}.",
            remediation="Enable missing Azure branch policy settings and refresh evidence.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data) and not _azure_branch_policies_api_support_complete(data):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Azure branch policy evidence is API-attested but lacks complete posture_support metadata.",
            remediation="Re-run collect-evidence with a current kit so policies_api_reachability is recorded.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    if _evidence_is_api_backed(data) and _azure_branch_policies_api_support_complete(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Azure Repos branch policies confirmed via live Azure DevOps API collection evidence.",
            remediation="Re-attest branch policy evidence after governance changes.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Azure branch policy evidence present and required settings self-attested as enabled.",
        remediation="Re-attest branch policy evidence after governance changes.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_az_plat_035(ctx: EvalContext) -> EvalOutcome:
    """AZ-PLAT-035: Azure pipeline governance evidence for approvals/checks and service connection posture."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "azure-pipeline-governance.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Azure pipeline governance posture cannot be proven from clone-only evidence.",
            remediation=(
                "Verify approvals/checks and service connection governance in Azure DevOps, "
                "and optionally add .oss-policy-kit/evidence/azure-pipeline-governance.json."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_azure_pipeline_governance_schema,
        evidence_name="Azure pipeline governance",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-azure-pipeline-governance.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture = data["posture"]
    assert isinstance(posture, dict)
    checks = (
        "approvals_required",
        "environment_checks_enabled",
        "service_connection_restricted",
        "federated_identity_preferred",
    )
    missing = [key for key in checks if posture.get(key) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"Azure pipeline governance evidence present, but missing strict setting(s): {', '.join(missing)}.",
            remediation=(
                "Enable missing governance settings (approvals/checks/restricted service connections/WIF preference)."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data) and not _azure_pipeline_governance_api_support_complete(data):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "Pipeline governance JSON is API-attested but posture_support does not prove all underlying "
                "Azure DevOps reads succeeded (environments, checks, pipelines, or service endpoints)."
            ),
            remediation="Re-run collect-evidence; widen PAT scopes if APIs returned partial data.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    if _evidence_is_api_backed(data) and _azure_pipeline_governance_api_support_complete(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Azure pipeline governance posture confirmed via live Azure DevOps API collection.",
            remediation="Refresh governance evidence whenever approvals, environments, or service connections change.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Azure pipeline governance evidence present with strict posture self-attested as enabled.",
        remediation="Refresh governance evidence whenever approvals/checks/service connection policy changes.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_az_ident_036(ctx: EvalContext) -> EvalOutcome:
    """AZ-IDENT-036: workload identity federation preference grounded in governance evidence when available."""

    gov = _azure_governance_evidence_dict(ctx)
    if gov is not None:
        evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "azure-pipeline-governance.json"
        ph = has_placeholder_values(gov)
        blocked = _evidence_placeholder_outcome(evidence, ph)
        if blocked is not None:
            return blocked
        posture = gov.get("posture")
        if isinstance(posture, dict) and posture.get("federated_identity_preferred") is True:
            if _evidence_is_api_backed(gov) and _azure_pipeline_governance_api_support_complete(gov):
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=(
                        "Workload identity federation preferred per live-collected Azure pipeline governance evidence."
                    ),
                    remediation="Keep federated service connections and avoid PAT-style deployment credentials.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="high",
                    evidence_collection_method=EvidenceCollectionMethod.LIVE,
                )
            if _evidence_is_api_backed(gov):
                return EvalOutcome(
                    status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                    reason="Governance evidence suggests federation, but API posture_support metadata is incomplete.",
                    remediation="Re-run collect-evidence so federation claims are backed by reachable Azure APIs.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="medium",
                    evidence_collection_method=EvidenceCollectionMethod.LIVE,
                )
            return EvalOutcome(
                status=ControlStatus.SELF_ATTESTED,
                reason="Governance evidence self-attests federated identity preference for deployment connections.",
                remediation="Prefer collect-evidence over manual JSON for stronger assurance.",
                evidence_sources=[str(evidence.resolve())],
                confidence="low",
                evidence_collection_method=EvidenceCollectionMethod.MANUAL,
            )
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason="Governance evidence present but federated_identity_preferred is not enabled.",
            remediation="Migrate deployment service connections to WorkloadIdentityFederation where applicable.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )

    if not ctx.azure_pipelines.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AZURE_PIPELINES_REASON,
            remediation="Use workload identity federation in Azure deployment pipelines where applicable.",
            evidence_sources=[],
            confidence="high",
        )
    if not ctx.azure_pipelines.azure_deploy_signal_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Azure deployment signal detected in supported pipeline files.",
            remediation="If deployment pipelines exist, annotate them with explicit identity posture signals.",
            evidence_sources=[],
            confidence="medium",
        )
    if ctx.azure_pipelines.workload_identity_signal_paths:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "AZ-IDENT-036: No evidence file found at the expected path. "
                "A keyword signal was detected in the pipeline YAML, but this cannot "
                "prove platform-level posture. Collect evidence via the platform collector "
                "or attest the configuration manually."
            ),
            remediation=(
                "Run collect-evidence for Azure or add azure-pipeline-governance.json so "
                "posture.federated_identity_preferred can be validated from real platform data."
            ),
            evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.workload_identity_signal_paths],
            confidence="low",
            operational_warnings=(
                "AZ-IDENT-036: YAML keyword signal alone is not sufficient for PASS; "
                "add platform evidence to lift confidence.",
            ),
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            "AZ-IDENT-036: No evidence file found at the expected path. "
            "A keyword signal was detected in the pipeline YAML, but this cannot "
            "prove platform-level posture. Collect evidence via the platform collector "
            "or attest the configuration manually."
        ),
        remediation=(
            "Confirm service connection authentication model (prefer workload identity federation), "
            "or add azure-pipeline-governance.json from collect-evidence."
        ),
        evidence_sources=[str(p.resolve()) for p in ctx.azure_pipelines.azure_deploy_signal_paths],
        confidence="low",
    )


def eval_az_sconn_056(ctx: EvalContext) -> EvalOutcome:
    """AZ-SCONN-056: service connection authentication posture from pipeline governance evidence."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "azure-pipeline-governance.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No azure-pipeline-governance.json to evaluate service connection authentication posture.",
            remediation="Run collect-evidence for Azure or scaffold and attest governance JSON.",
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_azure_pipeline_governance_schema,
        evidence_name="Azure pipeline governance",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-azure-pipeline-governance.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    conns = data.get("service_connections")
    if not isinstance(conns, list) or not conns:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Governance evidence lacks a non-empty service_connections inventory.",
            remediation="Re-collect so serviceendpoint/endpoints data is included, or document why none apply.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    _sconn_ok_auth = frozenset({"workload_identity_federation", "service_principal", "managed_identity"})
    _sconn_unknown_reason = (
        "Service connection authentication type is 'unknown'. "
        "Inspect the connection in Azure DevOps and attest the actual "
        "authentication method before this control can be evaluated."
    )
    _sconn_unknown_remediation = "Update the evidence file with the actual authentication value."
    for c in conns:
        if not isinstance(c, dict):
            continue
        raw_auth = c.get("authentication")
        if not isinstance(raw_auth, str) or not raw_auth.strip():
            return EvalOutcome(
                status=ControlStatus.NOT_EVALUATED,
                reason=_sconn_unknown_reason,
                remediation=_sconn_unknown_remediation,
                evidence_sources=[str(evidence.resolve())],
                confidence="low",
            )
        auth_l = raw_auth.strip().lower()
        if auth_l == "unknown":
            return EvalOutcome(
                status=ControlStatus.NOT_EVALUATED,
                reason=_sconn_unknown_reason,
                remediation=_sconn_unknown_remediation,
                evidence_sources=[str(evidence.resolve())],
                confidence="low",
            )
        if auth_l not in _sconn_ok_auth.union({"secret", "certificate"}):
            return EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=(
                    f"Service connection `{c.get('name', '<unnamed>')}` has unsupported authentication value "
                    f"'{raw_auth}'. Allowed values: workload_identity_federation, service_principal, "
                    "managed_identity, certificate, secret."
                ),
                remediation="Populate authentication for each service connection entry from Azure DevOps inventory.",
                evidence_sources=[str(evidence.resolve())],
                confidence="low",
            )
    if any(isinstance(c, dict) and c.get("authentication") == "secret" for c in conns):
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason="At least one service connection is recorded as secret-based (PAT/username/password/token).",
            remediation="Prefer WorkloadIdentityFederation or managed identities for deployment connections.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data) and _azure_pipeline_governance_api_support_complete(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="No secret-class service connections observed in live-collected governance inventory.",
            remediation="Re-collect after onboarding or rotating service connections.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Service connection inventory self-attests no secret-class authentication entries.",
        remediation="Prefer collect-evidence for API-backed inventory.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_az_wifev_057(ctx: EvalContext) -> EvalOutcome:
    """AZ-WIFEV-057: workload identity federation evidenced on service connections."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "azure-pipeline-governance.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No azure-pipeline-governance.json to evaluate workload identity federation evidence.",
            remediation="Run collect-evidence for Azure or scaffold governance JSON with service_connections.",
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_azure_pipeline_governance_schema,
        evidence_name="Azure pipeline governance",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-azure-pipeline-governance.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture = data.get("posture")
    if not isinstance(posture, dict) or "federated_identity_preferred" not in posture:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Evidence file missing posture.federated_identity_preferred field.",
            remediation=(
                "Set posture.federated_identity_preferred in azure-pipeline-governance.json after enabling WIF."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if posture.get("federated_identity_preferred") is False:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Federated identity is not preferred per governance evidence. "
                "Set posture.federated_identity_preferred: true after configuring workload "
                "identity federation."
            ),
            remediation="Configure workload identity federation for deployment service connections and re-attest.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    if posture.get("federated_identity_preferred") is not True:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Evidence file missing posture.federated_identity_preferred field.",
            remediation="Set posture.federated_identity_preferred to a boolean true/false value.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    conns = data.get("service_connections")
    wif_conns = (
        [
            c
            for c in conns
            if isinstance(c, dict)
            and str(c.get("authentication", "")).strip().lower() == "workload_identity_federation"
        ]
        if isinstance(conns, list)
        else []
    )
    has_wif = bool(wif_conns)
    proof_fields = ("federation_subject", "issuer_url", "audience")
    if has_wif:
        for c in wif_conns:
            empty_fields: list[str] = []
            for f in proof_fields:
                raw = c.get(f)
                if raw is None:
                    empty_fields.append(f)
                    continue
                if not isinstance(raw, str):
                    empty_fields.append(f)
                    continue
                stripped = raw.strip()
                if not stripped or stripped.startswith("<"):
                    empty_fields.append(f)
            if empty_fields:
                return EvalOutcome(
                    status=ControlStatus.NOT_EVALUATED,
                    reason=(
                        "Workload identity federation evidence is incomplete. "
                        "The following fields are missing or contain placeholder values: "
                        f"{', '.join(empty_fields)}. "
                        "Collect real WIF configuration values from the Azure DevOps service connection."
                    ),
                    remediation=(
                        "Update the evidence file with actual federation_subject, issuer_url, and audience values."
                    ),
                    evidence_sources=[str(evidence.resolve())],
                    confidence="low",
                )
    warn: tuple[str, ...] = ()
    if not has_wif:
        warn = (
            "posture.federated_identity_preferred is true but no service_connections entry documents "
            "workload_identity_federation; confirm the inventory is complete.",
        )
    ecm = (
        EvidenceCollectionMethod.LIVE
        if _evidence_is_api_backed(data) and _azure_pipeline_governance_api_support_complete(data)
        else EvidenceCollectionMethod.MANUAL
    )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="Governance evidence prefers federated identity for Azure DevOps deployment connections.",
        remediation="Expand federation coverage and re-collect after connection changes.",
        evidence_sources=[str(evidence.resolve())],
        confidence="medium",
        evidence_collection_method=ecm,
        operational_warnings=warn,
    )


def eval_az_artsbom_058(ctx: EvalContext) -> EvalOutcome:
    """AZ-ARTSBOM-058: SBOM attested against a concrete release artifact digest."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "azure-sbom-artifact.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No azure-sbom-artifact.json for artifact-bound SBOM attestation.",
            remediation="Add evidence per reports/schema/evidence-azure-sbom-artifact.schema.json.",
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_azure_sbom_artifact_schema,
        evidence_name="Azure SBOM artifact",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-azure-sbom-artifact.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    for d in _sbom_artifact_digest_strings(data):
        if is_placeholder_digest(d):
            return _digest_placeholder_manual_review(evidence)
        if not _is_valid_sha256_digest(d):
            return _digest_invalid_not_evaluated(evidence)
    posture = data["posture"]
    assert isinstance(posture, dict)
    required = ("sbom_covers_release_artifact", "sbom_digest_recorded", "artifact_digest_recorded")
    missing = [k for k in required if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"SBOM artifact evidence incomplete: {', '.join(missing)}.",
            remediation="Record digests for the release artifact and SBOM and assert coverage.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Artifact-bound SBOM posture confirmed via live collection metadata.",
            remediation="Refresh when pipeline outputs or SBOM artifacts change.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Artifact-bound SBOM posture self-attested as satisfied.",
        remediation="Prefer automation that stamps collection metadata from Azure DevOps.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_az_artprv_059(ctx: EvalContext) -> EvalOutcome:
    """AZ-ARTPRV-059: provenance / attestation attested against a concrete release artifact digest."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "azure-provenance-artifact.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No azure-provenance-artifact.json for artifact-bound provenance attestation.",
            remediation="Add evidence per reports/schema/evidence-azure-provenance-artifact.schema.json.",
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_azure_provenance_artifact_schema,
        evidence_name="Azure provenance artifact",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-azure-provenance-artifact.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    for d in _provenance_artifact_digest_strings(data):
        if is_placeholder_digest(d):
            return _digest_placeholder_manual_review(evidence)
        if not _is_valid_sha256_digest(d):
            return _digest_invalid_not_evaluated(evidence)
    posture = data["posture"]
    assert isinstance(posture, dict)
    required = ("attestation_covers_release_artifact", "attestation_digest_recorded", "artifact_digest_recorded")
    missing = [k for k in required if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"Provenance artifact evidence incomplete: {', '.join(missing)}.",
            remediation="Record digests for the artifact and attestation bundle.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Artifact-bound provenance posture confirmed via live collection metadata.",
            remediation="Refresh when signing material or release artifacts change.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Artifact-bound provenance posture self-attested as satisfied.",
        remediation="Prefer automation that emits collection metadata from your release pipeline.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_aws_ci_037(ctx: EvalContext) -> EvalOutcome:
    """AWS-CI-037: committed CodeBuild buildspec or CodePipeline-shaped file exists."""

    aws = ctx.aws_ci
    if aws.buildspec_paths or aws.codepipeline_paths:
        sources = [str(p.resolve()) for p in (*aws.buildspec_paths, *aws.codepipeline_paths)]
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Found AWS CodeBuild buildspec and/or committed CodePipeline definition file(s).",
            remediation="Keep committed pipeline exports curated and aligned with live AWS configuration.",
            evidence_sources=sources,
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No supported buildspec.yml or pipelines/aws/codepipeline* files found.",
        remediation="Add buildspec.yml or export CodePipeline JSON/YAML under pipelines/aws/ for evaluation.",
        evidence_sources=[],
        confidence="high",
    )


def eval_aws_secret_038(ctx: EvalContext) -> EvalOutcome:
    """AWS-SECRET-038: buildspec avoids obvious inline secrets and prefers managed secret sources."""

    aws = ctx.aws_ci
    if not aws.buildspec_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AWS_BUILDSPEC_REASON,
            remediation="Add a buildspec to evaluate CodeBuild secret handling signals.",
            evidence_sources=[],
            confidence="high",
        )
    if aws.inline_secret_risk_paths:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Potential inline secret material or high-risk credential pattern detected in buildspec text.",
            remediation="Remove inline secrets; use AWS Secrets Manager or Systems Manager Parameter Store references.",
            evidence_sources=[str(p.resolve()) for p in aws.inline_secret_risk_paths],
            confidence="low",
        )
    uses_managed = bool(aws.parameter_store_signal_paths or aws.secrets_manager_signal_paths)
    strict = ctx.profile_id in _STRICT_AWS_SECRET_PROFILE_IDS
    if strict and not uses_managed:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Strict profile expects Parameter Store or Secrets Manager references in buildspec env.",
            remediation=(
                "Declare secrets via env.parameter-store or env.secrets-manager per AWS CodeBuild buildspec reference."
            ),
            evidence_sources=[str(p.resolve()) for p in aws.buildspec_paths],
            confidence="medium",
        )
    if not uses_managed:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No Parameter Store or Secrets Manager env references detected; cannot claim managed secret sourcing."
            ),
            remediation=(
                "Prefer env.parameter-store / env.secrets-manager blocks instead of implicit environment secrets."
            ),
            evidence_sources=[str(p.resolve()) for p in aws.buildspec_paths],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="Buildspec references Parameter Store and/or Secrets Manager for environment secrets.",
        remediation="Keep secrets out of buildspec plaintext; rotate and scope parameters per least privilege.",
        evidence_sources=[
            str(p.resolve()) for p in (*aws.parameter_store_signal_paths, *aws.secrets_manager_signal_paths)
        ],
        confidence="high",
    )


def eval_aws_sec_039(ctx: EvalContext) -> EvalOutcome:
    """AWS-SEC-039: security scanning signal in CodeBuild buildspec."""

    aws = ctx.aws_ci
    if not aws.buildspec_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AWS_BUILDSPEC_REASON,
            remediation="Add security scanning commands to CodeBuild phases.",
            evidence_sources=[],
            confidence="high",
        )
    if aws.security_scan_signal_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Security scanning tool signal detected in buildspec."
                " (keyword signal in pipeline YAML — not verified as executed)"
            ),
            remediation="Keep scanners on default-branch and release build paths.",
            evidence_sources=[str(p.resolve()) for p in aws.security_scan_signal_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No security scanning tool signal detected in buildspec.",
        remediation="Add SAST/secret scanning appropriate to the stack (for example Semgrep, Trivy, CodeQL CLI).",
        evidence_sources=[str(p.resolve()) for p in aws.buildspec_paths],
        confidence="medium",
    )


def eval_aws_sca_040(ctx: EvalContext) -> EvalOutcome:
    """AWS-SCA-040: dependency audit or SCA signal in buildspec."""

    aws = ctx.aws_ci
    if not aws.buildspec_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AWS_BUILDSPEC_REASON,
            remediation="Add dependency audit tooling to CodeBuild phases.",
            evidence_sources=[],
            confidence="high",
        )
    if aws.dependency_audit_signal_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Dependency audit or SCA tool signal detected in buildspec."
                " (keyword signal in pipeline YAML — not verified as executed)"
            ),
            remediation="Keep SCA on PR validation builds where applicable.",
            evidence_sources=[str(p.resolve()) for p in aws.dependency_audit_signal_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No dependency audit or SCA signal detected in buildspec.",
        remediation="Add pip-audit, npm audit, osv-scanner, or equivalent dependency checks.",
        evidence_sources=[str(p.resolve()) for p in aws.buildspec_paths],
        confidence="medium",
    )


def eval_aws_sbom_041(ctx: EvalContext) -> EvalOutcome:
    """AWS-SBOM-041: SBOM generation signal in buildspec."""

    aws = ctx.aws_ci
    if not aws.buildspec_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AWS_BUILDSPEC_REASON,
            remediation="Add SBOM generation to CodeBuild packaging or release phases.",
            evidence_sources=[],
            confidence="high",
        )
    if aws.sbom_signal_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "SBOM generation signal detected in buildspec."
                " (keyword signal in pipeline YAML — not verified as executed)"
            ),
            remediation="Publish SBOM artifacts alongside build outputs.",
            evidence_sources=[str(p.resolve()) for p in aws.sbom_signal_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No SBOM generation signal detected in buildspec.",
        remediation="Add CycloneDX, Syft, SPDX, or equivalent SBOM tooling.",
        evidence_sources=[str(p.resolve()) for p in aws.buildspec_paths],
        confidence="medium",
    )


def eval_aws_pipe_042(ctx: EvalContext) -> EvalOutcome:
    """AWS-PIPE-042: committed CodePipeline export under pipelines/aws/ with minimal useful structure."""

    aws = ctx.aws_ci
    if aws.codepipeline_valid_export_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Committed CodePipeline export(s) include stage(s) and/or artifact store metadata "
                "(GetPipeline-shaped object under `pipeline`)."
            ),
            remediation="Treat exports as policy inputs; reconcile with live pipeline definitions regularly.",
            evidence_sources=[str(p.resolve()) for p in aws.codepipeline_valid_export_paths],
            confidence="high",
        )
    if aws.codepipeline_paths:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "CodePipeline-shaped file(s) exist under pipelines/aws/, but none meet the minimum structural bar "
                "(need `pipeline.stages` with at least one stage, or `pipeline.artifactStore` / `artifactStores`)."
            ),
            remediation="Export GetPipeline JSON (or equivalent) so `pipeline` is an object with stages or stores.",
            evidence_sources=[str(p.resolve()) for p in aws.codepipeline_paths],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No pipelines/aws/codepipeline*.{json,yaml,yml} file found.",
        remediation="Commit a curated export or pipeline-as-code file for static evaluation.",
        evidence_sources=[],
        confidence="high",
    )


def eval_aws_prov_043(ctx: EvalContext) -> EvalOutcome:
    """AWS-PROV-043: provenance or attestation signal in buildspec."""

    aws = ctx.aws_ci
    if not aws.buildspec_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason=NO_AWS_BUILDSPEC_REASON,
            remediation="Add provenance generation where release integrity requires it.",
            evidence_sources=[],
            confidence="high",
        )
    if aws.provenance_signal_paths:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Provenance or attestation tooling signal detected in buildspec."
                " (keyword signal in buildspec — not verified as executed)"
            ),
            remediation="Align provenance outputs with SLSA-style consumer expectations.",
            evidence_sources=[str(p.resolve()) for p in aws.provenance_signal_paths],
            confidence="low",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No provenance or attestation signal detected in buildspec.",
        remediation="Add cosign/sigstore attestations or equivalent provenance capture in release builds.",
        evidence_sources=[str(p.resolve()) for p in aws.buildspec_paths],
        confidence="low",
    )


def eval_aws_cp_044(ctx: EvalContext) -> EvalOutcome:
    """AWS-CP-044: CodePipeline promotion and artifact governance from evidence."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "aws-codepipeline.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="CodePipeline promotion posture cannot be proven from buildspec alone.",
            remediation=(
                "Review manual approvals, artifact encryption, and execution modes in AWS CodePipeline, "
                "then optionally add .oss-policy-kit/evidence/aws-codepipeline.json."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_aws_codepipeline_schema,
        evidence_name="AWS CodePipeline",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-aws-codepipeline.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture = data["posture"]
    assert isinstance(posture, dict)
    required = (
        "manual_approval_before_production",
        "artifact_store_encryption_enabled",
        "production_execution_mode_not_parallel",
    )
    missing = [k for k in required if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=(
                f"CodePipeline evidence present but required promotion control(s) not enabled: {', '.join(missing)}."
            ),
            remediation="Enable approvals, artifact encryption, and non-parallel execution where appropriate.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="CodePipeline governance posture confirmed via live AWS API collection evidence.",
            remediation="Refresh evidence after pipeline structure or security settings change.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="CodePipeline governance evidence present with strict posture self-attested as enabled.",
        remediation="Refresh evidence after pipeline structure or security settings change.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_aws_cb_045(ctx: EvalContext) -> EvalOutcome:
    """AWS-CB-045: CodeBuild project posture from evidence."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "aws-codebuild-project.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="CodeBuild project posture cannot be proven from buildspec alone.",
            remediation=(
                "Review CodeBuild project settings (privileged mode, credentials model) in AWS, "
                "then optionally add .oss-policy-kit/evidence/aws-codebuild-project.json."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_aws_codebuild_project_schema,
        evidence_name="AWS CodeBuild project",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-aws-codebuild-project.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture = data["posture"]
    assert isinstance(posture, dict)
    required: tuple[str, ...] = ("privileged_mode_disabled", "no_plaintext_credentials_in_project_config")
    if ctx.profile_id in _STRICT_AWS_CODEBUILD_PROJECT_PROFILE_IDS:
        required = required + ("codebuild_service_role_configured",)
    missing = [k for k in required if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"CodeBuild evidence present but required posture flag(s) not enabled: {', '.join(missing)}.",
            remediation="Disable privileged mode where possible and remove plaintext credentials from project config.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="CodeBuild project posture confirmed via live AWS API collection evidence.",
            remediation="Refresh evidence after project configuration changes.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="CodeBuild project evidence present with constrained posture self-attested as enabled.",
        remediation="Refresh evidence after project configuration changes.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_aws_cc_046(ctx: EvalContext) -> EvalOutcome:
    """AWS-CC-046: optional CodeCommit approval-rule posture from evidence (CodeCommit sources only)."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "aws-codecommit-review-posture.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No CodeCommit review posture evidence supplied (optional for non-CodeCommit sources).",
            remediation="If the default branch uses CodeCommit, add aws-codecommit-review-posture.json when needed.",
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_aws_codecommit_review_schema,
        evidence_name="AWS CodeCommit review posture",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-aws-codecommit-review-posture.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture = data["posture"]
    assert isinstance(posture, dict)
    required = ("approval_rule_templates_enabled", "minimum_approvals_enforced")
    missing = [k for k in required if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"CodeCommit evidence present but required review control(s) not enabled: {', '.join(missing)}.",
            remediation="Configure approval rule templates and minimum approvals per AWS CodeCommit guidance.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="CodeCommit review posture confirmed via live AWS API collection evidence.",
            remediation="Refresh evidence after approval rule template changes.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="CodeCommit review posture evidence present and self-attested as enabled.",
        remediation="Refresh evidence after approval rule template changes.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_aws_pipeiam_056(ctx: EvalContext) -> EvalOutcome:
    """AWS-PIPEIAM-056: CodePipeline service role / IAM execution boundary for the pipeline."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "aws-codepipeline.json"
    if evidence.is_file():
        data, error, ph = _validate_json_evidence(
            evidence,
            schema_loader=_aws_codepipeline_schema,
            evidence_name="AWS CodePipeline",
        )
        if not error and data is not None:
            blocked = _evidence_placeholder_outcome(evidence, ph)
            if blocked is not None:
                return blocked
            iam = data.get("iam")
            if isinstance(iam, dict) and iam.get("pipeline_service_role_arn_configured") is True:
                if _evidence_is_api_backed(data):
                    return EvalOutcome(
                        status=ControlStatus.PASS,
                        reason="CodePipeline service role ARN present in live-collected pipeline evidence.",
                        remediation="Re-collect after IAM or pipeline role changes.",
                        evidence_sources=[str(evidence.resolve())],
                        confidence="high",
                        evidence_collection_method=EvidenceCollectionMethod.LIVE,
                    )
                return EvalOutcome(
                    status=ControlStatus.SELF_ATTESTED,
                    reason="CodePipeline IAM posture self-attested with pipeline service role configured.",
                    remediation="Prefer collect-evidence so service role presence is API-derived.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="low",
                    evidence_collection_method=EvidenceCollectionMethod.MANUAL,
                )
    if ctx.aws_ci.codepipeline_committed_iam_role_paths:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "AWS-PIPEIAM-056: No evidence file found at the expected path. "
                "A keyword signal was detected in the pipeline YAML, but this cannot "
                "prove platform-level posture. Collect evidence via the platform collector "
                "or attest the configuration manually."
            ),
            remediation=(
                "Run collect-evidence for AWS or add API-backed pipeline/build JSON under .oss-policy-kit/evidence/."
            ),
            evidence_sources=[str(p.resolve()) for p in ctx.aws_ci.codepipeline_committed_iam_role_paths],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            "AWS-PIPEIAM-056: No evidence file found at the expected path. "
            "A keyword signal was detected in the pipeline YAML, but this cannot "
            "prove platform-level posture. Collect evidence via the platform collector "
            "or attest the configuration manually."
        ),
        remediation=(
            "Run collect-evidence with AWS_CODEPIPELINE_NAME set, or commit a GetPipeline export that includes "
            "`pipeline.roleArn` alongside stages or artifact stores."
        ),
        evidence_sources=[],
        confidence="low",
    )


def eval_aws_cbident_057(ctx: EvalContext) -> EvalOutcome:
    """AWS-CBIDENT-057: CodeBuild execution identity boundary (service role vs plaintext env credentials)."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "aws-codebuild-project.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "AWS-CBIDENT-057: No evidence file found at the expected path. "
                "A keyword signal was detected in the pipeline YAML, but this cannot "
                "prove platform-level posture. Collect evidence via the platform collector "
                "or attest the configuration manually."
            ),
            remediation="Collect CodeBuild project evidence or scaffold and attest identity fields explicitly.",
            evidence_sources=[],
            confidence="low",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_aws_codebuild_project_schema,
        evidence_name="AWS CodeBuild project",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-aws-codebuild-project.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    ident = data.get("identity")
    if not isinstance(ident, dict):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="CodeBuild evidence lacks structured `identity` block for credential-boundary checks.",
            remediation="Re-run collect-evidence (adds `identity`) or extend manual JSON per the published schema.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    need = ("service_role_arn_present", "no_plaintext_environment_credentials")
    missing = [k for k in need if ident.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"CodeBuild identity evidence present but required flag(s) not enabled: {', '.join(missing)}.",
            remediation="Ensure a service role is configured and remove PLAINTEXT secret-style environment variables.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="CodeBuild identity boundary confirmed via live AWS API collection evidence.",
            remediation="Refresh evidence after project credential or role changes.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="CodeBuild identity posture self-attested as compliant.",
        remediation="Prefer collect-evidence so identity fields map to BatchGetProjects output.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_aws_sbomart_058(ctx: EvalContext) -> EvalOutcome:
    """AWS-SBOMART-058: SBOM tied to a concrete release artifact (hash-attested)."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "aws-sbom-artifact.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No aws-sbom-artifact.json evidence for artifact-bound SBOM attestation.",
            remediation="Add evidence per reports/schema/evidence-aws-sbom-artifact.schema.json or skip this control.",
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_aws_sbom_artifact_schema,
        evidence_name="AWS SBOM artifact",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-aws-sbom-artifact.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    for d in _sbom_artifact_digest_strings(data):
        if is_placeholder_digest(d):
            return _digest_placeholder_manual_review(evidence)
        if not _is_valid_sha256_digest(d):
            return _digest_invalid_not_evaluated(evidence)
    posture = data["posture"]
    assert isinstance(posture, dict)
    required = ("sbom_covers_release_artifact", "sbom_digest_recorded", "artifact_digest_recorded")
    missing = [k for k in required if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"SBOM artifact evidence present but incomplete posture: {', '.join(missing)}.",
            remediation="Record digests for both the release artifact and SBOM and assert coverage.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Artifact-bound SBOM posture confirmed via live collection metadata.",
            remediation="Refresh when artifacts or SBOM outputs change.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Artifact-bound SBOM posture self-attested as satisfied.",
        remediation="Prefer pipeline automation that emits collection metadata (collect-evidence) over manual JSON.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_aws_provart_059(ctx: EvalContext) -> EvalOutcome:
    """AWS-PROVART-059: provenance / attestation tied to a concrete release artifact."""

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "aws-provenance-artifact.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No aws-provenance-artifact.json evidence for artifact-bound provenance attestation.",
            remediation="Add evidence per reports/schema/evidence-aws-provenance-artifact.schema.json or skip.",
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_aws_provenance_artifact_schema,
        evidence_name="AWS provenance artifact",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-aws-provenance-artifact.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    for d in _provenance_artifact_digest_strings(data):
        if is_placeholder_digest(d):
            return _digest_placeholder_manual_review(evidence)
        if not _is_valid_sha256_digest(d):
            return _digest_invalid_not_evaluated(evidence)
    posture = data["posture"]
    assert isinstance(posture, dict)
    required = ("attestation_covers_release_artifact", "attestation_digest_recorded", "artifact_digest_recorded")
    missing = [k for k in required if posture.get(k) is not True]
    if missing:
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason=f"Provenance artifact evidence present but incomplete posture: {', '.join(missing)}.",
            remediation="Record digests for the artifact and its attestation (for example cosign record).",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
            evidence_collection_method=(
                EvidenceCollectionMethod.LIVE if _evidence_is_api_backed(data) else EvidenceCollectionMethod.MANUAL
            ),
        )
    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Artifact-bound provenance posture confirmed via live collection metadata.",
            remediation="Refresh when signing keys, artifacts, or attestations change.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Artifact-bound provenance posture self-attested as satisfied.",
        remediation="Prefer automated attestation capture with collect-evidence metadata.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


# ── New evaluators — maturity uplift ─────────────────────────────────────────


def eval_dep_update_001(ctx: EvalContext) -> EvalOutcome:
    """DEP-UPDATE-001: Automated dependency update tool (Dependabot or Renovate) configured."""
    repo = ctx.repo_root
    for p in (repo / ".github" / "dependabot.yml", repo / ".github" / "dependabot.yaml"):
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Dependabot configuration file detected.",
                remediation="Keep Dependabot schedules aligned with project risk tolerance.",
                evidence_sources=[str(p.resolve())],
                confidence="high",
            )
    renovate_candidates = [
        repo / "renovate.json",
        repo / "renovate.json5",
        repo / ".renovaterc",
        repo / ".renovaterc.json",
        repo / ".github" / "renovate.json",
    ]
    for p in renovate_candidates:
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Renovate configuration file detected.",
                remediation="Keep Renovate schedules and automerge rules aligned with security policy.",
                evidence_sources=[str(p.resolve())],
                confidence="high",
            )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No automated dependency update tool detected (Dependabot or Renovate).",
        remediation=("Add .github/dependabot.yml for Dependabot or renovate.json at the repository root for Renovate."),
        evidence_sources=[],
        confidence="high",
    )


_SCORECARD_MIN_SCORE = 5.0


def eval_oss_scorecard_001(ctx: EvalContext) -> EvalOutcome:
    """OSS-SCORECARD-001: OpenSSF Scorecard score meets minimum threshold (5.0/10).

    Prefers the official aggregate ``score`` emitted by the Scorecard CLI. If
    only per-check scores are present, falls back to their arithmetic mean
    with reduced confidence (Scorecard uses a weighted aggregate internally,
    so the mean is only a proxy).
    """

    if ctx.scorecard is None:
        return EvalOutcome(
            status=ControlStatus.NOT_EVALUATED,
            reason="No OpenSSF Scorecard JSON provided; cannot evaluate scorecard score.",
            remediation=(
                "Generate a Scorecard report via 'scorecard --repo=<org>/<repo> --format=json' "
                "and pass it with --scorecard-json."
            ),
            evidence_sources=[],
            confidence="low",
        )
    src = [ctx.scorecard.raw_path or "scorecard"]
    official = ctx.scorecard.aggregate_score
    if official is not None:
        aggregate = round(float(official), 1)
        if aggregate >= _SCORECARD_MIN_SCORE:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"OpenSSF Scorecard aggregate score {aggregate}/10 (official `score` field) "
                    f"meets minimum threshold ({_SCORECARD_MIN_SCORE})."
                ),
                remediation="Continue improving scorecard checks to raise the score toward 8+.",
                evidence_sources=src,
                confidence="high",
            )
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"OpenSSF Scorecard aggregate score {aggregate}/10 (official `score` field) "
                f"is below minimum threshold ({_SCORECARD_MIN_SCORE})."
            ),
            remediation=(
                "Review the failing Scorecard checks. Common high-impact fixes: pin actions to SHAs "
                "(Pinned-Dependencies), add SECURITY.md (Security-Policy), enable branch "
                "protection (Branch-Protection)."
            ),
            evidence_sources=src,
            confidence="high",
        )
    scm = checks_as_map(ctx.scorecard)
    scores = [float(c.score) for c in scm.values() if c.score is not None and float(c.score) >= 0]
    if not scores:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=("Scorecard JSON present but no numeric aggregate `score` nor per-check scores could be extracted."),
            remediation=(
                "Ensure the file follows the OpenSSF Scorecard v2 JSON format (root `score` plus per-check entries)."
            ),
            evidence_sources=src,
            confidence="low",
        )
    proxy = round(sum(scores) / len(scores), 1)
    proxy_warning = (
        "Scorecard JSON lacks the official aggregate `score`; evaluator used an arithmetic mean "
        "of per-check scores as a proxy (Scorecard itself uses a weighted aggregate)."
    )
    if proxy >= _SCORECARD_MIN_SCORE:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"OpenSSF Scorecard proxy score {proxy}/10 (mean of per-check scores) "
                f"meets minimum threshold ({_SCORECARD_MIN_SCORE})."
            ),
            remediation=(
                "Regenerate Scorecard JSON with a recent CLI so the root `score` aggregate is available, "
                "then continue raising check scores toward 8+."
            ),
            evidence_sources=src,
            confidence="low",
            operational_warnings=(proxy_warning,),
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=(
            f"OpenSSF Scorecard proxy score {proxy}/10 (mean of per-check scores) "
            f"is below minimum threshold ({_SCORECARD_MIN_SCORE})."
        ),
        remediation=(
            "Review the failing Scorecard checks. Common high-impact fixes: pin actions to SHAs "
            "(Pinned-Dependencies), add SECURITY.md (Security-Policy), enable branch "
            "protection (Branch-Protection)."
        ),
        evidence_sources=src,
        confidence="low",
        operational_warnings=(proxy_warning,),
    )


_DOCKER_FROM_RE = re.compile(r"^FROM\s+(\S+)", re.MULTILINE)


def _find_dockerfiles(repo: Path) -> list[Path]:
    results: list[Path] = []
    for name in ("Dockerfile", "dockerfile"):
        p = repo / name
        if p.is_file():
            results.append(p)
    for p in repo.rglob("Dockerfile"):
        if p not in results and p.is_file():
            results.append(p)
    for p in repo.rglob("*.dockerfile"):
        if p.is_file():
            results.append(p)
    return results[:20]


def eval_cont_image_001(ctx: EvalContext) -> EvalOutcome:
    """CONT-IMAGE-001: Dockerfile base images pinned to immutable digest (@sha256:...)."""
    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Dockerfile detected at repository root or common paths.",
            remediation="Not applicable until a Dockerfile is added to the repository.",
            evidence_sources=[],
            confidence="high",
        )
    unpinned: list[str] = []
    for df in dockerfiles:
        with contextlib.suppress(OSError):
            content = df.read_text(encoding="utf-8", errors="replace")
            for ref in _DOCKER_FROM_RE.findall(content):
                if ref.lower() == "scratch":
                    continue
                if "@sha256:" not in ref:
                    unpinned.append(f"{df.name}: {ref}")
    if not unpinned:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="All Dockerfile FROM instructions use digest-pinned base images.",
            remediation="Keep base image digest pins updated via Dependabot or Renovate.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles],
            confidence="medium",
        )
    sample = unpinned[:3]
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=(
            "Dockerfile FROM instruction(s) without digest pin: "
            + "; ".join(sample)
            + (" (and more)" if len(unpinned) > 3 else "")
            + "."
        ),
        remediation=(
            "Pin base images to immutable SHA-256 digests: "
            "FROM ubuntu:22.04@sha256:<digest>. "
            "Use 'docker pull --quiet <image>' to resolve the digest."
        ),
        evidence_sources=[str(p.resolve()) for p in dockerfiles],
        confidence="medium",
    )


_USER_RE = re.compile(r"^\s*USER\s+(?!0\b)(?!root\b)(\S+)", re.MULTILINE | re.IGNORECASE)
_ROOT_USER_RE = re.compile(r"^\s*USER\s+(root|0)\s*$", re.MULTILINE | re.IGNORECASE)


def eval_cont_image_002(ctx: EvalContext) -> EvalOutcome:
    """CONT-IMAGE-002: Dockerfile declares a non-root USER instruction."""
    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Dockerfile detected at repository root or common paths.",
            remediation="Not applicable until a Dockerfile is added to the repository.",
            evidence_sources=[],
            confidence="high",
        )
    root_user: list[Path] = []
    missing_user: list[Path] = []
    for df in dockerfiles:
        with contextlib.suppress(OSError):
            content = df.read_text(encoding="utf-8", errors="replace")
            if _ROOT_USER_RE.search(content):
                root_user.append(df)
            elif not _USER_RE.search(content):
                missing_user.append(df)
    if root_user:
        names = ", ".join(p.name for p in root_user[:3])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Dockerfile(s) explicitly set USER root or USER 0: {names}.",
            remediation="Create a dedicated non-root user and switch to it before CMD/ENTRYPOINT.",
            evidence_sources=[str(p.resolve()) for p in root_user],
            confidence="medium",
        )
    if missing_user:
        names = ", ".join(p.name for p in missing_user[:3])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"Dockerfile(s) do not declare a non-root USER instruction: {names}.",
            remediation=(
                "Add 'RUN useradd -r -u 1001 appuser && USER appuser' before CMD/ENTRYPOINT "
                "to avoid running the process as root inside the container."
            ),
            evidence_sources=[str(p.resolve()) for p in missing_user],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Dockerfile(s) declare a non-root USER instruction ({len(dockerfiles)} file(s) checked).",
        remediation="Verify the declared user has the minimum filesystem permissions needed.",
        evidence_sources=[str(p.resolve()) for p in dockerfiles],
        confidence="medium",
    )


_IMAGE_SCAN_TOKENS = (
    "trivy",
    "grype",
    "snyk",
    "anchore",
    "clair",
    "docker scout",
    "aquasecurity/trivy",
    "lacework",
    "sysdig",
)


def eval_cont_image_003(ctx: EvalContext) -> EvalOutcome:
    """CONT-IMAGE-003: Container image scanning signal in CI workflows."""
    dockerfiles = _find_dockerfiles(ctx.repo_root)
    if not dockerfiles:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Dockerfile detected — image scanning is not applicable.",
            remediation="Not applicable until a Dockerfile is added.",
            evidence_sources=[],
            confidence="high",
        )
    all_ci_paths = (
        list(ctx.workflows.workflow_paths) + list(ctx.azure_pipelines.pipeline_paths) + list(ctx.aws_ci.buildspec_paths)
    )
    for p in all_ci_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(tok in text for tok in _IMAGE_SCAN_TOKENS):
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=(
                        f"Container image scanning tool signal detected in {p.name}. "
                        "(keyword signal in CI config — scan execution and policy thresholds not validated)"
                    ),
                    remediation="Keep image scanning on push and PR triggers; enforce severity thresholds.",
                    evidence_sources=[str(p.resolve())],
                    confidence="low",
                    operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
                )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No container image scanning signal detected in CI (Trivy, Grype, Snyk, Anchore, or equivalent).",
        remediation=(
            "Add an image scanning step to your CI pipeline. "
            "Example: uses: aquasecurity/trivy-action@<sha> with image-ref: <your-image>."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def _org_mfa_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-org-mfa-posture.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def eval_org_mfa_001(ctx: EvalContext) -> EvalOutcome:
    """ORG-MFA-001: Organization MFA enforcement posture evidenced."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "org-mfa-posture.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Organization MFA enforcement cannot be observed from a local repository clone.",
            remediation=(
                "Verify MFA enforcement in your organization security settings and add "
                ".oss-policy-kit/evidence/org-mfa-posture.json per the evidence schema."
            ),
            evidence_sources=[],
            confidence="high",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_org_mfa_schema,
        evidence_name="Organization MFA posture",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-org-mfa-posture.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture_raw = data.get("posture")
    posture: dict[str, Any] = dict(posture_raw) if isinstance(posture_raw, dict) else {}
    for k in ("mfa_required_for_all_members", "mfa_required_for_admins", "sso_enforced"):
        if k in data and k not in posture:
            posture[k] = data[k]

    all_m = posture.get("mfa_required_for_all_members")
    adm_m = posture.get("mfa_required_for_admins")
    if all_m is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Organization MFA evidence does not include mfa_required_for_all_members.",
            remediation="Populate mfa_required_for_all_members per the org-mfa-posture schema.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if all_m is False and adm_m is True:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "MFA is required for admins only, but not enforced for all organization members. "
                "This leaves non-admin members as a supply-chain risk vector."
            ),
            remediation="Enable MFA for every organization member, not only administrators.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    if all_m is False and adm_m is not True:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="MFA not enforced for organization members or admins. This is a critical identity control gap.",
            remediation="Enable MFA enforcement for all members and administrators in your organization settings.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    if adm_m is not True:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="MFA not enforced for organization administrators despite member-level MFA claims.",
            remediation="Require MFA for administrative accounts in your organization security policy.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )

    enforcement_scope_raw = data.get("enforcement_scope", None)
    enforcement_scope = enforcement_scope_raw.strip().lower() if isinstance(enforcement_scope_raw, str) else None
    if enforcement_scope in ("admins_only", "selected_teams", "partial"):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"MFA enforcement is scoped to '{enforcement_scope}' only. "
                "Full enforcement requires MFA for all organization members, "
                "not just administrators or selected teams."
            ),
            remediation=(
                "Configure MFA enforcement for all members in the organization settings, "
                "then set `enforcement_scope: all_members` in the evidence file."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )

    sso_warn: tuple[str, ...] = ()
    if posture.get("sso_enforced") is not True:
        sso_warn = ("SSO enforcement not confirmed in evidence; consider adding sso_enforced: true if applicable.",)
    if enforcement_scope is None:
        sso_warn = sso_warn + (
            "MFA enforcement scope was not specified in the evidence file. "
            "Consider adding 'enforcement_scope' to clarify who is covered.",
        )

    if _evidence_is_api_backed(data):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Organization MFA enforcement confirmed via live API collection evidence.",
            remediation="Refresh evidence after changes to organization membership or security settings.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.LIVE,
            operational_warnings=sso_warn,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Organization MFA enforcement self-attested as enabled for all members and admins.",
        remediation="Prefer collect-evidence to confirm MFA posture from the platform API.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        operational_warnings=sso_warn,
    )


_SBOM_FORMAT_MARKERS: dict[str, tuple[str, ...]] = {
    "spdx": ("SPDXVersion:", "spdxVersion", "SPDX-"),
    "cyclonedx": ("CycloneDX", "cyclonedx", "bomFormat"),
}


def _detect_sbom_format(content: str) -> str | None:
    sample = content[:4000]
    for fmt, markers in _SBOM_FORMAT_MARKERS.items():
        if any(m in sample for m in markers):
            return fmt
    return None


def _find_sbom_files(repo: Path) -> list[Path]:
    candidates: list[Path] = []
    for pat in ("*.spdx", "*.spdx.json", "*.cdx.json", "sbom.json", "sbom.xml", "bom.json", "bom.xml"):
        for p in repo.rglob(pat):
            if p.is_file():
                candidates.append(p)
    return candidates[:10]


def eval_build_sbom_qual_003(ctx: EvalContext) -> EvalOutcome:
    """BUILD-SBOM-QUAL-003: SBOM format validity — SPDX or CycloneDX document detectable in repo or evidence."""
    # Check evidence files for documented SBOM format first.
    for evid_name in ("azure-sbom-artifact.json", "aws-sbom-artifact.json"):
        evid = ctx.repo_root / ".oss-policy-kit" / "evidence" / evid_name
        if evid.is_file():
            with contextlib.suppress(OSError, json.JSONDecodeError):
                data = json.loads(evid.read_text(encoding="utf-8"))
                sbom_block = data.get("sbom") if isinstance(data, dict) else None
                fmt = str(sbom_block.get("format", "")).strip() if isinstance(sbom_block, dict) else ""
                if fmt and ("spdx" in fmt.lower() or "cyclonedx" in fmt.lower()):
                    return EvalOutcome(
                        status=ControlStatus.PASS,
                        reason=f"Evidence documents SBOM format '{fmt}' (SPDX/CycloneDX).",
                        remediation="Keep SBOM format and digest records current with each release.",
                        evidence_sources=[str(evid.resolve())],
                        confidence="medium",
                    )
    # Scan repo for SBOM files.
    sbom_files = _find_sbom_files(ctx.repo_root)
    if sbom_files:
        valid: list[str] = []
        invalid: list[str] = []
        for p in sbom_files:
            with contextlib.suppress(OSError):
                detected = _detect_sbom_format(p.read_text(encoding="utf-8", errors="replace"))
                if detected:
                    valid.append(f"{p.name} ({detected})")
                else:
                    invalid.append(p.name)
        if valid:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Valid SBOM format detected: {', '.join(valid[:3])}.",
                remediation="Keep SBOM files current with each release; sign and attest them for supply chain trust.",
                evidence_sources=[str(p.resolve()) for p in sbom_files],
                confidence="medium",
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"SBOM-like file(s) found but SPDX/CycloneDX format not confirmed: {', '.join(invalid[:3])}.",
            remediation=(
                "Use syft, CycloneDX CLI, or trivy to generate a valid SBOM and verify "
                "it contains SPDXVersion or bomFormat/CycloneDX markers."
            ),
            evidence_sources=[str(p.resolve()) for p in sbom_files],
            confidence="low",
        )
    # Check for CI signals that might produce an SBOM.
    all_ci = (
        list(ctx.workflows.workflow_paths) + list(ctx.azure_pipelines.pipeline_paths) + list(ctx.aws_ci.buildspec_paths)
    )
    for p in all_ci:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if "cyclonedx" in text or "spdx" in text or "syft" in text:
                return EvalOutcome(
                    status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                    reason=(
                        "SBOM keyword signal detected in CI, but no verifiable SBOM file or evidence found. "
                        "Add a CycloneDX or SPDX SBOM to the repository or add an evidence file."
                    ),
                    remediation=(
                        "Commit or publish the generated SBOM alongside release artifacts. "
                        "Prefer SPDX 2.3+ or CycloneDX 1.5+ for broad tool compatibility."
                    ),
                    evidence_sources=[str(p.resolve())],
                    confidence="low",
                )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No SBOM file or format evidence found in the repository.",
        remediation=(
            "Generate an SBOM in SPDX or CycloneDX format during release builds "
            "and include it as a verifiable release artifact."
        ),
        evidence_sources=[],
        confidence="medium",
    )


_AUDIT_STREAM_SIGNAL_PATHS: tuple[str, ...] = (
    ".github/audit-log-streaming.yml",
    ".github/audit-log-streaming.yaml",
    "RELEASE_OPERATIONS.md",
    "docs/release-readiness.md",
)

_AUDIT_STREAM_SIGNAL_KEYWORDS: tuple[str, ...] = (
    "audit_log_streaming",
    "audit-log-streaming",
    "audit log streaming",
)


def _audit_stream_signal_match(repo: Path) -> Path | None:
    """Return a clone-visible path that signals audit log streaming, or None."""

    for rel in _AUDIT_STREAM_SIGNAL_PATHS:
        p = repo / rel
        if not p.is_file():
            continue
        # Configuration YAMLs imply intent on their own; doc files require a keyword match
        # so a generic release-readiness.md without an audit-streaming section does not pass.
        if rel.endswith((".yml", ".yaml")):
            return p
        try:
            text = p.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if any(kw in text for kw in _AUDIT_STREAM_SIGNAL_KEYWORDS):
            return p
    return None


def eval_audit_stream_060(ctx: EvalContext) -> EvalOutcome:
    """AUDIT-STREAM-060: Audit log streaming to centralized SIEM/object store."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "audit-log-streaming.json"
    if not evidence.is_file():
        signal = _audit_stream_signal_match(ctx.repo_root)
        if signal is not None:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"Audit log streaming intent detected via clone signal ({signal.name}). "
                    "Heuristic only — promote to evidence-backed by adding "
                    ".oss-policy-kit/evidence/audit-log-streaming.json with destinations."
                ),
                remediation=(
                    "Document streaming destinations in .oss-policy-kit/evidence/audit-log-streaming.json "
                    "per evidence-audit-log-streaming.schema.json so trust projects to verified."
                ),
                evidence_sources=[str(signal.resolve())],
                confidence="low",
                operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "Centralized audit log streaming cannot be observed from a local clone. "
                "Add .oss-policy-kit/evidence/audit-log-streaming.json after configuring "
                "GitHub/Azure/AWS audit log streaming to a SIEM or object store (closes OWASP CICD-SEC-10)."
            ),
            remediation=(
                "Configure org-level audit log streaming (GitHub Enterprise audit-log streaming, "
                "Azure DevOps auditstreams, AWS CloudTrail) and record the destinations in evidence."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_audit_log_streaming_schema,
        evidence_name="Audit log streaming",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-audit-log-streaming.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    streaming_enabled = bool(data.get("streaming_enabled"))
    destinations = data.get("destinations") or []
    if not streaming_enabled or not destinations:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Audit log streaming evidence reports streaming_enabled=false or empty destinations[]. "
                "Centralized log forwarding is the OWASP CICD-SEC-10 mitigation."
            ),
            remediation="Enable audit log streaming for the platform org and register at least one destination.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    method = EvidenceCollectionMethod.STATIC
    coll = data.get("collection")
    if isinstance(coll, dict) and str(coll.get("evidence_collection_method", "")).strip().lower() == "live":
        method = EvidenceCollectionMethod.LIVE
    elif isinstance(coll, dict) and str(coll.get("evidence_collection_method", "")).strip().lower() == "manual":
        method = EvidenceCollectionMethod.MANUAL
    dest_kinds = ", ".join(sorted({str(d.get("kind", "?")) for d in destinations if isinstance(d, dict)}))
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Audit log streaming evidence is valid: {len(destinations)} destination(s) configured ({dest_kinds})."
        ),
        remediation="Re-attest evidence within freshness window when streaming destinations change.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=method,
    )


_PROV_VERIFY_FILES: tuple[tuple[str, Callable[[], dict[str, Any]]], ...] = (
    ("github-provenance-artifact.json", _github_provenance_artifact_schema),
    ("azure-provenance-artifact.json", _azure_provenance_artifact_schema),
    ("aws-provenance-artifact.json", _aws_provenance_artifact_schema),
)


def _prov_verify_lookup_order(profile_id: str) -> tuple[tuple[str, Callable[[], dict[str, Any]]], ...]:
    """Order provenance evidence files to prefer the family that matches *profile_id*."""

    pid = profile_id.lower()
    if pid.startswith("github-"):
        return _PROV_VERIFY_FILES
    if pid.startswith("azure-"):
        return tuple(sorted(_PROV_VERIFY_FILES, key=lambda x: 0 if "azure" in x[0] else 1))
    if pid.startswith("aws-"):
        return tuple(sorted(_PROV_VERIFY_FILES, key=lambda x: 0 if "aws" in x[0] else 1))
    return _PROV_VERIFY_FILES


def _verification_freshness_status(verified_at: str, *, max_age_days: int) -> str:
    try:
        dt = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return "unparseable"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    age = (now - dt).days
    if age < 0:
        return "future"
    if age <= max_age_days:
        return "fresh"
    return "stale"


def eval_prov_verify_061(ctx: EvalContext) -> EvalOutcome:
    """PROV-VERIFY-061: Build provenance attestation is verifiable (sigstore / Artifact Attestations)."""
    evidence_dir = ctx.repo_root / ".oss-policy-kit" / "evidence"
    candidate: Path | None = None
    schema_loader: Callable[[], dict[str, Any]] | None = None
    for filename, loader in _prov_verify_lookup_order(ctx.profile_id):
        p = evidence_dir / filename
        if p.is_file():
            candidate = p
            schema_loader = loader
            break
    if candidate is None or schema_loader is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No provenance-artifact evidence file found. PROV-VERIFY-061 requires a "
                "{github,azure,aws}-provenance-artifact.json with a populated verification block."
            ),
            remediation=(
                "Run `gh attestation verify` (or `cosign verify-bundle`) against the release artifact "
                "and record the result in .oss-policy-kit/evidence/<platform>-provenance-artifact.json "
                "under the verification field."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        candidate,
        schema_loader=schema_loader,
        evidence_name=f"{candidate.stem.replace('-', ' ')} verification",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation=f"Fix the evidence file or regenerate it with `gh attestation verify`. ({candidate.name})",
            evidence_sources=[str(candidate.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(candidate, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    verification = data.get("verification")
    if not isinstance(verification, dict):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"Evidence file {candidate.name} has no verification block. "
                "Provenance presence alone is signal-grade; PROV-VERIFY-061 requires "
                "an independent verification result (issuer, transparency-log inclusion, verified_at)."
            ),
            remediation=(
                "Run `gh attestation verify <artifact> --repo owner/name` (public repos use the sigstore "
                "public-good instance) and write the result into the verification block of this file."
            ),
            evidence_sources=[str(candidate.resolve())],
            confidence="medium",
        )
    transparency = bool(verification.get("transparency_log_inclusion"))
    if not transparency:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Verification block in {candidate.name} reports transparency_log_inclusion=false. "
                "Without transparency-log inclusion, the attestation cannot be retroactively audited."
            ),
            remediation=(
                "Re-issue the attestation through a builder that records inclusion in the Rekor transparency log."
            ),
            evidence_sources=[str(candidate.resolve())],
            confidence="high",
        )
    verified_at_raw = verification.get("verified_at")
    if not isinstance(verified_at_raw, str) or not verified_at_raw.strip():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"verification.verified_at is missing or empty in {candidate.name}.",
            remediation="Record the ISO8601 UTC timestamp at which the attestation was verified.",
            evidence_sources=[str(candidate.resolve())],
            confidence="low",
        )
    fresh = _verification_freshness_status(verified_at_raw, max_age_days=ctx.evidence_max_age_days)
    if fresh == "stale":
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Verification record in {candidate.name} is older than {ctx.evidence_max_age_days} days "
                f"(verified_at={verified_at_raw}). Re-verify the attestation before relying on this control."
            ),
            remediation="Re-run `gh attestation verify` (or cosign verify-bundle) and update verified_at.",
            evidence_sources=[str(candidate.resolve())],
            confidence="high",
        )
    if fresh in ("future", "unparseable"):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"verification.verified_at is unparseable or in the future ({verified_at_raw}).",
            remediation="Use a real ISO8601 UTC timestamp.",
            evidence_sources=[str(candidate.resolve())],
            confidence="low",
        )
    method = str(verification.get("method", "unknown"))
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Provenance attestation verified ({method}); transparency-log inclusion confirmed; "
            f"verified_at={verified_at_raw} within {ctx.evidence_max_age_days}-day freshness window."
        ),
        remediation="Re-verify on every release artifact emission to keep verified_at within the freshness window.",
        evidence_sources=[str(candidate.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.LIVE,
    )


_SELF_HOSTED_PATTERN = re.compile(r"runs-on\s*:\s*(.+)", re.IGNORECASE)


def _workflow_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _self_hosted_workflow_paths(repo: Path) -> tuple[list[Path], list[Path]]:
    """Return (all_self_hosted_paths, paths_marked_ephemeral) by raw scanning workflow YAMLs."""

    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.is_dir():
        return [], []
    all_self: list[Path] = []
    ephemeral_self: list[Path] = []
    for yml in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        text = _workflow_text(yml)
        if not text:
            continue
        is_self = False
        is_ephemeral = False
        for match in _SELF_HOSTED_PATTERN.finditer(text):
            line = match.group(1).strip().lower()
            if "self-hosted" in line:
                is_self = True
                if "ephemeral" in line:
                    is_ephemeral = True
        if is_self:
            all_self.append(yml)
            if is_ephemeral:
                ephemeral_self.append(yml)
    return all_self, ephemeral_self


def eval_gh_runner_062(ctx: EvalContext) -> EvalOutcome:
    """GH-RUNNER-062: Self-hosted runners are ephemeral and restricted from PR-triggered workflows."""
    if not ctx.workflows.workflow_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows found; self-hosted runner posture is not applicable.",
            remediation="N/A unless GitHub Actions is adopted for this repository.",
            evidence_sources=[],
            confidence="high",
        )
    pr_self_hosted = list(ctx.workflows.pr_self_hosted_runner_paths)
    if pr_self_hosted:
        names = ", ".join(p.name for p in pr_self_hosted[:5])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"PR-triggered workflows use self-hosted runners ({names}). This is the trivy-action "
                "2026-03 attack pattern: any forked-PR can run on the runner host and exfiltrate secrets."
            ),
            remediation=(
                "Move PR-triggered jobs to GitHub-hosted runners, or split CI so self-hosted only runs on "
                "push/schedule with restricted runner-groups."
            ),
            evidence_sources=[str(p.resolve()) for p in pr_self_hosted],
            confidence="high",
        )
    all_self, ephemeral = _self_hosted_workflow_paths(ctx.repo_root)
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "runner-groups.json"
    if not all_self and not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "No self-hosted runners detected in workflows; using GitHub-hosted runners "
                "avoids the runner-host attack surface."
            ),
            remediation="Stay on GitHub-hosted runners unless you have a strong justification for self-hosted.",
            evidence_sources=[],
            confidence="high",
        )
    if all_self and not ephemeral:
        names = ", ".join(p.name for p in all_self[:5])
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"Self-hosted runners detected ({names}) but no `ephemeral` label found on `runs-on:`. "
                "Persistent runner state is the dominant 2026 supply-chain risk for self-hosted CI."
            ),
            remediation=(
                "Add `ephemeral` to the `runs-on:` label list (e.g. `runs-on: [self-hosted, ephemeral]`) "
                "and configure the runner group with ephemeral / just-in-time registration."
            ),
            evidence_sources=[str(p.resolve()) for p in all_self],
            confidence="medium",
        )
    if all_self and len(ephemeral) < len(all_self):
        non_ephem = [p for p in all_self if p not in ephemeral]
        names = ", ".join(p.name for p in non_ephem[:5])
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"Some self-hosted workflows declare `ephemeral` but others do not ({names}). "
                "Mixed posture reduces the attack-surface guarantees ephemeral runners provide."
            ),
            remediation="Apply the `ephemeral` label uniformly to every workflow that uses `self-hosted`.",
            evidence_sources=[str(p.resolve()) for p in all_self],
            confidence="medium",
        )
    if all_self and ephemeral and len(ephemeral) == len(all_self) and not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                f"All self-hosted workflows declare the `ephemeral` label ({len(ephemeral)} workflow(s)). "
                "Promote to evidence-backed by adding .oss-policy-kit/evidence/runner-groups.json."
            ),
            remediation=(
                "Document runner-group posture in .oss-policy-kit/evidence/runner-groups.json so trust "
                "projects to verified."
            ),
            evidence_sources=[str(p.resolve()) for p in ephemeral],
            confidence="medium",
            operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
        )
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Self-hosted runner posture cannot be fully assessed without a runner-groups.json evidence file.",
            remediation="Add .oss-policy-kit/evidence/runner-groups.json per evidence-runner-groups.schema.json.",
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        evidence, schema_loader=_runner_groups_schema, evidence_name="Runner groups"
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-runner-groups.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    groups = data.get("runner_groups") or []
    if not isinstance(groups, list) or not groups:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="runner-groups.json contains no runner_groups entries.",
            remediation="Configure at least one runner group with restricted_to_private_repos: true.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    risky = [
        g
        for g in groups
        if isinstance(g, dict)
        and (g.get("allows_public_repositories") is True or g.get("restricted_to_private_repos") is False)
    ]
    if risky:
        names = ", ".join(str(g.get("name", "?")) for g in risky)
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Runner group(s) {names} allow public repositories or are not restricted to private repos. "
                "Public-fork workflows running on self-hosted runners is the trivy-action attack pattern."
            ),
            remediation=(
                "Set restricted_to_private_repos: true and allows_public_repositories: false on every runner group."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"All {len(groups)} runner group(s) restricted to private repos and disallow public repositories.",
        remediation="Re-attest periodically; verify ephemeral runners remain in use.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.LIVE
        if isinstance(data.get("collection"), dict)
        and str(data["collection"].get("evidence_collection_method", "")).strip().lower() == "live"
        else EvidenceCollectionMethod.MANUAL,
    )


_RELEASE_ARCHIVE_SIGNAL_PATHS: tuple[str, ...] = (
    "RELEASE_ARCHIVAL.md",
    ".github/release-archival.yml",
    ".github/release-archival.yaml",
    "docs/release-readiness.md",
    "docs/release-archival.md",
)
_RELEASE_ARCHIVE_KEYWORDS: tuple[str, ...] = (
    "release archival",
    "release_archival",
    "release-archival",
    "retention policy",
    "retention_years",
)


def _release_archive_signal_match(repo: Path) -> Path | None:
    for rel in _RELEASE_ARCHIVE_SIGNAL_PATHS:
        p = repo / rel
        if not p.is_file():
            continue
        if rel.endswith((".yml", ".yaml")):
            return p
        try:
            text = p.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        if any(kw in text for kw in _RELEASE_ARCHIVE_KEYWORDS):
            return p
    return None


def eval_release_archive_063(ctx: EvalContext) -> EvalOutcome:
    """RELEASE-ARCHIVE-063: Release artifacts have an explicit archival/retention policy."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "release-archival-policy.json"
    if not evidence.is_file():
        signal = _release_archive_signal_match(ctx.repo_root)
        if signal is not None:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"Release archival/retention policy intent detected via {signal.name}. "
                    "Heuristic only — promote to evidence-backed by adding "
                    ".oss-policy-kit/evidence/release-archival-policy.json with retention_years."
                ),
                remediation=(
                    "Document retention_years (>= 10 for EU CRA alignment), archive_destination, "
                    "and vulnerability_handling_doc in .oss-policy-kit/evidence/release-archival-policy.json."
                ),
                evidence_sources=[str(signal.resolve())],
                confidence="low",
                operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No release archival/retention policy evidence found. Closes NIST SSDF PS.3 (Archive & "
                "protect each release) and aligns EU CRA 10-year retention. Add either a policy file "
                "(RELEASE_ARCHIVAL.md / .github/release-archival.yml) or "
                ".oss-policy-kit/evidence/release-archival-policy.json."
            ),
            remediation=(
                "Document the team's release artifact retention policy and archival destination "
                "(github-releases / S3 / Software Heritage). EU CRA expects retention_years >= 10."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_release_archival_policy_schema,
        evidence_name="Release archival policy",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-release-archival-policy.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    retention = data.get("retention_years")
    archive_dest = str(data.get("archive_destination", "")).strip()
    vuln_doc = str(data.get("vulnerability_handling_doc", "")).strip()
    if not isinstance(retention, int) or retention < 0:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="release-archival-policy.json has missing or invalid retention_years.",
            remediation="Set retention_years to a non-negative integer (>= 10 aligns with EU CRA).",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if not archive_dest:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="release-archival-policy.json reports an empty archive_destination.",
            remediation="Set archive_destination to a real location (github-releases, s3://, swh:archive, etc.).",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    if not vuln_doc:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="release-archival-policy.json does not reference a vulnerability_handling_doc.",
            remediation="Point vulnerability_handling_doc at SECURITY.md (or equivalent).",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    if retention < 10:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"retention_years={retention} is below EU CRA's 10-year expectation. "
                "Acceptable for non-EU products; review for CRA-affected scopes."
            ),
            remediation="Increase retention_years to >= 10 if you place products on the EU market.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Release archival policy: retention_years={retention} (>= 10), "
            f"archive_destination={archive_dest}, vulnerability_handling_doc={vuln_doc}."
        ),
        remediation="Re-attest periodically and keep retention storage active.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


_SAST_SEMGREP_EVIDENCE_FILENAME = "sast-semgrep.json"
_SAST_SEMGREP_SCHEMA_PREFIX = "oss-policy-kit/evidence/sast-semgrep/"


def eval_sast_semgrep_064(ctx: EvalContext) -> EvalOutcome:
    """SAST-SEMGREP-064: SAST evidence (Semgrep) is present and current.

    Reads ``.oss-policy-kit/evidence/sast-semgrep.json`` (produced by
    ``oss-policy-kit scan-sast``) and reports:

    - ``manual-review-required`` when the evidence file is missing.
    - ``manual-review-required`` when Semgrep was not installed at scan
      time (status ``not_available``); the gap is recorded honestly.
    - ``fail`` when there are any HIGH or CRITICAL severity findings.
    - ``pass`` when the run completed without HIGH/CRITICAL findings.
    """

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / _SAST_SEMGREP_EVIDENCE_FILENAME
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=("No Semgrep evidence file found. SAST findings cannot be verified from a clone alone."),
            remediation=(
                "Run `oss-policy-kit scan-sast --target .` (requires Semgrep installed) "
                "to populate .oss-policy-kit/evidence/sast-semgrep.json."
            ),
            evidence_sources=[],
            confidence="medium",
        )

    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Could not parse Semgrep evidence file: {exc}",
            remediation="Re-run `oss-policy-kit scan-sast` to regenerate the evidence file.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    schema = str(data.get("schema_version", ""))
    if not schema.startswith(_SAST_SEMGREP_SCHEMA_PREFIX):
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"Unexpected schema_version in {evidence.name}: {schema!r}. "
                f"Expected prefix {_SAST_SEMGREP_SCHEMA_PREFIX!r}."
            ),
            remediation="Regenerate via `oss-policy-kit scan-sast` to align with the current contract.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    status = str(data.get("status", "unknown")).lower()
    if status == "not_available":
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "Semgrep was not installed when scan-sast ran; the evidence is a presence stub, not a real SAST result."
            ),
            remediation=(
                "Install Semgrep (`pip install semgrep`) on the runner that executes "
                "`oss-policy-kit scan-sast` and re-run it to produce real findings."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if status in {"timeout", "error"}:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Semgrep evidence reports status={status!r}; SAST results are inconclusive.",
            remediation="Investigate the Semgrep run (see diagnostics.raw_stderr_excerpt) and re-run scan-sast.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )

    severity_counts = data.get("findings_by_severity", {}) or {}
    if not isinstance(severity_counts, dict):
        severity_counts = {}
    high = int(severity_counts.get("ERROR", 0) or 0) + int(severity_counts.get("HIGH", 0) or 0)
    critical = int(severity_counts.get("CRITICAL", 0) or 0)
    if critical or high:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Semgrep reported {critical} CRITICAL and {high} HIGH/ERROR severity finding(s). "
                "SAST gate considers HIGH+ findings blocking by default."
            ),
            remediation=(
                "Review evaluation-report.md and fix HIGH/CRITICAL findings, or document an "
                "explicit waiver in waivers.yaml with owner, reason, and expires_on."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )

    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Semgrep completed cleanly: {int(data.get('findings_total', 0) or 0)} total finding(s), "
            "no HIGH or CRITICAL severity entries."
        ),
        remediation="Keep Semgrep up to date and re-scan at least once per release.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


EVALUATOR_REGISTRY: dict[str, Callable[[EvalContext], EvalOutcome]] = {
    "GOV-SEC-001": eval_gov_sec_001,
    "GOV-CON-002": eval_gov_con_002,
    "GOV-COWN-003": eval_gov_cown_003,
    "GOV-LIC-004": eval_gov_lic_004,
    "CI-WF-005": eval_ci_wf_005,
    "CI-PERM-006": eval_ci_perm_006,
    "CI-DANGER-007": eval_ci_danger_007,
    "CI-PIN-008": eval_ci_pin_008,
    "CI-LEAST-009": eval_ci_least_009,
    "SEC-CODEQL-010": eval_sec_codeql_010,
    "SEC-DEPREV-011": eval_sec_deprev_011,
    "REL-CHANGE-012": eval_rel_change_012,
    "GOV-DISC-013": eval_gov_disc_013,
    "GOV-WAIV-014": eval_gov_waiv_014,
    "PLAT-BRPROT-015": eval_plat_brprot_015,
    "SEC-SECRETS-050": eval_sec_secrets_050,
    "SEC-GITIGNORE-051": eval_sec_gitignore_051,
    "SEC-PINLOCK-052": eval_sec_pinlock_052,
    "GH-WF-018": eval_gh_wf_018,
    "GH-WF-019": eval_gh_wf_019,
    "GH-WF-020": eval_gh_wf_020,
    "GH-REL-021": eval_gh_rel_021,
    "GH-DEPLOY-022": eval_gh_dep_022,
    "GH-PROV-023": eval_gh_prov_023,
    "GH-PLAT-024": eval_gh_plat_024,
    "GH-PLAT-025": eval_gh_plat_025,
    "GH-PLAT-026": eval_gh_plat_026,
    "AZ-PIPE-027": eval_az_pipe_027,
    "AZ-PIPE-028": eval_az_pipe_028,
    "AZ-PIPE-029": eval_az_pipe_029,
    "AZ-PIPE-030": eval_az_pipe_030,
    "AZ-SEC-031": eval_az_sec_031,
    "AZ-SCA-032": eval_az_sca_032,
    "AZ-SBOM-033": eval_az_sbom_033,
    "AZ-PLAT-034": eval_az_plat_034,
    "AZ-PLAT-035": eval_az_plat_035,
    "AZ-IDENT-036": eval_az_ident_036,
    "AZ-SCONN-056": eval_az_sconn_056,
    "AZ-WIFEV-057": eval_az_wifev_057,
    "AZ-ARTSBOM-058": eval_az_artsbom_058,
    "AZ-ARTPRV-059": eval_az_artprv_059,
    "AWS-CI-037": eval_aws_ci_037,
    "AWS-SECRET-038": eval_aws_secret_038,
    "AWS-SEC-039": eval_aws_sec_039,
    "AWS-SCA-040": eval_aws_sca_040,
    "AWS-SBOM-041": eval_aws_sbom_041,
    "AWS-PIPE-042": eval_aws_pipe_042,
    "AWS-PROV-043": eval_aws_prov_043,
    "AWS-CP-044": eval_aws_cp_044,
    "AWS-CB-045": eval_aws_cb_045,
    "AWS-CC-046": eval_aws_cc_046,
    "AWS-PIPEIAM-056": eval_aws_pipeiam_056,
    "AWS-CBIDENT-057": eval_aws_cbident_057,
    "AWS-SBOMART-058": eval_aws_sbomart_058,
    "AWS-PROVART-059": eval_aws_provart_059,
    "GH-MERGEQ-053": eval_gh_mergeq_053,
    "GOV-EVIDFRESH-054": eval_gov_evidfresh_054,
    "CI-WFCALLSHA-055": eval_ci_wfcallsha_055,
    "DEP-UPDATE-001": eval_dep_update_001,
    "OSS-SCORECARD-001": eval_oss_scorecard_001,
    "CONT-IMAGE-001": eval_cont_image_001,
    "CONT-IMAGE-002": eval_cont_image_002,
    "CONT-IMAGE-003": eval_cont_image_003,
    "ORG-MFA-001": eval_org_mfa_001,
    "BUILD-SBOM-QUAL-003": eval_build_sbom_qual_003,
    "AUDIT-STREAM-060": eval_audit_stream_060,
    "PROV-VERIFY-061": eval_prov_verify_061,
    "GH-RUNNER-062": eval_gh_runner_062,
    "RELEASE-ARCHIVE-063": eval_release_archive_063,
    "SAST-SEMGREP-064": eval_sast_semgrep_064,
}


def _load_external_evaluators() -> None:
    """Load evaluators registered via ``oss_policy_kit.evaluators`` entry-point group.

    Third-party plugins can register custom controls by declaring entry points
    in the ``oss_policy_kit.evaluators`` group. External plugins cannot
    override built-in control IDs.
    """

    try:
        eps = importlib.metadata.entry_points().select(group="oss_policy_kit.evaluators")
    except Exception:  # noqa: BLE001 - best-effort discovery
        return
    for ep in eps:
        if ep.name in EVALUATOR_REGISTRY:
            continue
        try:
            func = ep.load()
        except Exception:  # noqa: BLE001 - skip broken plugins
            continue
        if callable(func):
            EVALUATOR_REGISTRY[ep.name] = func


_load_external_evaluators()
