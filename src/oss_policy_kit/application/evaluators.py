"""Per-control local evaluators (filesystem + workflow static analysis)."""

from __future__ import annotations

import contextlib
import importlib.metadata
import importlib.resources as ir
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from oss_policy_kit.adapters.scorecard_json import ScorecardBundle, checks_as_map
from oss_policy_kit.application.evaluators_common import (
    DIGEST_PLACEHOLDER_REASON as _DIGEST_PLACEHOLDER_REASON,
)
from oss_policy_kit.application.evaluators_common import (
    INVALID_DIGEST_REASON as _INVALID_DIGEST_REASON,
)
from oss_policy_kit.application.evaluators_common import (
    evidence_is_api_backed as _evidence_is_api_backed,
)
from oss_policy_kit.application.evaluators_common import (
    evidence_placeholder_outcome as _evidence_placeholder_outcome,
)
from oss_policy_kit.application.evaluators_common import (
    is_valid_sha256_digest as _is_valid_sha256_digest,
)
from oss_policy_kit.application.evaluators_common import (
    validate_json_evidence as _validate_json_evidence,
)
from oss_policy_kit.application.evidence_placeholders import has_placeholder_values, is_placeholder_digest
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.gitlab_ci_parser import GitLabCiAnalysis
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


def _ai_agent_baseline_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-ai-agent-baseline.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


def _disclosure_policy_schema() -> dict[str, Any]:
    raw = ir.files("oss_policy_kit.data.schema").joinpath("evidence-disclosure-policy.schema.json").read_bytes()
    return cast(dict[str, Any], json.loads(raw))


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
    #: GitLab CI pipeline analysis (v5.9.0). Default empty so existing call sites and
    #: test fixtures stay valid without an explicit constructor argument.
    gitlab_ci: GitLabCiAnalysis = field(default_factory=GitLabCiAnalysis)


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
            reason="Disclosure reporting mechanism not implemented (SECURITY.md missing at repository root).",
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
            reason=(
                "In-repo secret scanning step not implemented "
                "(no GitHub Actions workflows found in .github/workflows/)."
            ),
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
    # Skip raw SARIF output files (scanner output, not kit-attestation evidence).
    # SARIF files have their own freshness contract via invocations[].startTimeUtc;
    # GOV-EVIDFRESH-054 covers attested_at / collected_at / generated_at on the
    # kit's structured evidence files only. Convention: scanner SARIF lives under
    # .oss-policy-kit/evidence/sast/<tool>.sarif.json — see SAST-OSV-068, SAST-ZIZMOR-066,
    # SAST-POUTINE-067, SAST-GITLEAKS-069 (v5.9.0).
    sast_dir = evid_root / "sast"
    json_files = [p for p in json_files if not (sast_dir in p.parents or p.name.endswith(".sarif.json"))]
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
        # v6.0.0 (ADR-007): if the per-artifact provenance evidence file is
        # present with a populated verification block, return an
        # evidence-backed PASS. If the evidence file is absent, preserve the
        # v5.x signal-grade PASS so adopters who relied on the workflow signal
        # alone do not see a gate regression.
        evidence_path = ctx.repo_root / ".oss-policy-kit" / "evidence" / "github-provenance-artifact.json"
        verification_recorded = False
        if evidence_path.is_file():
            with contextlib.suppress(OSError, json.JSONDecodeError):
                data = json.loads(evidence_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    verification = data.get("verification")
                    if isinstance(verification, dict) and verification.get("transparency_log_inclusion"):
                        verification_recorded = True
        if verification_recorded:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    "Provenance/attestation signal detected in workflow configuration AND "
                    "verification block recorded in github-provenance-artifact.json "
                    "(evidence-backed per ADR-007)."
                ),
                remediation="Re-verify on every release and keep verification.verified_at within the freshness window.",
                evidence_sources=[str(p.resolve()) for p in ctx.workflows.workflow_paths]
                + [str(evidence_path.resolve())],
                confidence="high",
                evidence_collection_method=EvidenceCollectionMethod.LIVE,
            )
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=(
                "Provenance/attestation signal detected in workflow configuration "
                "(workflow signal only; artifact-level verification is not confirmed from clone-only evidence)."
            ),
            remediation=(
                "Add a per-artifact provenance evidence file at .oss-policy-kit/evidence/"
                "github-provenance-artifact.json with the verification block populated "
                "(method, verified_at, transparency_log_inclusion) so this control returns "
                "an evidence-backed PASS instead of the signal-grade PASS shown here."
            ),
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
    from oss_policy_kit.application.evaluators_common import find_dockerfiles

    return find_dockerfiles(repo)


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


def _detect_sbom_format_and_version(content: str) -> tuple[str | None, str | None]:
    """Return ``(format, version)`` for an SBOM blob; either may be None.

    Recognises:

    - **CycloneDX** JSON via ``bomFormat`` and ``specVersion`` (1.0 ... 1.6+).
    - **SPDX 2.x** JSON via ``spdxVersion: SPDX-2.<minor>``.
    - **SPDX 2.x** tag-value via ``SPDXVersion: SPDX-2.<minor>``.
    - **SPDX 3.0+** JSON-LD via ``@context`` referencing the SPDX 3 spec, or
      ``creationInfo.specVersion: 3.<minor>.<patch>`` in an embedded
      element. The 3.x family changed shape significantly; the kit recognises
      v3 explicitly so BSI TR-03183-2 v2.1.0 validation can require it.
    """

    sample = content[:8000]
    # CycloneDX JSON
    if '"bomFormat"' in sample and ("CycloneDX" in sample or "cyclonedx" in sample.lower()):
        ver = None
        m = re.search(r'"specVersion"\s*:\s*"(\d+\.\d+)"', sample)
        if m:
            ver = m.group(1)
        return ("cyclonedx", ver)
    # SPDX 3.x JSON-LD
    if "spdx.dev/spec/3" in sample or '"@context"' in sample and "spdx" in sample.lower():
        m = re.search(r'"specVersion"\s*:\s*"(3\.\d+\.\d+)"', sample)
        if m:
            return ("spdx", m.group(1))
        if "spdx.dev/spec/3" in sample:
            return ("spdx", "3.0")
    # SPDX 2.x JSON
    m = re.search(r'"spdxVersion"\s*:\s*"SPDX-(\d+\.\d+)"', sample)
    if m:
        return ("spdx", m.group(1))
    # SPDX tag-value (2.x)
    m = re.search(r"SPDXVersion:\s*SPDX-(\d+\.\d+)", sample)
    if m:
        return ("spdx", m.group(1))
    return (_detect_sbom_format(content), None)


# ---------------------------------------------------------------------------
# BSI TR-03183-2 v2.1.0 validation (V6-09).
#
# The German Federal Office for Information Security (BSI) Technical
# Guideline TR-03183-2 v2.1.0 specifies fields a Software Bill of Materials
# must carry to be considered "compliant" for the German cybersecurity
# procurement context: package identifiers (PURL/CPE), cryptographic hashes,
# license declaration, supplier identity, plus an explicit separation of
# vulnerability data into VEX documents (an SBOM that embeds vulnerabilities
# is not BSI-compliant).
#
# The kit performs lightweight structural validation. Adopters that need
# legal BSI conformance should run a dedicated BSI-conformance tool; this
# check surfaces the most common gaps clone-side.
# ---------------------------------------------------------------------------

# Cached compiled regexes; declared at module scope so we do not recompile
# on every evaluator invocation.
_BSI_HASH_PATTERN = re.compile(r'"(hashes|sha\d+|checksums?)"', re.IGNORECASE)
_BSI_PURL_PATTERN = re.compile(r'"(purl|packageURL)"', re.IGNORECASE)
_BSI_CPE_PATTERN = re.compile(r'"(cpe|cpe22Type|cpe23Type)"')
_BSI_LICENSE_PATTERN = re.compile(r'"(licenses?|licenseConcluded|licenseDeclared)"', re.IGNORECASE)
_BSI_SUPPLIER_PATTERN = re.compile(r'"(supplier|originator|publisher|author)"', re.IGNORECASE)
_BSI_VULN_PATTERN = re.compile(r'"vulnerabilities"\s*:\s*\[')


def _validate_bsi_tr_03183_v2_1(content: str, fmt: str | None, version: str | None) -> dict[str, bool] | None:
    """Validate an SBOM blob against BSI TR-03183-2 v2.1.0 required fields.

    Returns ``None`` when the SBOM format/version is not in scope (BSI v2.1.0
    targets CycloneDX 1.6+ and SPDX 3.0+; older versions are out of scope and
    receive no verdict). Returns a dict otherwise with the following keys:

    - ``identifiers_present`` (bool) — at least one of PURL or CPE detected.
    - ``hashes_present`` (bool) — cryptographic hash field detected.
    - ``licenses_present`` (bool) — license declaration detected.
    - ``supplier_present`` (bool) — supplier / originator / author detected.
    - ``vulnerability_data_separated`` (bool) — the SBOM does NOT embed a
      ``vulnerabilities[]`` array (BSI requires VEX separation).

    Heuristic: regex over the document text. The kit does not parse SPDX
    JSON-LD or CycloneDX schema fully — adopters needing strict conformance
    should pair this with a dedicated BSI conformance tool.
    """

    if fmt not in {"cyclonedx", "spdx"}:
        return None
    if fmt == "cyclonedx":
        if version is None:
            return None
        try:
            major, minor = version.split(".", 1)
            if int(major) < 1 or (int(major) == 1 and int(minor) < 6):
                return None
        except (ValueError, AttributeError):
            return None
    if fmt == "spdx" and (version is None or not version.startswith("3.")):
        return None

    return {
        "identifiers_present": bool(_BSI_PURL_PATTERN.search(content) or _BSI_CPE_PATTERN.search(content)),
        "hashes_present": bool(_BSI_HASH_PATTERN.search(content)),
        "licenses_present": bool(_BSI_LICENSE_PATTERN.search(content)),
        "supplier_present": bool(_BSI_SUPPLIER_PATTERN.search(content)),
        "vulnerability_data_separated": not bool(_BSI_VULN_PATTERN.search(content)),
    }


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
        bsi_notes: list[str] = []
        for p in sbom_files:
            with contextlib.suppress(OSError):
                content = p.read_text(encoding="utf-8", errors="replace")
                fmt_detail, version = _detect_sbom_format_and_version(content)
                if fmt_detail:
                    label = f"{p.name} ({fmt_detail}{f' {version}' if version else ''})"
                    valid.append(label)
                    bsi = _validate_bsi_tr_03183_v2_1(content, fmt_detail, version)
                    if bsi is not None:
                        missing = [
                            k.removesuffix("_present").removesuffix("_separated") for k, v in bsi.items() if not v
                        ]
                        if missing:
                            bsi_notes.append(f"{p.name} BSI TR-03183-2 v2.1.0: missing {', '.join(missing)}")
                        else:
                            bsi_notes.append(f"{p.name} BSI TR-03183-2 v2.1.0: all required fields present")
                else:
                    invalid.append(p.name)
        if valid:
            reason = f"Valid SBOM format detected: {', '.join(valid[:3])}."
            if bsi_notes:
                reason = f"{reason} {' | '.join(bsi_notes[:3])}."
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=reason,
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


_DISCLOSURE_SLA_KEYWORDS: tuple[str, ...] = (
    "respond within",
    "acknowledge within",
    "acknowledgement within",
    "response within",
    "we will respond",
    "we aim to respond",
    "response time",
    "response sla",
    "triage within",
    "initial response",
)


def _disclosure_sla_signal_match(repo: Path) -> tuple[Path, str] | None:
    """Return (path, matched_keyword) if SECURITY.md mentions a response SLA, else None.

    Heuristic only — looking for any of the phrases in :data:`_DISCLOSURE_SLA_KEYWORDS`
    in ``SECURITY.md`` or ``.github/SECURITY.md``. The intent is "did the maintainer
    write down *any* SLA-shaped commitment", not "is the SLA fast enough". The latter
    judgement belongs to the operator / auditor.
    """

    for rel in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        p = repo / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for kw in _DISCLOSURE_SLA_KEYWORDS:
            if kw in text:
                return (p, kw)
    return None


def eval_gov_disc_065(ctx: EvalContext) -> EvalOutcome:
    """GOV-DISC-065: Disclosure channel SLA documented (CRA reporting readiness).

    Closes a gap left by ``GOV-DISC-013`` (signal-grade existence-check on responsible
    disclosure mention) for adopters preparing for the EU CRA 2026-09-11 24-hour
    reporting deadline. The CRA report is *outbound* (manufacturer to ENISA); this
    control checks the *inbound* SLA (researcher to manufacturer), which is a
    necessary precondition for the outbound clock to be meetable.
    """

    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "disclosure-policy.json"
    if not evidence.is_file():
        signal = _disclosure_sla_signal_match(ctx.repo_root)
        if signal is not None:
            path, kw = signal
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"Disclosure response-SLA intent detected via clone signal "
                    f"({path.name}, keyword '{kw}'). Heuristic only — promote to "
                    "evidence-backed by adding "
                    ".oss-policy-kit/evidence/disclosure-policy.json with explicit "
                    "acknowledgement_sla_hours, triage_sla_hours, and public_disclosure_policy."
                ),
                remediation=(
                    "Document the disclosure SLA in "
                    ".oss-policy-kit/evidence/disclosure-policy.json per "
                    "evidence-disclosure-policy.schema.json so trust projects to verified."
                ),
                evidence_sources=[str(path.resolve())],
                confidence="low",
                operational_warnings=(_KEYWORD_CI_SIGNAL_WARN,),
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No disclosure SLA found in SECURITY.md and no evidence file present. "
                "EU CRA 2026-09-11 24-hour reporting depends on having a documented "
                "inbound disclosure channel with a stated acknowledgement window."
            ),
            remediation=(
                "Add an acknowledgement SLA to SECURITY.md (e.g. 'we will acknowledge "
                "within 72 hours') or attach "
                ".oss-policy-kit/evidence/disclosure-policy.json per "
                "evidence-disclosure-policy.schema.json."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data, error, ph = _validate_json_evidence(
        evidence,
        schema_loader=_disclosure_policy_schema,
        evidence_name="Disclosure policy",
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation="Regenerate evidence using reports/schema/evidence-disclosure-policy.schema.json.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    contact = data.get("contact") or {}
    ack_sla = data.get("acknowledgement_sla_hours")
    triage_sla = data.get("triage_sla_hours")
    pdp = data.get("public_disclosure_policy") or {}
    missing: list[str] = []
    if not isinstance(contact.get("method"), str) or not isinstance(contact.get("value"), str):
        missing.append("contact.method / contact.value")
    if not isinstance(ack_sla, int) or ack_sla < 1:
        missing.append("acknowledgement_sla_hours")
    if not isinstance(triage_sla, int) or triage_sla < 1:
        missing.append("triage_sla_hours")
    if not isinstance(pdp.get("default_window_days"), int) or "negotiable" not in pdp:
        missing.append("public_disclosure_policy.default_window_days / negotiable")
    if missing:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Disclosure policy evidence is missing required SLA fields: "
                + ", ".join(missing)
                + ". The kit does not judge whether the SLA is fast enough; it requires "
                "that an SLA is documented at all."
            ),
            remediation=(
                "Fill the missing fields in .oss-policy-kit/evidence/disclosure-policy.json "
                "per evidence-disclosure-policy.schema.json."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
        )
    method = EvidenceCollectionMethod.STATIC
    coll = data.get("collection")
    if isinstance(coll, dict) and str(coll.get("evidence_collection_method", "")).strip().lower() == "live":
        method = EvidenceCollectionMethod.LIVE
    elif isinstance(coll, dict) and str(coll.get("evidence_collection_method", "")).strip().lower() == "manual":
        method = EvidenceCollectionMethod.MANUAL
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Disclosure policy evidence is valid: contact={contact.get('method')}, "
            f"acknowledgement_sla_hours={ack_sla}, triage_sla_hours={triage_sla}, "
            f"public_disclosure_window={pdp.get('default_window_days')}d "
            f"(negotiable={pdp.get('negotiable')})."
        ),
        remediation="Re-attest evidence within freshness window when the policy changes.",
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
    source_raw = verification.get("source")
    source_suffix = ""
    if isinstance(source_raw, str) and source_raw.strip():
        source_suffix = f" source={source_raw.strip()};"
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Provenance attestation verified ({method});{source_suffix} transparency-log inclusion confirmed; "
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


# ---------------------------------------------------------------------------
# SARIF-ingest adapters (F4-02b zizmor, F4-02c poutine). Reads raw SARIF 2.1.0
# files dropped at .oss-policy-kit/evidence/sast/<tool>.sarif.json. Distinct
# from the SEMGREP path (SAST-SEMGREP-064) which consumes a kit-emitted JSON
# wrapper; raw SARIF keeps the kit honest about ingesting third-party output
# without re-implementing scanner-specific normalization.
# ---------------------------------------------------------------------------


def _parse_sarif_findings(
    sarif_path: Path,
) -> tuple[dict[str, int] | None, str | None]:
    """Return ({"error": int, "warning": int, "note": int, "none": int}, None)
    on success, or (None, error_message) on parse failure.

    SARIF 2.1.0 result-level levels are: error, warning, note, none. When a
    result omits ``level``, the rule's ``defaultConfiguration.level`` applies
    (per the SARIF spec). Missing both is treated as ``warning`` per the spec.
    """

    try:
        raw = sarif_path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"Could not read SARIF file: {exc}"
    except UnicodeDecodeError as exc:
        return None, f"Could not decode SARIF file as UTF-8: {exc}"
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Could not parse SARIF JSON: {exc}"
    except RecursionError as exc:
        return None, f"Could not parse SARIF JSON: document is too deeply nested ({exc})"
    if (
        not isinstance(doc, dict) or doc.get("$schema", "").endswith("sarif-schema-2.1.0.json") is False
    ) and "runs" not in doc:
        # Accept SARIF docs without an explicit $schema; just require the runs[] array.
        return None, "SARIF file missing top-level 'runs' array."
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return None, "SARIF 'runs' is not an array."
    counts: dict[str, int] = {"error": 0, "warning": 0, "note": 0, "none": 0}
    for run in runs:
        if not isinstance(run, dict):
            continue
        rule_levels: dict[str, str] = {}
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                rid = rule.get("id")
                if not isinstance(rid, str):
                    continue
                default_level = (rule.get("defaultConfiguration") or {}).get("level")
                if isinstance(default_level, str):
                    rule_levels[rid] = default_level
        results = run.get("results") or []
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            level = result.get("level")
            if not isinstance(level, str):
                rid = result.get("ruleId")
                level = rule_levels.get(rid, "warning") if isinstance(rid, str) else "warning"
            level = level.lower()
            if level not in counts:
                level = "warning"
            counts[level] += 1
    return counts, None


def _eval_sarif_adapter(
    ctx: EvalContext,
    *,
    tool_name: str,
    evidence_relpath: str,
    scan_command_hint: str,
    fail_on_error: bool = True,
    fail_on_warning: bool = False,
) -> EvalOutcome:
    """Generic SARIF-ingest evaluator shared by zizmor / poutine / OSV / Gitleaks.

    Returns:

    - ``manual-review-required`` if the evidence file is missing.
    - ``manual-review-required`` if SARIF parsing fails.
    - ``fail`` if ``fail_on_error`` and there is at least one ``error``-level
      finding (or any finding when ``fail_on_warning=True``).
    - ``pass`` otherwise, surfacing the counts in ``reason``.
    """

    evidence = ctx.repo_root / evidence_relpath
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"No {tool_name} SARIF evidence at {evidence_relpath}. Findings cannot be verified from a clone alone."
            ),
            remediation=(f"{scan_command_hint} and drop the resulting SARIF at {evidence_relpath}."),
            evidence_sources=[],
            confidence="medium",
        )
    counts, err = _parse_sarif_findings(evidence)
    if err is not None or counts is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=err or f"{tool_name} SARIF parse failed.",
            remediation=f"Regenerate the {tool_name} SARIF and re-attach to {evidence_relpath}.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    total = sum(counts.values())
    if fail_on_warning and total > 0:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{tool_name} reported {total} finding(s): "
                f"error={counts['error']}, warning={counts['warning']}, "
                f"note={counts['note']}, none={counts['none']}."
            ),
            remediation=f"Address {tool_name} findings or document waivers under waivers/.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    if fail_on_error and counts["error"] > 0:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{tool_name} reported {counts['error']} error-level finding(s) "
                f"(warning={counts['warning']}, note={counts['note']})."
            ),
            remediation=f"Address {tool_name} error-level findings or document waivers under waivers/.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"{tool_name} SARIF parsed cleanly: error={counts['error']}, "
            f"warning={counts['warning']}, note={counts['note']}, none={counts['none']}."
        ),
        remediation=f"Re-scan with {tool_name} at least once per release.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


_ZIZMOR_SEVERITY_KEYS: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
    "unknown",
)


def _parse_zizmor_severity_properties(
    sarif_path: Path,
) -> tuple[dict[str, int] | None, str | None]:
    """Return zizmor-specific severity counts from ``result.properties``.

    zizmor surfaces its own severity vocabulary via
    ``result.properties.security_severity_level`` (one of ``Critical``, ``High``,
    ``Medium``, ``Low``, ``Informational``, ``Unknown``). The standard SARIF
    ``level`` (error/warning/note/none) read by ``_parse_sarif_findings`` remains
    the source of truth for the gate decision; this helper produces supplementary
    counts surfaced in the evaluator reason so operators can see the upstream-tool
    severity vocabulary alongside the SARIF level.

    Returns ``(counts, None)`` on success — ``counts`` is a dict keyed by
    lowercased severity name with all six keys present (zero where absent).
    Returns ``(None, message)`` on parse failure.
    """
    try:
        raw = sarif_path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"Could not read SARIF file: {exc}"
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Could not parse SARIF JSON: {exc}"
    if not isinstance(doc, dict):
        return None, "SARIF file is not a JSON object."
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return None, "SARIF 'runs' is not an array."
    counts: dict[str, int] = {k: 0 for k in _ZIZMOR_SEVERITY_KEYS}
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results") or []
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            props = result.get("properties") or {}
            if not isinstance(props, dict):
                continue
            sev = props.get("security_severity_level")
            if not isinstance(sev, str):
                continue
            key = sev.strip().lower()
            if key not in counts:
                key = "unknown"
            counts[key] += 1
    return counts, None


def eval_sast_zizmor_066(ctx: EvalContext) -> EvalOutcome:
    """SAST-ZIZMOR-066: zizmor SARIF findings on GitHub Actions workflows.

    The gate decision is driven by the standard SARIF ``level`` (error/warning/
    note/none) shared with the other Fase 4 adapters. When zizmor surfaces its
    own severity vocabulary via ``result.properties.security_severity_level``
    (Critical/High/Medium/Low/Informational), those counts are appended to the
    reason for operator visibility but do not change the pass/fail outcome.
    """
    outcome = _eval_sarif_adapter(
        ctx,
        tool_name="zizmor",
        evidence_relpath=".oss-policy-kit/evidence/sast/zizmor.sarif.json",
        scan_command_hint="Run `zizmor --format sarif .github/workflows/ > zizmor.sarif.json`",
        fail_on_error=True,
    )
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "sast" / "zizmor.sarif.json"
    if evidence.is_file() and outcome.status in (ControlStatus.PASS, ControlStatus.FAIL):
        sev_counts, _ = _parse_zizmor_severity_properties(evidence)
        if sev_counts is not None and sum(sev_counts.values()) > 0:
            non_zero = ", ".join(f"{k}={v}" for k, v in sev_counts.items() if v > 0)
            outcome.reason = f"{outcome.reason} zizmor severity properties: {non_zero}."
    return outcome


def eval_sast_poutine_067(ctx: EvalContext) -> EvalOutcome:
    """SAST-POUTINE-067: poutine SARIF findings on GitHub Actions / GitLab CI pipelines."""
    return _eval_sarif_adapter(
        ctx,
        tool_name="poutine",
        evidence_relpath=".oss-policy-kit/evidence/sast/poutine.sarif.json",
        scan_command_hint="Run `poutine analyze-local . --format sarif > poutine.sarif.json`",
        fail_on_error=True,
    )


def eval_sast_osv_068(ctx: EvalContext) -> EvalOutcome:
    """SAST-OSV-068: OSV-Scanner v2 SARIF findings (reachability-aware SCA)."""
    return _eval_sarif_adapter(
        ctx,
        tool_name="osv-scanner",
        evidence_relpath=".oss-policy-kit/evidence/sast/osv-scanner.sarif.json",
        scan_command_hint=(
            "Run `osv-scanner --format sarif --recursive . > osv-scanner.sarif.json` (v2+ for reachability)"
        ),
        fail_on_error=True,
    )


def eval_sast_gitleaks_069(ctx: EvalContext) -> EvalOutcome:
    """SAST-GITLEAKS-069: Gitleaks SARIF findings (secret leak detection)."""
    return _eval_sarif_adapter(
        ctx,
        tool_name="gitleaks",
        evidence_relpath=".oss-policy-kit/evidence/sast/gitleaks.sarif.json",
        # Secrets are zero-tolerance — even a single warning-level finding
        # should block until reviewed/waived.
        scan_command_hint="Run `gitleaks detect --report-format sarif --report-path gitleaks.sarif.json`",
        fail_on_error=True,
        fail_on_warning=True,
    )


# ---------------------------------------------------------------------------
# GitLab CI controls (v5.9.0). See ADR-003 for the broader 12-control family
# design; v5.9.0 ships an initial subset of 6 controls. The evaluators read
# the ``ctx.gitlab_ci`` GitLabCiAnalysis produced by analyze_gitlab_ci().
# ---------------------------------------------------------------------------


def eval_gl_pipe_001(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-001: GitLab CI pipeline files present and parseable."""

    analysis = ctx.gitlab_ci
    if not analysis.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="No .gitlab-ci.yml found at repo root or under .gitlab/.",
            remediation="Add a .gitlab-ci.yml describing your build/test pipeline.",
            evidence_sources=[],
            confidence="high",
        )
    if analysis.parse_errors:
        names = ", ".join(p.name for p, _ in analysis.parse_errors)
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"GitLab CI pipeline files failed to parse: {names}.",
            remediation="Repair YAML syntax errors in the listed pipeline files.",
            evidence_sources=[str(p.resolve()) for p, _ in analysis.parse_errors],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Found {len(analysis.pipeline_paths)} GitLab CI pipeline file(s) (all parseable).",
        remediation="Keep .gitlab-ci.yml minimal, pinned, and least-privilege.",
        evidence_sources=[str(p.resolve()) for p in analysis.pipeline_paths],
        confidence="high",
    )


def eval_gl_pipe_002(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-002: GitLab CI image references pinned to a tag or digest."""

    analysis = ctx.gitlab_ci
    if not analysis.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitLab CI pipelines to evaluate.",
            remediation="Add a .gitlab-ci.yml with `image:` references using tags or digests.",
            evidence_sources=[],
            confidence="high",
        )
    if not analysis.image_refs_pinned and not analysis.image_refs_unpinned and not analysis.image_refs_mutable_tag:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No `image:` declarations found in any GitLab CI pipeline.",
            remediation="If your jobs need container images, declare them explicitly with pinned references.",
            evidence_sources=[str(p.resolve()) for p in analysis.pipeline_paths],
            confidence="medium",
        )
    if analysis.image_refs_unpinned:
        unpinned_preview = ", ".join(ref for _, ref in analysis.image_refs_unpinned[:5])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"GitLab CI uses {len(analysis.image_refs_unpinned)} unpinned image reference(s): "
                f"{unpinned_preview}{' …' if len(analysis.image_refs_unpinned) > 5 else ''}."
            ),
            remediation=(
                "Pin every image to a specific tag (`image: alpine:3.19`) or a digest "
                "(`image: alpine@sha256:...`). Floating tags drift silently."
            ),
            evidence_sources=[str(p.resolve()) for p, _ in analysis.image_refs_unpinned],
            confidence="high",
        )
    if analysis.image_refs_mutable_tag:
        mutable_preview = ", ".join(ref for _, ref in analysis.image_refs_mutable_tag[:5])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"GitLab CI uses {len(analysis.image_refs_mutable_tag)} image reference(s) "
                f"with a mutable / floating tag (latest, edge, stable, main, master, nightly, lts): "
                f"{mutable_preview}{' …' if len(analysis.image_refs_mutable_tag) > 5 else ''}."
            ),
            remediation=(
                "Replace mutable tags with a specific version (`image: python:3.12.4`) "
                "or a digest (`image: python@sha256:...`). Mutable tags drift silently "
                "between pipeline runs and break reproducibility."
            ),
            evidence_sources=[str(p.resolve()) for p, _ in analysis.image_refs_mutable_tag],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"All {len(analysis.image_refs_pinned)} GitLab CI `image:` reference(s) are pinned.",
        remediation="Prefer digest pinning over tag pinning for the highest assurance.",
        evidence_sources=[str(p.resolve()) for p, _ in analysis.image_refs_pinned],
        confidence="high",
    )


def eval_gl_pipe_003(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-003: GitLab CI scripts do not pipe network downloads to a shell."""

    analysis = ctx.gitlab_ci
    if not analysis.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitLab CI pipelines to evaluate.",
            remediation="Add a .gitlab-ci.yml; this control inspects `script:` blocks for unsafe patterns.",
            evidence_sources=[],
            confidence="high",
        )
    if analysis.script_uses_curl_pipe_shell:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(analysis.script_uses_curl_pipe_shell)} pipeline(s) contain "
                "`curl ... | sh` / `wget ... | sh` patterns. These execute arbitrary "
                "remote code without verification."
            ),
            remediation=(
                "Replace `curl URL | sh` with a download-verify-execute pattern (pin URL "
                "+ verify checksum/signature before running)."
            ),
            evidence_sources=[str(p.resolve()) for p in analysis.script_uses_curl_pipe_shell],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No `curl|sh` / `wget|sh` patterns detected in GitLab CI `script:` blocks.",
        remediation="Continue to download-verify-execute or pin binary dependencies.",
        evidence_sources=[str(p.resolve()) for p in analysis.pipeline_paths],
        confidence="medium",
    )


def eval_gl_pipe_004(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-004: GitLab CI jobs do not declare broad `inherit: secrets: true`."""

    analysis = ctx.gitlab_ci
    if not analysis.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitLab CI pipelines to evaluate.",
            remediation="Add a .gitlab-ci.yml; this control checks for broad secret inheritance.",
            evidence_sources=[],
            confidence="high",
        )
    if analysis.jobs_with_inherit_secrets:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(analysis.jobs_with_inherit_secrets)} pipeline(s) declare "
                "`inherit: secrets: true`. This grants every inheriting job access "
                "to every defined secret — least-privilege violation."
            ),
            remediation=(
                "Replace blanket inheritance with explicit `secrets:` per job, listing "
                "only the secrets each job actually needs."
            ),
            evidence_sources=[str(p.resolve()) for p in analysis.jobs_with_inherit_secrets],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No `inherit: secrets: true` declarations detected in GitLab CI pipelines.",
        remediation="Continue declaring `secrets:` explicitly per job that needs them.",
        evidence_sources=[str(p.resolve()) for p in analysis.pipeline_paths],
        confidence="high",
    )


def eval_gl_pipe_005(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-005: GitLab CI `include:` does not reference unpinned remote URLs."""

    analysis = ctx.gitlab_ci
    if not analysis.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitLab CI pipelines to evaluate.",
            remediation="Add a .gitlab-ci.yml; this control reviews `include:` references.",
            evidence_sources=[],
            confidence="high",
        )
    if analysis.includes_remote:
        preview = ", ".join(ref for _, ref in analysis.includes_remote[:3])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(analysis.includes_remote)} `include:` entries reference remote URLs "
                f"(supply-chain risk): {preview}{' …' if len(analysis.includes_remote) > 3 else ''}."
            ),
            remediation=(
                "Prefer `include: local: ./...` for in-repo files, or `include: project:` "
                "with a pinned `ref:`. Remote URLs without integrity verification can change "
                "between pipeline runs."
            ),
            evidence_sources=[str(p.resolve()) for p, _ in analysis.includes_remote],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No remote `include:` references detected; supply-chain risk reduced.",
        remediation="Prefer local includes or pinned cross-project includes (project + ref).",
        evidence_sources=[str(p.resolve()) for p in analysis.pipeline_paths],
        confidence="medium",
    )


def eval_gl_pipe_006(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-006: GitLab CI jobs use trigger restrictions (rules / only / except)."""

    analysis = ctx.gitlab_ci
    if not analysis.pipeline_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitLab CI pipelines to evaluate.",
            remediation="Add a .gitlab-ci.yml; this control checks for trigger restrictions.",
            evidence_sources=[],
            confidence="high",
        )
    if not analysis.jobs_with_trigger_restrictions:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "No pipeline declares `rules:`, `only:`, `except:`, or `when:`. Jobs run "
                "on every commit/event by default, which is rarely the intended behavior "
                "for security-sensitive jobs."
            ),
            remediation=(
                "Add `rules:` (preferred) or `only:` / `except:` clauses to scope jobs to "
                "specific branches, MR events, or schedules."
            ),
            evidence_sources=[str(p.resolve()) for p in analysis.pipeline_paths],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"{len(analysis.jobs_with_trigger_restrictions)} pipeline(s) declare trigger "
            "restrictions (`rules:` / `only:` / `except:` / `when:`)."
        ),
        remediation="Audit `rules:` regularly; prefer them over deprecated `only:` / `except:`.",
        evidence_sources=[str(p.resolve()) for p in analysis.jobs_with_trigger_restrictions],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# GL-PIPE-007..012 — gitlab-level-2 additions (PR-14, O-09).
#
# Six new signal-grade controls covering OIDC tokens, self-hosted runner
# scoping, audit-event streaming, environment approvals, MR review rules,
# and artifact retention. Each evaluator does a focused keyword scan over
# the GitLab CI pipeline files; the existing ``gitlab_ci_parser`` analyzer
# is not extended in this PR — that work is tracked for v6.1.0+.
# ---------------------------------------------------------------------------


def _scan_gitlab_pipelines(ctx: EvalContext, hints: tuple[str, ...]) -> list[Path]:
    """Return GitLab pipeline files whose text contains any of ``hints`` (case-insensitive)."""
    matched: list[Path] = []
    for p in ctx.gitlab_ci.pipeline_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(h in text for h in hints):
                matched.append(p)
    return matched


def _gl_no_pipeline_response(control_id: str, remediation: str) -> EvalOutcome:
    return EvalOutcome(
        status=ControlStatus.NOT_APPLICABLE,
        reason=f"No GitLab CI pipelines to evaluate; {control_id} is not applicable.",
        remediation=remediation,
        evidence_sources=[],
        confidence="high",
    )


def eval_gl_pipe_007(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-007: GitLab CI uses OIDC (id_tokens) for cloud / registry access."""
    if not ctx.gitlab_ci.pipeline_paths:
        return _gl_no_pipeline_response(
            "GL-PIPE-007",
            "Add a .gitlab-ci.yml; this control checks for id_tokens (OIDC) usage.",
        )
    matched = _scan_gitlab_pipelines(ctx, ("id_tokens:", "id_token:", "aud:"))
    if not matched:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "No GitLab pipeline declares `id_tokens:` (OIDC) for cloud / registry access. "
                "Long-lived credentials are the alternative; OIDC is the GitLab GA path since "
                "January 2026."
            ),
            remediation=(
                "Declare `id_tokens:` at the job level with the appropriate `aud:` and exchange "
                "the GitLab OIDC token for short-lived cloud / registry credentials. See GitLab "
                "OIDC docs."
            ),
            evidence_sources=[str(p.resolve()) for p in ctx.gitlab_ci.pipeline_paths],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(matched)} pipeline(s) declare `id_tokens:` / OIDC posture.",
        remediation="Keep id_tokens audience scoped to the minimum required.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="medium",
    )


def eval_gl_pipe_008(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-008: GitLab CI scopes self-hosted runner usage via tags."""
    if not ctx.gitlab_ci.pipeline_paths:
        return _gl_no_pipeline_response(
            "GL-PIPE-008",
            "Add a .gitlab-ci.yml; this control checks for `tags:` scoping on jobs.",
        )
    matched = _scan_gitlab_pipelines(ctx, ("tags:",))
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No GitLab pipeline declares `tags:` for runner scoping. Jobs may run on any "
                "runner the project can reach."
            ),
            remediation=(
                "Add `tags:` to jobs that must run on specific runner pools (especially self-"
                "hosted runners) so untrusted MR pipelines cannot accidentally execute there."
            ),
            evidence_sources=[str(p.resolve()) for p in ctx.gitlab_ci.pipeline_paths],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(matched)} pipeline(s) use `tags:` to scope runner selection.",
        remediation="Confirm the tagged runners enforce isolation from MR pipelines on protected branches.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_gl_pipe_009(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-009: audit-event streaming or external export documented for the project."""
    # Look in either pipeline files or known doc locations.
    candidates: list[Path] = list(ctx.gitlab_ci.pipeline_paths)
    for rel in ("AUDIT.md", "docs/audit-streaming.md", "RELEASE_OPERATIONS.md", ".gitlab/audit-streaming.yml"):
        p = ctx.repo_root / rel
        if p.is_file():
            candidates.append(p)
    matched: list[Path] = []
    for p in candidates:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(h in text for h in ("audit_event", "audit-event", "audit streaming", "audit_streaming")):
                matched.append(p)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=("No audit-event streaming / external export reference found in pipelines or common doc locations."),
            remediation=(
                "Document the project-level audit-event streaming destination (e.g. SIEM, "
                "object store) in AUDIT.md or .gitlab/audit-streaming.yml so reviewers can "
                "confirm the trail leaves GitLab."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Audit-event streaming reference detected ({matched[0].name}).",
        remediation="Confirm the destination is monitored and retained per the organisation's policy.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_gl_pipe_010(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-010: environment approval rules declared for protected envs."""
    if not ctx.gitlab_ci.pipeline_paths:
        return _gl_no_pipeline_response(
            "GL-PIPE-010",
            "Add a .gitlab-ci.yml; this control checks for `environment:` declarations with approval rules.",
        )
    matched = _scan_gitlab_pipelines(ctx, ("environment:", "deployment_tier:", "approval"))
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No `environment:` / `deployment_tier:` / approval declaration found in pipelines.",
            remediation=(
                "For deploys to production / staging, declare `environment:` with `name:`, "
                "`deployment_tier:`, and configure protected-environment approvals at the "
                "project level."
            ),
            evidence_sources=[str(p.resolve()) for p in ctx.gitlab_ci.pipeline_paths],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(matched)} pipeline(s) declare environment / deployment-tier metadata.",
        remediation="Confirm protected-environment approvals are configured in project settings.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_gl_pipe_011(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-011: merge-request rules enforce code-review approvals."""
    # MR review rules are a project setting; look for project-level evidence file.
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "gitlab-mr-rules.json"
    if evidence.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(evidence.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("min_approvers", 0) >= 1:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=f"MR rule evidence documents min_approvers={data['min_approvers']}.",
                    remediation="SLSA Source L4 requires 2+ approvers; consider raising the threshold.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="high",
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            "No .oss-policy-kit/evidence/gitlab-mr-rules.json evidence; MR approval enforcement "
            "cannot be verified from a clone."
        ),
        remediation=(
            "Document the project's MR approval rules (min approvers, code owner approval) in the evidence file."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def eval_gl_pipe_012(ctx: EvalContext) -> EvalOutcome:
    """GL-PIPE-012: artifact retention or signed-release posture documented."""
    if not ctx.gitlab_ci.pipeline_paths:
        return _gl_no_pipeline_response(
            "GL-PIPE-012",
            "Add a .gitlab-ci.yml; this control checks for artifact retention / signing posture.",
        )
    matched = _scan_gitlab_pipelines(ctx, ("expire_in:", "artifacts:", "cosign", "sigstore", "rekor"))
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No artifact retention (`expire_in:`) or signed-release tooling (cosign / "
                "sigstore / rekor) detected in pipelines."
            ),
            remediation=(
                "Declare `expire_in:` on artifacts and sign release outputs (e.g. cosign sign-blob, "
                "cosign attest) before publishing."
            ),
            evidence_sources=[str(p.resolve()) for p in ctx.gitlab_ci.pipeline_paths],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(matched)} pipeline(s) document artifact retention / signing posture.",
        remediation="Audit `expire_in:` thresholds and confirm signing keys are managed via OIDC / KMS.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


# ---------------------------------------------------------------------------
# GH-EGRESS-HRN-001 (V6-04 — Onda 2).
#
# Signal-grade detection of Harden-Runner (or equivalent runtime egress
# control) presence in GitHub Actions workflows. Detects:
#
# - ``step-security/harden-runner`` action invocation.
# - GitHub native egress firewall config (when it ships GA — Q4 2026 / Q1 2027
#   expected per the GitHub Actions 2026 security roadmap). Today the kit only
#   matches the keywords; the native config shape will be added when GA lands.
#
# Signal grade: the kit cannot verify the runtime egress enforcement actually
# blocks traffic; it only confirms the declarative intent exists in the
# workflow source. Adopters needing enforcement evidence should pair this with
# Step Security's audit trail or a separate runtime control.
# ---------------------------------------------------------------------------

_HARDEN_RUNNER_PATTERNS: tuple[str, ...] = (
    "step-security/harden-runner",
    "stepsecurity/harden-runner",
)


def eval_gh_egress_hrn_001(ctx: EvalContext) -> EvalOutcome:
    """GH-EGRESS-HRN-001: GitHub Actions workflows declare Harden-Runner egress controls."""

    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows present.",
            remediation=(
                "If this repository uses GitHub Actions, declare Harden-Runner with "
                "`step-security/harden-runner@<sha>` in every workflow that touches release "
                "artifacts or runs untrusted code."
            ),
            evidence_sources=[],
            confidence="high",
        )
    matched: list[Path] = []
    for p in paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(pat in text for pat in _HARDEN_RUNNER_PATTERNS):
                matched.append(p)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"No Harden-Runner egress control detected in {len(paths)} workflow file(s). "
                "Harden-Runner is the de-facto OSS runtime egress control while GitHub's "
                "native egress firewall is pre-GA (Q4 2026 / Q1 2027 expected)."
            ),
            remediation=(
                "Add `uses: step-security/harden-runner@<sha>` as the first step in every "
                "workflow that produces release artifacts or runs untrusted PR code. Pin to "
                "a full commit SHA per CI-PIN-008."
            ),
            evidence_sources=[str(p.resolve()) for p in paths],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(f"Harden-Runner egress control detected in {len(matched)} of {len(paths)} workflow file(s)."),
        remediation=(
            "Keep Harden-Runner pinned by SHA and review the audit-mode allowlist before tightening to block-mode."
        ),
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# AIBOM-PRESENT-001 + LLM-218A-* family (PR-10, V6-01 + V6-08).
#
# Clone-side AI-security signals aligned with NIST SP 800-218A (Generative
# AI SSDF Community Profile). All signal-grade except LLM-218A-PS-001
# (evidence-backed via the llm-release-integrity/v1 schema).
# ---------------------------------------------------------------------------

_LLM_SDK_HINTS: tuple[str, ...] = (
    "transformers",
    "openai",
    "anthropic",
    "langchain",
    "llama-index",
    "llamaindex",
    "huggingface",
    "huggingface_hub",
    "mistralai",
    "cohere",
)

_AI_SECURITY_HEADINGS: tuple[str, ...] = (
    "ai security considerations",
    "ai/llm security",
    "llm security considerations",
    "model security",
    "generative ai security",
)


def eval_aibom_present_001(ctx: EvalContext) -> EvalOutcome:
    """AIBOM-PRESENT-001: AI Bill of Materials present in evidence directory."""
    candidates: list[Path] = []
    for rel in (".oss-policy-kit/evidence/aibom", "aibom"):
        d = ctx.repo_root / rel
        if d.is_dir():
            with contextlib.suppress(OSError):
                candidates.extend(p for p in d.glob("*.json") if p.is_file())
    # Cycle 2 (PR-26): also recognise a CycloneDX 1.7 ML-BOM anywhere in the
    # repo via the machine-learning-model component marker.
    if not candidates:
        with contextlib.suppress(OSError):
            for p in list(ctx.repo_root.rglob("*.cdx.json")) + list(ctx.repo_root.rglob("bom.json")):
                if not p.is_file() or ".git" in p.parts:
                    continue
                sample = p.read_text(encoding="utf-8", errors="replace")[:8000].lower()
                if "machine-learning-model" in sample or "modelcard" in sample or "ml-bom" in sample:
                    candidates.append(p)
    if not candidates:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No AIBOM file found at .oss-policy-kit/evidence/aibom/*.json or aibom/*.json. "
                "CycloneDX ML-BOM and SPDX 3.0 AI components are the two recognised formats."
            ),
            remediation=(
                "Generate an AIBOM (CycloneDX ML-BOM via cdxgen with ML profile, or SPDX 3.0 AI "
                "components) and drop the JSON at .oss-policy-kit/evidence/aibom/."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"AIBOM detected: {len(candidates)} file(s) under the evidence directory.",
        remediation="Re-generate the AIBOM on every model release.",
        evidence_sources=[str(p.resolve()) for p in candidates],
        confidence="medium",
    )


def _scan_readme_for_section(repo: Path, headings: tuple[str, ...]) -> Path | None:
    for rel in ("SECURITY.md", "README.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        p = repo / rel
        if not p.is_file():
            continue
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(h in text for h in headings):
                return p
    return None


def eval_llm_218a_po_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PO-001: AI Security Considerations section present."""
    p = _scan_readme_for_section(ctx.repo_root, _AI_SECURITY_HEADINGS)
    if p is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No 'AI Security Considerations' / 'LLM Security' section found in SECURITY.md or README.md.",
            remediation=(
                "Add a section explicitly named 'AI Security Considerations' to SECURITY.md "
                "documenting the intended use, abuse cases, and mitigations of any AI components."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"AI Security Considerations section detected in {p.name}.",
        remediation="Keep the section in sync with model upgrades and capability changes.",
        evidence_sources=[str(p.resolve())],
        confidence="low",
    )


def eval_llm_218a_po_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PO-002: Prompt / system-instruction registry directory present."""
    for rel in ("prompts", "system_prompts", "system-prompts", "prompt-registry"):
        d = ctx.repo_root / rel
        if d.is_dir():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Prompt registry directory detected: {rel}/.",
                remediation="Document the prompt lifecycle (versioning, review, deprecation).",
                evidence_sources=[str(d.resolve())],
                confidence="low",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No prompt registry directory found (prompts/, system_prompts/, prompt-registry/).",
        remediation=(
            "Maintain prompts under version control in a dedicated directory so audit and rollback are possible."
        ),
        evidence_sources=[],
        confidence="low",
    )


def eval_llm_218a_ps_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PS-001: LLM release-integrity evidence file (evidence-backed)."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "llm-release-integrity.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No .oss-policy-kit/evidence/llm-release-integrity.json file. The evidence file "
                "should record model_sha, model_version, and eval_suite_results_path per release."
            ),
            remediation=(
                "Create the evidence file with the schema_version=llm-release-integrity/v1, "
                "the model SHA, the model version, and a path to the eval-suite results."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(evidence.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("model_sha") and data.get("model_version"):
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(f"LLM release-integrity evidence present (model_version={data.get('model_version')})."),
                remediation="Refresh per release; keep eval_suite_results_path pointing to current results.",
                evidence_sources=[str(evidence.resolve())],
                confidence="medium",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="llm-release-integrity.json present but missing required fields.",
        remediation="Populate model_sha, model_version, and eval_suite_results_path.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_llm_218a_ps_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PS-002: Model versioning artifacts (signal-grade)."""
    for rel in ("models/MODEL_CARD.md", "MODEL_CARD.md", "model-card.md", "docs/model-card.md"):
        p = ctx.repo_root / rel
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Model card found at {rel}; model versioning artifact present.",
                remediation="Update the model card on every release.",
                evidence_sources=[str(p.resolve())],
                confidence="low",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No model card or model-versioning artifact found.",
        remediation="Add a MODEL_CARD.md (e.g. HuggingFace model-card pattern) at the repo root.",
        evidence_sources=[],
        confidence="low",
    )


def _scan_for_llm_sdks(repo: Path) -> Path | None:
    for rel in ("requirements.txt", "pyproject.toml", "package.json", "Pipfile", "poetry.lock"):
        p = repo / rel
        if not p.is_file():
            continue
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(sdk in text for sdk in _LLM_SDK_HINTS):
                return p
    return None


def eval_llm_218a_pw_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PW-001: LLM SDK dependencies declared."""
    p = _scan_for_llm_sdks(ctx.repo_root)
    if p is None:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No LLM SDK dependency detected; LLM controls do not apply to this repo.",
            remediation="If this repo uses an LLM SDK (transformers / openai / anthropic / langchain), declare it.",
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"LLM SDK dependency declared in {p.name}.",
        remediation="Pin the SDK by version (CI-PIN-001) and track upgrades via Dependabot/Renovate.",
        evidence_sources=[str(p.resolve())],
        confidence="medium",
    )


def eval_llm_218a_pw_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-PW-002: Prompt-injection or adversarial test file present."""
    found: list[Path] = []
    for pattern in ("test_*prompt*injection*.py", "test_*adversarial*.py", "test_*jailbreak*.py"):
        with contextlib.suppress(OSError):
            for p in ctx.repo_root.rglob(pattern):
                if p.is_file():
                    found.append(p)
    if not found:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No prompt-injection or adversarial test file found.",
            remediation=(
                "Add tests under tests/ matching test_*prompt*injection*.py, test_*adversarial*.py, "
                "or test_*jailbreak*.py covering at least the OWASP LLM Top 10 #1 (prompt injection)."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(found)} adversarial / prompt-injection test file(s) detected.",
        remediation="Refresh test corpus as new attack patterns emerge.",
        evidence_sources=[str(p.resolve()) for p in found[:5]],
        confidence="low",
    )


def eval_llm_218a_rv_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-218A-RV-001: Dependabot/Renovate config explicitly lists LLM SDKs."""
    candidates = [
        ctx.repo_root / ".github" / "dependabot.yml",
        ctx.repo_root / ".github" / "dependabot.yaml",
        ctx.repo_root / "renovate.json",
        ctx.repo_root / ".renovaterc.json",
    ]
    for p in candidates:
        if not p.is_file():
            continue
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(sdk in text for sdk in _LLM_SDK_HINTS):
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=f"Dependency-update config ({p.name}) explicitly references an LLM SDK.",
                    remediation="Keep the SDK in the config so security updates land promptly.",
                    evidence_sources=[str(p.resolve())],
                    confidence="low",
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Dependency-update config does not explicitly reference an LLM SDK.",
        remediation=("Add an explicit package-ecosystem entry covering the LLM SDK(s) used by this project."),
        evidence_sources=[],
        confidence="low",
    )


# ---------------------------------------------------------------------------
# WORM-* family (PR-19, Cycle 2) — Shai-Hulud / TeamPCP defense layer.
#
# Detects clone-side signals of npm/PyPI worm activity. All signal-grade.
# See docs/shai-hulud-defense.md and ADR-015.
# ---------------------------------------------------------------------------

_POSTINSTALL_DANGER_HINTS: tuple[str, ...] = (
    "curl ",
    "wget ",
    "| sh",
    "| bash",
    "base64 -d",
    "base64 --decode",
    "process.env",
    "os.environ",
    "eval(",
    "exec(",
    "nc -e",
    "powershell -encoded",
    "iwr ",
    "invoke-webrequest",
)


def eval_worm_postinstall_001(ctx: EvalContext) -> EvalOutcome:
    """WORM-POSTINSTALL-001: package.json postinstall script lacks credential-harvest primitives."""
    pkg = ctx.repo_root / "package.json"
    if not pkg.is_file():
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No package.json present; postinstall worm pattern does not apply.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(pkg.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            raw_scripts = data.get("scripts")
            scripts = cast(dict[str, Any], raw_scripts) if isinstance(raw_scripts, dict) else {}
            postinstall = str(scripts.get("postinstall", "")).lower()
            if not postinstall:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason="No postinstall script declared in package.json.",
                    remediation="Continue avoiding postinstall hooks unless strictly required.",
                    evidence_sources=[str(pkg.resolve())],
                    confidence="high",
                )
            hits = [h for h in _POSTINSTALL_DANGER_HINTS if h in postinstall]
            if hits:
                return EvalOutcome(
                    status=ControlStatus.FAIL,
                    reason=(
                        f"package.json postinstall contains credential-harvest primitives "
                        f"({', '.join(hits[:3])}). Pattern observed in Shai-Hulud / TeamPCP attacks 2026."
                    ),
                    remediation=(
                        "Audit the postinstall script; remove network egress + env-var dumps. "
                        "See docs/shai-hulud-defense.md."
                    ),
                    evidence_sources=[str(pkg.resolve())],
                    confidence="high",
                )
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="package.json postinstall present but no credential-harvest primitive detected.",
                remediation="Periodically audit postinstall content; pin it via a separate version-controlled file.",
                evidence_sources=[str(pkg.resolve())],
                confidence="medium",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="package.json present but unparseable.",
        remediation="Fix package.json JSON syntax.",
        evidence_sources=[str(pkg.resolve())],
        confidence="low",
    )


def eval_worm_lockfile_drift_001(ctx: EvalContext) -> EvalOutcome:
    """WORM-LOCKFILE-DRIFT-001: manifest not modified more recently than lockfile."""
    pairs: list[tuple[Path, Path]] = []
    for manifest, lockfile in (
        ("package.json", "package-lock.json"),
        ("package.json", "yarn.lock"),
        ("pyproject.toml", "poetry.lock"),
        ("pyproject.toml", "uv.lock"),
        ("requirements.txt", "requirements.lock"),
    ):
        m = ctx.repo_root / manifest
        lk = ctx.repo_root / lockfile
        if m.is_file() and lk.is_file():
            pairs.append((m, lk))
    if not pairs:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No manifest + lockfile pair detected; lockfile drift check does not apply.",
            remediation="Adopt a lockfile (package-lock.json, poetry.lock, uv.lock) to enable this check.",
            evidence_sources=[],
            confidence="high",
        )
    drifted: list[tuple[Path, Path]] = []
    for m, lk in pairs:
        with contextlib.suppress(OSError):
            if m.stat().st_mtime > lk.stat().st_mtime + 60:
                drifted.append((m, lk))
    if drifted:
        sample = ", ".join(f"{m.name}>{lk.name}" for m, lk in drifted[:3])
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"Manifest modified more recently than lockfile ({sample}). "
                "Shai-Hulud worm rewrites manifests; verify the diff is intentional."
            ),
            remediation=(
                "Regenerate the lockfile (npm install, poetry lock, uv lock) and commit it together "
                "with the manifest change. Investigate any unexplained drift."
            ),
            evidence_sources=[str(p.resolve()) for pair in drifted for p in pair],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Lockfile is at least as fresh as the manifest for {len(pairs)} pair(s).",
        remediation="Keep lockfile updates atomic with manifest changes.",
        evidence_sources=[str(p.resolve()) for pair in pairs for p in pair],
        confidence="medium",
    )


def eval_worm_publish_scope_001(ctx: EvalContext) -> EvalOutcome:
    """WORM-PUBLISH-SCOPE-001: publish workflow scoped to main/release branches."""
    publish_paths: list[Path] = []
    for p in ctx.workflows.workflow_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if "npm publish" in text or "twine upload" in text or "pypi-publish" in text or "cargo publish" in text:
                publish_paths.append(p)
    if not publish_paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No publish workflow detected.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    risky: list[Path] = []
    for p in publish_paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            # Look for tag-only or branch-restricted triggers.
            has_branch_restriction = any(
                pat in text
                for pat in (
                    "branches: [main",
                    "branches: [master",
                    "branches: ['main'",
                    'branches: ["main"',
                    "branches: [release",
                    "tags:",
                    "tags: ['v",
                    'tags: ["v',
                )
            )
            if not has_branch_restriction:
                risky.append(p)
    if risky:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(risky)} publish workflow(s) lack explicit branch / tag scope. "
                "Shai-Hulud-style worms exploit unscoped publish triggers to push poisoned versions."
            ),
            remediation=(
                "Restrict the publish workflow to `on: { push: { tags: ['v*'] } }` or "
                "`on: { push: { branches: [main] } }` plus an environment with required approvers."
            ),
            evidence_sources=[str(p.resolve()) for p in risky],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(publish_paths)} publish workflow(s) scoped to main/release branches or tags.",
        remediation="Keep the scope tight; require environment approvals for production publishes.",
        evidence_sources=[str(p.resolve()) for p in publish_paths],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# LLM-AI-ACT-001..003 (PR-11, V6-02) — EU AI Act Article 11 + Annex IV signals.
#
# Advisory profile. The kit does NOT substitute for a conformity assessment
# (Article 43); see docs/eu-ai-act-readiness.md for the explicit caveat.
# ---------------------------------------------------------------------------

_INTENDED_PURPOSE_HEADINGS: tuple[str, ...] = (
    "intended purpose",
    "intended use",
    "intended users",
    "limitations",
    "foreseeable misuse",
)

_OUTPUT_FILTER_HINTS: tuple[str, ...] = (
    "output_filter",
    "output-filter",
    "content_moderation",
    "content-moderation",
    "moderation_api",
    "openai.moderations",
    "guardrails",
    "nemoguardrails",
)

_RISK_MGMT_PATHS: tuple[str, ...] = (
    "risk-management.md",
    "RISKS.md",
    "docs/risk-management.md",
    "docs/RISKS.md",
)

_RISK_MGMT_HEADINGS: tuple[str, ...] = (
    "risk management",
    "risk assessment",
    "ai risk register",
)


def eval_llm_ai_act_001(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-001: Intended purpose / users / limitations documented (Annex IV §1)."""
    p = _scan_readme_for_section(ctx.repo_root, _INTENDED_PURPOSE_HEADINGS)
    if p is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No 'Intended Purpose' / 'Intended Users' / 'Limitations' section found in "
                "SECURITY.md or README.md (Annex IV §1)."
            ),
            remediation=(
                "Add a section explicitly documenting the intended purpose, intended users, and "
                "foreseeable limitations of the AI system. Required by EU AI Act Annex IV §1."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Intended purpose / users / limitations section detected in {p.name} (Annex IV §1).",
        remediation=(
            "Keep the section in sync with model upgrades. Conformity assessment by a notified body "
            "is still required and out of scope for the kit."
        ),
        evidence_sources=[str(p.resolve())],
        confidence="low",
    )


def eval_llm_ai_act_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-002: Output filtering / content moderation pattern detected (Annex IV §3)."""
    # Scan src/, tests/, or root code files for output-filter / moderation patterns.
    matched: list[Path] = []
    for ext in ("*.py", "*.js", "*.ts", "*.mjs"):
        with contextlib.suppress(OSError):
            for p in ctx.repo_root.rglob(ext):
                if not p.is_file():
                    continue
                if any(skip in p.parts for skip in (".git", ".venv", "node_modules", "__pycache__")):
                    continue
                with contextlib.suppress(OSError):
                    text = p.read_text(encoding="utf-8", errors="replace").lower()
                    if any(h in text for h in _OUTPUT_FILTER_HINTS):
                        matched.append(p)
                        if len(matched) >= 5:
                            break
        if len(matched) >= 5:
            break
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=("No output-filtering / content-moderation reference found in source code (Annex IV §3)."),
            remediation=(
                "Implement an output filter (e.g. OpenAI Moderations API, NVIDIA NeMo Guardrails, "
                "or a custom classifier) and reference it in the AI pipeline."
            ),
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Output-filtering / content-moderation pattern detected in {len(matched)} file(s) (Annex IV §3).",
        remediation="Periodically review the moderation thresholds and the evaluation dataset.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_llm_ai_act_003(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-003: Risk management documentation present (Annex IV §5)."""
    for rel in _RISK_MGMT_PATHS:
        p = ctx.repo_root / rel
        if p.is_file():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Risk-management documentation found at {rel} (Annex IV §5).",
                remediation="Keep the risk register current with each release; review with a notified body.",
                evidence_sources=[str(p.resolve())],
                confidence="medium",
            )
    # Fall back to SECURITY.md section
    section_match = _scan_readme_for_section(ctx.repo_root, _RISK_MGMT_HEADINGS)
    if section_match is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Risk-management section detected in {section_match.name} (Annex IV §5).",
            remediation="Consider extracting to a dedicated risk-management.md for clearer audit traceability.",
            evidence_sources=[str(section_match.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No risk-management documentation found (risk-management.md, RISKS.md, or SECURITY.md section).",
        remediation=(
            "Document the AI risk-management process (hazard identification, residual risk, mitigation "
            "measures) in risk-management.md. Required by EU AI Act Annex IV §5."
        ),
        evidence_sources=[],
        confidence="low",
    )


# ---------------------------------------------------------------------------
# AI-AGENT-001..010 — source-side and build-time baseline for AI agents.
#
# These controls are intentionally clone/evidence focused. They do not enforce
# runtime agent policy; use them as source-time posture signals before pairing
# with a runtime policy/enforcement layer.
# ---------------------------------------------------------------------------

_AI_AGENT_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".hg", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".venv", "__pycache__", "node_modules"}
)

_AI_AGENT_TEXT_PATTERNS: tuple[str, ...] = (
    "*.py",
    "*.js",
    "*.ts",
    "*.tsx",
    "*.mjs",
    "*.json",
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.md",
)

_MCP_CONFIG_PATHS: tuple[str, ...] = (
    "mcp.json",
    "mcp.config.json",
    ".mcp.json",
    ".mcp/config.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
)

_MCP_AUTH_HINTS: tuple[str, ...] = (
    "bearer",
    "oauth",
    "oidc",
    "jwt",
    "mtls",
    "mTLS",
    "api_key",
    "authorization",
    "token_audience",
    "validate_token",
)

_MCP_AUTH_DISABLED_HINTS: tuple[str, ...] = (
    '"auth": "none"',
    '"auth": none',
    "auth: none",
    "authn: none",
    "no_auth",
    "disable_auth",
    "token_passthrough",
    "token passthrough",
)

_AI_AGENT_TOOL_ALLOWLIST_PATHS: tuple[str, ...] = (
    "allowed_tools.yaml",
    "allowed_tools.yml",
    "allowed_tools.json",
    "tools.allowlist.yaml",
    "tools.allowlist.yml",
    "tools.yaml",
    "tools.yml",
    "tools.json",
    "agent-tools.yaml",
    "agent-tools.yml",
)

_AI_AGENT_TOOL_WILDCARD_HINTS: tuple[str, ...] = (
    "all_available_tools",
    "allow_all_tools",
    "tools: all",
    '"tools": "*"',
    '"tools": ["*"]',
    "tool_choice: auto_all",
)

_AI_AGENT_PROMPT_DIRS: tuple[str, ...] = ("prompts", "system_prompts", "system-prompts", "prompt-registry")

_AI_AGENT_HARDCODED_PROMPT_HINTS: tuple[str, ...] = (
    "system_prompt =",
    "systemprompt =",
    '"role": "system"',
    "'role': 'system'",
    "system_instruction =",
)

_AI_AGENT_TEST_PATTERNS: tuple[str, ...] = (
    "test_*prompt*injection*.*",
    "test_*jailbreak*.*",
    "test_*red_team*.*",
    "test_*redteam*.*",
    "test_*adversarial*.*",
)

_AI_AGENT_RATE_LIMIT_HINTS: tuple[str, ...] = (
    "rate_limit",
    "ratelimit",
    "quota",
    "max_requests",
    "requests_per_minute",
    "tokens_per_minute",
    "throttle",
)

_AI_AGENT_IDENTITY_HINTS: tuple[str, ...] = (
    "agent_identity",
    "service_account",
    "workload_identity",
    "managed_identity",
    "client_id",
    "oidc_audience",
    "token_audience",
    "subject_token",
)

_AI_AGENT_IDENTITY_ANTIPATTERNS: tuple[str, ...] = (
    "use_user_credentials",
    "user_token_passthrough",
    "token_passthrough",
    "pass_through_token",
)

_AI_AGENT_MODEL_HINTS: tuple[str, ...] = (
    "model",
    "openai",
    "anthropic",
    "claude",
    "gpt-",
    "gemini",
    "mistral",
    "llama",
)

_AI_AGENT_PINNED_MODEL_RE = re.compile(
    r"\b(?:claude-[\w.-]+-\d{8}|gpt-[\w.-]+-\d{4}-\d{2}-\d{2}|gemini-[\w.-]+-\d{8}|"
    r"mistral-[\w.-]+-\d{8}|llama-[\w.-]+(?:-\d+(?:\.\d+){1,2}|-v\d+))\b",
    re.IGNORECASE,
)


def _iter_ai_agent_text_files(repo: Path) -> list[Path]:
    found: list[Path] = []
    for pat in _AI_AGENT_TEXT_PATTERNS:
        with contextlib.suppress(OSError):
            for p in repo.rglob(pat):
                if not p.is_file():
                    continue
                if any(part in _AI_AGENT_SKIP_DIRS for part in p.parts):
                    continue
                found.append(p)
                if len(found) >= 200:
                    return found
    return found


def _read_lower(path: Path) -> str:
    with contextlib.suppress(OSError):
        return path.read_text(encoding="utf-8", errors="replace").lower()
    return ""


def _find_any_text_hint(repo: Path, hints: tuple[str, ...]) -> list[Path]:
    matched: list[Path] = []
    normalized = tuple(h.lower() for h in hints)
    for p in _iter_ai_agent_text_files(repo):
        text = _read_lower(p)
        if text and any(h in text for h in normalized):
            matched.append(p)
            if len(matched) >= 5:
                break
    return matched


def _find_prompt_registry(repo: Path) -> Path | None:
    for rel in _AI_AGENT_PROMPT_DIRS:
        p = repo / rel
        if p.is_dir():
            return p
    return None


def _codeowners_text(repo: Path) -> tuple[Path, str] | None:
    for rel in ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"):
        p = repo / rel
        if p.is_file():
            text = _read_lower(p)
            return p, text
    return None


def _codeowners_covers_prompt_path(repo: Path, prompt_dir: Path) -> tuple[Path, bool] | None:
    entry = _codeowners_text(repo)
    if entry is None:
        return None
    owner_file, text = entry
    rel = prompt_dir.relative_to(repo).as_posix().lower()
    return owner_file, rel in text or f"/{rel}" in text or "*" in text


def _ai_agent_evidence_path(ctx: EvalContext, filename: str) -> Path:
    return ctx.repo_root / ".oss-policy-kit" / "evidence" / "ai-agent" / filename


def _load_ai_agent_evidence(
    ctx: EvalContext,
    filename: str,
    evidence_name: str,
) -> tuple[Path, dict[str, Any] | None, EvalOutcome | None]:
    evidence = _ai_agent_evidence_path(ctx, filename)
    if not evidence.is_file():
        return (
            evidence,
            None,
            EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=f"No .oss-policy-kit/evidence/ai-agent/{filename} evidence file present.",
                remediation=f"Create {filename} using schema_version=ai-agent-baseline/v1.",
                evidence_sources=[],
                confidence="medium",
            ),
        )
    data, error, placeholders = _validate_json_evidence(
        evidence,
        schema_loader=_ai_agent_baseline_schema,
        evidence_name=evidence_name,
    )
    if error:
        return (
            evidence,
            None,
            EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=error,
                remediation="Fix the evidence JSON to match evidence-ai-agent-baseline.schema.json.",
                evidence_sources=[str(evidence.resolve())],
                confidence="low",
            ),
        )
    ph = _evidence_placeholder_outcome(evidence, placeholders)
    if ph is not None:
        return evidence, None, ph
    return evidence, data, None


def eval_ai_agent_001(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-001: MCP server authentication present."""
    configs = [ctx.repo_root / rel for rel in _MCP_CONFIG_PATHS if (ctx.repo_root / rel).is_file()]
    if not configs:
        with contextlib.suppress(OSError):
            configs.extend(p for p in ctx.repo_root.rglob("*.mcp.yaml") if p.is_file())
            configs.extend(p for p in ctx.repo_root.rglob("*.mcp.yml") if p.is_file())
    if not configs:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No MCP server configuration file detected.",
            remediation="No MCP-specific action required unless this repository ships an MCP server.",
            evidence_sources=[],
            confidence="medium",
        )
    disabled: list[Path] = []
    authenticated: list[Path] = []
    for p in configs:
        text = _read_lower(p)
        if any(h in text for h in _MCP_AUTH_DISABLED_HINTS):
            disabled.append(p)
        elif any(h.lower() in text for h in _MCP_AUTH_HINTS):
            authenticated.append(p)
    if disabled:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"MCP configuration disables or bypasses authentication in {len(disabled)} file(s).",
            remediation=(
                "Require OAuth/OIDC, bearer-token validation, mTLS, or an equivalent authn layer for MCP access."
            ),
            evidence_sources=[str(p.resolve()) for p in disabled],
            confidence="medium",
        )
    if authenticated:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"MCP authentication signal detected in {len(authenticated)} config file(s).",
            remediation="Validate tokens are issued for this MCP server and avoid token passthrough.",
            evidence_sources=[str(p.resolve()) for p in authenticated],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP configuration is present but no authentication signal was detected.",
        remediation="Document the MCP authentication mode in mcp.json or an evidence file.",
        evidence_sources=[str(p.resolve()) for p in configs],
        confidence="low",
    )


def eval_ai_agent_002(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-002: Tool allowlist explicitly defined."""
    candidates = [ctx.repo_root / rel for rel in _AI_AGENT_TOOL_ALLOWLIST_PATHS if (ctx.repo_root / rel).is_file()]
    candidates.extend(ctx.repo_root / rel for rel in _MCP_CONFIG_PATHS if (ctx.repo_root / rel).is_file())
    if not candidates:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No explicit agent tool allowlist file found.",
            remediation="Add allowed_tools.yaml/json or document allowed MCP tools in mcp.json.",
            evidence_sources=[],
            confidence="low",
        )
    wildcard = [p for p in candidates if any(h in _read_lower(p) for h in _AI_AGENT_TOOL_WILDCARD_HINTS)]
    if wildcard:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Agent tool allowlist uses an allow-all or wildcard pattern.",
            remediation="Replace allow-all tool selection with a named, least-privilege allowlist.",
            evidence_sources=[str(p.resolve()) for p in wildcard],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Explicit agent tool allowlist/config detected in {len(candidates)} file(s).",
        remediation="Review the allowlist as tools are added or removed.",
        evidence_sources=[str(p.resolve()) for p in candidates[:5]],
        confidence="low",
    )


def eval_ai_agent_003(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-003: System prompt versioned and reviewed."""
    prompt_dir = _find_prompt_registry(ctx.repo_root)
    if prompt_dir is None:
        hardcoded = _find_any_text_hint(ctx.repo_root, _AI_AGENT_HARDCODED_PROMPT_HINTS)
        if hardcoded:
            return EvalOutcome(
                status=ControlStatus.FAIL,
                reason="System prompt appears hardcoded in source and no prompt registry directory exists.",
                remediation="Move system prompts into prompts/ and require CODEOWNERS review for that path.",
                evidence_sources=[str(p.resolve()) for p in hardcoded],
                confidence="low",
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No prompts/, system_prompts/, or prompt-registry/ directory found.",
            remediation="Store system prompts in a versioned prompt registry and cover it with CODEOWNERS.",
            evidence_sources=[],
            confidence="low",
        )
    owner = _codeowners_covers_prompt_path(ctx.repo_root, prompt_dir)
    if owner is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Prompt registry detected at {prompt_dir.name}/ but no CODEOWNERS file was found.",
            remediation="Add CODEOWNERS coverage for the prompt registry so prompt changes are reviewed.",
            evidence_sources=[str(prompt_dir.resolve())],
            confidence="low",
        )
    owner_file, covered = owner
    if not covered:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"CODEOWNERS exists but does not cover {prompt_dir.name}/.",
            remediation="Add a CODEOWNERS entry for the prompt registry path.",
            evidence_sources=[str(prompt_dir.resolve()), str(owner_file.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Prompt registry {prompt_dir.name}/ is versioned and covered by CODEOWNERS.",
        remediation="Keep prompt changes in normal review flow.",
        evidence_sources=[str(prompt_dir.resolve()), str(owner_file.resolve())],
        confidence="medium",
    )


def eval_ai_agent_004(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-004: Prompt injection test fixtures present."""
    found: list[Path] = []
    for pat in _AI_AGENT_TEST_PATTERNS:
        with contextlib.suppress(OSError):
            for p in (ctx.repo_root / "tests").rglob(pat):
                if p.is_file():
                    found.append(p)
    security_tests = ctx.repo_root / "tests" / "security"
    if security_tests.is_dir():
        with contextlib.suppress(OSError):
            found.extend(p for p in security_tests.rglob("*") if p.is_file())
    if not found:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No prompt-injection, jailbreak, red-team, or adversarial test fixture found.",
            remediation="Add security tests covering prompt injection and tool-misuse cases.",
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"{len(found)} agent adversarial/security test file(s) detected.",
        remediation="Refresh the corpus as agent capabilities and tools change.",
        evidence_sources=[str(p.resolve()) for p in found[:5]],
        confidence="low",
    )


def eval_ai_agent_005(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-005: Output sanitization layer documented."""
    evidence, data, outcome = _load_ai_agent_evidence(ctx, "output-sanitization.json", "AI agent output sanitization")
    if outcome is not None:
        return outcome
    assert data is not None
    applied_to = data.get("applied_to")
    if data.get("method") and isinstance(applied_to, list) and applied_to and data.get("bypass_review_process"):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Output sanitization evidence documents method, covered surfaces, and bypass review process.",
            remediation="Refresh this evidence when output channels or bypass criteria change.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="output-sanitization.json is missing method, applied_to, or bypass_review_process.",
        remediation="Populate all required output-sanitization fields.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_ai_agent_006(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-006: Rate limiting / quota config present."""
    matched = _find_any_text_hint(ctx.repo_root, _AI_AGENT_RATE_LIMIT_HINTS)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No agent rate-limit, quota, throttle, or token budget signal detected.",
            remediation="Document or configure per-agent rate limits and token/request quotas.",
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Rate-limit / quota signal detected in {len(matched)} file(s).",
        remediation="Keep quotas aligned with model/provider limits and abuse cases.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_ai_agent_007(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-007: Audit log of tool calls implemented."""
    evidence, data, outcome = _load_ai_agent_evidence(ctx, "audit-log-config.json", "AI agent audit log")
    if outcome is not None:
        return outcome
    assert data is not None
    retention = data.get("retention_days")
    if data.get("destination") and isinstance(retention, int) and retention > 0 and data.get("pii_redaction") is True:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Tool-call audit logging evidence present with {retention} day retention and PII redaction.",
            remediation="Verify the destination is monitored and access-controlled.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="audit-log-config.json is missing destination, positive retention_days, or pii_redaction=true.",
        remediation="Populate audit-log evidence with destination, retention_days, and pii_redaction.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_ai_agent_008(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-008: Agent identity / authn configured."""
    antipatterns = _find_any_text_hint(ctx.repo_root, _AI_AGENT_IDENTITY_ANTIPATTERNS)
    if antipatterns:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason="Agent identity anti-pattern detected (user credential or token passthrough).",
            remediation="Use a dedicated agent identity or service account with audience-bound tokens.",
            evidence_sources=[str(p.resolve()) for p in antipatterns],
            confidence="medium",
        )
    matched = _find_any_text_hint(ctx.repo_root, _AI_AGENT_IDENTITY_HINTS)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No dedicated agent identity, service account, OIDC, or audience-bound token signal detected.",
            remediation="Configure agent identity separately from end-user credentials.",
            evidence_sources=[],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"Dedicated agent identity/authn signal detected in {len(matched)} file(s).",
        remediation="Keep agent credentials least-privileged and rotate them through platform identity.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="low",
    )


def eval_ai_agent_009(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-009: Sensitive context not in agent memory."""
    evidence, data, outcome = _load_ai_agent_evidence(ctx, "memory-policy.json", "AI agent memory policy")
    if outcome is not None:
        return outcome
    assert data is not None
    excluded = data.get("excluded_context_types")
    retention = str(data.get("retention_policy", "")).strip()
    if isinstance(excluded, list) and excluded and retention:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Memory policy excludes {len(excluded)} sensitive context type(s).",
            remediation="Review the excluded context list when new tools or memory stores are added.",
            evidence_sources=[str(evidence.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="memory-policy.json is missing excluded_context_types or retention_policy.",
        remediation="Document what must never enter long-term agent memory and how memory is retained/purged.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_ai_agent_010(ctx: EvalContext) -> EvalOutcome:
    """AI-AGENT-010: Model + version pinning enforced."""
    model_files: list[Path] = []
    unpinned: list[Path] = []
    for p in _iter_ai_agent_text_files(ctx.repo_root):
        text = _read_lower(p)
        if not text or not any(h in text for h in _AI_AGENT_MODEL_HINTS):
            continue
        model_files.append(p)
        if _AI_AGENT_PINNED_MODEL_RE.search(text):
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"Version-pinned model identifier detected in {p.name}.",
                remediation="Review model pins intentionally; avoid floating aliases in release branches.",
                evidence_sources=[str(p.resolve())],
                confidence="medium",
            )
        if "model" in text and any(h in text for h in ("gpt-", "claude", "gemini", "mistral", "llama")):
            unpinned.append(p)
    if unpinned:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Model configuration appears to use floating provider/model aliases without a dated or versioned pin."
            ),
            remediation="Pin the model identifier to a dated/versioned provider release where supported.",
            evidence_sources=[str(p.resolve()) for p in unpinned[:5]],
            confidence="medium",
        )
    if model_files:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Model-related files exist but no recognizable version-pinned model identifier was detected.",
            remediation="Document the model version in config or evidence so releases are reproducible.",
            evidence_sources=[str(p.resolve()) for p in model_files[:5]],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No model configuration or pinned model identifier detected.",
        remediation="Add a model config that pins the provider/model version used by the agent.",
        evidence_sources=[],
        confidence="low",
    )


# ---------------------------------------------------------------------------
# PUBLISH-OIDC-001..003 (PR-9, V6-06).
#
# Signal-grade detection of Trusted Publishing posture across the major
# package registries that ship OIDC publishing as GA in 2025-2026 (PyPI,
# npm, RubyGems, crates.io, plus GitLab OIDC publishing). The kit detects
# the declarative intent in the workflow source; it does not verify the
# publish actually succeeded.
#
# See ADR-014 for the design rationale and the rejected alternatives.
# ---------------------------------------------------------------------------

# Workflow keywords that indicate a registry-publish step. Case-insensitive.
_PUBLISH_KEYWORDS: tuple[str, ...] = (
    "pypi.org",
    "pypi-publish",
    "pypa/gh-action-pypi-publish",
    "twine upload",
    "npm publish",
    "actions/setup-node",  # weak; refined by NPM_TOKEN absence in PUBLISH-OIDC-002
    "gem push",
    "rubygems-publish",
    "cargo publish",
    "rubygems_api_key",
)

_OIDC_TOKEN_PATTERN = re.compile(r"id-token:\s*write", re.IGNORECASE)
_LONG_LIVED_PASSWORD_PATTERN = re.compile(
    r"\b(NPM_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|RUBYGEMS_API_KEY|CARGO_REGISTRY_TOKEN|password:\s*\$\{\{?\s*secrets\.)",
    re.IGNORECASE,
)
_NPM_PROVENANCE_PATTERN = re.compile(r"(--provenance\b|provenance:\s*true)", re.IGNORECASE)


def _publish_workflows(paths: list[Path]) -> list[Path]:
    """Return the subset of workflow paths that look like publish workflows."""
    out: list[Path] = []
    for p in paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(kw in text for kw in _PUBLISH_KEYWORDS):
                out.append(p)
    return out


def eval_publish_oidc_001(ctx: EvalContext) -> EvalOutcome:
    """PUBLISH-OIDC-001: publish workflow declares ``permissions: id-token: write``."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows present.",
            remediation="No action required. This control activates when a publish workflow is defined.",
            evidence_sources=[],
            confidence="high",
        )
    publish = _publish_workflows(paths)
    if not publish:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No publish workflow detected (no PyPI / npm / RubyGems / crates keyword in any workflow).",
            remediation=(
                "If this repo publishes to a package registry, the publish workflow should declare "
                "``permissions: id-token: write`` so the registry can attest the build via OIDC."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    matched: list[Path] = []
    for p in publish:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace")
            if _OIDC_TOKEN_PATTERN.search(text):
                matched.append(p)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(publish)} publish workflow(s) detected but none declare ``permissions: id-token: write``. "
                "Trusted Publishing requires this permission for the runtime to mint the OIDC token."
            ),
            remediation=(
                "Add ``permissions: { id-token: write }`` at the workflow or job level. "
                "See PyPI Trusted Publishers docs / npm Trusted Publishers docs."
            ),
            evidence_sources=[str(p.resolve()) for p in publish],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(f"{len(matched)} of {len(publish)} publish workflow(s) declare ``permissions: id-token: write``."),
        remediation=(
            "Keep id-token: write scoped to the publish job, not the whole workflow, and pin the "
            "publish action by SHA per CI-PIN-008."
        ),
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="medium",
    )


def eval_publish_oidc_002(ctx: EvalContext) -> EvalOutcome:
    """PUBLISH-OIDC-002: publish step omits long-lived registry token / password."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows present.",
            remediation="No action required. This control activates when a publish workflow is defined.",
            evidence_sources=[],
            confidence="high",
        )
    publish = _publish_workflows(paths)
    if not publish:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No publish workflow detected.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="medium",
        )
    offenders: list[Path] = []
    for p in publish:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace")
            if _LONG_LIVED_PASSWORD_PATTERN.search(text):
                offenders.append(p)
    if offenders:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(offenders)} publish workflow(s) still reference a long-lived token "
                "(NPM_TOKEN / PYPI_TOKEN / TWINE_PASSWORD / RUBYGEMS_API_KEY / CARGO_REGISTRY_TOKEN / "
                "password: secrets.*). Trusted Publishing removes the need for these."
            ),
            remediation=(
                "Migrate to Trusted Publishing (PyPI / npm / RubyGems / crates) and remove the "
                "long-lived secret. Document the cut-over and rotate the legacy token out of the "
                "registry afterward."
            ),
            evidence_sources=[str(p.resolve()) for p in offenders],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"None of the {len(publish)} publish workflow(s) reference a long-lived registry token; "
            "Trusted Publishing posture is consistent."
        ),
        remediation="Confirm the legacy registry token was rotated out after the cut-over.",
        evidence_sources=[str(p.resolve()) for p in publish],
        confidence="medium",
    )


def eval_publish_oidc_003(ctx: EvalContext) -> EvalOutcome:
    """PUBLISH-OIDC-003: npm publish step uses ``--provenance`` (or registry-equivalent)."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows present.",
            remediation="No action required. This control activates when an npm publish workflow is defined.",
            evidence_sources=[],
            confidence="high",
        )
    npm_publish: list[Path] = []
    for p in paths:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if "npm publish" in text:
                npm_publish.append(p)
    if not npm_publish:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No npm publish step detected.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="medium",
        )
    with_provenance: list[Path] = []
    for p in npm_publish:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace")
            if _NPM_PROVENANCE_PATTERN.search(text):
                with_provenance.append(p)
    if not with_provenance:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(npm_publish)} npm publish workflow(s) found but none declare ``--provenance`` "
                "or ``provenance: true``. Trusted Publishing on npm requires the flag for the provenance "
                "attestation to be generated."
            ),
            remediation=(
                "Add ``--provenance`` to the ``npm publish`` command, or set ``provenance: true`` on the "
                "publish action input. See npm Trusted Publishers docs."
            ),
            evidence_sources=[str(p.resolve()) for p in npm_publish],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(f"{len(with_provenance)} of {len(npm_publish)} npm publish workflow(s) declare provenance."),
        remediation="Keep the provenance flag enabled; remove if migrating off npm-trusted-publishing only.",
        evidence_sources=[str(p.resolve()) for p in with_provenance],
        confidence="medium",
    )


# ---------------------------------------------------------------------------
# SLSA-SRC-001..005 — SLSA v1.0 Source Track Level 1 (PR-13, O-06, ADR-006).
#
# Most SLSA Source L1 requirements overlap with existing kit controls
# (branch protection, audit log, code review). Rather than duplicate them
# under SLSA-vocabulary IDs naïvely, four of the five evaluators below
# delegate the underlying signal lookup to the existing controls and only
# wrap the result with the SLSA-vocabulary identity. The one genuinely new
# signal — commit-signature enforcement — is detected by SLSA-SRC-002.
# ---------------------------------------------------------------------------


_COMMIT_SIGNATURE_HINTS: tuple[str, ...] = (
    "required_signatures",
    "require_signatures",
    "requiresignaturecommits",
    "signed-commits",
    "signed commits",
    "gpg verify-commit",
    "git verify-commit",
    "require_signed_commits",
)


def eval_slsa_src_001(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-001: Version-controlled source (.git present)."""
    if (ctx.repo_root / ".git").exists():
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Repository is under git version control (.git present).",
            remediation="Continue using git for source versioning.",
            evidence_sources=[str((ctx.repo_root / ".git").resolve())],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="No .git directory detected; source is not under version control.",
        remediation="Initialise a git repository and push to a hosted SCM.",
        evidence_sources=[],
        confidence="high",
    )


def eval_slsa_src_002(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-002: Commit-signature enforcement signal."""
    workflow_paths = list(ctx.workflows.workflow_paths)
    # Look in workflow files and known ruleset hint locations.
    candidates: list[Path] = list(workflow_paths)
    for rel in (
        ".github/rulesets",
        ".github/branch-protection.yml",
        ".github/branch-protection.yaml",
        ".oss-policy-kit/evidence/branch-protection.json",
    ):
        p = ctx.repo_root / rel
        if p.exists():
            if p.is_dir():
                with contextlib.suppress(OSError):
                    candidates.extend(c for c in p.rglob("*") if c.is_file())
            else:
                candidates.append(p)
    matched: list[Path] = []
    for p in candidates:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(h in text for h in _COMMIT_SIGNATURE_HINTS):
                matched.append(p)
    if not matched:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No commit-signature enforcement signal detected (no required_signatures or "
                "equivalent in workflows / rulesets / branch-protection evidence)."
            ),
            remediation=(
                "Enable required signatures via repository ruleset (GitHub: Settings → Rules → "
                "Rulesets → Require signed commits), or document the enforcement in the "
                "branch-protection.json evidence file."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=(
            f"Commit-signature enforcement signal detected in {len(matched)} location(s) "
            "(workflows, rulesets, or branch-protection evidence)."
        ),
        remediation="Audit the rule periodically; ensure it stays attached to protected branches.",
        evidence_sources=[str(p.resolve()) for p in matched],
        confidence="medium",
    )


def eval_slsa_src_003(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-003: Branch protection present (delegates to PLAT-BRPROT-015 evidence)."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "No branch-protection.json evidence file present. SLSA Source L1 requires "
                "documented protected branches."
            ),
            remediation=(
                "Run `oss-policy-kit collect-evidence --platform github` (or the equivalent for "
                "your SCM) to populate .oss-policy-kit/evidence/branch-protection.json."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(evidence.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("required_status_checks"):
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Branch protection rules documented in branch-protection.json evidence file.",
                remediation="Keep the evidence file current with the live ruleset.",
                evidence_sources=[str(evidence.resolve())],
                confidence="high",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="branch-protection.json present but no required_status_checks documented.",
        remediation="Populate the evidence file with the active branch protection rules.",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def eval_slsa_src_004(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-004: Two-party review on protected branches."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No branch-protection.json evidence; two-party review cannot be verified.",
            remediation=(
                "Run `oss-policy-kit collect-evidence --platform github` and ensure the resulting "
                "evidence file documents required_approving_review_count >= 1."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(evidence.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            count = data.get("required_approving_review_count")
            if isinstance(count, int) and count >= 1:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason=f"Branch protection requires {count} approving review(s).",
                    remediation="SLSA Source L4 requires 2+ approving reviews; consider raising the threshold.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="high",
                )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="branch-protection.json present but required_approving_review_count is missing or zero.",
        remediation="Set required_approving_review_count >= 1 on protected branches.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
    )


def eval_slsa_src_005(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-005: Audit log of source-changing events (delegates to AUDIT-STREAM-060)."""
    return eval_audit_stream_060(ctx)


# ===========================================================================
# Cycle 2 (v6.0.0) evaluators — PR-20 .. PR-32.
#
# Market signals: Shai-Hulud worm campaign (PR-19, shipped), OSPS Baseline
# v2026.02.19, EU AI Act Annex IV (effective 2026-08-02), EU CRA Art. 13/14,
# EPSS+KEV triage, SLSA v1.2 Source L2, MCP tool poisoning, OWASP Agentic
# Top 10, GitHub Actions 2026 roadmap, distroless base images, post-Trivy
# scanner integrity. See docs/decisions/ ADRs and the Cycle 2 plan.
# ===========================================================================


def _read_first_existing(repo: Path, relpaths: tuple[str, ...]) -> tuple[Path | None, str]:
    """Return ``(path, lowercased_text)`` for the first readable file, else ``(None, "")``."""
    for rel in relpaths:
        p = repo / rel
        if p.is_file():
            with contextlib.suppress(OSError):
                return p, p.read_text(encoding="utf-8", errors="replace").lower()
    return None, ""


# --- PR-20: OSPS Baseline v2026.02.19 + Scorecard v6 conformance ----------
def eval_osps_scorecard_v6_001(ctx: EvalContext) -> EvalOutcome:
    """OSPS-SCORECARD-V6-001: Scorecard v6 OSPS Baseline conformance evidence."""
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "scorecard-osps.json"
    if not evidence.is_file():
        legacy = ctx.repo_root / ".oss-policy-kit" / "evidence" / "scorecard.json"
        if legacy.is_file():
            return EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=(
                    "Classic Scorecard result present but no OSPS Baseline conformance "
                    "(scorecard-osps.json). Scorecard v6 emits a PASS/FAIL/UNKNOWN conformance "
                    "verdict aligned to OSPS Baseline v2026.02.19."
                ),
                remediation="Run `scorecard --format=osps` once Scorecard v6 ships (writes scorecard-osps.json).",
                evidence_sources=[str(legacy.resolve())],
                confidence="medium",
            )
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No Scorecard OSPS conformance evidence at .oss-policy-kit/evidence/scorecard-osps.json.",
            remediation=(
                "Run `scorecard --format=osps --repo=<url> > scorecard-osps.json` and drop it under "
                ".oss-policy-kit/evidence/. See docs/osps-baseline-2026-mapping.md."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(evidence.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            verdict = str(data.get("conformance") or data.get("result") or data.get("overall") or "").strip().lower()
            if verdict in {"pass", "passed", "conformant", "true"}:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason="Scorecard v6 reports OSPS Baseline conformance (PASS).",
                    remediation="Re-run Scorecard on each release to keep the conformance verdict current.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="high",
                    evidence_collection_method=EvidenceCollectionMethod.LIVE,
                )
            if verdict in {"fail", "failed", "non-conformant", "false"}:
                return EvalOutcome(
                    status=ControlStatus.FAIL,
                    reason="Scorecard v6 reports OSPS Baseline non-conformance (FAIL).",
                    remediation="Address the failing OSPS Baseline checks reported by Scorecard.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="high",
                    evidence_collection_method=EvidenceCollectionMethod.LIVE,
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="scorecard-osps.json present but no recognisable conformance verdict (pass/fail).",
        remediation="Regenerate the OSPS conformance report with Scorecard v6 (`--format=osps`).",
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


# --- PR-21: EU AI Act Annex IV expansion (advisory) -----------------------
def _load_ai_system_doc(ctx: EvalContext) -> tuple[dict[str, Any] | None, Path]:
    p = ctx.repo_root / ".oss-policy-kit" / "evidence" / "ai-system-technical-doc.json"
    if not p.is_file():
        return None, p
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return cast(dict[str, Any], data), p
    return None, p


def _annex_iv_section(ctx: EvalContext, field: str, label: str, remediation: str) -> EvalOutcome:
    data, p = _load_ai_system_doc(ctx)
    if data is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                f"No ai-system-technical-doc.json evidence; Annex IV {label} cannot be verified. "
                "Advisory only — the kit does NOT substitute for an EU AI Act conformity assessment."
            ),
            remediation=remediation,
            evidence_sources=[],
            confidence="medium",
        )
    value = data.get(field)
    populated = (isinstance(value, str) and value.strip() != "") or (isinstance(value, (list, dict)) and len(value) > 0)
    if populated:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Annex IV {label} documented in ai-system-technical-doc.json (field '{field}').",
            remediation="Keep the technical documentation current as the AI system evolves.",
            evidence_sources=[str(p.resolve())],
            confidence="medium",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=f"ai-system-technical-doc.json present but Annex IV {label} (field '{field}') is empty or missing.",
        remediation=remediation,
        evidence_sources=[str(p.resolve())],
        confidence="medium",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_llm_ai_act_dev_002(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-DEV-002: development/design + training-data description (Annex IV section 2)."""
    return _annex_iv_section(
        ctx,
        "development_design",
        "section 2 (development, design choices, training/validation/test data)",
        "Populate 'development_design' in ai-system-technical-doc.json. See docs/eu-ai-act-readiness.md.",
    )


def eval_llm_ai_act_perf_004(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-PERF-004: performance metrics + accuracy (Annex IV section 4)."""
    return _annex_iv_section(
        ctx,
        "performance_metrics",
        "section 4 (performance metrics, accuracy, robustness)",
        "Populate 'performance_metrics' in ai-system-technical-doc.json.",
    )


def eval_llm_ai_act_cyber_006(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-CYBER-006: cybersecurity measures (Annex IV section 6)."""
    return _annex_iv_section(
        ctx,
        "cybersecurity_measures",
        "section 6 (cybersecurity measures)",
        "Populate 'cybersecurity_measures' in ai-system-technical-doc.json.",
    )


def eval_llm_ai_act_change_007(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-CHANGE-007: lifecycle change record (Annex IV section 7)."""
    return _annex_iv_section(
        ctx,
        "lifecycle_changes",
        "section 7 (lifecycle changes through the system's life)",
        "Populate 'lifecycle_changes' in ai-system-technical-doc.json.",
    )


def eval_llm_ai_act_std_008(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-STD-008: applied harmonised standards (Annex IV section 7)."""
    return _annex_iv_section(
        ctx,
        "applied_standards",
        "applied harmonised standards (e.g. prEN 18286)",
        "Populate 'applied_standards' in ai-system-technical-doc.json.",
    )


def eval_llm_ai_act_pmm_009(ctx: EvalContext) -> EvalOutcome:
    """LLM-AI-ACT-PMM-009: post-market monitoring plan (Annex IV section 8)."""
    return _annex_iv_section(
        ctx,
        "post_market_monitoring_plan",
        "section 8 (post-market monitoring plan)",
        "Populate 'post_market_monitoring_plan' in ai-system-technical-doc.json.",
    )


# --- PR-22: EU CRA Article 13 + 14 + product classification ---------------
def eval_cra_art13_sbd_001(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART13-SBD-001: security-by-design intent declared."""
    p, _ = _read_first_existing(ctx.repo_root, ("SECURITY.md", "README.md", "docs/security.md"))
    section = _scan_readme_for_section(
        ctx.repo_root, ("security by design", "secure by design", "security-by-design", "secure-by-design")
    )
    adr_hit = (
        any(adr.is_file() for adr in (ctx.repo_root / "docs" / "decisions").glob("*.md"))
        if (ctx.repo_root / "docs" / "decisions").is_dir()
        else False
    )
    if section is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Security-by-design intent documented in {section.name} (CRA Article 13).",
            remediation="Keep the security-by-design statement aligned with the threat model.",
            evidence_sources=[str(section.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=(
            "No explicit security-by-design statement found in SECURITY.md / README"
            + (" (ADR directory present — document the intent there)." if adr_hit else ".")
        ),
        remediation="Add a 'Security by design' section to SECURITY.md or an ADR (CRA Art. 13). See cra-readiness.md.",
        evidence_sources=[str(p.resolve())] if p else [],
        confidence="medium",
    )


def eval_cra_art13_defaults_002(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART13-DEFAULTS-002: secure-by-default configuration documented."""
    section = _scan_readme_for_section(
        ctx.repo_root, ("secure default", "secure-by-default", "default configuration", "hardened default")
    )
    if section is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Secure-by-default configuration documented in {section.name} (CRA Article 13).",
            remediation="Review defaults each release; ensure ship-secure (no permissive fallback).",
            evidence_sources=[str(section.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No secure-by-default configuration statement found in SECURITY.md / README.",
        remediation="Document the secure default configuration (CRA Article 13). See docs/cra-readiness.md.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_cra_art14_csaf_001(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART14-CSAF-001: CSAF advisory feed present."""
    candidates = (
        ".well-known/csaf",
        ".well-known/csaf/provider-metadata.json",
        "csaf",
        "advisories.json",
        "security/advisories.json",
    )
    for rel in candidates:
        p = ctx.repo_root / rel
        if p.exists():
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"CSAF advisory feed signal present ({rel}) — CRA Article 14 reporting readiness.",
                remediation="Keep the CSAF feed populated with machine-readable advisories per release.",
                evidence_sources=[str(p.resolve())],
                confidence="medium",
            )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No CSAF advisory feed detected (.well-known/csaf, csaf/, or advisories.json).",
        remediation=(
            "Publish CSAF advisories (.well-known/csaf/provider-metadata.json) to support CRA Article 14 "
            "machine-readable reporting. See docs/cra-readiness.md."
        ),
        evidence_sources=[],
        confidence="medium",
    )


def eval_cra_art14_coord_002(ctx: EvalContext) -> EvalOutcome:
    """CRA-ART14-COORD-002: coordinated vulnerability disclosure policy documented."""
    disclosure = ctx.repo_root / ".oss-policy-kit" / "evidence" / "disclosure-policy.json"
    if disclosure.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(disclosure.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("coordinated_disclosure") is True:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason="disclosure-policy.json declares coordinated_disclosure: true (CRA Article 14).",
                    remediation="Keep the disclosure SLA and contact current.",
                    evidence_sources=[str(disclosure.resolve())],
                    confidence="high",
                )
    section = _scan_readme_for_section(
        ctx.repo_root, ("coordinated disclosure", "coordinated vulnerability disclosure", "responsible disclosure")
    )
    if section is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Coordinated disclosure policy documented in {section.name} (CRA Article 14).",
            remediation="Mirror the policy into disclosure-policy.json (coordinated_disclosure: true) for machine use.",
            evidence_sources=[str(section.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No coordinated vulnerability disclosure policy found in SECURITY.md or disclosure-policy.json.",
        remediation="Document a coordinated disclosure policy (CRA Article 14). See docs/cra-readiness.md.",
        evidence_sources=[],
        confidence="medium",
    )


def eval_cra_product_class_001(ctx: EvalContext) -> EvalOutcome:
    """CRA-PRODUCT-CLASS-001: CRA product classification declared."""
    p, text = _read_first_existing(
        ctx.repo_root, ("cra-classification.md", "docs/cra-classification.md", "docs/cra-readiness.md")
    )
    class_terms = (
        "important product",
        "critical product",
        "default category",
        "class i",
        "class ii",
        "annex iii",
        "annex iv",
    )
    if p is not None and any(t in text for t in class_terms):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"CRA product classification declared in {p.name} (Implementing Reg (EU) 2025/2392).",
            remediation="Re-check the classification when scope or features change.",
            evidence_sources=[str(p.resolve())],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No CRA product classification declared (important / critical / default per Impl. Reg (EU) 2025/2392).",
        remediation="Add docs/cra-classification.md declaring the product class. See docs/cra-readiness.md.",
        evidence_sources=[],
        confidence="low",
    )


# --- PR-23: EPSS + CISA KEV prioritization in SCA -------------------------
_OSV_SARIF_RELPATH = ".oss-policy-kit/evidence/sast/osv-scanner.sarif.json"


def _scan_sarif_epss_kev(
    sarif_path: Path, *, epss_threshold: float = 0.5, cvss_threshold: float = 7.0
) -> tuple[list[str], list[str], str | None]:
    """Return ``(kev_ids, high_epss_ids, error)`` from SARIF result.properties."""
    try:
        doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        return [], [], f"Could not read SARIF: {exc}"
    except json.JSONDecodeError as exc:
        return [], [], f"Could not parse SARIF JSON: {exc}"
    if not isinstance(doc, dict):
        return [], [], "SARIF top-level is not an object."
    kev: list[str] = []
    high_epss: list[str] = []
    runs = doc.get("runs")
    for run in runs if isinstance(runs, list) else []:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            props = result.get("properties")
            if not isinstance(props, dict):
                continue
            ident = str(result.get("ruleId") or props.get("cve") or props.get("id") or "finding")
            kev_flag = props.get("kev")
            kev_str = kev_flag.strip().lower() if isinstance(kev_flag, str) else ""
            if kev_flag in (True, 1) or kev_str in {"true", "yes", "1"}:
                kev.append(ident)
            epss_raw = props.get("epss_score", props.get("epss"))
            cvss_raw = props.get("cvss_score", props.get("security-severity"))
            epss_val: float | None = None
            cvss_val: float | None = None
            with contextlib.suppress(TypeError, ValueError):
                if epss_raw is not None:
                    epss_val = float(epss_raw)
            with contextlib.suppress(TypeError, ValueError):
                if cvss_raw is not None:
                    cvss_val = float(cvss_raw)
            if epss_val is not None and epss_val >= epss_threshold and (cvss_val is None or cvss_val >= cvss_threshold):
                high_epss.append(ident)
    return kev, high_epss, None


def eval_sca_kev_001(ctx: EvalContext) -> EvalOutcome:
    """SCA-KEV-001: no dependency CVE present in CISA KEV (SARIF kev property)."""
    evidence = ctx.repo_root / _OSV_SARIF_RELPATH
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"No OSV-Scanner SARIF at {_OSV_SARIF_RELPATH}; KEV status cannot be verified.",
            remediation="Run OSV-Scanner v2+ with KEV enrichment, attach the SARIF. See docs/triage-cvss-epss-kev.md.",
            evidence_sources=[],
            confidence="medium",
        )
    kev, _, err = _scan_sarif_epss_kev(evidence)
    if err is not None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=err,
            remediation="Regenerate the OSV-Scanner SARIF.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if kev:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(kev)} dependency CVE(s) present in the CISA KEV catalog "
                f"({', '.join(sorted(set(kev))[:3])}). KEV = confirmed active exploitation."
            ),
            remediation="Patch or remove KEV-listed dependencies immediately; KEV overrides standard severity.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No dependency CVE flagged as CISA KEV in the OSV-Scanner SARIF.",
        remediation="Keep dependencies current; re-scan on each release with KEV enrichment.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_sca_epss_001(ctx: EvalContext) -> EvalOutcome:
    """SCA-EPSS-001: no high-EPSS high-severity dependency CVE unaddressed."""
    evidence = ctx.repo_root / _OSV_SARIF_RELPATH
    if not evidence.is_file():
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"No OSV-Scanner SARIF at {_OSV_SARIF_RELPATH}; EPSS prioritization cannot be verified.",
            remediation="Run OSV-Scanner v2+ with EPSS enrichment, attach the SARIF. See docs/triage-cvss-epss-kev.md.",
            evidence_sources=[],
            confidence="medium",
        )
    _, high_epss, err = _scan_sarif_epss_kev(evidence)
    if err is not None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=err,
            remediation="Regenerate the OSV-Scanner SARIF.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if high_epss:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(high_epss)} dependency CVE(s) with EPSS >= 0.5 and CVSS >= 7.0 "
                f"({', '.join(sorted(set(high_epss))[:3])}). High exploit probability."
            ),
            remediation="Prioritise patching high-EPSS high-severity CVEs ahead of the standard backlog.",
            evidence_sources=[str(evidence.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason="No high-EPSS high-severity dependency CVE detected in the OSV-Scanner SARIF.",
        remediation="Re-evaluate EPSS scores periodically; they change as exploit telemetry evolves.",
        evidence_sources=[str(evidence.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


# --- PR-25: SLSA v1.2 Source Track Level 2 --------------------------------
def _branch_protection_evidence(ctx: EvalContext) -> tuple[dict[str, Any] | None, Path]:
    p = ctx.repo_root / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    if not p.is_file():
        return None, p
    with contextlib.suppress(OSError, json.JSONDecodeError):
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return cast(dict[str, Any], data), p
    return None, p


def eval_slsa_src_006(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-006: signed commits required (SLSA Source L2)."""
    data, p = _branch_protection_evidence(ctx)
    if data is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No branch-protection.json evidence; required-signed-commits enforcement cannot be verified.",
            remediation="Run `oss-policy-kit collect-evidence --platform github`; ensure required_signatures: true.",
            evidence_sources=[],
            confidence="medium",
        )
    if data.get("required_signatures") is True or data.get("required_signed_commits") is True:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="branch-protection.json enforces required signed commits (SLSA Source L2).",
            remediation="Keep required signatures attached to all protected branches.",
            evidence_sources=[str(p.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason="branch-protection.json present but required_signatures is off (SLSA Source L2 needs signed commits).",
        remediation="Enable required signed commits via repository ruleset and refresh the evidence file.",
        evidence_sources=[str(p.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_slsa_src_007(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-007: two-party review threshold enforced (SLSA Source L2)."""
    data, p = _branch_protection_evidence(ctx)
    if data is None:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No branch-protection.json evidence; two-party L2 review threshold cannot be verified.",
            remediation="Run `collect-evidence --platform github`; set required_approving_review_count >= 2.",
            evidence_sources=[],
            confidence="medium",
        )
    count = data.get("required_approving_review_count")
    if isinstance(count, int) and count >= 2:
        codeowner = data.get("require_code_owner_reviews") is True
        suffix = " with codeowner approval" if codeowner else ""
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Branch protection requires {count} approving reviews{suffix} (SLSA Source L2).",
            remediation="Maintain the >=2 reviewer threshold; require codeowner approval for sensitive paths.",
            evidence_sources=[str(p.resolve())],
            confidence="high",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=f"required_approving_review_count is {count!r}; SLSA Source L2 requires >= 2 approvers.",
        remediation="Raise required_approving_review_count to >= 2 on protected branches.",
        evidence_sources=[str(p.resolve())],
        confidence="high",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_slsa_src_008(ctx: EvalContext) -> EvalOutcome:
    """SLSA-SRC-008: source-change audit log streamed externally (delegates to AUDIT-STREAM-060)."""
    return eval_audit_stream_060(ctx)


# --- PR-27: MCP server security -------------------------------------------
_MCP_CONFIG_FILES: tuple[str, ...] = ("mcp.json", ".mcp.json", "mcp_server.json", "server.json")
_MCP_DEP_HINTS: tuple[str, ...] = (
    "modelcontextprotocol",
    "model-context-protocol",
    "fastmcp",
    "mcp-server",
    '"mcp"',
    "mcp[",
)


def _mcp_applicable(repo: Path) -> tuple[bool, list[Path]]:
    found: list[Path] = []
    for rel in _MCP_CONFIG_FILES:
        p = repo / rel
        if p.is_file():
            found.append(p)
    for rel in ("pyproject.toml", "package.json", "requirements.txt"):
        p = repo / rel
        if p.is_file():
            with contextlib.suppress(OSError):
                text = p.read_text(encoding="utf-8", errors="replace").lower()
                if any(h in text for h in _MCP_DEP_HINTS):
                    found.append(p)
    if (repo / ".mcp").is_dir():
        found.append(repo / ".mcp")
    return (len(found) > 0, found)


def _mcp_na(reason_kind: str) -> EvalOutcome:
    return EvalOutcome(
        status=ControlStatus.NOT_APPLICABLE,
        reason=f"No MCP server detected (no mcp.json / MCP dependency); {reason_kind} check does not apply.",
        remediation="No action required unless this repository hosts an MCP server.",
        evidence_sources=[],
        confidence="high",
    )


def eval_mcp_tool_hash_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-TOOL-HASH-001: MCP tool descriptions hash-pinned (tool-poisoning defense)."""
    applicable, found = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("tool-description hash")
    evidence = ctx.repo_root / ".oss-policy-kit" / "evidence" / "mcp-tool-descriptions.json"
    if evidence.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(evidence.read_text(encoding="utf-8"))
            text = json.dumps(data).lower() if data is not None else ""
            if "sha256" in text or "hash" in text:
                return EvalOutcome(
                    status=ControlStatus.PASS,
                    reason="mcp-tool-descriptions.json pins tool-description hashes (tool-poisoning defense).",
                    remediation="Recompute and compare the hashes in CI on every MCP server change.",
                    evidence_sources=[str(evidence.resolve())],
                    confidence="medium",
                )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no hash-pinned tool descriptions (mcp-tool-descriptions.json with sha256).",
        remediation=(
            "Record SHA-256 hashes of each MCP tool description in "
            ".oss-policy-kit/evidence/mcp-tool-descriptions.json and verify in CI. See docs/mcp-server-security.md."
        ),
        evidence_sources=[str(p.resolve()) for p in found[:2]],
        confidence="medium",
    )


def _mcp_text_signal(repo: Path, found: list[Path], needles: tuple[str, ...]) -> Path | None:
    scan: list[Path] = list(found)
    for rel in ("README.md", "SECURITY.md", "docs/mcp-server-security.md", "mcp.json", ".mcp.json"):
        p = repo / rel
        if p.is_file() and p not in scan:
            scan.append(p)
    for p in scan:
        if p.is_dir():
            continue
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(n in text for n in needles):
                return p
    return None


def eval_mcp_confirm_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-CONFIRM-001: destructive operations require explicit confirmation."""
    applicable, found = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("destructive-confirmation")
    hit = _mcp_text_signal(
        ctx.repo_root,
        found,
        (
            "requires confirmation",
            "require confirmation",
            "human_in_the_loop",
            "human-in-the-loop",
            "confirm before",
            "destructive",
        ),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Destructive-operation confirmation signal detected in {hit.name}.",
            remediation="Ensure every state-changing MCP tool enforces an explicit confirmation step.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no destructive-operation confirmation pattern found.",
        remediation="Require explicit user confirmation for destructive MCP tools. See docs/mcp-server-security.md.",
        evidence_sources=[],
        confidence="low",
    )


def eval_mcp_egress_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-EGRESS-001: MCP server egress allowlist documented."""
    applicable, found = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("egress-allowlist")
    hit = _mcp_text_signal(
        ctx.repo_root,
        found,
        ("egress allowlist", "egress allow-list", "allowed_hosts", "allowed-hosts", "allowlist", "outbound allowlist"),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"MCP egress allowlist signal detected in {hit.name}.",
            remediation="Keep the egress allowlist tight; deny by default.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no egress allowlist documented.",
        remediation="Document an egress allowlist for the MCP server (deny-by-default). See docs/mcp-server-security.",
        evidence_sources=[],
        confidence="low",
    )


def eval_mcp_injection_test_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-INJECTION-TEST-001: prompt-injection / tool-poisoning tests present."""
    applicable, _ = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("injection-test")
    matches: list[Path] = []
    for base in ("tests", "test", "."):
        d = ctx.repo_root / base
        if not d.is_dir():
            continue
        with contextlib.suppress(OSError):
            for f in d.rglob("*.py"):
                name = f.name.lower()
                is_injection = "mcp" in name and "injection" in name
                is_poison = "tool_poison" in name or "tool-poison" in name or ("poisoning" in name and "tool" in name)
                if is_injection or is_poison:
                    matches.append(f)
    if matches:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"{len(matches)} MCP prompt-injection / tool-poisoning test file(s) detected.",
            remediation="Keep the injection test corpus updated with new attack patterns.",
            evidence_sources=[str(m.resolve()) for m in matches[:3]],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no prompt-injection / tool-poisoning tests found.",
        remediation="Add tests like test_mcp_injection.py / test_tool_poisoning.py. See docs/mcp-server-security.",
        evidence_sources=[],
        confidence="low",
    )


def eval_mcp_scope_001(ctx: EvalContext) -> EvalOutcome:
    """MCP-SCOPE-001: per-tool least-privilege scope documented."""
    applicable, found = _mcp_applicable(ctx.repo_root)
    if not applicable:
        return _mcp_na("per-tool scope")
    hit = _mcp_text_signal(
        ctx.repo_root,
        found,
        ("least privilege", "least-privilege", '"scope"', "permissions", "scopes", "read-only", "readonly"),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"MCP per-tool scope / least-privilege signal detected in {hit.name}.",
            remediation="Document explicit scope per tool; avoid broad write/admin grants.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="MCP server detected but no per-tool least-privilege scope documented.",
        remediation="Document least-privilege scope per MCP tool. See docs/mcp-server-security.md.",
        evidence_sources=[],
        confidence="low",
    )


# --- PR-28: OWASP Top 10 for Agentic Applications (ASI01-10) ---------------
_AGENT_DEP_HINTS: tuple[str, ...] = (
    "langchain",
    "langgraph",
    "autogen",
    "crewai",
    "llama-index",
    "llamaindex",
    "openai-agents",
    "semantic-kernel",
    "agno",
    "pydantic-ai",
    "smolagents",
)
_AGENT_PATH_HINTS: tuple[str, ...] = ("agents", "agent.py", "agent.ts", "system_prompt", "prompts")


def _agentic_applicable(repo: Path) -> tuple[bool, list[Path]]:
    found: list[Path] = []
    for rel in ("pyproject.toml", "package.json", "requirements.txt"):
        p = repo / rel
        if p.is_file():
            with contextlib.suppress(OSError):
                text = p.read_text(encoding="utf-8", errors="replace").lower()
                if any(h in text for h in _AGENT_DEP_HINTS):
                    found.append(p)
    for rel in _AGENT_PATH_HINTS:
        p = repo / rel
        if p.exists():
            found.append(p)
    mcp_applicable, mcp_found = _mcp_applicable(repo)
    if mcp_applicable:
        found.extend(mcp_found)
    return (len(found) > 0, found)


def _agentic_na(asi: str) -> EvalOutcome:
    return EvalOutcome(
        status=ControlStatus.NOT_APPLICABLE,
        reason=f"No agentic-AI framework detected; {asi} check does not apply.",
        remediation="No action required unless this repository ships an AI agent.",
        evidence_sources=[],
        confidence="high",
    )


def _agentic_signal(
    repo: Path, found: list[Path], needles: tuple[str, ...], extra_docs: tuple[str, ...] = ()
) -> Path | None:
    scan: list[Path] = []
    for rel in ("README.md", "SECURITY.md", *extra_docs):
        p = repo / rel
        if p.is_file():
            scan.append(p)
    for p in found:
        if p.is_file() and p not in scan:
            scan.append(p)
    for p in scan:
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(n in text for n in needles):
                return p
    return None


def eval_agent_asi_goal_001(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-GOAL-001 (ASI01): goal/system-prompt version-controlled + integrity-checked."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI01 goal-manipulation")
    prompt_locations = [
        ctx.repo_root / "prompts",
        ctx.repo_root / "system_prompt.md",
        ctx.repo_root / "system_prompt.txt",
        ctx.repo_root / "SYSTEM_PROMPT.md",
    ]
    present = [p for p in prompt_locations if p.exists()]
    if present:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Version-controlled system prompt / goal definition detected ({present[0].name}).",
            remediation="Sign or hash the system prompt and verify integrity at load time (ASI01).",
            evidence_sources=[str(p.resolve()) for p in present[:2]],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no version-controlled system prompt / goal file found.",
        remediation="Store the agent goal/system prompt under version control and integrity-check it (OWASP ASI01).",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_tool_002(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-TOOL-002 (ASI02): tool allowlist + per-tool least privilege documented."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI02 tool-misuse")
    hit = _agentic_signal(
        ctx.repo_root,
        found,
        (
            "tool allowlist",
            "tool allow-list",
            "allowed tools",
            "least privilege",
            "least-privilege",
            "tool permissions",
        ),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Agent tool allowlist / least-privilege signal detected in {hit.name} (ASI02).",
            remediation="Keep the tool allowlist tight; scope each tool to least privilege.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no tool allowlist / least-privilege documentation found.",
        remediation="Document the agent tool allowlist with per-tool least privilege (OWASP ASI02).",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_memory_006(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-MEMORY-006 (ASI06): persistent-memory purge / poisoning policy documented."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI06 memory-poisoning")
    hit = _agentic_signal(
        ctx.repo_root,
        found,
        ("memory purge", "memory retention", "memory poisoning", "memory hygiene", "purge policy", "clear memory"),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Agent memory purge / poisoning policy signal detected in {hit.name} (ASI06).",
            remediation="Enforce the memory purge policy; validate writes to long-term memory.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no memory purge / poisoning policy documented.",
        remediation="Document a persistent-memory purge / poisoning-resistance policy (OWASP ASI06).",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_inter_007(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-INTER-007 (ASI07): inter-agent communication mutual authentication signal."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI07 inter-agent communication")
    hit = _agentic_signal(
        ctx.repo_root,
        found,
        ("mutual auth", "mtls", "mutual tls", "agent-to-agent auth", "signed messages", "message signing"),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Inter-agent mutual authentication signal detected in {hit.name} (ASI07).",
            remediation="Ensure all agent-to-agent channels enforce mutual authentication.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no inter-agent mutual authentication signal found.",
        remediation="Use mutual authentication (mTLS / signed messages) for inter-agent traffic (OWASP ASI07).",
        evidence_sources=[],
        confidence="low",
    )


def eval_agent_asi_confirm_009(ctx: EvalContext) -> EvalOutcome:
    """AGENT-ASI-CONFIRM-009 (ASI09): human checkpoint required for destructive operations."""
    applicable, found = _agentic_applicable(ctx.repo_root)
    if not applicable:
        return _agentic_na("ASI09 human-agent trust")
    hit = _agentic_signal(
        ctx.repo_root,
        found,
        (
            "human approval",
            "human-in-the-loop",
            "human in the loop",
            "human checkpoint",
            "requires approval",
            "manual approval",
        ),
    )
    if hit is not None:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Human-checkpoint signal for destructive operations detected in {hit.name} (ASI09).",
            remediation="Require a human checkpoint for irreversible / high-impact agent actions.",
            evidence_sources=[str(hit.resolve())],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="Agentic framework detected but no human-checkpoint signal for destructive operations found.",
        remediation="Require human approval for destructive agent operations (OWASP ASI09).",
        evidence_sources=[],
        confidence="low",
    )


# --- PR-29..32: GitHub Actions 2026 + container + scanner integrity --------
def eval_gh_egress_native_001(ctx: EvalContext) -> EvalOutcome:
    """GH-EGRESS-NATIVE-001: GitHub Actions native egress firewall policy declared."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows detected; native egress firewall check does not apply.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    needles = ("firewall:", "network-configuration", "egress-policy", "network_policy", "actions/network")
    matched: list[Path] = []
    for p in paths:
        text = _workflow_text(p).lower()
        if any(n in text for n in needles):
            matched.append(p)
    if matched:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"Native egress firewall policy declared in {len(matched)} workflow(s).",
            remediation="Keep the egress allowlist minimal; pair with Harden-Runner for defense in depth.",
            evidence_sources=[str(p.resolve()) for p in matched[:3]],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No GitHub Actions native egress firewall policy detected (preview feature, 2026 roadmap).",
        remediation="Adopt the native egress firewall (or Harden-Runner GH-EGRESS-HRN-001) to restrict runner egress.",
        evidence_sources=[],
        confidence="low",
    )


def eval_gh_wf_lockfile_001(ctx: EvalContext) -> EvalOutcome:
    """GH-WF-LOCKFILE-001: GitHub Actions workflow lockfile present (action SHA pinning)."""
    wf_dir = ctx.repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No .github/workflows directory; workflow lockfile check does not apply.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    candidates = [
        wf_dir / "lockfile.yml",
        wf_dir / "lockfile.yaml",
        wf_dir / "actions.lock",
        ctx.repo_root / ".github" / "actions.lock",
        ctx.repo_root / ".github" / "workflows.lock",
    ]
    present = [p for p in candidates if p.is_file()]
    if present:
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"GitHub Actions workflow lockfile present ({present[0].name}).",
            remediation="Regenerate the lockfile whenever action references change.",
            evidence_sources=[str(p.resolve()) for p in present[:2]],
            confidence="low",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason="No GitHub Actions workflow lockfile detected (preview feature, 2026 roadmap).",
        remediation="Adopt the workflow lockfile to pin action SHAs between runs once it reaches GA.",
        evidence_sources=[],
        confidence="low",
    )


_DISTROLESS_MARKERS: tuple[str, ...] = (
    "gcr.io/distroless",
    "cgr.dev/chainguard",
    "chainguard/",
    "wolfi-base",
    "chainguard-base",
    "scratch",
    "distroless",
)


def eval_cont_distroless_001(ctx: EvalContext) -> EvalOutcome:
    """CONT-DISTROLESS-001: container base image is distroless / minimal."""
    dockerfiles: list[Path] = []
    for name in ("Dockerfile", "Containerfile"):
        p = ctx.repo_root / name
        if p.is_file():
            dockerfiles.append(p)
    with contextlib.suppress(OSError):
        for p in ctx.repo_root.glob("**/Dockerfile"):
            if p not in dockerfiles and ".git" not in p.parts:
                dockerfiles.append(p)
    if not dockerfiles:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No Dockerfile / Containerfile detected; distroless base check does not apply.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    from_lines: list[str] = []
    for p in dockerfiles:
        with contextlib.suppress(OSError):
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip().lower()
                if stripped.startswith("from "):
                    from_lines.append(stripped)
    if not from_lines:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Dockerfile present but no FROM line parsed.",
            remediation="Ensure the Dockerfile declares a base image.",
            evidence_sources=[str(dockerfiles[0].resolve())],
            confidence="low",
        )
    final_from = from_lines[-1]
    if any(m in line for line in from_lines for m in _DISTROLESS_MARKERS):
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason="Container build uses a distroless / minimal base image (Chainguard, Wolfi, distroless, scratch).",
            remediation="Keep using minimal bases; rebuild regularly to inherit upstream CVE fixes.",
            evidence_sources=[str(p.resolve()) for p in dockerfiles[:2]],
            confidence="medium",
        )
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=f"Final base image does not appear distroless/minimal ({final_from[:80]}).",
        remediation="Consider a distroless / Chainguard / Wolfi / scratch base to reduce attack surface.",
        evidence_sources=[str(p.resolve()) for p in dockerfiles[:2]],
        confidence="low",
    )


_SCANNER_ACTION_HINTS: tuple[str, ...] = (
    "aquasecurity/trivy-action",
    "trivy-action",
    "anchore/scan-action",
    "anchore/sbom-action",
    "github/codeql-action",
    "returntocorp/semgrep",
    "semgrep/semgrep",
    "snyk/actions",
    "checkmarx",
    "gitleaks/gitleaks-action",
    "zaproxy",
    "grype",
)
_SHA_PIN_PATTERN = re.compile(r"@[0-9a-f]{40}\b")


def eval_scanner_integrity_001(ctx: EvalContext) -> EvalOutcome:
    """SCANNER-INTEGRITY-001: scanner actions pinned by SHA (post-Trivy supply-chain defense)."""
    paths = list(ctx.workflows.workflow_paths)
    if not paths:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No GitHub Actions workflows detected; scanner integrity check does not apply.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    unpinned: list[str] = []
    pinned = 0
    seen_scanner = False
    for p in paths:
        for raw_line in _workflow_text(p).splitlines():
            line = raw_line.strip()
            if "uses:" not in line:
                continue
            low = line.lower()
            if not any(h in low for h in _SCANNER_ACTION_HINTS):
                continue
            seen_scanner = True
            ref = line.split("uses:", 1)[1].strip().strip("'\"")
            if _SHA_PIN_PATTERN.search(ref):
                pinned += 1
            else:
                unpinned.append(f"{p.name}: {ref}")
    if not seen_scanner:
        return EvalOutcome(
            status=ControlStatus.NOT_APPLICABLE,
            reason="No scanner actions referenced in workflows; scanner integrity check does not apply.",
            remediation="No action required.",
            evidence_sources=[],
            confidence="high",
        )
    if unpinned:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{len(unpinned)} scanner action reference(s) not pinned by full SHA "
                f"({unpinned[0]}). Trivy attack (2026-03) showed unpinned scanner actions are a supply-chain vector."
            ),
            remediation="Pin every scanner action to a full 40-char commit SHA; verify with `gh attestation verify`.",
            evidence_sources=[str(p.resolve()) for p in paths[:3]],
            confidence="high",
        )
    return EvalOutcome(
        status=ControlStatus.PASS,
        reason=f"All {pinned} scanner action reference(s) pinned by full commit SHA.",
        remediation="Keep scanner actions SHA-pinned and re-verify attestations on each bump.",
        evidence_sources=[str(p.resolve()) for p in paths[:3]],
        confidence="medium",
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
    "GH-EGRESS-HRN-001": eval_gh_egress_hrn_001,
    "PUBLISH-OIDC-001": eval_publish_oidc_001,
    "PUBLISH-OIDC-002": eval_publish_oidc_002,
    "PUBLISH-OIDC-003": eval_publish_oidc_003,
    "SLSA-SRC-001": eval_slsa_src_001,
    "SLSA-SRC-002": eval_slsa_src_002,
    "SLSA-SRC-003": eval_slsa_src_003,
    "SLSA-SRC-004": eval_slsa_src_004,
    "SLSA-SRC-005": eval_slsa_src_005,
    # --- Cycle 2 (v6.0.0) ---
    "OSPS-SCORECARD-V6-001": eval_osps_scorecard_v6_001,
    "LLM-AI-ACT-DEV-002": eval_llm_ai_act_dev_002,
    "LLM-AI-ACT-PERF-004": eval_llm_ai_act_perf_004,
    "LLM-AI-ACT-CYBER-006": eval_llm_ai_act_cyber_006,
    "LLM-AI-ACT-CHANGE-007": eval_llm_ai_act_change_007,
    "LLM-AI-ACT-STD-008": eval_llm_ai_act_std_008,
    "LLM-AI-ACT-PMM-009": eval_llm_ai_act_pmm_009,
    "CRA-ART13-SBD-001": eval_cra_art13_sbd_001,
    "CRA-ART13-DEFAULTS-002": eval_cra_art13_defaults_002,
    "CRA-ART14-CSAF-001": eval_cra_art14_csaf_001,
    "CRA-ART14-COORD-002": eval_cra_art14_coord_002,
    "CRA-PRODUCT-CLASS-001": eval_cra_product_class_001,
    "SCA-KEV-001": eval_sca_kev_001,
    "SCA-EPSS-001": eval_sca_epss_001,
    "SLSA-SRC-006": eval_slsa_src_006,
    "SLSA-SRC-007": eval_slsa_src_007,
    "SLSA-SRC-008": eval_slsa_src_008,
    "MCP-TOOL-HASH-001": eval_mcp_tool_hash_001,
    "MCP-CONFIRM-001": eval_mcp_confirm_001,
    "MCP-EGRESS-001": eval_mcp_egress_001,
    "MCP-INJECTION-TEST-001": eval_mcp_injection_test_001,
    "MCP-SCOPE-001": eval_mcp_scope_001,
    "AGENT-ASI-GOAL-001": eval_agent_asi_goal_001,
    "AGENT-ASI-TOOL-002": eval_agent_asi_tool_002,
    "AGENT-ASI-MEMORY-006": eval_agent_asi_memory_006,
    "AGENT-ASI-INTER-007": eval_agent_asi_inter_007,
    "AGENT-ASI-CONFIRM-009": eval_agent_asi_confirm_009,
    "GH-EGRESS-NATIVE-001": eval_gh_egress_native_001,
    "GH-WF-LOCKFILE-001": eval_gh_wf_lockfile_001,
    "CONT-DISTROLESS-001": eval_cont_distroless_001,
    "SCANNER-INTEGRITY-001": eval_scanner_integrity_001,
    "GL-PIPE-007": eval_gl_pipe_007,
    "GL-PIPE-008": eval_gl_pipe_008,
    "GL-PIPE-009": eval_gl_pipe_009,
    "GL-PIPE-010": eval_gl_pipe_010,
    "GL-PIPE-011": eval_gl_pipe_011,
    "GL-PIPE-012": eval_gl_pipe_012,
    "AIBOM-PRESENT-001": eval_aibom_present_001,
    "LLM-218A-PO-001": eval_llm_218a_po_001,
    "LLM-218A-PO-002": eval_llm_218a_po_002,
    "LLM-218A-PS-001": eval_llm_218a_ps_001,
    "LLM-218A-PS-002": eval_llm_218a_ps_002,
    "LLM-218A-PW-001": eval_llm_218a_pw_001,
    "LLM-218A-PW-002": eval_llm_218a_pw_002,
    "LLM-218A-RV-001": eval_llm_218a_rv_001,
    "LLM-AI-ACT-001": eval_llm_ai_act_001,
    "LLM-AI-ACT-002": eval_llm_ai_act_002,
    "LLM-AI-ACT-003": eval_llm_ai_act_003,
    "WORM-POSTINSTALL-001": eval_worm_postinstall_001,
    "WORM-LOCKFILE-DRIFT-001": eval_worm_lockfile_drift_001,
    "WORM-PUBLISH-SCOPE-001": eval_worm_publish_scope_001,
    "AI-AGENT-001": eval_ai_agent_001,
    "AI-AGENT-002": eval_ai_agent_002,
    "AI-AGENT-003": eval_ai_agent_003,
    "AI-AGENT-004": eval_ai_agent_004,
    "AI-AGENT-005": eval_ai_agent_005,
    "AI-AGENT-006": eval_ai_agent_006,
    "AI-AGENT-007": eval_ai_agent_007,
    "AI-AGENT-008": eval_ai_agent_008,
    "AI-AGENT-009": eval_ai_agent_009,
    "AI-AGENT-010": eval_ai_agent_010,
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
    "GOV-DISC-065": eval_gov_disc_065,
    "SAST-ZIZMOR-066": eval_sast_zizmor_066,
    "SAST-POUTINE-067": eval_sast_poutine_067,
    "SAST-OSV-068": eval_sast_osv_068,
    "SAST-GITLEAKS-069": eval_sast_gitleaks_069,
    "GL-PIPE-001": eval_gl_pipe_001,
    "GL-PIPE-002": eval_gl_pipe_002,
    "GL-PIPE-003": eval_gl_pipe_003,
    "GL-PIPE-004": eval_gl_pipe_004,
    "GL-PIPE-005": eval_gl_pipe_005,
    "GL-PIPE-006": eval_gl_pipe_006,
}


def _load_iac_evaluators() -> None:
    """Register the 12 IAC-TF-* evaluators built dynamically in ``evaluators_iac``.

    Kept as a separate loader so the in-package boundary stays clean: the
    Terraform rule pack lives in its own module and this file only owns the
    final registration step (mirrors the external-evaluator loader below).
    """

    from oss_policy_kit.application.evaluators_iac import build_iac_evaluators

    for control_id, fn in build_iac_evaluators().items():
        EVALUATOR_REGISTRY.setdefault(control_id, fn)


def _load_fuzzing_evaluators() -> None:
    """Register the SEC-FUZZ-* evaluators built in ``evaluators_fuzzing``."""

    from oss_policy_kit.application.evaluators_fuzzing import build_fuzzing_evaluators

    for control_id, fn in build_fuzzing_evaluators().items():
        EVALUATOR_REGISTRY.setdefault(control_id, fn)


def _load_container_evaluators() -> None:
    """Register the CONT-RUNTIME-* + CONT-SIGN-001 evaluators built in ``evaluators_containers``."""

    from oss_policy_kit.application.evaluators_containers import build_container_evaluators

    for control_id, fn in build_container_evaluators().items():
        EVALUATOR_REGISTRY.setdefault(control_id, fn)


def _load_k8s_evaluators() -> None:
    """Register the K8S-* evaluators built in ``evaluators_k8s``."""

    from oss_policy_kit.application.evaluators_k8s import build_k8s_evaluators

    for control_id, fn in build_k8s_evaluators().items():
        EVALUATOR_REGISTRY.setdefault(control_id, fn)


def _load_iac_cfn_evaluators() -> None:
    """Register the v5.7 IAC-CFN-* evaluators built in ``evaluators_iac_cfn``."""

    from oss_policy_kit.application.evaluators_iac_cfn import build_iac_cfn_evaluators

    for control_id, fn in build_iac_cfn_evaluators().items():
        EVALUATOR_REGISTRY.setdefault(control_id, fn)


def _load_iac_pulumi_evaluators() -> None:
    """Register the v5.7 IAC-PUL-* evaluators built in ``evaluators_iac_pulumi``."""

    from oss_policy_kit.application.evaluators_iac_pulumi import build_iac_pulumi_evaluators

    for control_id, fn in build_iac_pulumi_evaluators().items():
        EVALUATOR_REGISTRY.setdefault(control_id, fn)


def _load_iac_bicep_evaluators() -> None:
    """Register the v5.7 IAC-BICEP-* evaluators built in ``evaluators_iac_bicep``."""

    from oss_policy_kit.application.evaluators_iac_bicep import build_iac_bicep_evaluators

    for control_id, fn in build_iac_bicep_evaluators().items():
        EVALUATOR_REGISTRY.setdefault(control_id, fn)


def _load_webhook_evaluators() -> None:
    """Register the v5.7 SEC-WEBHOOK-* evaluators built in ``evaluators_webhook``."""

    from oss_policy_kit.application.evaluators_webhook import build_webhook_evaluators

    for control_id, fn in build_webhook_evaluators().items():
        EVALUATOR_REGISTRY.setdefault(control_id, fn)


_load_iac_evaluators()
_load_fuzzing_evaluators()
_load_container_evaluators()
_load_k8s_evaluators()
_load_iac_cfn_evaluators()
_load_iac_pulumi_evaluators()
_load_iac_bicep_evaluators()
_load_webhook_evaluators()


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
