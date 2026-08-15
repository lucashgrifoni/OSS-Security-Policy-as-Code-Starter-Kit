"""Shared imports, constants, helpers, and EvalContext for the evaluators package.

Extracted verbatim from the former monolithic ``evaluators.py`` (M8). Re-exports
every top-level name via ``__all__`` so family modules can ``from ._shared import *``
and keep identical behavior with no body changes.
"""

from __future__ import annotations

import contextlib
import importlib.metadata
import json
import math
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, NamedTuple, cast

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
    as_mapping,
    strip_yaml_comments,
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
from oss_policy_kit.application.evidence_loading import load_evidence_schema
from oss_policy_kit.application.evidence_placeholders import has_placeholder_values, is_placeholder_digest
from oss_policy_kit.application.input_limits import (
    BAD_INPUT_ERRORS,
    MAX_JSON_DEPTH,
    MAX_SARIF_BYTES,
    bad_input_detail,
    max_json_nesting_depth,
    oversize_reason,
)
from oss_policy_kit.application.input_limits import (
    _advance_json_string as _advance_json_string_impl,
)
from oss_policy_kit.application.insights_evidence import InsightsEvidence
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome, EvidenceCollectionMethod, utc_now
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.gitlab_ci_parser import GitLabCiAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

_DOT_MCP_JSON = ".mcp.json"
_GITHUB_DIR = ".github"
_KIT_DIR = ".oss-policy-kit"
_MAILTO = "mailto:"
_MCP_JSON = "mcp.json"
_PACKAGE_JSON = "package.json"
_PYPROJECT_TOML = "pyproject.toml"
_README_MD = "README.md"
_REQUIREMENTS_TXT = "requirements.txt"
_SECURITY_AT = "security@"
_SECURITY_MD = "SECURITY.md"

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
_EVIDENCE_MAX_AGE_DAYS: int = 90
_EVIDENCE_EXPIRY_WARN_DAYS: int = 14
_KEYWORD_CI_SIGNAL_WARN = (
    "Signal detected via keyword match; verify in CI execution logs or add platform evidence for hard-gate use."
)
_SUPPLEMENTAL_SIGNAL_WARN = (
    "Signal came from supplemental evidence only; "
    "prefer in-repo workflow evidence or API-backed collection for hard gates."
)
_REQUIRED_BRANCH_PROTECTION_FLAGS = (
    "require_pull_request_reviews",
    "dismiss_stale_reviews",
    "require_status_checks",
    "enforce_admins",
    "restrict_force_push",
)


def _branch_protection_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-branch-protection.schema.json")


def _rulesets_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-github-rulesets.schema.json")


def _environment_protection_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-github-environment-protection.schema.json")


def _secret_scanning_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-github-secret-scanning.schema.json")


def _release_immutability_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-github-release-immutability.schema.json")


def _actions_policy_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-github-actions-policy.schema.json")


def _azure_branch_policies_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-azure-branch-policies.schema.json")


def _azure_pipeline_governance_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-azure-pipeline-governance.schema.json")


def _azure_sbom_artifact_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-azure-sbom-artifact.schema.json")


def _azure_provenance_artifact_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-azure-provenance-artifact.schema.json")


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
    return load_evidence_schema("evidence-aws-codebuild-project.schema.json")


def _aws_codepipeline_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-aws-codepipeline.schema.json")


def _aws_sbom_artifact_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-aws-sbom-artifact.schema.json")


def _aws_provenance_artifact_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-aws-provenance-artifact.schema.json")


def _github_provenance_artifact_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-github-provenance-artifact.schema.json")


def _gitlab_mr_rules_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-gitlab-mr-rules.schema.json")


def _audit_log_streaming_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-audit-log-streaming.schema.json")


def _runner_groups_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-runner-groups.schema.json")


def _release_archival_policy_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-release-archival-policy.schema.json")


def _ai_agent_baseline_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-ai-agent-baseline.schema.json")


def _disclosure_policy_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-disclosure-policy.schema.json")


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
    #: Parsed, structurally validated Security Insights evidence for the target (ADR-033).
    #: Default None: only populated when ``evaluate --use-insights-evidence`` is set. When
    #: None, no control consumes self-reported Insights signals (clone-only verdicts stand).
    insights_evidence: InsightsEvidence | None = None
    #: ADR-028 (opt-in, default off): when True, a control whose pass is anchored on a
    #: verified attestation record (e.g. PROV-VERIFY-061) resolves to ATTESTED instead of
    #: PASS. Only set by ``evaluate --enable-attested``; never relaxes a FAIL/MRR outcome.
    enable_attested: bool = False


def insights_self_attested_outcome(
    ctx: EvalContext,
    *,
    control_label: str,
    remediation: str,
) -> EvalOutcome | None:
    """Lift a clone-only ``manual-review-required`` disclosure verdict to a
    ``SELF_ATTESTED`` PASS when the target's Security Insights file self-declares an
    inbound vulnerability-reporting channel (ADR-033, opt-in via ``--use-insights-evidence``).

    Returns ``None`` when the wiring is off (no evidence in ``ctx``) or the file
    declares no channel — the caller then keeps its clone-only verdict.

    Call this ONLY on a ``manual-review-required`` path. A self-report must never
    override a deterministic ``FAIL`` and must never relabel an evidence-backed
    ``PASS``; the allowlisted controls (GOV-DISC-013, CRA-ART14-COORD-002,
    GOV-DISC-065) consult it only where the clone yields no signal.
    """

    evidence = ctx.insights_evidence
    if evidence is None or not evidence.declares_vulnerability_reporting_channel():
        return None
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason=(
            f"{control_label} self-attested via the project's Security Insights file "
            f"({evidence.source_rel}): accepts-vulnerability-reports is declared with a "
            "reporting channel. Provenance: self-reported — NOT independently verified from "
            "the clone, consumed only because --use-insights-evidence is set."
        ),
        remediation=remediation,
        evidence_sources=[f"{evidence.source_rel} (self-reported)"],
        confidence="low",
        extra={"provenance": "self-reported", "insights_source": evidence.source_rel},
    )


def _exists_ci_readme(repo: Path) -> bool:
    p = repo / _GITHUB_DIR / "workflows" / _README_MD
    return p.is_file()


def _has_changelog(repo: Path) -> bool:
    names = [
        repo / "CHANGELOG.md",
        repo / "CHANGES.md",
        repo / "docs" / "CHANGELOG.md",
        repo / _GITHUB_DIR / "RELEASE.md",
    ]
    return any(p.is_file() for p in names)


# Build-instructions signal (OSPS-DO-07): a build-tool entrypoint, a dedicated
# INSTALL file, or a build/install/development section heading in a doc.
_BUILD_TOOL_FILES = (
    "Makefile",
    "makefile",
    "GNUmakefile",
    "Taskfile.yml",
    "Taskfile.yaml",
    "justfile",
    "Justfile",
    "noxfile.py",
    "tox.ini",
    "Earthfile",
    "build.sh",
    "INSTALL",
    "INSTALL.md",
)
_BUILD_DOC_CANDIDATES = (
    "README.md",
    "README.rst",
    "README.txt",
    "CONTRIBUTING.md",
    "docs/INSTALL.md",
    "docs/building.md",
    "docs/build.md",
    "docs/development.md",
)
_BUILD_HEADING_PATTERN = re.compile(
    r"(?im)^\s{0,3}#{1,6}\s*"
    r"(building|build from source|installation|install(?:ing| from source)?|"
    r"from source|compiling|compile|development setup|getting started|setup|how to build)\b"
)


def _has_build_instructions(repo: Path) -> bool:
    """Signal (OSPS-DO-07): does the clone document how to build from source?

    True when a build-tool entrypoint exists (Makefile/Taskfile/justfile/nox/tox/...),
    a dedicated INSTALL file is present, or a README/CONTRIBUTING/docs file carries a
    build/install/development section heading. Filesystem-only, best-effort (signal grade).
    """
    if any((repo / name).is_file() for name in _BUILD_TOOL_FILES):
        return True
    candidates = [repo / rel for rel in _BUILD_DOC_CANDIDATES]
    candidates.append(repo / _GITHUB_DIR / "CONTRIBUTING.md")
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _BUILD_HEADING_PATTERN.search(text):
            return True
    return False


def _has_license(repo: Path) -> bool:
    for p in repo.iterdir():
        if not p.is_file():
            continue
        n = p.name.lower()
        if n.startswith("license") or n == "copying":
            return True
    return False


def _has_codeowners(repo: Path) -> bool:
    return (repo / "CODEOWNERS").is_file() or (repo / _GITHUB_DIR / "CODEOWNERS").is_file()


def _read_security(repo: Path) -> str | None:
    for name in (_SECURITY_MD, "security.md"):
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


_CODEQL_ACTION_PATTERNS = (
    "github/codeql-action/analyze",
    "github/codeql-action/autobuild",
    "github/codeql-action/init",
)


def _gov_disc_013_private_reporting_signals(lower: str) -> bool:
    """Return True when SECURITY.md text strongly suggests a private reporting path."""

    if any(
        k in lower
        for k in (
            _SECURITY_AT,
            _MAILTO,
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
            _SECURITY_AT,
            _MAILTO,
        )
    ):
        return True
    disclosure_en = "responsible disclosure" in lower or "coordinated disclosure" in lower
    if disclosure_en and any(x in lower for x in ("privat", "privad", _MAILTO, _SECURITY_AT, "canal")):
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
    return div_pt and any(x in lower for x in ("privad", "privat", "canal", "email", _MAILTO, _SECURITY_AT))


def _github_workflow_raw_suggests_release_or_deploy(raw: str) -> bool:
    """Whether a workflow looks like it releases or deploys, from its text.

    Comments blanked: this decides applicability for BUILD-SBOM-QUAL-003, which the derived
    sweep caught moving FAIL -> UNKNOWN on three platforms when a single comment was added.
    """

    stripped = strip_yaml_comments(raw)
    lower = stripped.lower()
    if re.search(r"(^|\n)\s*release\s*:", stripped) or re.search(r"\bon\s*:\s*release\b", lower):
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
    for m in re.finditer(r"\$\{\{\s*secrets\.(\w+)\s*\}\}", text):
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


def _iter_workflow_jobs(doc: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(job_name, job_dict)`` for every job in a workflow document."""

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_name, job in jobs.items():
        if isinstance(job, dict):
            yield str(job_name), job


def _job_uses_locations(job_name: str, job: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return ``(job_name, step_label, uses)`` tuples for one job (job-level + step-level)."""

    out: list[tuple[str, str, str]] = []
    ju = job.get("uses")
    if isinstance(ju, str):
        out.append((job_name, "job", ju.strip()))
    steps = job.get("steps")
    if not isinstance(steps, list):
        return out
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        su = step.get("uses")
        if not isinstance(su, str):
            continue
        label = step.get("name") if isinstance(step.get("name"), str) else None
        out.append((job_name, label or f"step[{idx}]", su.strip()))
    return out


def _iter_structured_workflow_uses_with_location(
    doc: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """Return ``(job_name, step_label, uses)`` for every structural ``uses:`` string.

    ``step_label`` is ``job`` when the ``uses`` is at the job level, or the step ``name``/``uses``
    identifier when at the step level. This lets evaluators report exact workflow locations
    without re-parsing raw text.
    """

    out: list[tuple[str, str, str]] = []
    for job_name, job in _iter_workflow_jobs(doc):
        out.extend(_job_uses_locations(job_name, job))
    return out


def _iter_structured_workflow_uses_strings(doc: dict[str, Any]) -> list[str]:
    return [uses for _job, _label, uses in _iter_structured_workflow_uses_with_location(doc)]


def _reusable_workflow_uses_from_strings(uses_values: list[str]) -> list[str]:
    return [u for u in uses_values if ".github/workflows" in u.lower()]


def _parse_branch_protection_evidence(evidence: Path) -> EvalOutcome:
    """Validate and interpret a branch-protection evidence file."""
    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            # M-002: `str(OSError)` appends the filename it was handed, and by here that
            # filename is the caller's fully resolved path -- so `{exc}` would print the
            # adopter's home directory and OS account name in a reason the report renders
            # verbatim. `bad_input_detail` is the project's path-free rendering of a read
            # failure. This reader feeds PLAT-BRPROT-015 and all four SLSA-SRC-* controls,
            # so the leak had five ways out.
            reason=f"Branch protection evidence file is unreadable or invalid JSON: {bad_input_detail(exc)}.",
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
        # ADR-045: the two branches above already answer `manual-review-required` for a file
        # this reader cannot use; a schema violation is the same kind of fact and now agrees
        # with them. `--fail-on degraded` is how an operator makes it block.
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
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
_GITIGNORE_SECRET_FRAGMENTS = (".env", "*.pem", "*.key", "secrets.", "credentials")
_PIN_REQ_PIN = re.compile(r"==\s*[0-9A-Za-z._-]+")


def _lockfile_has_content(path: Path) -> bool:
    """True when a lockfile actually locks something.

    ``is_file()`` was the whole test, so a zero-byte ``uv.lock`` -- what an interrupted
    ``uv lock`` or a ``touch`` leaves behind -- satisfied SEC-PINLOCK-052 and reported
    "Dependency lockfile or pinned requirements detected". An empty file pins nothing; the
    control exists to establish that versions are fixed, and an empty file establishes the
    opposite. Content is required, not just presence.
    """

    if not path.is_file():
        return False
    with contextlib.suppress(OSError):
        return bool(path.read_text(encoding="utf-8", errors="replace").strip())
    return False


def _python_lock_or_pins(repo: Path) -> bool:
    if any(_lockfile_has_content(repo / n) for n in ("poetry.lock", "Pipfile.lock", "uv.lock")):
        return True
    if any(_lockfile_has_content(repo / n) for n in ("requirements.lock", "requirements-lock.txt")):
        return True
    req = repo / _REQUIREMENTS_TXT
    if req.is_file():
        body = ""
        with contextlib.suppress(OSError):
            body = req.read_text(encoding="utf-8", errors="replace")
        return bool(_PIN_REQ_PIN.search(body))
    return False


def _parse_evidence_date(value: str) -> date | None:
    s = value.strip()
    if len(s) >= 10:
        with contextlib.suppress(ValueError):
            return date.fromisoformat(s[:10])
    with contextlib.suppress(ValueError):
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    return None


def _digest_invalid_not_evaluated(evidence: Path) -> EvalOutcome:
    return EvalOutcome(
        status=ControlStatus.NOT_EVALUATED,
        reason=_INVALID_DIGEST_REASON,
        remediation=("Populate digest_sha256 with the real 64-character hex SHA-256 of the artifact/SBOM/attestation."),
        evidence_sources=[str(evidence.resolve())],
        confidence="low",
    )


def _digest_gate_outcome(evidence: Path, digests: Iterable[str]) -> EvalOutcome | None:
    """Refuse the first digest that is a template or is not a real SHA-256; ``None`` when all pass.

    The two refusals stay apart on purpose. A placeholder digest is a scaffold nobody filled in,
    so a human has to go and look (``manual-review-required``); a malformed one is evidence the
    kit cannot interpret at all, and claiming anything about it would be a guess
    (``not-evaluated``). Collapsing them would tell an adopter the same thing about two quite
    different problems.

    Four artifact-attestation controls -- SBOM and provenance, on AWS and on Azure -- ran
    identical copies of this loop. One copy is one place to keep the distinction correct.
    """

    for digest in digests:
        if is_placeholder_digest(digest):
            return _digest_placeholder_manual_review(evidence)
        if not _is_valid_sha256_digest(digest):
            return _digest_invalid_not_evaluated(evidence)
    return None


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
    evidence = ctx.repo_root / _KIT_DIR / "evidence" / "azure-pipeline-governance.json"
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


_SCORECARD_MIN_SCORE = 5.0
_DOCKER_FROM_RE = re.compile(r"^FROM\s+(\S+)", re.MULTILINE)


def _find_dockerfiles(repo: Path) -> list[Path]:
    from oss_policy_kit.application.evaluators_common import find_dockerfiles

    return find_dockerfiles(repo)


_USER_RE = re.compile(r"^\s*USER\s+(?!0\b)(?!root\b)(\S+)", re.MULTILINE | re.IGNORECASE)
_ROOT_USER_RE = re.compile(r"^\s*USER\s+(root|0)\s*$", re.MULTILINE | re.IGNORECASE)
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


def _org_mfa_schema() -> dict[str, Any]:
    return load_evidence_schema("evidence-org-mfa-posture.schema.json")


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


def _detect_spdx_version(sample: str) -> tuple[str, str] | None:
    """Detect SPDX 3.x JSON-LD or SPDX 2.x JSON/tag-value; return ``("spdx", version)`` or None."""

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
        m = re.search(r'"specVersion"\s*:\s*"(\d+\.\d+)"', sample)
        return ("cyclonedx", m.group(1) if m else None)
    spdx = _detect_spdx_version(sample)
    if spdx is not None:
        return spdx
    return (_detect_sbom_format(content), None)


_BSI_HASH_PATTERN = re.compile(r'"(hashes|sha\d+|checksums?)"', re.IGNORECASE)
_BSI_PURL_PATTERN = re.compile(r'"(purl|packageURL)"', re.IGNORECASE)
_BSI_CPE_PATTERN = re.compile(r'"(cpe|cpe22Type|cpe23Type)"')
_BSI_LICENSE_PATTERN = re.compile(r'"(licenses?|licenseConcluded|licenseDeclared)"', re.IGNORECASE)
_BSI_SUPPLIER_PATTERN = re.compile(r'"(supplier|originator|publisher|author)"', re.IGNORECASE)
_BSI_VULN_PATTERN = re.compile(r'"vulnerabilities"\s*:\s*\[')


def _bsi_v2_1_in_scope(fmt: str | None, version: str | None) -> bool:
    """True when the SBOM format/version is in scope for BSI TR-03183-2 v2.1.0 (CycloneDX 1.6+, SPDX 3.0+)."""

    if fmt not in {"cyclonedx", "spdx"}:
        return False
    if fmt == "cyclonedx":
        if version is None:
            return False
        try:
            major, minor = version.split(".", 1)
            if int(major) < 1 or (int(major) == 1 and int(minor) < 6):
                return False
        except (ValueError, AttributeError):
            return False
    return not (fmt == "spdx" and (version is None or not version.startswith("3.")))


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

    if not _bsi_v2_1_in_scope(fmt, version):
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

    for rel in (_SECURITY_MD, ".github/SECURITY.md", "docs/SECURITY.md"):
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
    now = utc_now()
    age = (now - dt).days
    if age < 0:
        return "future"
    if age <= max_age_days:
        return "fresh"
    return "stale"


_SELF_HOSTED_PATTERN = re.compile(r"runs-on\s*:\s*(.+)", re.IGNORECASE)


def _workflow_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _classify_self_hosted_runner(text: str) -> tuple[bool, bool]:
    """Return ``(is_self_hosted, is_ephemeral)`` from workflow text via the runner pattern.

    Comments are blanked first: GH-RUNNER-062 moved a repository off PASS because a
    ``# runs-on: self-hosted`` line someone had commented out looked like a self-hosted
    runner to it. Which runner a job uses is decided by the line that runs, not the one
    beside it.
    """

    text = strip_yaml_comments(text)
    is_self = False
    is_ephemeral = False
    for match in _SELF_HOSTED_PATTERN.finditer(text):
        line = match.group(1).strip().lower()
        if "self-hosted" in line:
            is_self = True
            if "ephemeral" in line:
                is_ephemeral = True
    return is_self, is_ephemeral


def _self_hosted_workflow_paths(repo: Path) -> tuple[list[Path], list[Path]]:
    """Return (all_self_hosted_paths, paths_marked_ephemeral) by raw scanning workflow YAMLs."""

    wf_dir = repo / _GITHUB_DIR / "workflows"
    if not wf_dir.is_dir():
        return [], []
    all_self: list[Path] = []
    ephemeral_self: list[Path] = []
    for yml in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
        text = _workflow_text(yml)
        if not text:
            continue
        is_self, is_ephemeral = _classify_self_hosted_runner(text)
        if is_self:
            all_self.append(yml)
            if is_ephemeral:
                ephemeral_self.append(yml)
    return all_self, ephemeral_self


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


_SAST_SEMGREP_EVIDENCE_FILENAME = "sast-semgrep.json"
_SAST_SEMGREP_SCHEMA_PREFIX = "oss-policy-kit/evidence/sast-semgrep/"
# Re-exported from the module that owns defensive reading, so SARIF and every other
# user-controlled document are measured by one scanner against one budget. Two copies
# of a depth guard is two things to keep in step, and the SARIF copy was the only one
# any loader actually consulted.
_MAX_SARIF_JSON_DEPTH = MAX_JSON_DEPTH
_advance_json_string = _advance_json_string_impl
_max_json_nesting_depth = max_json_nesting_depth


def _load_sarif_runs(sarif_path: Path) -> tuple[list[Any] | None, str | None]:
    """Read + validate a SARIF file, returning ``(runs_list, None)`` or ``(None, error)``.

    Every error string here becomes an evaluator ``reason``, so none of them may embed the
    exception object: ``str(OSError)`` carries the filename it was handed (M-002).
    ``bad_input_detail`` is the one place allowed to decide how a bad file is described.
    """

    oversize = oversize_reason(sarif_path, MAX_SARIF_BYTES, label="SARIF")
    if oversize is not None:
        return None, oversize
    try:
        raw = sarif_path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"Could not read SARIF file: {bad_input_detail(exc)}."
    except UnicodeDecodeError as exc:
        return None, f"Could not decode SARIF file as UTF-8: {bad_input_detail(exc)}."
    if _max_json_nesting_depth(raw) > _MAX_SARIF_JSON_DEPTH:
        return None, "Could not parse SARIF JSON: document is too deeply nested."
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Could not parse SARIF JSON: {bad_input_detail(exc)}."
    except RecursionError:
        return None, "Could not parse SARIF JSON: document is too deeply nested."
    # This condition used to be one expression, and it could not protect the test it guarded:
    # when *doc* was not a mapping, `not isinstance(...)` short-circuited the `or` and thereby
    # FORCED `"runs" not in doc` to run against the very non-mapping it had just detected --
    # TypeError for a number or null, and for a string a silent substring test that fell
    # through to `.get`. A non-string `$schema` raised on `.endswith` before the `and` was
    # reached at all. Every one of those is exit 3 with no report, from files that third-party
    # tools and adopter `jq` glue produce: `jq -s '.[0]' *.sarif` over an empty glob writes
    # literally `null`. Four controls read this, across eight shipped profiles, and
    # `evaluate-many` aborted the whole fleet on the first bad file.
    if not isinstance(doc, dict):
        return None, f"SARIF file root must be a JSON object, not a {type(doc).__name__}."
    schema = doc.get("$schema")
    declares_sarif_schema = isinstance(schema, str) and schema.endswith("sarif-schema-2.1.0.json")
    if not declares_sarif_schema and "runs" not in doc:
        # Accept SARIF docs without an explicit $schema; just require the runs[] array.
        return None, "SARIF file missing top-level 'runs' array."
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return None, "SARIF 'runs' is not an array."
    return runs, None


def _sarif_rule_levels(run: dict[str, Any]) -> dict[str, str]:
    """Map ``ruleId -> defaultConfiguration.level`` for one SARIF run."""

    rule_levels: dict[str, str] = {}
    # `(x or {}).get(...)` reads like a null-safe walk and is not one: `or` substitutes only
    # for a FALSY value, so `tool: "semgrep"` -- a truthy string -- reached `.get` and raised.
    rules = as_mapping(as_mapping(as_mapping(run).get("tool")).get("driver")).get("rules") or []
    if not isinstance(rules, list):
        return rule_levels
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rid = rule.get("id")
        if not isinstance(rid, str):
            continue
        default_level = as_mapping(rule.get("defaultConfiguration")).get("level")
        if isinstance(default_level, str):
            rule_levels[rid] = default_level
    return rule_levels


def _count_sarif_run(run: dict[str, Any], rule_levels: dict[str, str], counts: dict[str, int]) -> None:
    """Tally one run's result levels into ``counts`` (in place)."""

    results = run.get("results") or []
    if not isinstance(results, list):
        return
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


def _parse_sarif_findings(
    sarif_path: Path,
) -> tuple[dict[str, int] | None, str | None]:
    """Return ({"error": int, "warning": int, "note": int, "none": int}, None)
    on success, or (None, error_message) on parse failure.

    SARIF 2.1.0 result-level levels are: error, warning, note, none. When a
    result omits ``level``, the rule's ``defaultConfiguration.level`` applies
    (per the SARIF spec). Missing both is treated as ``warning`` per the spec.
    """

    runs, err = _load_sarif_runs(sarif_path)
    if err is not None or runs is None:
        return None, err
    counts: dict[str, int] = {"error": 0, "warning": 0, "note": 0, "none": 0}
    for run in runs:
        if isinstance(run, dict):
            _count_sarif_run(run, _sarif_rule_levels(run), counts)
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


def _iter_sarif_results(doc: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield each ``result`` dict across all runs of a SARIF document."""

    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results") or []
        if not isinstance(results, list):
            continue
        for result in results:
            if isinstance(result, dict):
                yield result


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
    oversize = oversize_reason(sarif_path, MAX_SARIF_BYTES, label="SARIF")
    if oversize is not None:
        return None, oversize
    try:
        raw = sarif_path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"Could not read SARIF file: {bad_input_detail(exc)}."
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Could not parse SARIF JSON: {bad_input_detail(exc)}."
    if not isinstance(doc, dict):
        return None, "SARIF file is not a JSON object."
    runs = doc.get("runs") or []
    if not isinstance(runs, list):
        return None, "SARIF 'runs' is not an array."
    counts: dict[str, int] = dict.fromkeys(_ZIZMOR_SEVERITY_KEYS, 0)
    for result in _iter_sarif_results(doc):
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


def _scan_gitlab_pipelines(ctx: EvalContext, hints: tuple[str, ...]) -> list[Path]:
    """Return GitLab pipeline files whose text contains any of ``hints`` (case-insensitive).

    Comments are blanked first. GL-PIPE-012 granted a PASS -- "pipeline(s) document artifact
    retention / signing posture" -- for a pipeline whose only mention of `cosign` was a note
    saying it had not been set up yet. GL-PIPE-009 reads through the same scanner.
    """

    matched: list[Path] = []
    for p in ctx.gitlab_ci.pipeline_paths:
        with contextlib.suppress(OSError):
            text = strip_yaml_comments(p.read_text(encoding="utf-8", errors="replace")).lower()
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


_HARDEN_RUNNER_PATTERNS: tuple[str, ...] = (
    "step-security/harden-runner",
    "stepsecurity/harden-runner",
)
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


def _scan_readme_for_section(repo: Path, headings: tuple[str, ...]) -> Path | None:
    for rel in (_SECURITY_MD, _README_MD, ".github/SECURITY.md", "docs/SECURITY.md"):
        p = repo / rel
        if not p.is_file():
            continue
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(h in text for h in headings):
                return p
    return None


def _scan_for_llm_sdks(repo: Path) -> Path | None:
    for rel in (_REQUIREMENTS_TXT, _PYPROJECT_TOML, _PACKAGE_JSON, "Pipfile", "poetry.lock"):
        p = repo / rel
        if not p.is_file():
            continue
        with contextlib.suppress(OSError):
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            if any(sdk in text for sdk in _LLM_SDK_HINTS):
                return p
    return None


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
    _MCP_JSON,
    "mcp.config.json",
    _DOT_MCP_JSON,
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


def _is_ai_agent_text_file(p: Path) -> bool:
    """True for a regular file not inside a skipped directory."""

    return p.is_file() and not any(part in _AI_AGENT_SKIP_DIRS for part in p.parts)


def _iter_ai_agent_text_files(repo: Path) -> list[Path]:
    found: list[Path] = []
    for pat in _AI_AGENT_TEXT_PATTERNS:
        with contextlib.suppress(OSError):
            for p in repo.rglob(pat):
                if _is_ai_agent_text_file(p):
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
    return ctx.repo_root / _KIT_DIR / "evidence" / "ai-agent" / filename


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


def _read_first_existing(repo: Path, relpaths: tuple[str, ...]) -> tuple[Path | None, str]:
    """Return ``(path, lowercased_text)`` for the first readable file, else ``(None, "")``."""
    for rel in relpaths:
        p = repo / rel
        if p.is_file():
            with contextlib.suppress(OSError):
                return p, p.read_text(encoding="utf-8", errors="replace").lower()
    return None, ""


def _load_ai_system_doc(ctx: EvalContext) -> tuple[dict[str, Any] | None, Path]:
    p = ctx.repo_root / _KIT_DIR / "evidence" / "ai-system-technical-doc.json"
    if not p.is_file():
        return None, p
    with contextlib.suppress(OSError, UnicodeDecodeError, json.JSONDecodeError):
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


_OSV_SARIF_RELPATH = ".oss-policy-kit/evidence/sast/osv-scanner.sarif.json"


def _safe_float(raw: Any) -> float | None:
    """Coerce a value to float, returning None for None / non-numeric / non-finite input.

    A non-finite value (``inf``/``nan``, e.g. from a SARIF ``epss_score: 1e400`` or
    ``"NaN"``) must not survive: ``inf`` would always clear an EPSS/CVSS threshold and
    ``nan`` compares false to every threshold, silently warping the KEV/high-EPSS
    classification. Mirrors ``finding_sarif._safe_float``.
    """

    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _classify_epss_kev_result(
    result: Any, epss_threshold: float, cvss_threshold: float
) -> tuple[str | None, str | None]:
    """Return ``(kev_ident, high_epss_ident)`` for one SARIF result (each None when not applicable)."""

    if not isinstance(result, dict):
        return None, None
    props = result.get("properties")
    if not isinstance(props, dict):
        return None, None
    ident = str(result.get("ruleId") or props.get("cve") or props.get("id") or "finding")
    kev_flag = props.get("kev")
    kev_str = kev_flag.strip().lower() if isinstance(kev_flag, str) else ""
    is_kev = kev_flag in (True, 1) or kev_str in {"true", "yes", "1"}
    epss_val = _safe_float(props.get("epss_score", props.get("epss")))
    cvss_val = _safe_float(props.get("cvss_score", props.get("security-severity")))
    is_high_epss = (
        epss_val is not None and epss_val >= epss_threshold and (cvss_val is None or cvss_val >= cvss_threshold)
    )
    return (ident if is_kev else None), (ident if is_high_epss else None)


class SarifEpssKevScan(NamedTuple):
    """What one pass over an OSV SARIF could establish about KEV / EPSS.

    ``saw_kev_property`` and ``saw_epss_property`` exist because an empty ``kev`` list
    has two completely different meanings, and the caller was reading both as the
    reassuring one: "enrichment ran and flagged nothing" versus "this SARIF carries no
    enrichment at all". Plain ``osv-scanner --format sarif`` emits no ``properties.kev``,
    so the second case is the common one -- and the kit was answering it with
    PASS / confidence=high / assurance=evidence-backed on a file containing Log4Shell.

    Errors keep index 2 so ``scan(...)[2]`` still reads the error.
    """

    kev: list[str]
    high_epss: list[str]
    error: str | None
    saw_kev_property: bool = False
    saw_epss_property: bool = False


def _result_carries_enrichment(result: Any) -> tuple[bool, bool]:
    """Whether one SARIF result carries a KEV / an EPSS property at all, any value."""

    if not isinstance(result, dict):
        return False, False
    props = result.get("properties")
    if not isinstance(props, dict):
        return False, False
    return "kev" in props, ("epss_score" in props or "epss" in props)


def _scan_sarif_epss_kev(
    sarif_path: Path, *, epss_threshold: float = 0.5, cvss_threshold: float = 7.0
) -> SarifEpssKevScan:
    """Scan SARIF ``result.properties`` for KEV flags and high-EPSS findings."""
    try:
        doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    except BAD_INPUT_ERRORS as exc:
        return SarifEpssKevScan([], [], f"Could not read SARIF: {bad_input_detail(exc)}")
    if not isinstance(doc, dict):
        return SarifEpssKevScan([], [], "SARIF top-level is not an object.")
    kev: list[str] = []
    high_epss: list[str] = []
    saw_kev = False
    saw_epss = False
    for result in _iter_sarif_results(doc):
        has_kev, has_epss = _result_carries_enrichment(result)
        saw_kev = saw_kev or has_kev
        saw_epss = saw_epss or has_epss
        kev_id, high_id = _classify_epss_kev_result(result, epss_threshold, cvss_threshold)
        if kev_id is not None:
            kev.append(kev_id)
        if high_id is not None:
            high_epss.append(high_id)
    return SarifEpssKevScan(kev, high_epss, None, saw_kev, saw_epss)


def _branch_protection_evidence(ctx: EvalContext) -> tuple[dict[str, Any] | None, Path]:
    p = ctx.repo_root / _KIT_DIR / "evidence" / "branch-protection.json"
    if not p.is_file():
        return None, p
    with contextlib.suppress(OSError, UnicodeDecodeError, json.JSONDecodeError):
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return cast(dict[str, Any], data), p
    return None, p


_MCP_CONFIG_FILES: tuple[str, ...] = (_MCP_JSON, _DOT_MCP_JSON, "mcp_server.json", "server.json")
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
    for rel in (_PYPROJECT_TOML, _PACKAGE_JSON, _REQUIREMENTS_TXT):
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


def _mcp_text_signal(repo: Path, found: list[Path], needles: tuple[str, ...]) -> Path | None:
    scan: list[Path] = list(found)
    for rel in (_README_MD, _SECURITY_MD, "docs/mcp-server-security.md", _MCP_JSON, _DOT_MCP_JSON):
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
    for rel in (_PYPROJECT_TOML, _PACKAGE_JSON, _REQUIREMENTS_TXT):
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
    for rel in (_README_MD, _SECURITY_MD, *extra_docs):
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


_DISTROLESS_MARKERS: tuple[str, ...] = (
    "gcr.io/distroless",
    "cgr.dev/chainguard",
    "chainguard/",
    "wolfi-base",
    "chainguard-base",
    "scratch",
    "distroless",
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

__all__ = [
    "Any",
    "AwsCiAnalysis",
    "AzurePipelineAnalysis",
    "Callable",
    "ControlStatus",
    "Draft202012Validator",
    "EvalContext",
    "EvalOutcome",
    "EvidenceCollectionMethod",
    "GitLabCiAnalysis",
    "NO_AWS_BUILDSPEC_REASON",
    "NO_AZURE_PIPELINES_REASON",
    "Path",
    "ScorecardBundle",
    "UTC",
    "ValidationError",
    "WorkflowAnalysis",
    "_AGENT_DEP_HINTS",
    "_AGENT_PATH_HINTS",
    "_AI_AGENT_HARDCODED_PROMPT_HINTS",
    "_AI_AGENT_IDENTITY_ANTIPATTERNS",
    "_AI_AGENT_IDENTITY_HINTS",
    "_AI_AGENT_MODEL_HINTS",
    "_AI_AGENT_PINNED_MODEL_RE",
    "_AI_AGENT_PROMPT_DIRS",
    "_AI_AGENT_RATE_LIMIT_HINTS",
    "_AI_AGENT_SKIP_DIRS",
    "_AI_AGENT_TEST_PATTERNS",
    "_AI_AGENT_TEXT_PATTERNS",
    "_AI_AGENT_TOOL_ALLOWLIST_PATHS",
    "_AI_AGENT_TOOL_WILDCARD_HINTS",
    "_AI_SECURITY_HEADINGS",
    "_AUDIT_STREAM_SIGNAL_KEYWORDS",
    "_AUDIT_STREAM_SIGNAL_PATHS",
    "_AZURE_BP_SUPPORT_KEYS",
    "_AZURE_GOV_SUPPORT_KEYS",
    "_BSI_CPE_PATTERN",
    "_BSI_HASH_PATTERN",
    "_BSI_LICENSE_PATTERN",
    "_BSI_PURL_PATTERN",
    "_BSI_SUPPLIER_PATTERN",
    "_BSI_VULN_PATTERN",
    "_CODEQL_ACTION_PATTERNS",
    "_COMMIT_SIGNATURE_HINTS",
    "_DIGEST_PLACEHOLDER_REASON",
    "_DISCLOSURE_SLA_KEYWORDS",
    "_DISTROLESS_MARKERS",
    "_DOCKER_FROM_RE",
    "_EVIDENCE_EXPIRY_WARN_DAYS",
    "_EVIDENCE_MAX_AGE_DAYS",
    "_GITIGNORE_SECRET_FRAGMENTS",
    "_HARDEN_RUNNER_PATTERNS",
    "_IMAGE_SCAN_TOKENS",
    "_INTENDED_PURPOSE_HEADINGS",
    "_INVALID_DIGEST_REASON",
    "_KEYWORD_CI_SIGNAL_WARN",
    "_LLM_SDK_HINTS",
    "_LONG_LIVED_CLOUD_SECRET_SNIPPETS",
    "_LONG_LIVED_PASSWORD_PATTERN",
    "_MAX_SARIF_JSON_DEPTH",
    "_MCP_AUTH_DISABLED_HINTS",
    "_MCP_AUTH_HINTS",
    "_MCP_CONFIG_FILES",
    "_MCP_CONFIG_PATHS",
    "_MCP_DEP_HINTS",
    "_NPM_PROVENANCE_PATTERN",
    "_OIDC_TOKEN_PATTERN",
    "_OSV_SARIF_RELPATH",
    "_OUTPUT_FILTER_HINTS",
    "_PIN_REQ_PIN",
    "_POSTINSTALL_DANGER_HINTS",
    "_PROV_VERIFY_FILES",
    "_PUBLISH_KEYWORDS",
    "_RELEASE_ARCHIVE_KEYWORDS",
    "_RELEASE_ARCHIVE_SIGNAL_PATHS",
    "_REQUIRED_BRANCH_PROTECTION_FLAGS",
    "_REUSABLE_WORKFLOW_USES_LINE",
    "_RISK_MGMT_HEADINGS",
    "_RISK_MGMT_PATHS",
    "_ROOT_USER_RE",
    "_SAST_SEMGREP_EVIDENCE_FILENAME",
    "_SAST_SEMGREP_SCHEMA_PREFIX",
    "_SBOM_FORMAT_MARKERS",
    "_SCANNER_ACTION_HINTS",
    "_SCORECARD_MIN_SCORE",
    "_SECRET_SCAN_EXTRA_PATTERNS",
    "_SECRET_SCAN_TOKENS",
    "_SELF_HOSTED_PATTERN",
    "_SHA_PIN_PATTERN",
    "_STRICT_AWS_CODEBUILD_PROJECT_PROFILE_IDS",
    "_STRICT_AWS_SECRET_PROFILE_IDS",
    "_SUPPLEMENTAL_SIGNAL_WARN",
    "_USER_RE",
    "_ZIZMOR_SEVERITY_KEYS",
    "_agentic_applicable",
    "_agentic_na",
    "_agentic_signal",
    "_ai_agent_baseline_schema",
    "_ai_agent_evidence_path",
    "_annex_iv_section",
    "_any_github_workflow_suggests_release_or_deploy",
    "_audit_log_streaming_schema",
    "_audit_stream_signal_match",
    "_aws_codebuild_project_schema",
    "_aws_codepipeline_schema",
    "_aws_provenance_artifact_schema",
    "_aws_sbom_artifact_schema",
    "_azure_branch_policies_api_support_complete",
    "_azure_branch_policies_schema",
    "_azure_governance_evidence_dict",
    "_azure_pipeline_governance_api_support_complete",
    "_azure_pipeline_governance_schema",
    "_azure_provenance_artifact_schema",
    "_azure_sbom_artifact_schema",
    "_branch_protection_evidence",
    "_branch_protection_schema",
    "_codeowners_covers_prompt_path",
    "_codeowners_text",
    "_detect_sbom_format",
    "_detect_sbom_format_and_version",
    "_digest_gate_outcome",
    "_digest_invalid_not_evaluated",
    "_digest_placeholder_manual_review",
    "_disclosure_policy_schema",
    "_disclosure_sla_signal_match",
    "_environment_protection_schema",
    "_eval_sarif_adapter",
    "_evidence_is_api_backed",
    "_evidence_placeholder_outcome",
    "_exists_ci_readme",
    "_find_any_text_hint",
    "_find_dockerfiles",
    "_find_prompt_registry",
    "_find_sbom_files",
    "_github_provenance_artifact_schema",
    "_github_workflow_raw_suggests_release_or_deploy",
    "_gl_no_pipeline_response",
    "_gov_disc_013_private_reporting_signals",
    "_has_changelog",
    "_has_codeowners",
    "_has_license",
    "_has_placeholder_security_contact",
    "_is_valid_sha256_digest",
    "_iter_ai_agent_text_files",
    "_iter_structured_workflow_uses_strings",
    "_iter_structured_workflow_uses_with_location",
    "_load_ai_agent_evidence",
    "_load_ai_system_doc",
    "_max_json_nesting_depth",
    "_mcp_applicable",
    "_mcp_na",
    "_mcp_text_signal",
    "_org_mfa_schema",
    "_parse_branch_protection_evidence",
    "_parse_evidence_date",
    "_parse_sarif_findings",
    "_parse_zizmor_severity_properties",
    "_prov_verify_lookup_order",
    "_provenance_artifact_digest_strings",
    "_publish_workflows",
    "_python_lock_or_pins",
    "_read_first_existing",
    "_read_lower",
    "_read_security",
    "_release_archival_policy_schema",
    "_release_archive_signal_match",
    "_reusable_workflow_ref_has_full_sha",
    "_reusable_workflow_uses_from_strings",
    "_rulesets_schema",
    "_runner_groups_schema",
    "_sbom_artifact_digest_strings",
    "_scan_for_llm_sdks",
    "_scan_gitlab_pipelines",
    "_scan_readme_for_section",
    "_scan_sarif_epss_kev",
    "_secret_scanning_schema",
    "_self_hosted_workflow_paths",
    "_validate_bsi_tr_03183_v2_1",
    "_validate_json_evidence",
    "_verification_freshness_status",
    "_workflow_text",
    "_workflow_text_has_long_lived_cloud_secret",
    "annotations",
    "cast",
    "checks_as_map",
    "contextlib",
    "dataclass",
    "date",
    "datetime",
    "field",
    "has_placeholder_values",
    "importlib",
    "insights_self_attested_outcome",
    "is_placeholder_digest",
    "json",
    "load_evidence_schema",
    "load_yaml_file",
    "re",
]
