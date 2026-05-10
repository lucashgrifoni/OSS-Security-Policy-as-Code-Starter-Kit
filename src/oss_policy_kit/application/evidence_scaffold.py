"""Generate starter evidence JSON files under `.oss-policy-kit/evidence/`.

Manual evidence mode: templates must be filled in by hand. For automatic evidence
collection via platform APIs, use ``collect-evidence`` instead of this scaffold.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from oss_policy_kit.domain.errors import InvalidInputError
from oss_policy_kit.domain.models import utc_today


def scaffold_attested_date_yyyy_mm_dd(*, today: date | None = None) -> str:
    """Return the attestation date stamp used in scaffold templates (UTC calendar day)."""

    d = today if today is not None else utc_today()
    return d.isoformat()


def _github_templates(attested_at: str) -> dict[str, dict[str, Any]]:
    return {
        "branch-protection.json": {
            "schema_version": "branch-protection/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_GITHUB_HANDLE",
            "branch": "main",
            "protections": {
                "require_pull_request_reviews": True,
                "dismiss_stale_reviews": True,
                "require_status_checks": True,
                "enforce_admins": True,
                "restrict_force_push": True,
            },
            "notes": ("Replace attested_at / attested_by and confirm flags against the real repository settings."),
        },
        "github-rulesets.json": {
            "schema_version": "github-rulesets/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_GITHUB_HANDLE",
            "repository": "org/repo",
            "posture": {
                "require_pull_request": True,
                "require_status_checks": True,
                "restrict_force_push": True,
                "require_code_owner_review": True,
            },
            "notes": "Self-attested values; the kit does not query the live platform.",
        },
        "github-environment-protection.json": {
            "schema_version": "github-environment-protection/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_GITHUB_HANDLE",
            "environments": [
                {
                    "name": "production",
                    "requires_reviewers": True,
                    "prevent_self_review": True,
                    "wait_timer_minutes": 0,
                }
            ],
            "notes": "Adjust environment names and timers to match the real repository.",
        },
        "github-secret-scanning.json": {
            "schema_version": "github-secret-scanning/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_GITHUB_HANDLE",
            "repository": "org/repo",
            "posture": {
                "secret_scanning_enabled": True,
                "push_protection_enabled": True,
                "validity_checks_enabled": True,
            },
            "notes": "Confirm toggles against GitHub Advanced Security where applicable.",
        },
    }


def _azure_templates(attested_at: str) -> dict[str, dict[str, Any]]:
    return {
        "azure-branch-policies.json": {
            "schema_version": "azure-branch-policies/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_AZDO_USER",
            "project": "REPLACE_ME_PROJECT",
            "repository": "REPLACE_ME_REPO",
            "branch": "main",
            "posture": {
                "minimum_reviewers_enabled": True,
                "build_validation_enabled": True,
                "comment_resolution_required": True,
                "reset_votes_on_push": True,
                "block_last_pusher_approval": True,
                "bypass_policy_restricted": True,
            },
            "notes": "Fill project/repository and validate against Azure Repos.",
        },
        "azure-pipeline-governance.json": {
            "schema_version": "azure-pipeline-governance/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_AZDO_USER",
            "project": "REPLACE_ME_PROJECT",
            "posture": {
                "approvals_required": True,
                "environment_checks_enabled": True,
                "service_connection_restricted": True,
                "federated_identity_preferred": True,
            },
            "service_connections": [
                {
                    "name": "REPLACE_ME_SERVICE_CONNECTION",
                    "authentication": "managed_identity",
                },
                {
                    "name": "REPLACE_ME_WIF_SERVICE_CONNECTION",
                    "authentication": "workload_identity_federation",
                    "federation_subject": "repo:org/repo:ref:refs/heads/main",
                    "issuer_url": "https://token.actions.githubusercontent.com",
                    "audience": "api://AzureADTokenExchange",
                },
            ],
            "notes": (
                "List real service connections; replace managed_identity with the actual authentication enum "
                "(workload_identity_federation, service_principal, managed_identity) from Azure DevOps."
            ),
        },
        "azure-sbom-artifact.json": {
            "schema_version": "azure-sbom-artifact/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_AZDO_USER",
            "artifact": {
                "uri": "REPLACE_ME_ARTIFACT_URI",
                "digest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            "sbom": {
                "format": "cyclonedx",
                "digest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            "posture": {
                "sbom_covers_release_artifact": True,
                "sbom_digest_recorded": True,
                "artifact_digest_recorded": True,
            },
            "notes": "Bind CycloneDX/SPDX digest to the shipped build artifact; prefer collect-evidence metadata.",
        },
        "azure-provenance-artifact.json": {
            "schema_version": "azure-provenance-artifact/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_AZDO_USER",
            "artifact": {
                "uri": "REPLACE_ME_ARTIFACT_URI",
                "digest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            "attestation": {
                "kind": "cosign",
                "digest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            },
            "posture": {
                "attestation_covers_release_artifact": True,
                "attestation_digest_recorded": True,
                "artifact_digest_recorded": True,
            },
            "notes": "Record attestation digest for the same artifact URI as the release binary or image.",
        },
    }


def _aws_templates(attested_at: str) -> dict[str, dict[str, Any]]:
    return {
        "aws-codebuild-project.json": {
            "schema_version": "aws-codebuild-project/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_AWS_PRINCIPAL",
            "project": "REPLACE_ME_CODEBUILD_PROJECT",
            "posture": {
                "privileged_mode_disabled": True,
                "no_plaintext_credentials_in_project_config": True,
                "codebuild_service_role_configured": True,
            },
            "identity": {
                "service_role_arn_present": True,
                "no_plaintext_environment_credentials": True,
            },
            "notes": (
                "Update project and confirm in the AWS CodeBuild console; prefer collect-evidence for live metadata."
            ),
        },
        "aws-codepipeline.json": {
            "schema_version": "aws-codepipeline/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_AWS_PRINCIPAL",
            "pipeline": "REPLACE_ME_PIPELINE",
            "posture": {
                "manual_approval_before_production": True,
                "artifact_store_encryption_enabled": True,
                "production_execution_mode_not_parallel": True,
            },
            "iam": {"pipeline_service_role_arn_configured": True},
            "notes": (
                "Describe real stages and manual approvals before production; "
                "prefer collect-evidence for live metadata."
            ),
        },
        "aws-sbom-artifact.json": {
            "schema_version": "aws-sbom-artifact/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_AWS_PRINCIPAL",
            "artifact": {
                "uri": "REPLACE_ME_S3_OR_ARTIFACT_URI",
                "digest_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            },
            "sbom": {
                "format": "cyclonedx",
                "digest_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
            "posture": {
                "sbom_covers_release_artifact": True,
                "sbom_digest_recorded": True,
                "artifact_digest_recorded": True,
            },
            "notes": (
                "Record real digests for the shipped artifact and SBOM; "
                "prefer automation that adds collection metadata."
            ),
        },
        "aws-provenance-artifact.json": {
            "schema_version": "aws-provenance-artifact/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_AWS_PRINCIPAL",
            "artifact": {
                "uri": "REPLACE_ME_S3_OR_ARTIFACT_URI",
                "digest_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            },
            "attestation": {
                "kind": "cosign",
                "digest_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
            "posture": {
                "attestation_covers_release_artifact": True,
                "attestation_digest_recorded": True,
                "artifact_digest_recorded": True,
            },
            "notes": "Point attestation digest at the record covering the same artifact digest.",
        },
    }


def _common_templates(attested_at: str, platform: str) -> dict[str, dict[str, Any]]:
    return {
        "org-mfa-posture.json": {
            "schema_version": "org-mfa-posture/v1",
            "attested_at": attested_at,
            "attested_by": "REPLACE_ME_HANDLE",
            "org_name": "REPLACE_ME_ORG",
            "platform": platform,
            "mfa_required_for_all_members": True,
            "mfa_required_for_admins": True,
            "enforcement_scope": "all_members",
            "sso_enforced": False,
            "phishing_resistant_mfa": False,
            "notes": (
                "Set mfa_required_for_all_members=true when the organization enforces MFA for every member. "
                "Confirm in organization security settings before attesting."
            ),
        },
    }


_README_BODY = """# Self-attested evidence

These JSON files are **maintainer-supplied** and are not automatically verified against
GitHub, Azure, or AWS. They let `release-hardening-*` profiles evaluate declared posture when
platform signals are not visible in the clone.

1. Fill in `attested_by`, dates, and repository/project names.
2. Adjust `posture` / `protections` booleans to match real configuration.
3. Re-run: `python -m oss_policy_kit evaluate --target . --profile <your-release-hardening>`.

## Safe re-runs

By default, `scaffold-evidence` **does not overwrite** existing files (so manual edits are kept).
Use `--force` only when you intentionally want to replace templates.
"""


@dataclass(slots=True)
class ScaffoldEvidenceResult:
    """Paths touched by `scaffold_evidence_files` grouped by outcome."""

    created: list[Path] = field(default_factory=list)
    skipped: list[Path] = field(default_factory=list)
    overwritten: list[Path] = field(default_factory=list)


def scaffold_evidence_files(
    repo_root: Path,
    platform: str,
    *,
    force: bool = False,
    today: date | None = None,
) -> ScaffoldEvidenceResult:
    """Create `.oss-policy-kit/evidence/` with JSON templates for *platform* (github, azure, aws).

    Manual evidence mode: generates template JSON files that must be filled in by hand.
    For automatic evidence collection via platform APIs, use ``collect-evidence`` instead.

    Unless *force* is True, existing files are left unchanged and listed under ``skipped``.
    """

    plat = platform.lower().strip()
    attested = scaffold_attested_date_yyyy_mm_dd(today=today)
    if plat == "github":
        templates = {**_github_templates(attested), **_common_templates(attested, "github")}
    elif plat == "azure":
        templates = {**_azure_templates(attested), **_common_templates(attested, "azure-devops")}
    elif plat == "aws":
        templates = {**_aws_templates(attested), **_common_templates(attested, "aws-iam")}
    else:
        raise InvalidInputError("platform must be one of: github, azure, aws")

    result = ScaffoldEvidenceResult()
    ev = repo_root / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True, exist_ok=True)

    for name, payload in templates.items():
        dest = ev / name
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        if dest.is_file():
            if not force:
                result.skipped.append(dest)
                continue
            dest.write_text(text, encoding="utf-8")
            result.overwritten.append(dest)
        else:
            dest.write_text(text, encoding="utf-8")
            result.created.append(dest)

    readme = ev / "README.md"
    if readme.is_file():
        if not force:
            result.skipped.append(readme)
        else:
            readme.write_text(_README_BODY, encoding="utf-8")
            result.overwritten.append(readme)
    else:
        readme.write_text(_README_BODY, encoding="utf-8")
        result.created.append(readme)

    return result
