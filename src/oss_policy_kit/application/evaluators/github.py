"""github control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import *  # noqa: F403


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
