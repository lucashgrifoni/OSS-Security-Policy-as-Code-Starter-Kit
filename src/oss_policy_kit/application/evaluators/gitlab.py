"""gitlab control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import (
    ControlStatus,
    EvalContext,
    EvalOutcome,
    Path,
    _evidence_placeholder_outcome,
    _gitlab_mr_rules_schema,
    _gl_no_pipeline_response,
    _scan_gitlab_pipelines,
    _validate_json_evidence,
    contextlib,
)

_NO_GITLAB_PIPELINES_REASON = "No GitLab CI pipelines to evaluate."


def _gl_unreadable_pipelines(ctx: EvalContext, what: str) -> EvalOutcome | None:
    """Manual review when a pipeline could not be parsed, for controls that PASS on absence.

    A control whose PASS means "we looked and found nothing" must not return it when part of
    what it was meant to look at never parsed. GL-PIPE-003 answered "No `curl|sh` / `wget|sh`
    patterns detected in GitLab CI `script:` blocks" for a pipeline whose `script:` contained
    exactly that, because one extra invalid line had emptied the structured scan. The break
    bought the pass.

    Controls that FAIL on a parse error -- GL-PIPE-001 exists to report exactly that -- do not
    call this; they have already said the useful thing.
    """

    if not ctx.gitlab_ci.parse_errors:
        return None
    names = ", ".join(sorted({p.name for p, _ in ctx.gitlab_ci.parse_errors}))
    return EvalOutcome(
        status=ControlStatus.MANUAL_REVIEW_REQUIRED,
        reason=f"{what} could not be read: {names} failed to parse, so this control scanned only the rest.",
        remediation="Fix the YAML syntax in the listed pipeline file(s), then re-run evaluation.",
        evidence_sources=[str(p.resolve()) for p, _ in ctx.gitlab_ci.parse_errors],
        confidence="low",
    )


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
            reason=_NO_GITLAB_PIPELINES_REASON,
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
            reason=_NO_GITLAB_PIPELINES_REASON,
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
    unreadable = _gl_unreadable_pipelines(ctx, "`script:` blocks")
    if unreadable is not None:
        return unreadable
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
            reason=_NO_GITLAB_PIPELINES_REASON,
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
            reason=_NO_GITLAB_PIPELINES_REASON,
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
            reason=_NO_GITLAB_PIPELINES_REASON,
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
        # The schema for this file has shipped since the control was written -- in the wheel
        # and in reports/schema/ -- and nothing loaded it. Hand-rolled checks stood in its
        # place and let four things through: an untouched scaffold still carrying
        # REPLACE_ME_GITLAB_USER reported PASS "documents min_approvers=2"; a file missing a
        # required field, or declaring a foreign schema_version, also reported PASS; and
        # min_approvers: 1.5 passed although the schema says integer. A schema that nothing
        # reads is documentation of an intention, not a contract.
        data, error, placeholders = _validate_json_evidence(
            evidence, schema_loader=_gitlab_mr_rules_schema, evidence_name="GitLab MR rules"
        )
        if error:
            return EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=error,
                remediation="Regenerate evidence using reports/schema/evidence-gitlab-mr-rules.schema.json.",
                evidence_sources=[str(evidence.resolve())],
                confidence="low",
            )
        blocked = _evidence_placeholder_outcome(evidence, placeholders)
        if blocked is not None:
            return blocked
        assert data is not None
        approvers = data["min_approvers"]  # schema: integer, minimum 0
        if approvers < 1:
            # Readable evidence showing the protection is off. ADR-045 reserves
            # manual-review for evidence that cannot be READ; this one reads fine and says
            # no approvals are required. It used to fall through to "No ... evidence" --
            # the kit hiding a real finding behind a sentence denying the file exists.
            return EvalOutcome(
                status=ControlStatus.FAIL,
                reason=(
                    f"MR rule evidence documents min_approvers={approvers}: merge requests can be "
                    "merged without an approval."
                ),
                remediation="Require at least one approver on the project approval settings or an approval rule.",
                evidence_sources=[str(evidence.resolve())],
                confidence="high",
            )
        return EvalOutcome(
            status=ControlStatus.PASS,
            reason=f"MR rule evidence documents min_approvers={approvers}.",
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
