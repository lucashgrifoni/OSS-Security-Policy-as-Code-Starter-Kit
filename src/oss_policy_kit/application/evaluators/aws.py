"""aws control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import *  # noqa: F403


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
