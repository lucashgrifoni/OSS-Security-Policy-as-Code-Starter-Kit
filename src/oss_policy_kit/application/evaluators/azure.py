"""azure control evaluators (moved verbatim from evaluators.py, M8)."""

from __future__ import annotations

from typing import Any

from oss_policy_kit.application.evaluators._shared import (
    _KEYWORD_CI_SIGNAL_WARN,
    NO_AZURE_PIPELINES_REASON,
    ControlStatus,
    EvalContext,
    EvalOutcome,
    EvidenceCollectionMethod,
    Path,
    _azure_branch_policies_api_support_complete,
    _azure_branch_policies_schema,
    _azure_governance_evidence_dict,
    _azure_pipeline_governance_api_support_complete,
    _azure_pipeline_governance_schema,
    _azure_provenance_artifact_schema,
    _azure_sbom_artifact_schema,
    _digest_invalid_not_evaluated,
    _digest_placeholder_manual_review,
    _evidence_is_api_backed,
    _evidence_placeholder_outcome,
    _is_valid_sha256_digest,
    _provenance_artifact_digest_strings,
    _sbom_artifact_digest_strings,
    _validate_json_evidence,
    contextlib,
    has_placeholder_values,
    is_placeholder_digest,
)

_AZURE_PIPELINE_GOV_JSON = "azure-pipeline-governance.json"
_AZURE_PIPELINE_GOV_LABEL = "Azure pipeline governance"
_AZURE_PIPELINE_GOV_REMEDIATION = (
    "Regenerate evidence using reports/schema/evidence-azure-pipeline-governance.schema.json."
)
_KIT_DIR = ".oss-policy-kit"


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

    evidence = ctx.repo_root / _KIT_DIR / "evidence" / "azure-branch-policies.json"
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

    evidence = ctx.repo_root / _KIT_DIR / "evidence" / _AZURE_PIPELINE_GOV_JSON
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
        evidence_name=_AZURE_PIPELINE_GOV_LABEL,
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation=_AZURE_PIPELINE_GOV_REMEDIATION,
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


def _az_ident_governance_outcome(gov: dict[str, Any], evidence: Path) -> EvalOutcome:
    """Outcome for AZ-IDENT-036 when governance evidence is present (PASS/MANUAL/SELF_ATTESTED)."""

    src = [str(evidence.resolve())]
    posture = gov.get("posture")
    if isinstance(posture, dict) and posture.get("federated_identity_preferred") is True:
        if _evidence_is_api_backed(gov) and _azure_pipeline_governance_api_support_complete(gov):
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason="Workload identity federation preferred per live-collected Azure pipeline governance evidence.",
                remediation="Keep federated service connections and avoid PAT-style deployment credentials.",
                evidence_sources=src,
                confidence="high",
                evidence_collection_method=EvidenceCollectionMethod.LIVE,
            )
        if _evidence_is_api_backed(gov):
            return EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason="Governance evidence suggests federation, but API posture_support metadata is incomplete.",
                remediation="Re-run collect-evidence so federation claims are backed by reachable Azure APIs.",
                evidence_sources=src,
                confidence="medium",
                evidence_collection_method=EvidenceCollectionMethod.LIVE,
            )
        return EvalOutcome(
            status=ControlStatus.SELF_ATTESTED,
            reason="Governance evidence self-attests federated identity preference for deployment connections.",
            remediation="Prefer collect-evidence over manual JSON for stronger assurance.",
            evidence_sources=src,
            confidence="low",
            evidence_collection_method=EvidenceCollectionMethod.MANUAL,
        )
    return EvalOutcome(
        status=ControlStatus.SELF_ATTESTED,
        reason="Governance evidence present but federated_identity_preferred is not enabled.",
        remediation="Migrate deployment service connections to WorkloadIdentityFederation where applicable.",
        evidence_sources=src,
        confidence="low",
        evidence_collection_method=EvidenceCollectionMethod.MANUAL,
    )


def eval_az_ident_036(ctx: EvalContext) -> EvalOutcome:
    """AZ-IDENT-036: workload identity federation preference grounded in governance evidence when available."""

    gov = _azure_governance_evidence_dict(ctx)
    if gov is not None:
        evidence = ctx.repo_root / _KIT_DIR / "evidence" / _AZURE_PIPELINE_GOV_JSON
        ph = has_placeholder_values(gov)
        blocked = _evidence_placeholder_outcome(evidence, ph)
        if blocked is not None:
            return blocked
        return _az_ident_governance_outcome(gov, evidence)

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


_SCONN_ALLOWED_AUTH = frozenset(
    {"workload_identity_federation", "service_principal", "managed_identity", "secret", "certificate"}
)
_SCONN_UNKNOWN_REASON = (
    "Service connection authentication type is 'unknown'. "
    "Inspect the connection in Azure DevOps and attest the actual "
    "authentication method before this control can be evaluated."
)


def _sconn_auth_outcome(conns: list[Any], evidence: Path) -> EvalOutcome | None:
    """Return NOT_EVALUATED/MANUAL for an unknown/unsupported connection auth value, else None."""

    src = [str(evidence.resolve())]
    for c in conns:
        if not isinstance(c, dict):
            continue
        raw_auth = c.get("authentication")
        if not isinstance(raw_auth, str) or not raw_auth.strip():
            return EvalOutcome(
                status=ControlStatus.NOT_EVALUATED,
                reason=_SCONN_UNKNOWN_REASON,
                remediation="Update the evidence file with the actual authentication value.",
                evidence_sources=src,
                confidence="low",
            )
        auth_l = raw_auth.strip().lower()
        if auth_l == "unknown":
            return EvalOutcome(
                status=ControlStatus.NOT_EVALUATED,
                reason=_SCONN_UNKNOWN_REASON,
                remediation="Update the evidence file with the actual authentication value.",
                evidence_sources=src,
                confidence="low",
            )
        if auth_l not in _SCONN_ALLOWED_AUTH:
            return EvalOutcome(
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                reason=(
                    f"Service connection `{c.get('name', '<unnamed>')}` has unsupported authentication value "
                    f"'{raw_auth}'. Allowed values: workload_identity_federation, service_principal, "
                    "managed_identity, certificate, secret."
                ),
                remediation="Populate authentication for each service connection entry from Azure DevOps inventory.",
                evidence_sources=src,
                confidence="low",
            )
    return None


def eval_az_sconn_056(ctx: EvalContext) -> EvalOutcome:
    """AZ-SCONN-056: service connection authentication posture from pipeline governance evidence."""

    evidence = ctx.repo_root / _KIT_DIR / "evidence" / _AZURE_PIPELINE_GOV_JSON
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
        evidence_name=_AZURE_PIPELINE_GOV_LABEL,
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation=_AZURE_PIPELINE_GOV_REMEDIATION,
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
    auth_outcome = _sconn_auth_outcome(conns, evidence)
    if auth_outcome is not None:
        return auth_outcome
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


def _az_wif_posture_outcome(posture: Any, evidence: Path) -> EvalOutcome | None:
    """Return a MANUAL/FAIL outcome for the WIF posture flag, or None when it is explicitly true."""

    src = [str(evidence.resolve())]
    if not isinstance(posture, dict) or "federated_identity_preferred" not in posture:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Evidence file missing posture.federated_identity_preferred field.",
            remediation=(
                "Set posture.federated_identity_preferred in azure-pipeline-governance.json after enabling WIF."
            ),
            evidence_sources=src,
            confidence="low",
        )
    pref = posture.get("federated_identity_preferred")
    if pref is False:
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                "Federated identity is not preferred per governance evidence. "
                "Set posture.federated_identity_preferred: true after configuring workload "
                "identity federation."
            ),
            remediation="Configure workload identity federation for deployment service connections and re-attest.",
            evidence_sources=src,
            confidence="medium",
        )
    if pref is not True:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="Evidence file missing posture.federated_identity_preferred field.",
            remediation="Set posture.federated_identity_preferred to a boolean true/false value.",
            evidence_sources=src,
            confidence="low",
        )
    return None


def _wif_empty_proof_fields(conn: dict[str, Any]) -> list[str]:
    """Return WIF proof fields that are missing, non-string, or placeholder (``<...>``)."""

    empty: list[str] = []
    for f in ("federation_subject", "issuer_url", "audience"):
        raw = conn.get(f)
        if not isinstance(raw, str):
            empty.append(f)
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("<"):
            empty.append(f)
    return empty


def _incomplete_wif_outcome(wif_conns: list[Any], evidence: Path) -> EvalOutcome | None:
    """Return a NOT_EVALUATED outcome when any WIF connection lacks complete proof fields."""

    for conn in wif_conns:
        if _wif_empty_proof_fields(conn):
            return EvalOutcome(
                status=ControlStatus.NOT_EVALUATED,
                reason=(
                    "Workload identity federation evidence is incomplete. "
                    "The following fields are missing or contain placeholder values: "
                    f"{', '.join(_wif_empty_proof_fields(conn))}. "
                    "Collect real WIF configuration values from the Azure DevOps service connection."
                ),
                remediation="Update the evidence file with actual federation_subject, issuer_url, and audience values.",
                evidence_sources=[str(evidence.resolve())],
                confidence="low",
            )
    return None


def eval_az_wifev_057(ctx: EvalContext) -> EvalOutcome:
    """AZ-WIFEV-057: workload identity federation evidenced on service connections."""

    evidence = ctx.repo_root / _KIT_DIR / "evidence" / _AZURE_PIPELINE_GOV_JSON
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
        evidence_name=_AZURE_PIPELINE_GOV_LABEL,
    )
    if error:
        return EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=error,
            remediation=_AZURE_PIPELINE_GOV_REMEDIATION,
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    blocked = _evidence_placeholder_outcome(evidence, ph)
    if blocked is not None:
        return blocked
    assert data is not None
    posture_outcome = _az_wif_posture_outcome(data.get("posture"), evidence)
    if posture_outcome is not None:
        return posture_outcome

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
    incomplete = _incomplete_wif_outcome(wif_conns, evidence)
    if incomplete is not None:
        return incomplete
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

    evidence = ctx.repo_root / _KIT_DIR / "evidence" / "azure-sbom-artifact.json"
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

    evidence = ctx.repo_root / _KIT_DIR / "evidence" / "azure-provenance-artifact.json"
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
