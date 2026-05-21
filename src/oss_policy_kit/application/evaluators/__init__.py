"""Per-control local evaluators (filesystem + workflow static analysis)."""

from __future__ import annotations

from oss_policy_kit.application.evaluators._shared import *  # noqa: F403
from oss_policy_kit.application.evaluators.ai import *  # noqa: F403
from oss_policy_kit.application.evaluators.aws import *  # noqa: F403
from oss_policy_kit.application.evaluators.azure import *  # noqa: F403
from oss_policy_kit.application.evaluators.cicd import *  # noqa: F403
from oss_policy_kit.application.evaluators.cra import *  # noqa: F403
from oss_policy_kit.application.evaluators.github import *  # noqa: F403
from oss_policy_kit.application.evaluators.gitlab import *  # noqa: F403
from oss_policy_kit.application.evaluators.governance import *  # noqa: F403
from oss_policy_kit.application.evaluators.supply_chain import *  # noqa: F403

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
