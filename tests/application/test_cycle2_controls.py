"""Cycle 2 (v6.0.0) controls — PR-20 .. PR-32.

Covers catalog/registry wiring, the six new bundled/extended profiles, and
representative PASS / FAIL / NOT_APPLICABLE / MANUAL_REVIEW behaviour for each
new control family. Unit tests use ``SimpleNamespace`` contexts (mirroring
``test_worm_controls.py``); a couple of integration tests run the full engine.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from oss_policy_kit.application.evaluators import (
    EVALUATOR_REGISTRY,
    eval_agent_asi_goal_001,
    eval_agent_asi_tool_002,
    eval_cont_distroless_001,
    eval_cra_art13_sbd_001,
    eval_cra_art13_support_003,
    eval_cra_art14_csaf_001,
    eval_cra_product_class_001,
    eval_gh_wf_lockfile_001,
    eval_llm_ai_act_cyber_006,
    eval_llm_ai_act_dev_002,
    eval_mcp_tool_hash_001,
    eval_osps_scorecard_v6_001,
    eval_sca_epss_001,
    eval_sca_kev_001,
    eval_scanner_integrity_001,
    eval_slsa_src_006,
    eval_slsa_src_007,
)
from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)
from oss_policy_kit.domain.models import ControlStatus

_NEW_CONTROLS = (
    "OSPS-SCORECARD-V6-001",
    "LLM-AI-ACT-DEV-002",
    "LLM-AI-ACT-PERF-004",
    "LLM-AI-ACT-CYBER-006",
    "LLM-AI-ACT-CHANGE-007",
    "LLM-AI-ACT-STD-008",
    "LLM-AI-ACT-PMM-009",
    "CRA-ART13-SBD-001",
    "CRA-ART13-DEFAULTS-002",
    "CRA-ART14-CSAF-001",
    "CRA-ART14-COORD-002",
    "CRA-PRODUCT-CLASS-001",
    "SCA-KEV-001",
    "SCA-EPSS-001",
    "SLSA-SRC-006",
    "SLSA-SRC-007",
    "SLSA-SRC-008",
    "MCP-TOOL-HASH-001",
    "MCP-CONFIRM-001",
    "MCP-EGRESS-001",
    "MCP-INJECTION-TEST-001",
    "MCP-SCOPE-001",
    "AGENT-ASI-GOAL-001",
    "AGENT-ASI-TOOL-002",
    "AGENT-ASI-MEMORY-006",
    "AGENT-ASI-INTER-007",
    "AGENT-ASI-CONFIRM-009",
    "GH-EGRESS-NATIVE-001",
    "GH-WF-LOCKFILE-001",
    "CONT-DISTROLESS-001",
    "SCANNER-INTEGRITY-001",
)


def test_all_cycle2_controls_present_in_catalog_and_registry() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for cid in _NEW_CONTROLS:
        assert cid in catalog, f"{cid} missing from catalog"
        assert cid in EVALUATOR_REGISTRY, f"{cid} missing from registry"
        assert catalog[cid].lifecycle == "experimental", cid
        assert catalog[cid].assurance in {"signal", "evidence-backed"}, cid


def test_new_profiles_load_with_expected_controls() -> None:
    root = bundled_kit_root()
    cases = {
        "osps-baseline-2026-1": "OSPS-SCORECARD-V6-001",
        "cra-eu-conformance-evidence-1": "CRA-ART14-CSAF-001",
        "slsa-source-l2-1": "SLSA-SRC-007",
        "appsec-mcp-server-1": "MCP-TOOL-HASH-001",
        "appsec-agentic-asi-1": "AGENT-ASI-GOAL-001",
    }
    for pid, expected in cases.items():
        spec = load_profile_by_id(root, pid)
        assert expected in spec.control_ids, f"{pid} should bundle {expected}"


def test_cra_ready_2_1_alias_was_removed_in_v10() -> None:
    """ADR-029: the deprecated `cra-eu-ready-2-1` alias completed its one-major cycle
    (v9.x) and was removed in v10.0.0 — resolving it is a hard error with a pointer."""
    import pytest

    from oss_policy_kit.domain.errors import LoadError

    root = bundled_kit_root()
    with pytest.raises(LoadError, match=r"removed in v10\.0\.0"):
        load_profile_by_id(root, "cra-eu-ready-2-1")
    canonical = load_profile_by_id(root, "cra-eu-conformance-evidence-1")
    assert canonical.id == "cra-eu-conformance-evidence-1"
    # the tightened obligation-evidence controls are present
    for cid in ("CISA-SBD-VDP-001", "BUILD-SBOM-QUAL-003", "RELEASE-ARCHIVE-063"):
        assert cid in canonical.control_ids


def test_extended_profiles_include_new_controls() -> None:
    root = bundled_kit_root()
    assert "LLM-AI-ACT-CYBER-006" in load_profile_by_id(root, "cra-eu-ai-act-art11-1").control_ids
    sca = load_profile_by_id(root, "appsec-sast-sca-1").control_ids
    assert "SCA-KEV-001" in sca
    assert "SCA-EPSS-001" in sca
    assert "CONT-DISTROLESS-001" in load_profile_by_id(root, "container-baseline-1").control_ids
    publish = load_profile_by_id(root, "oss-publish-readiness-1").control_ids
    assert "SCANNER-INTEGRITY-001" in publish
    assert "GH-EGRESS-NATIVE-001" in publish
    assert "GH-WF-LOCKFILE-001" in publish


# --- PR-20: OSPS Scorecard v6 ---------------------------------------------
def test_osps_scorecard_v6_pass_on_conformant_evidence(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence" / "scorecard-osps.json"
    ev.parent.mkdir(parents=True)
    ev.write_text(json.dumps({"conformance": "pass"}), encoding="utf-8")
    out = eval_osps_scorecard_v6_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_osps_scorecard_v6_manual_when_absent(tmp_path: Path) -> None:
    out = eval_osps_scorecard_v6_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --- PR-21: Annex IV evidence ---------------------------------------------
def test_annex_iv_pass_when_section_populated(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence" / "ai-system-technical-doc.json"
    ev.parent.mkdir(parents=True)
    ev.write_text(json.dumps({"development_design": "Trained on dataset X."}), encoding="utf-8")
    out = eval_llm_ai_act_dev_002(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_annex_iv_fail_when_section_missing(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence" / "ai-system-technical-doc.json"
    ev.parent.mkdir(parents=True)
    ev.write_text(json.dumps({"development_design": "x"}), encoding="utf-8")
    out = eval_llm_ai_act_cyber_006(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.FAIL


def test_annex_iv_manual_when_no_evidence(tmp_path: Path) -> None:
    out = eval_llm_ai_act_dev_002(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --- PR-22: CRA Article 13 / 14 -------------------------------------------
def test_cra_art13_pass_on_security_by_design(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text("# Security\n## Security by design\nWe ...\n", encoding="utf-8")
    out = eval_cra_art13_sbd_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_cra_art14_csaf_pass_on_well_known(tmp_path: Path) -> None:
    csaf = tmp_path / ".well-known" / "csaf" / "provider-metadata.json"
    csaf.parent.mkdir(parents=True)
    csaf.write_text("{}", encoding="utf-8")
    out = eval_cra_art14_csaf_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_cra_product_class_manual_when_absent(tmp_path: Path) -> None:
    out = eval_cra_product_class_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --- T2.4 (v8.1.0): CRA Article 13 / Annex I support-period signal ---------
def test_cra_support_period_pass_on_supported_versions(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text(
        "# Security\n\n## Supported Versions\n\n| Version | Supported |\n|---|---|\n| 8.x | yes |\n",
        encoding="utf-8",
    )
    out = eval_cra_art13_support_003(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS
    # Honest wording: readiness signal, never a CRA conformity/certification claim.
    blob = f"{out.reason} {out.remediation}".lower()
    assert "certified" not in blob
    assert "conformity" not in blob
    assert "compliant" not in blob


def test_cra_support_period_manual_when_absent(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text("# Security\n\nReport issues to security@example.com\n", encoding="utf-8")
    out = eval_cra_art13_support_003(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_cra_support_period_pass_on_support_window_doc(tmp_path: Path) -> None:
    (tmp_path / "SUPPORT.md").write_text(
        "# Support\n\nSecurity updates for 24 months after release.\n", encoding="utf-8"
    )
    out = eval_cra_art13_support_003(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


# --- PR-23: EPSS + KEV -----------------------------------------------------
def _write_osv_sarif(repo: Path, results: list[dict]) -> None:
    p = repo / ".oss-policy-kit" / "evidence" / "sast" / "osv-scanner.sarif.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"runs": [{"results": results}]}), encoding="utf-8")


def test_sca_kev_fails_on_kev_finding(tmp_path: Path) -> None:
    _write_osv_sarif(tmp_path, [{"ruleId": "CVE-2025-0001", "properties": {"kev": True}}])
    out = eval_sca_kev_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.FAIL


def test_sca_kev_passes_when_enrichment_ran_and_flagged_nothing(tmp_path: Path) -> None:
    """PASS requires the enrichment to have actually run -- a `kev` field must be present."""

    _write_osv_sarif(tmp_path, [{"ruleId": "CVE-2025-0002", "properties": {"kev": False, "epss_score": 0.1}}])
    out = eval_sca_kev_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_sca_kev_is_manual_review_when_the_sarif_carries_no_kev_data(tmp_path: Path) -> None:
    """This test asserted PASS, which was the defect.

    A SARIF with no `properties.kev` anywhere -- what plain `osv-scanner --format sarif`
    emits -- cannot support "no dependency CVE is KEV-listed". The kit was making that
    claim at confidence=high over a file containing Log4Shell.
    """

    _write_osv_sarif(tmp_path, [{"ruleId": "CVE-2021-44228", "properties": {"epss_score": 0.1}}])
    out = eval_sca_kev_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "no KEV enrichment" in out.reason


def test_sca_epss_fails_on_high_epss(tmp_path: Path) -> None:
    _write_osv_sarif(tmp_path, [{"ruleId": "CVE-2025-0003", "properties": {"epss_score": 0.9, "cvss_score": 8.1}}])
    out = eval_sca_epss_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.FAIL


def test_sca_epss_manual_when_no_evidence(tmp_path: Path) -> None:
    out = eval_sca_epss_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --- PR-25: SLSA Source L2 -------------------------------------------------
#: The five flags `protections` marks required. A partial block is rejected by the schema, so a
#: fixture that sets only the flag under test never reaches the control at all.
_PROTECTIONS_BASELINE = {
    "require_pull_request_reviews": False,
    "dismiss_stale_reviews": False,
    "require_status_checks": False,
    "enforce_admins": False,
    "restrict_force_push": False,
}


def _branch_protection_document(protections: dict) -> dict:
    """A schema-valid document whose flags are all off except the ones a test names."""

    return {
        "schema_version": "branch-protection/v1",
        "attested_at": "2026-06-15",
        "attested_by": "platform-team",
        "branch": "main",
        "protections": {**_PROTECTIONS_BASELINE, **protections},
    }


def _write_branch_protection(repo: Path, protections: dict) -> None:
    """Write evidence in the shape ``evidence-branch-protection.schema.json`` actually accepts.

    The flags live under ``protections``; the schema is closed, so a document that puts them at
    the root is rejected and the control never sees them. These tests used to write that root
    shape and assert a verdict, which pinned a reader no schema-valid file could satisfy.
    """

    p = repo / ".oss-policy-kit" / "evidence" / "branch-protection.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps(_branch_protection_document(protections)), encoding="utf-8")


def test_slsa_src_006_pass_on_required_signatures(tmp_path: Path) -> None:
    _write_branch_protection(tmp_path, {"require_signed_commits": True})
    out = eval_slsa_src_006(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_slsa_src_007_fails_when_no_review_is_required_at_all(tmp_path: Path) -> None:
    """Zero required approvals cannot reach a threshold of two, so this much IS decidable."""

    _write_branch_protection(tmp_path, {"require_pull_request_reviews": False})
    out = eval_slsa_src_007(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.FAIL


def test_slsa_src_007_will_not_read_review_required_as_two_approvers(tmp_path: Path) -> None:
    """`branch-protection/v1` records *whether* review is required, never how many approve.

    Reading the >= 1 boolean as proof of the SLSA L2 >= 2 threshold would turn unknown into
    clean. The control says so instead, and names the missing threshold in its remediation.
    """

    _write_branch_protection(tmp_path, {"require_pull_request_reviews": True})
    out = eval_slsa_src_007(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "approver count" in out.reason


# --- PR-27: MCP ------------------------------------------------------------
def test_mcp_tool_hash_not_applicable_without_mcp(tmp_path: Path) -> None:
    out = eval_mcp_tool_hash_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_mcp_tool_hash_pass_with_hashes(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text('{"tools": []}', encoding="utf-8")
    ev = tmp_path / ".oss-policy-kit" / "evidence" / "mcp-tool-descriptions.json"
    ev.parent.mkdir(parents=True)
    ev.write_text(json.dumps({"echo": {"sha256": "abc"}}), encoding="utf-8")
    out = eval_mcp_tool_hash_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


# --- PR-28: Agentic ASI ----------------------------------------------------
def test_agent_asi_goal_not_applicable_without_framework(tmp_path: Path) -> None:
    out = eval_agent_asi_goal_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_agent_asi_tool_pass_with_signal(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = ['langgraph']\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Agent\nWe use a tool allowlist with least privilege.\n", encoding="utf-8")
    out = eval_agent_asi_tool_002(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


# --- PR-29..32 -------------------------------------------------------------
def test_gh_wf_lockfile_not_applicable_without_workflows(tmp_path: Path) -> None:
    out = eval_gh_wf_lockfile_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_distroless_pass_on_chainguard_base(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM cgr.dev/chainguard/python:latest\n", encoding="utf-8")
    out = eval_cont_distroless_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_distroless_manual_on_heavy_base(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:22.04\n", encoding="utf-8")
    out = eval_cont_distroless_001(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_scanner_integrity_fail_on_unpinned_scanner(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows" / "scan.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("jobs:\n  s:\n    steps:\n      - uses: aquasecurity/trivy-action@master\n", encoding="utf-8")
    ctx = SimpleNamespace(repo_root=tmp_path, workflows=SimpleNamespace(workflow_paths=(wf,)))
    out = eval_scanner_integrity_001(ctx)
    assert out.status is ControlStatus.FAIL


def test_scanner_integrity_pass_on_pinned_scanner(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows" / "scan.yml"
    wf.parent.mkdir(parents=True)
    sha = "a" * 40
    wf.write_text(f"jobs:\n  s:\n    steps:\n      - uses: aquasecurity/trivy-action@{sha}\n", encoding="utf-8")
    ctx = SimpleNamespace(repo_root=tmp_path, workflows=SimpleNamespace(workflow_paths=(wf,)))
    out = eval_scanner_integrity_001(ctx)
    assert out.status is ControlStatus.PASS


# --- PR-24: Rekor v2 enum --------------------------------------------------
def test_rekor_v2_enum_present_in_provenance_schemas() -> None:
    schema_dir = bundled_kit_root() / "schema"
    for name in (
        "evidence-github-provenance-artifact.schema.json",
        "evidence-aws-provenance-artifact.schema.json",
        "evidence-azure-provenance-artifact.schema.json",
    ):
        data = json.loads((schema_dir / name).read_text(encoding="utf-8"))
        source = data["properties"]["verification"]["properties"]["source"]
        assert "rekor-v2-tile-inclusion" in source["enum"], name
