"""Positive-signal (PASS/FAIL) branch coverage for ``evaluators/ai.py``.

The existing AI-agent profile tests largely exercise the NOT_APPLICABLE /
MANUAL_REVIEW default paths. These tests construct repositories that carry the
concrete signals (prompt registries, MCP configs, evidence files, model pins)
so each evaluator's success / failure branch is exercised.
"""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import _shared as s
from oss_policy_kit.application.evaluators import ai
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> s.EvalContext:
    return s.EvalContext(
        repo_root=tmp_path,
        profile_id="ai-agent-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(tmp_path: Path, rel: str, text: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _agent_evidence(tmp_path: Path, filename: str, payload: dict) -> Path:
    return _write(tmp_path, f".oss-policy-kit/evidence/ai-agent/{filename}", json.dumps(payload))


def _make_mcp(tmp_path: Path) -> None:
    """Mark the repo as an MCP server so MCP evaluators become applicable."""
    _write(tmp_path, "mcp.json", json.dumps({"name": "srv"}))


def _make_agentic(tmp_path: Path) -> None:
    """Mark the repo as agentic so ASI evaluators become applicable."""
    _write(tmp_path, "requirements.txt", "langchain==0.1.0\n")


# --------------------------------------------------------------------------- #
# LLM-218A + AI-ACT documentation evaluators
# --------------------------------------------------------------------------- #


def test_po_001_pass(tmp_path: Path) -> None:
    _write(tmp_path, "SECURITY.md", "## AI Security Considerations\nWe mitigate prompt injection.\n")
    assert ai.eval_llm_218a_po_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_po_002_pass(tmp_path: Path) -> None:
    (tmp_path / "prompts").mkdir()
    assert ai.eval_llm_218a_po_002(_ctx(tmp_path)).status == ControlStatus.PASS


def test_ps_001_pass_and_incomplete(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".oss-policy-kit/evidence/llm-release-integrity.json",
        json.dumps({"model_sha": "abc", "model_version": "1.2.3"}),
    )
    assert ai.eval_llm_218a_ps_001(_ctx(tmp_path)).status == ControlStatus.PASS
    _write(tmp_path, ".oss-policy-kit/evidence/llm-release-integrity.json", json.dumps({"model_sha": "abc"}))
    assert ai.eval_llm_218a_ps_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_ps_002_pass(tmp_path: Path) -> None:
    _write(tmp_path, "MODEL_CARD.md", "# Model card\n")
    assert ai.eval_llm_218a_ps_002(_ctx(tmp_path)).status == ControlStatus.PASS


def test_pw_001_pass(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "anthropic==0.30.0\n")
    assert ai.eval_llm_218a_pw_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_pw_002_pass(tmp_path: Path) -> None:
    _write(tmp_path, "tests/test_prompt_injection.py", "def test_x():\n    pass\n")
    assert ai.eval_llm_218a_pw_002(_ctx(tmp_path)).status == ControlStatus.PASS


def test_rv_001_pass(tmp_path: Path) -> None:
    _write(tmp_path, ".github/dependabot.yml", "updates:\n  - package-ecosystem: pip  # openai\n")
    assert ai.eval_llm_218a_rv_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_ai_act_001_pass(tmp_path: Path) -> None:
    _write(tmp_path, "README.md", "## Intended Purpose\nThis tool assists reviewers.\n")
    assert ai.eval_llm_ai_act_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_ai_act_002_pass(tmp_path: Path) -> None:
    _write(tmp_path, "src/filter.py", "def f():\n    return content_moderation()\n")
    assert ai.eval_llm_ai_act_002(_ctx(tmp_path)).status == ControlStatus.PASS


def test_output_filter_file_skips_vendored(tmp_path: Path) -> None:
    p = _write(tmp_path, "node_modules/x.py", "output_filter = 1\n")
    assert ai._file_has_output_filter(p) is False


def test_ai_act_003_pass_file_and_section(tmp_path: Path) -> None:
    _write(tmp_path, "risk-management.md", "# Risk management\n")
    assert ai.eval_llm_ai_act_003(_ctx(tmp_path)).status == ControlStatus.PASS
    # Section fallback (no dedicated file, but SECURITY.md heading).
    tmp2 = tmp_path / "alt"
    tmp2.mkdir()
    _write(tmp2, "SECURITY.md", "## Risk Assessment\nWe track AI risks.\n")
    assert ai.eval_llm_ai_act_003(_ctx(tmp2)).status == ControlStatus.PASS


# --------------------------------------------------------------------------- #
# AI-AGENT-001..010
# --------------------------------------------------------------------------- #


def test_agent_001_authenticated_and_disabled(tmp_path: Path) -> None:
    _write(tmp_path, "mcp.json", json.dumps({"auth": "oauth", "token_audience": "srv"}))
    assert ai.eval_ai_agent_001(_ctx(tmp_path)).status == ControlStatus.PASS
    tmp2 = tmp_path / "d"
    tmp2.mkdir()
    _write(tmp2, "mcp.json", '{"auth": "none"}')
    assert ai.eval_ai_agent_001(_ctx(tmp2)).status == ControlStatus.FAIL


def test_agent_001_present_no_signal(tmp_path: Path) -> None:
    _write(tmp_path, "mcp.json", json.dumps({"name": "srv"}))
    assert ai.eval_ai_agent_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_agent_002_pass_and_wildcard(tmp_path: Path) -> None:
    _write(tmp_path, "allowed_tools.yaml", "tools:\n  - read_file\n")
    assert ai.eval_ai_agent_002(_ctx(tmp_path)).status == ControlStatus.PASS
    tmp2 = tmp_path / "w"
    tmp2.mkdir()
    _write(tmp2, "allowed_tools.yaml", "allow_all_tools: true\n")
    assert ai.eval_ai_agent_002(_ctx(tmp2)).status == ControlStatus.FAIL


def test_agent_003_pass_and_hardcoded(tmp_path: Path) -> None:
    (tmp_path / "prompts").mkdir()
    _write(tmp_path, "CODEOWNERS", "/prompts/ @team\n")
    assert ai.eval_ai_agent_003(_ctx(tmp_path)).status == ControlStatus.PASS
    # No registry but hardcoded prompt -> FAIL.
    tmp2 = tmp_path / "h"
    tmp2.mkdir()
    _write(tmp2, "app.py", 'system_prompt = "you are an agent"\n')
    assert ai.eval_ai_agent_003(_ctx(tmp2)).status == ControlStatus.FAIL


def test_agent_003_registry_without_codeowners(tmp_path: Path) -> None:
    (tmp_path / "prompts").mkdir()
    assert ai.eval_ai_agent_003(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_agent_003_codeowners_not_covering(tmp_path: Path) -> None:
    (tmp_path / "prompts").mkdir()
    _write(tmp_path, "CODEOWNERS", "/src/ @team\n")
    assert ai.eval_ai_agent_003(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_agent_004_pass(tmp_path: Path) -> None:
    _write(tmp_path, "tests/test_prompt_injection_agent.py", "def test_x():\n    pass\n")
    assert ai.eval_ai_agent_004(_ctx(tmp_path)).status == ControlStatus.PASS


def test_agent_004_security_dir(tmp_path: Path) -> None:
    _write(tmp_path, "tests/security/test_misc.py", "def test_x():\n    pass\n")
    assert ai.eval_ai_agent_004(_ctx(tmp_path)).status == ControlStatus.PASS


def test_agent_005_pass(tmp_path: Path) -> None:
    _agent_evidence(
        tmp_path,
        "output-sanitization.json",
        {
            "schema_version": "ai-agent-baseline/v1",
            "control_id": "AI-AGENT-005",
            "attested_at": "2026-05-01",
            "attested_by": "platform team",
            "method": "regex+classifier",
            "applied_to": ["chat", "tool_output"],
            "bypass_review_process": "Two-maintainer approval required.",
        },
    )
    assert ai.eval_ai_agent_005(_ctx(tmp_path)).status == ControlStatus.PASS


def test_agent_005_incomplete(tmp_path: Path) -> None:
    _agent_evidence(
        tmp_path,
        "output-sanitization.json",
        {
            "schema_version": "ai-agent-baseline/v1",
            "control_id": "AI-AGENT-005",
            "attested_at": "2026-05-01",
            "attested_by": "team",
            "method": "x",
        },
    )
    assert ai.eval_ai_agent_005(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_agent_006_pass(tmp_path: Path) -> None:
    _write(tmp_path, "config.yaml", "rate_limit: 100\n")
    assert ai.eval_ai_agent_006(_ctx(tmp_path)).status == ControlStatus.PASS


def test_agent_007_pass(tmp_path: Path) -> None:
    _agent_evidence(
        tmp_path,
        "audit-log-config.json",
        {
            "schema_version": "ai-agent-baseline/v1",
            "control_id": "AI-AGENT-007",
            "attested_at": "2026-05-01",
            "attested_by": "team",
            "destination": "splunk",
            "retention_days": 365,
            "pii_redaction": True,
        },
    )
    assert ai.eval_ai_agent_007(_ctx(tmp_path)).status == ControlStatus.PASS


def test_agent_007_incomplete(tmp_path: Path) -> None:
    _agent_evidence(
        tmp_path,
        "audit-log-config.json",
        {
            "schema_version": "ai-agent-baseline/v1",
            "control_id": "AI-AGENT-007",
            "attested_at": "2026-05-01",
            "attested_by": "team",
            "destination": "splunk",
        },
    )
    assert ai.eval_ai_agent_007(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_agent_008_pass_and_antipattern(tmp_path: Path) -> None:
    _write(tmp_path, "config.yaml", "agent_identity: svc-account\n")
    assert ai.eval_ai_agent_008(_ctx(tmp_path)).status == ControlStatus.PASS
    tmp2 = tmp_path / "a"
    tmp2.mkdir()
    _write(tmp2, "config.yaml", "user_token_passthrough: true\n")
    assert ai.eval_ai_agent_008(_ctx(tmp2)).status == ControlStatus.FAIL


def test_agent_009_pass(tmp_path: Path) -> None:
    _agent_evidence(
        tmp_path,
        "memory-policy.json",
        {
            "schema_version": "ai-agent-baseline/v1",
            "control_id": "AI-AGENT-009",
            "attested_at": "2026-05-01",
            "attested_by": "team",
            "excluded_context_types": ["secrets", "pii"],
            "retention_policy": "30d rolling purge",
        },
    )
    assert ai.eval_ai_agent_009(_ctx(tmp_path)).status == ControlStatus.PASS


def test_agent_009_incomplete(tmp_path: Path) -> None:
    _agent_evidence(
        tmp_path,
        "memory-policy.json",
        {
            "schema_version": "ai-agent-baseline/v1",
            "control_id": "AI-AGENT-009",
            "attested_at": "2026-05-01",
            "attested_by": "team",
        },
    )
    assert ai.eval_ai_agent_009(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_agent_010_pinned(tmp_path: Path) -> None:
    _write(tmp_path, "config.yaml", "model: claude-sonnet-4-20250101\n")
    assert ai.eval_ai_agent_010(_ctx(tmp_path)).status == ControlStatus.PASS


def test_agent_010_unpinned_fail(tmp_path: Path) -> None:
    _write(tmp_path, "config.yaml", "model: gpt-4o\n")
    assert ai.eval_ai_agent_010(_ctx(tmp_path)).status == ControlStatus.FAIL


# --------------------------------------------------------------------------- #
# Annex IV section evaluators (via _annex_iv_section)
# --------------------------------------------------------------------------- #


def test_annex_iv_evaluators_pass(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".oss-policy-kit/evidence/ai-system-technical-doc.json",
        json.dumps(
            {
                "development_design": "Trained on X.",
                "performance_metrics": "F1=0.9",
                "cybersecurity_measures": "Threat model + pentest.",
                "lifecycle_changes": "v1 -> v2 migration.",
                "applied_standards": ["prEN 18286"],
                "post_market_monitoring_plan": "Quarterly drift review.",
            }
        ),
    )
    ctx = _ctx(tmp_path)
    assert ai.eval_llm_ai_act_dev_002(ctx).status == ControlStatus.PASS
    assert ai.eval_llm_ai_act_perf_004(ctx).status == ControlStatus.PASS
    assert ai.eval_llm_ai_act_cyber_006(ctx).status == ControlStatus.PASS
    assert ai.eval_llm_ai_act_change_007(ctx).status == ControlStatus.PASS
    assert ai.eval_llm_ai_act_std_008(ctx).status == ControlStatus.PASS
    assert ai.eval_llm_ai_act_pmm_009(ctx).status == ControlStatus.PASS


# --------------------------------------------------------------------------- #
# MCP evaluators (applicable via mcp.json)
# --------------------------------------------------------------------------- #


def test_mcp_tool_hash_001_pass(tmp_path: Path) -> None:
    _make_mcp(tmp_path)
    _write(
        tmp_path,
        ".oss-policy-kit/evidence/mcp-tool-descriptions.json",
        json.dumps({"tools": [{"name": "t", "sha256": "deadbeef"}]}),
    )
    assert ai.eval_mcp_tool_hash_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_mcp_tool_hash_001_no_evidence(tmp_path: Path) -> None:
    _make_mcp(tmp_path)
    assert ai.eval_mcp_tool_hash_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_mcp_confirm_001_pass(tmp_path: Path) -> None:
    _make_mcp(tmp_path)
    _write(tmp_path, "README.md", "Destructive operations require confirmation.\n")
    assert ai.eval_mcp_confirm_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_mcp_egress_001_pass(tmp_path: Path) -> None:
    _make_mcp(tmp_path)
    _write(tmp_path, "SECURITY.md", "We enforce an egress allowlist (deny by default).\n")
    assert ai.eval_mcp_egress_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_mcp_injection_test_001_pass(tmp_path: Path) -> None:
    _make_mcp(tmp_path)
    _write(tmp_path, "tests/test_mcp_injection.py", "def test_x():\n    pass\n")
    assert ai.eval_mcp_injection_test_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_mcp_injection_test_001_no_tests(tmp_path: Path) -> None:
    _make_mcp(tmp_path)
    assert ai.eval_mcp_injection_test_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_mcp_scope_001_pass(tmp_path: Path) -> None:
    _make_mcp(tmp_path)
    _write(tmp_path, "SECURITY.md", "Each MCP tool runs with least-privilege scopes.\n")
    assert ai.eval_mcp_scope_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_mcp_evaluators_not_applicable(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    assert ai.eval_mcp_tool_hash_001(ctx).status == ControlStatus.NOT_APPLICABLE
    assert ai.eval_mcp_confirm_001(ctx).status == ControlStatus.NOT_APPLICABLE
    assert ai.eval_mcp_egress_001(ctx).status == ControlStatus.NOT_APPLICABLE
    assert ai.eval_mcp_injection_test_001(ctx).status == ControlStatus.NOT_APPLICABLE
    assert ai.eval_mcp_scope_001(ctx).status == ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# OWASP ASI evaluators (applicable via agentic framework)
# --------------------------------------------------------------------------- #


def test_asi_goal_001_pass(tmp_path: Path) -> None:
    _make_agentic(tmp_path)
    (tmp_path / "prompts").mkdir()
    assert ai.eval_agent_asi_goal_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_asi_goal_001_no_prompt(tmp_path: Path) -> None:
    _make_agentic(tmp_path)
    assert ai.eval_agent_asi_goal_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_asi_tool_002_pass(tmp_path: Path) -> None:
    _make_agentic(tmp_path)
    _write(tmp_path, "README.md", "We document the tool allowlist with least-privilege scoping.\n")
    assert ai.eval_agent_asi_tool_002(_ctx(tmp_path)).status == ControlStatus.PASS


def test_asi_memory_006_pass(tmp_path: Path) -> None:
    _make_agentic(tmp_path)
    _write(tmp_path, "README.md", "Our memory purge policy clears stale context daily.\n")
    assert ai.eval_agent_asi_memory_006(_ctx(tmp_path)).status == ControlStatus.PASS


def test_asi_inter_007_pass(tmp_path: Path) -> None:
    _make_agentic(tmp_path)
    _write(tmp_path, "README.md", "Inter-agent traffic uses mTLS for mutual auth.\n")
    assert ai.eval_agent_asi_inter_007(_ctx(tmp_path)).status == ControlStatus.PASS


def test_asi_confirm_009_pass(tmp_path: Path) -> None:
    _make_agentic(tmp_path)
    _write(tmp_path, "README.md", "Destructive actions need human approval (human-in-the-loop).\n")
    assert ai.eval_agent_asi_confirm_009(_ctx(tmp_path)).status == ControlStatus.PASS


def test_asi_evaluators_not_applicable(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    assert ai.eval_agent_asi_goal_001(ctx).status == ControlStatus.NOT_APPLICABLE
    assert ai.eval_agent_asi_tool_002(ctx).status == ControlStatus.NOT_APPLICABLE
    assert ai.eval_agent_asi_memory_006(ctx).status == ControlStatus.NOT_APPLICABLE
    assert ai.eval_agent_asi_inter_007(ctx).status == ControlStatus.NOT_APPLICABLE
    assert ai.eval_agent_asi_confirm_009(ctx).status == ControlStatus.NOT_APPLICABLE
