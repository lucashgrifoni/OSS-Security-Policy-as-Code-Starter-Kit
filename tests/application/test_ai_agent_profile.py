"""AI agent source-side baseline profile and controls."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.evaluators import (
    EVALUATOR_REGISTRY,
    eval_ai_agent_001,
    eval_ai_agent_002,
    eval_ai_agent_003,
    eval_ai_agent_004,
    eval_ai_agent_005,
    eval_ai_agent_006,
    eval_ai_agent_007,
    eval_ai_agent_008,
    eval_ai_agent_009,
    eval_ai_agent_010,
)
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus

AI_AGENT_CONTROLS = tuple(f"AI-AGENT-{n:03d}" for n in range(1, 11))


def _write_agent_evidence(repo: Path) -> None:
    evidence = repo / ".oss-policy-kit" / "evidence" / "ai-agent"
    evidence.mkdir(parents=True)
    (evidence / "output-sanitization.json").write_text(
        """{
  "schema_version": "ai-agent-baseline/v1",
  "control_id": "AI-AGENT-005",
  "attested_at": "2026-05-19",
  "attested_by": "test",
  "method": "central response sanitizer",
  "applied_to": ["final_answer"],
  "bypass_review_process": "security review"
}
""",
        encoding="utf-8",
    )
    (evidence / "audit-log-config.json").write_text(
        """{
  "schema_version": "ai-agent-baseline/v1",
  "control_id": "AI-AGENT-007",
  "attested_at": "2026-05-19",
  "attested_by": "test",
  "destination": "siem",
  "retention_days": 90,
  "pii_redaction": true
}
""",
        encoding="utf-8",
    )
    (evidence / "memory-policy.json").write_text(
        """{
  "schema_version": "ai-agent-baseline/v1",
  "control_id": "AI-AGENT-009",
  "attested_at": "2026-05-19",
  "attested_by": "test",
  "excluded_context_types": ["secrets", "tokens"],
  "retention_policy": "ephemeral only"
}
""",
        encoding="utf-8",
    )


def test_ai_agent_controls_present_in_catalog_and_registry() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")

    for cid in AI_AGENT_CONTROLS:
        assert cid in catalog
        assert cid in EVALUATOR_REGISTRY
        assert catalog[cid].lifecycle == "experimental"


def test_ai_agent_profile_includes_all_controls() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "ai-agent-baseline-1")

    for cid in AI_AGENT_CONTROLS:
        assert cid in spec.control_ids


def test_ai_agent_001_fails_when_mcp_auth_disabled(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text('{"auth": "none", "tools": ["read"]}\n', encoding="utf-8")

    out = eval_ai_agent_001(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.FAIL
    assert "disables" in out.reason


def test_ai_agent_002_fails_on_allow_all_tools(tmp_path: Path) -> None:
    (tmp_path / "allowed_tools.yaml").write_text("tools: all\n", encoding="utf-8")

    out = eval_ai_agent_002(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.FAIL
    assert "allow-all" in out.reason


def test_ai_agent_003_fails_on_hardcoded_system_prompt_without_registry(tmp_path: Path) -> None:
    src = tmp_path / "agent.py"
    src.write_text('system_prompt = "You are a release agent"\n', encoding="utf-8")

    out = eval_ai_agent_003(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.FAIL
    assert "hardcoded" in out.reason


def test_ai_agent_004_passes_with_prompt_injection_test(tmp_path: Path) -> None:
    test_file = tmp_path / "tests" / "test_prompt_injection.py"
    test_file.parent.mkdir()
    test_file.write_text("def test_prompt_injection(): pass\n", encoding="utf-8")

    out = eval_ai_agent_004(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.PASS


def test_ai_agent_evidence_backed_controls_pass_with_valid_evidence(tmp_path: Path) -> None:
    _write_agent_evidence(tmp_path)

    for eval_fn in (eval_ai_agent_005, eval_ai_agent_007, eval_ai_agent_009):
        out = eval_fn(SimpleNamespace(repo_root=tmp_path))
        assert out.status is ControlStatus.PASS


def test_ai_agent_006_passes_with_quota_config(tmp_path: Path) -> None:
    (tmp_path / "agent.yaml").write_text("tokens_per_minute: 120000\n", encoding="utf-8")

    out = eval_ai_agent_006(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.PASS


def test_ai_agent_008_fails_on_token_passthrough(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text("USER_TOKEN_PASSTHROUGH = True\n", encoding="utf-8")

    out = eval_ai_agent_008(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.FAIL


def test_ai_agent_010_fails_on_floating_model_alias(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text('MODEL = "gpt-4o"\n', encoding="utf-8")

    out = eval_ai_agent_010(SimpleNamespace(repo_root=tmp_path))

    assert out.status is ControlStatus.FAIL


def test_ai_agent_fixture_passes_profile() -> None:
    repo = Path("examples/ai-agent-baseline-repo").resolve()
    root = bundled_kit_root()
    spec = load_profile_by_id(root, "ai-agent-baseline-1")
    catalog = load_catalog(root / "controls" / "catalog.yaml")

    report = evaluate_repository(repo, spec, catalog, waiver_outcome=None, scorecard=None)
    statuses = {r.control_id: r.status for r in report.results}

    assert {cid: statuses[cid] for cid in AI_AGENT_CONTROLS} == {
        cid: ControlStatus.PASS for cid in AI_AGENT_CONTROLS
    }
