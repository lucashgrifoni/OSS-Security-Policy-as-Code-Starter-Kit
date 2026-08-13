"""Regression: a mis-encoded (UTF-16) evidence JSON must not crash evaluation.

Raio-x bugs #3 and #4 (group evaluator-evidence-read): the evidence-read helpers
guarded their ``read_text(encoding="utf-8")`` with
``contextlib.suppress(OSError, json.JSONDecodeError)``. A UTF-16-encoded evidence
file (BOM ``\\xff\\xfe``) raises ``UnicodeDecodeError`` at read time, which is NOT a
subclass of either suppressed type, so the exception escaped the guardless engine
loop to a top-level ``Unexpected error`` (exit 3) and NO report was written.

The fix adds ``UnicodeDecodeError`` to every such suppress across the owned
evaluators so the affected control degrades honestly (manual-review-required /
unreadable) and a full report is still produced.

Each test below FAILS before the fix (raises ``UnicodeDecodeError``) and passes
after. The subprocess tests additionally prove the real CLI no longer exits 3 and
still writes ``evaluation-report.json``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import _shared as s
from oss_policy_kit.application.evaluators import ai, cra, github, gitlab, governance, supply_chain
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_KIT = ".oss-policy-kit"
# Valid JSON content, deliberately written with the wrong (UTF-16) encoding.
_UTF16_JSON = '{"required_status_checks": true, "min_approvers": 2}'


def _ctx(tmp_path: Path) -> s.EvalContext:
    return s.EvalContext(
        repo_root=tmp_path,
        profile_id="test-profile",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_utf16(tmp_path: Path, rel: str, content: str = _UTF16_JSON) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    # UTF-16 with BOM: read_text(encoding="utf-8") raises UnicodeDecodeError on \xff.
    p.write_bytes(content.encode("utf-16"))
    assert p.read_bytes()[:2] == b"\xff\xfe"
    return p


# --------------------------------------------------------------------------- #
# Bug #3 — every listed evidence-read control-evaluator must degrade, not crash.
# One parametrization per owned suppress site that lives inside a control eval.
# --------------------------------------------------------------------------- #


def _prep_mcp_tool_hash(tmp_path: Path) -> None:
    # eval_mcp_tool_hash_001 only reaches its read site when the repo is an MCP server.
    (tmp_path / "mcp.json").write_text(json.dumps({"name": "srv"}), encoding="utf-8")
    _write_utf16(tmp_path, f"{_KIT}/evidence/mcp-tool-descriptions.json")


def _prep_osps(tmp_path: Path) -> None:
    _write_utf16(tmp_path, f"{_KIT}/evidence/scorecard-osps.json")


_MRR = ControlStatus.MANUAL_REVIEW_REQUIRED

# id, prep(tmp_path) -> writes UTF-16 evidence, invoke(tmp_path) -> EvalOutcome,
# expected honest-degradation status (never PASS, never a crash).
_EVAL_CASES: list[tuple[str, Callable[[Path], object], Callable[[Path], s.EvalOutcome], ControlStatus]] = [
    (
        "ai.eval_llm_218a_ps_001",  # ai.py:111
        lambda t: _write_utf16(t, f"{_KIT}/evidence/llm-release-integrity.json"),
        lambda t: ai.eval_llm_218a_ps_001(_ctx(t)),
        _MRR,
    ),
    (
        "ai.eval_mcp_tool_hash_001",  # ai.py:732
        _prep_mcp_tool_hash,
        lambda t: ai.eval_mcp_tool_hash_001(_ctx(t)),
        _MRR,
    ),
    (
        "cra.eval_cra_art14_coord_002",  # cra.py:106
        lambda t: _write_utf16(t, f"{_KIT}/evidence/disclosure-policy.json"),
        lambda t: cra.eval_cra_art14_coord_002(_ctx(t)),
        _MRR,
    ),
    (
        "cra.eval_cisa_sbd_secrets_005",  # cra.py:360
        lambda t: _write_utf16(t, f"{_KIT}/evidence/sast/gitleaks.sarif.json"),
        lambda t: cra.eval_cisa_sbd_secrets_005(_ctx(t)),
        _MRR,
    ),
    (
        "gitlab.eval_gl_pipe_011",  # gitlab.py:391
        lambda t: _write_utf16(t, f"{_KIT}/evidence/gitlab-mr-rules.json"),
        lambda t: gitlab.eval_gl_pipe_011(_ctx(t)),
        _MRR,
    ),
    (
        "governance.eval_osps_scorecard_v6_001",  # governance.py:1509
        _prep_osps,
        lambda t: governance.eval_osps_scorecard_v6_001(_ctx(t)),
        _MRR,
    ),
    (
        "supply_chain.eval_worm_postinstall_001",  # supply_chain.py:247 (package.json)
        lambda t: _write_utf16(t, "package.json"),
        lambda t: supply_chain.eval_worm_postinstall_001(_ctx(t)),
        _MRR,
    ),
    (
        "supply_chain.eval_slsa_src_003",  # supply_chain.py:489
        lambda t: _write_utf16(t, f"{_KIT}/evidence/branch-protection.json"),
        lambda t: supply_chain.eval_slsa_src_003(_ctx(t)),
        _MRR,
    ),
    (
        # The one row that used to expect `fail`, and the asymmetry was written right here as if
        # it were a design ("present-but-unverifiable fails closed"). It was not: ADR-045 settled
        # that a control which cannot READ its evidence reports `manual-review-required`, and this
        # control reached that state through a silent `contextlib.suppress` fall-through rather
        # than an explicit error branch, which is why the ADR-045 sweep did not find it.
        "supply_chain.eval_slsa_src_004",  # supply_chain.py, via _slsa_branch_protections
        lambda t: _write_utf16(t, f"{_KIT}/evidence/branch-protection.json"),
        lambda t: supply_chain.eval_slsa_src_004(_ctx(t)),
        _MRR,
    ),
]


@pytest.mark.parametrize("case_id, prep, invoke, expected", _EVAL_CASES, ids=[c[0] for c in _EVAL_CASES])
def test_utf16_evidence_degrades_not_crashes(
    tmp_path: Path,
    case_id: str,
    prep: Callable[[Path], object],
    invoke: Callable[[Path], s.EvalOutcome],
    expected: ControlStatus,
) -> None:
    """Bug #3: a UTF-16 evidence file must NOT raise UnicodeDecodeError.

    Before the fix the read raised UnicodeDecodeError (escaping the suppress and
    aborting the whole run with exit 3); after the fix the control degrades
    honestly and never silently PASSes. Every row expects `manual-review-required`:
    a control that cannot read its evidence has not established that the control is
    unsatisfied, so it must not report `fail` either (ADR-045).
    """
    prep(tmp_path)
    outcome = invoke(tmp_path)  # must not raise
    assert outcome.status is expected, (
        f"{case_id}: unreadable evidence must degrade to {expected}, got {outcome.status}"
    )
    assert outcome.status is not ControlStatus.PASS  # never silently clean


def test_shared_branch_protection_helper_utf16(tmp_path: Path) -> None:
    """Bug #3: _shared._branch_protection_evidence (_shared.py:1854) tolerates UTF-16."""
    _write_utf16(tmp_path, f"{_KIT}/evidence/branch-protection.json")
    data, path = s._branch_protection_evidence(_ctx(tmp_path))  # must not raise
    assert data is None
    assert path.name == "branch-protection.json"


def test_github_provenance_helper_utf16(tmp_path: Path) -> None:
    """Bug #3: github._gh_provenance_verification_recorded (github.py:290) tolerates UTF-16."""
    evidence = _write_utf16(tmp_path, f"{_KIT}/evidence/provenance-artifact.json")
    assert github._gh_provenance_verification_recorded(evidence) is False  # must not raise


def test_governance_sbom_format_helper_utf16(tmp_path: Path) -> None:
    """Bug #3: governance._evidence_sbom_format (governance.py:703) tolerates UTF-16."""
    evidence = _write_utf16(tmp_path, f"{_KIT}/evidence/release-hardening.json")
    assert governance._evidence_sbom_format(evidence) is None  # must not raise


# --------------------------------------------------------------------------- #
# Bug #4 — Annex-IV LLM technical-doc read (ai-system-technical-doc.json).
# --------------------------------------------------------------------------- #


def test_shared_load_ai_system_doc_utf16(tmp_path: Path) -> None:
    """Bug #4: _shared._load_ai_system_doc (_shared.py:1750) tolerates UTF-16."""
    _write_utf16(tmp_path, f"{_KIT}/evidence/ai-system-technical-doc.json")
    data, path = s._load_ai_system_doc(_ctx(tmp_path))  # must not raise
    assert data is None
    assert path.name == "ai-system-technical-doc.json"


def test_annex_iv_control_utf16_ai_system_doc(tmp_path: Path) -> None:
    """Bug #4: an Annex-IV LLM control degrades (not crashes) on a UTF-16 doc."""
    _write_utf16(tmp_path, f"{_KIT}/evidence/ai-system-technical-doc.json")
    outcome = ai.eval_llm_ai_act_dev_002(_ctx(tmp_path))  # must not raise
    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# End-to-end: the real CLI must not exit 3 and must still write a full report.
# --------------------------------------------------------------------------- #


def _run_evaluate(target: Path, profile: str, out: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "NO_COLOR": "1", "COLUMNS": "200", "TERM": "dumb"}
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(target),
            "--profile",
            profile,
            "--output-dir",
            str(out),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def test_cli_utf16_branch_protection_no_exit3_bug3(tmp_path: Path) -> None:
    """Bug #3 end-to-end: UTF-16 branch-protection.json no longer aborts with exit 3."""
    _write_utf16(tmp_path, f"{_KIT}/evidence/branch-protection.json")
    out = tmp_path / "out"
    result = _run_evaluate(tmp_path, "slsa-source-l1-1", out)
    assert result.returncode != 3, f"exit 3 regression:\n{result.stdout}\n{result.stderr}"
    assert "Unexpected error" not in (result.stdout + result.stderr)
    assert (out / "evaluation-report.json").is_file(), "no report written"


def test_cli_utf16_ai_system_doc_no_exit3_bug4(tmp_path: Path) -> None:
    """Bug #4 end-to-end: UTF-16 ai-system-technical-doc.json no longer aborts with exit 3."""
    _write_utf16(
        tmp_path,
        f"{_KIT}/evidence/ai-system-technical-doc.json",
        '{"intended_purpose": "demo"}',
    )
    out = tmp_path / "out"
    result = _run_evaluate(tmp_path, "cra-eu-ai-act-art11-1", out)
    assert result.returncode != 3, f"exit 3 regression:\n{result.stdout}\n{result.stderr}"
    assert "Unexpected error" not in (result.stdout + result.stderr)
    assert (out / "evaluation-report.json").is_file(), "no report written"
