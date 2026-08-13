"""Evaluators for the v5.7 ``IAC-BICEP-*`` controls (Bicep posture).

Thin readers of ``.oss-policy-kit/evidence/iac-bicep.json`` written by
``oss-policy-kit scan-bicep``. Mirrors ``evaluators_iac.py`` (Terraform)
exactly.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from oss_policy_kit.application._evidence_rules import (
    files_scanned_list,
    rule_finding_count,
    sample_finding_files,
)
from oss_policy_kit.application.evaluators_common import read_scanner_evidence
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

_EVIDENCE_FILENAME = "iac-bicep.json"
_SCHEMA_PREFIX = "oss-policy-kit/evidence/iac-bicep/"


def _evidence_path(repo_root: Path) -> Path:
    return repo_root / ".oss-policy-kit" / "evidence" / _EVIDENCE_FILENAME


def _load_evidence(repo_root: Path) -> tuple[dict[str, Any] | None, EvalOutcome | None]:
    evidence = _evidence_path(repo_root)
    if not evidence.is_file():
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No Bicep IaC evidence file found. Bicep posture cannot be verified from a clone alone.",
            remediation="Run `oss-policy-kit scan-bicep --target .` to produce evidence.",
            evidence_sources=[],
            confidence="medium",
        )
    data = read_scanner_evidence(
        evidence, label="Bicep IaC", regenerate_cmd="oss-policy-kit scan-bicep", schema_prefix=_SCHEMA_PREFIX
    )
    if isinstance(data, EvalOutcome):
        return None, data
    status = str(data.get("status", "unknown")).lower()
    if status in {"timeout", "error"}:
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Bicep IaC evidence reports status={status!r}; results are inconclusive.",
            remediation="Investigate diagnostics in the evidence file and re-run scan-bicep.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    return data, None


def _make_bicep_evaluator(rule_id: str, summary: str) -> Callable[[Any], EvalOutcome]:
    def _eval(ctx: Any) -> EvalOutcome:
        evidence_path = _evidence_path(ctx.repo_root)
        data, gate = _load_evidence(ctx.repo_root)
        if gate is not None:
            return gate
        assert data is not None
        sources = [str(evidence_path.resolve())]
        files_scanned = files_scanned_list(data)
        if not files_scanned:
            return EvalOutcome(
                status=ControlStatus.NOT_APPLICABLE,
                reason="No Bicep files detected in repository; control is not applicable.",
                remediation="No action required. Add Bicep files to enable Bicep posture evaluation.",
                evidence_sources=sources,
                confidence="high",
            )
        count = rule_finding_count(data, rule_id)
        if count == 0:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"No {rule_id} findings detected across {len(files_scanned)} scanned Bicep file(s).",
                remediation="Re-scan after Bicep changes to keep evidence fresh.",
                evidence_sources=sources,
                confidence="high",
            )
        sample_files = sample_finding_files(data, rule_id)
        files_hint = f" Sources: {', '.join(sample_files)}." if sample_files else ""
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"{rule_id} ({summary}) raised {count} finding(s) on the scanned Bicep files.{files_hint}",
            remediation=(
                "Review evaluation-report.md for details and remediate the listed resources, "
                "or document an explicit waiver in waivers.yaml with owner, reason, and expires_at."
            ),
            evidence_sources=sources,
            confidence="high",
        )

    _eval.__name__ = f"eval_iac_bicep_{rule_id.split('-')[-1].lower()}"
    _eval.__doc__ = f"{rule_id}: {summary} (reads iac-bicep.json evidence)."
    return _eval


IAC_BICEP_RULES: tuple[tuple[str, str], ...] = (
    ("IAC-BICEP-001", "Storage account configured for public access"),
    ("IAC-BICEP-002", "NSG rule allows management port inbound from '*'"),
    ("IAC-BICEP-003", "Role assignment grants Owner / Contributor / User Access Admin"),
    ("IAC-BICEP-004", "Storage / SQL / Disk resource without encryption-at-rest"),
    ("IAC-BICEP-005", "Sensitive resource has no diagnosticSettings paired"),
    ("IAC-BICEP-006", "Direct public IP declared without documented intent"),
)


def build_iac_bicep_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    return {rule_id: _make_bicep_evaluator(rule_id, summary) for rule_id, summary in IAC_BICEP_RULES}
