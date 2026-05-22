"""Evaluators for the v5.7 ``IAC-PUL-*`` controls (Pulumi posture).

Thin readers of ``.oss-policy-kit/evidence/iac-pulumi.json`` written by
``oss-policy-kit scan-pulumi``. Mirrors ``evaluators_iac.py`` (Terraform)
exactly.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from oss_policy_kit.application._evidence_rules import (
    files_scanned_list,
    rule_finding_count,
    sample_finding_files,
)
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

_EVIDENCE_FILENAME = "iac-pulumi.json"
_SCHEMA_PREFIX = "oss-policy-kit/evidence/iac-pulumi/"


def _evidence_path(repo_root: Path) -> Path:
    return repo_root / ".oss-policy-kit" / "evidence" / _EVIDENCE_FILENAME


def _load_evidence(repo_root: Path) -> tuple[dict[str, Any] | None, EvalOutcome | None]:
    evidence = _evidence_path(repo_root)
    if not evidence.is_file():
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No Pulumi IaC evidence file found. Pulumi posture cannot be verified from a clone alone.",
            remediation="Run `oss-policy-kit scan-pulumi --target .` to produce evidence.",
            evidence_sources=[],
            confidence="medium",
        )
    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Could not parse Pulumi IaC evidence file: {exc}",
            remediation="Re-run `oss-policy-kit scan-pulumi` to regenerate the evidence file.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    schema = str(data.get("schema_version", ""))
    if not schema.startswith(_SCHEMA_PREFIX):
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Unexpected schema_version in {evidence.name}: {schema!r}. Expected prefix {_SCHEMA_PREFIX!r}.",
            remediation="Regenerate via `oss-policy-kit scan-pulumi` to align with the current contract.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    status = str(data.get("status", "unknown")).lower()
    if status in {"timeout", "error"}:
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Pulumi IaC evidence reports status={status!r}; results are inconclusive.",
            remediation="Investigate diagnostics in the evidence file and re-run scan-pulumi.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    return data, None


def _make_pulumi_evaluator(rule_id: str, summary: str) -> Callable[[Any], EvalOutcome]:
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
                reason="No Pulumi (Python) programs detected in repository; control is not applicable.",
                remediation="No action required. Add a Pulumi Python program to enable Pulumi posture evaluation.",
                evidence_sources=sources,
                confidence="high",
            )
        count = rule_finding_count(data, rule_id)
        if count == 0:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"No {rule_id} findings detected across {len(files_scanned)} scanned Pulumi program(s).",
                remediation="Re-scan after Pulumi changes to keep evidence fresh.",
                evidence_sources=sources,
                confidence="high",
            )
        sample_files = sample_finding_files(data, rule_id)
        files_hint = f" Sources: {', '.join(sample_files)}." if sample_files else ""
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"{rule_id} ({summary}) raised {count} finding(s) on the scanned Pulumi programs.{files_hint}",
            remediation=(
                "Review evaluation-report.md for details and remediate the listed resources, "
                "or document an explicit waiver in waivers.yaml with owner, reason, and expires_on."
            ),
            evidence_sources=sources,
            confidence="high",
        )

    _eval.__name__ = f"eval_iac_pul_{rule_id.split('-')[-1].lower()}"
    _eval.__doc__ = f"{rule_id}: {summary} (reads iac-pulumi.json evidence)."
    return _eval


IAC_PUL_RULES: tuple[tuple[str, str], ...] = (
    ("IAC-PUL-001", "Object storage configured for public access"),
    ("IAC-PUL-002", "Security group exposes management port to 0.0.0.0/0"),
    ("IAC-PUL-003", "IAM grants AdministratorAccess or Action=* + Resource=*"),
    ("IAC-PUL-004", "Storage / RDS / EBS resource without encryption-at-rest"),
    ("IAC-PUL-005", "Default VPC / subnet / security group used in declarations"),
    ("IAC-PUL-006", "Workload assigned a public IP without explicit intent"),
)


def build_iac_pulumi_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    return {rule_id: _make_pulumi_evaluator(rule_id, summary) for rule_id, summary in IAC_PUL_RULES}
