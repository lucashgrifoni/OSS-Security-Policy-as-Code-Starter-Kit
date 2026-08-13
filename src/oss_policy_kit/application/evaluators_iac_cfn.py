"""Evaluators for the v5.7 ``IAC-CFN-*`` controls (CloudFormation posture).

Thin readers of ``.oss-policy-kit/evidence/iac-cfn.json`` written by
``oss-policy-kit scan-cfn``. Mirrors ``evaluators_iac.py`` (Terraform)
exactly.

- evidence missing -> ``manual-review-required`` (cannot prove from a
  clone alone);
- ``status: error`` -> ``manual-review-required`` with the diagnostic;
- ``status: ok``, ``files_scanned`` empty -> ``not-applicable``;
- ``status: ok`` and the rule has ``>= 1`` finding -> ``fail``;
- ``status: ok`` and zero findings for the rule -> ``pass``.
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

_EVIDENCE_FILENAME = "iac-cfn.json"
_SCHEMA_PREFIX = "oss-policy-kit/evidence/iac-cfn/"


def _evidence_path(repo_root: Path) -> Path:
    return repo_root / ".oss-policy-kit" / "evidence" / _EVIDENCE_FILENAME


def _load_evidence(repo_root: Path) -> tuple[dict[str, Any] | None, EvalOutcome | None]:
    evidence = _evidence_path(repo_root)
    if not evidence.is_file():
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No CloudFormation IaC evidence file found. CFN posture cannot be verified from a clone alone.",
            remediation="Run `oss-policy-kit scan-cfn --target .` to produce evidence.",
            evidence_sources=[],
            confidence="medium",
        )
    data = read_scanner_evidence(
        evidence, label="CloudFormation IaC", regenerate_cmd="oss-policy-kit scan-cfn", schema_prefix=_SCHEMA_PREFIX
    )
    if isinstance(data, EvalOutcome):
        return None, data
    status = str(data.get("status", "unknown")).lower()
    if status in {"timeout", "error"}:
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"CloudFormation IaC evidence reports status={status!r}; results are inconclusive.",
            remediation="Investigate diagnostics in the evidence file and re-run scan-cfn.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    return data, None


def _make_cfn_evaluator(rule_id: str, summary: str) -> Callable[[Any], EvalOutcome]:
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
                reason="No CloudFormation templates detected in repository; control is not applicable.",
                remediation="No action required. Add CloudFormation templates to enable CFN posture evaluation.",
                evidence_sources=sources,
                confidence="high",
            )
        count = rule_finding_count(data, rule_id)
        if count == 0:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"No {rule_id} findings detected across {len(files_scanned)} scanned CloudFormation template(s)."
                ),
                remediation="Re-scan after CFN changes to keep evidence fresh.",
                evidence_sources=sources,
                confidence="high",
            )
        sample_files = sample_finding_files(data, rule_id)
        files_hint = f" Sources: {', '.join(sample_files)}." if sample_files else ""
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(
                f"{rule_id} ({summary}) raised {count} finding(s) on the scanned CloudFormation templates.{files_hint}"
            ),
            remediation=(
                "Review evaluation-report.md for details and remediate the listed resources, "
                "or document an explicit waiver in waivers.yaml with owner, reason, and expires_at."
            ),
            evidence_sources=sources,
            confidence="high",
        )

    _eval.__name__ = f"eval_iac_cfn_{rule_id.split('-')[-1].lower()}"
    _eval.__doc__ = f"{rule_id}: {summary} (reads iac-cfn.json evidence)."
    return _eval


IAC_CFN_RULES: tuple[tuple[str, str], ...] = (
    ("IAC-CFN-001", "S3 bucket configured for public access"),
    ("IAC-CFN-002", "Security group exposes management port to 0.0.0.0/0"),
    ("IAC-CFN-003", "IAM grants AdministratorAccess or Action=* + Resource=*"),
    ("IAC-CFN-004", "Storage / RDS / EBS resource without encryption-at-rest"),
    ("IAC-CFN-005", "Audit / access logging disabled on sensitive resources"),
    ("IAC-CFN-006", "Workload assigned a public IP without explicit intent"),
)


def build_iac_cfn_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    return {rule_id: _make_cfn_evaluator(rule_id, summary) for rule_id, summary in IAC_CFN_RULES}
