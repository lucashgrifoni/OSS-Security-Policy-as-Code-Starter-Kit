"""Evaluators for the ``IAC-TF-*`` controls (Terraform / OpenTofu posture).

Each evaluator is a thin reader of ``.oss-policy-kit/evidence/iac-terraform.json``
(written by ``oss-policy-kit scan-iac``). The kit deliberately keeps the
evaluator side small: detection logic lives in
``infrastructure/iac/scanner.py``, the evidence schema is
``oss-policy-kit/evidence/iac-terraform/v1``, and the contract mirrors the
SAST adapter exactly:

- evidence file missing -> ``manual-review-required`` (cannot prove from a
  clone alone);
- ``status: not_available`` -> ``manual-review-required`` (parser missing);
- ``status: error`` / ``timeout`` -> ``manual-review-required`` with the
  diagnostic;
- ``status: ok`` and the rule has ``>= 1`` finding -> ``fail``;
- ``status: ok`` and zero findings for the rule -> ``pass``.

The evaluators are wired into ``EVALUATOR_REGISTRY`` via
``register_iac_evaluators()`` so the existing import-time registry stays
small and the package boundary is clean.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from oss_policy_kit.application._evidence_rules import (
    absent_technology_outcome,
    files_scanned_list,
    rule_finding_count,
    sample_finding_files,
    unread_sources_note,
)
from oss_policy_kit.application.evaluators_common import read_scanner_evidence
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

_EVIDENCE_FILENAME = "iac-terraform.json"
_SCHEMA_PREFIX = "oss-policy-kit/evidence/iac-terraform/"


def _evidence_path(repo_root: Path) -> Path:
    return repo_root / ".oss-policy-kit" / "evidence" / _EVIDENCE_FILENAME


def _load_evidence(repo_root: Path) -> tuple[dict[str, Any] | None, EvalOutcome | None]:
    """Return ``(payload, None)`` on success or ``(None, gating_outcome)`` on issue."""

    evidence = _evidence_path(repo_root)
    if not evidence.is_file():
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=("No Terraform IaC evidence file found. IaC posture cannot be verified from a clone alone."),
            remediation=(
                "Run `oss-policy-kit scan-iac --target .` (install the iac extra: `pip install 'oss-policy-kit[iac]'`)."
            ),
            evidence_sources=[],
            confidence="medium",
        )
    data = read_scanner_evidence(
        evidence, label="Terraform IaC", regenerate_cmd="oss-policy-kit scan-iac", schema_prefix=_SCHEMA_PREFIX
    )
    if isinstance(data, EvalOutcome):
        return None, data
    status = str(data.get("status", "unknown")).lower()
    if status == "not_available":
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=(
                "python-hcl2 was not available when scan-iac ran; the evidence is a presence stub, not a real IaC scan."
            ),
            remediation=(
                "Install the iac extra (`pip install 'oss-policy-kit[iac]'`) on the runner "
                "that executes `oss-policy-kit scan-iac` and re-run it."
            ),
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    if status in {"timeout", "error"}:
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Terraform IaC evidence reports status={status!r}; results are inconclusive.",
            remediation="Investigate diagnostics in the evidence file and re-run scan-iac.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    return data, None


def _make_iac_evaluator(rule_id: str, summary: str) -> Callable[[Any], EvalOutcome]:
    """Build an evaluator function for one ``IAC-TF-*`` rule.

    The closure captures the rule id and the human-readable summary so each
    of the 12 evaluators differs only by data, not by code.
    """

    def _eval(ctx: Any) -> EvalOutcome:
        evidence_path = _evidence_path(ctx.repo_root)
        data, gate = _load_evidence(ctx.repo_root)
        if gate is not None:
            return gate
        assert data is not None
        sources = [str(evidence_path.resolve())]
        files_scanned = files_scanned_list(data)
        if not files_scanned:
            blocked = absent_technology_outcome(data, technology="Terraform / OpenTofu", sources=sources)
            if blocked is not None:
                return blocked
            return EvalOutcome(
                status=ControlStatus.NOT_APPLICABLE,
                reason=("No Terraform / OpenTofu sources detected in repository; control is not applicable."),
                remediation="No action required. Add Terraform sources to enable IaC posture evaluation.",
                evidence_sources=sources,
                confidence="high",
            )
        count = rule_finding_count(data, rule_id)
        if count == 0:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=(
                    f"No {rule_id} findings detected across {len(files_scanned)} scanned Terraform source(s)."
                    f"{unread_sources_note(data)}"
                ),
                remediation="Re-scan after Terraform changes to keep evidence fresh.",
                evidence_sources=sources,
                confidence="high",
            )
        sample_files = sample_finding_files(data, rule_id)
        files_hint = f" Sources: {', '.join(sample_files)}." if sample_files else ""
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=(f"{rule_id} ({summary}) raised {count} finding(s) on the scanned Terraform sources.{files_hint}"),
            remediation=(
                "Review evaluation-report.md for details and remediate the listed resources, "
                "or document an explicit waiver in waivers.yaml with owner, justification, and expires_at."
            ),
            evidence_sources=sources,
            confidence="high",
        )

    _eval.__name__ = f"eval_iac_tf_{rule_id.split('-')[-1].lower()}"
    _eval.__doc__ = f"{rule_id}: {summary} (reads iac-terraform.json evidence)."
    return _eval


# Stable list of (rule_id, one-line summary) used both for evaluator
# generation and for the catalog title -- single source of truth.
IAC_TF_RULES: tuple[tuple[str, str], ...] = (
    ("IAC-TF-001", "Object storage configured for public access"),
    ("IAC-TF-002", "Security group exposes management port to 0.0.0.0/0"),
    ("IAC-TF-003", "IAM grants AdministratorAccess or Action=* + Resource=*"),
    ("IAC-TF-004", "Storage / RDS / EBS resource without encryption-at-rest"),
    ("IAC-TF-005", "Audit / access logging disabled on sensitive resources"),
    ("IAC-TF-006", "Default VPC / subnet / security group used in declarations"),
    ("IAC-TF-007", "Workload assigned a public IP without explicit intent"),
    ("IAC-TF-008", "AWS resources without owner/cost_center tags"),
    ("IAC-TF-009", "Terraform provider versions not pinned"),
    ("IAC-TF-010", "Terraform local backend used (no remote + encryption + locking)"),
    ("IAC-TF-011", "Production-naming data store missing lifecycle.prevent_destroy"),
    ("IAC-TF-012", "data.aws_iam_policy_document statement uses wildcard principal"),
)


def build_iac_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every IAC-TF rule."""

    return {rule_id: _make_iac_evaluator(rule_id, summary) for rule_id, summary in IAC_TF_RULES}
