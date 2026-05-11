"""Evaluators for the v5.6 ``K8S-*`` controls (Kubernetes manifest posture).

Mirrors ``evaluators_iac.py`` exactly: each evaluator is a thin reader of
``.oss-policy-kit/evidence/k8s-baseline.json`` (written by
``oss-policy-kit scan-k8s``).

- evidence missing -> ``manual-review-required`` (cannot prove from a
  clone alone);
- ``status: error`` -> ``manual-review-required`` with the diagnostic;
- ``status: ok`` and the rule has ``>= 1`` finding -> ``fail``;
- ``status: ok`` and zero findings for the rule -> ``pass``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

_EVIDENCE_FILENAME = "k8s-baseline.json"
_SCHEMA_PREFIX = "oss-policy-kit/evidence/k8s-baseline/"


def _evidence_path(repo_root: Path) -> Path:
    return repo_root / ".oss-policy-kit" / "evidence" / _EVIDENCE_FILENAME


def _load_evidence(repo_root: Path) -> tuple[dict[str, Any] | None, EvalOutcome | None]:
    evidence = _evidence_path(repo_root)
    if not evidence.is_file():
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason="No Kubernetes evidence file found. K8s posture cannot be verified from a clone alone.",
            remediation="Run `oss-policy-kit scan-k8s --target .` to produce evidence.",
            evidence_sources=[],
            confidence="medium",
        )
    try:
        data = json.loads(evidence.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Could not parse Kubernetes evidence file: {exc}",
            remediation="Re-run `oss-policy-kit scan-k8s` to regenerate the evidence file.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    schema = str(data.get("schema_version", ""))
    if not schema.startswith(_SCHEMA_PREFIX):
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Unexpected schema_version in {evidence.name}: {schema!r}. Expected prefix {_SCHEMA_PREFIX!r}.",
            remediation="Regenerate via `oss-policy-kit scan-k8s` to align with the current contract.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    status = str(data.get("status", "unknown")).lower()
    if status in {"timeout", "error"}:
        return None, EvalOutcome(
            status=ControlStatus.MANUAL_REVIEW_REQUIRED,
            reason=f"Kubernetes evidence reports status={status!r}; results are inconclusive.",
            remediation="Investigate diagnostics in the evidence file and re-run scan-k8s.",
            evidence_sources=[str(evidence.resolve())],
            confidence="low",
        )
    return data, None


def _make_k8s_evaluator(rule_id: str, summary: str) -> Callable[[Any], EvalOutcome]:
    """Build an evaluator function for one ``K8S-*`` rule."""

    def _eval(ctx: Any) -> EvalOutcome:
        evidence_path = _evidence_path(ctx.repo_root)
        data, gate = _load_evidence(ctx.repo_root)
        if gate is not None:
            return gate
        assert data is not None
        files_scanned = data.get("files_scanned") or []
        if not isinstance(files_scanned, list):
            files_scanned = []
        sources = [str(evidence_path.resolve())]
        if not files_scanned:
            return EvalOutcome(
                status=ControlStatus.NOT_APPLICABLE,
                reason=("No Kubernetes manifests detected in repository; control is not applicable."),
                remediation="No action required. Add Kubernetes manifests to enable K8s posture evaluation.",
                evidence_sources=sources,
                confidence="high",
            )
        by_rule = data.get("findings_by_rule") or {}
        if not isinstance(by_rule, dict):
            by_rule = {}
        count = int(by_rule.get(rule_id, 0) or 0)
        if count == 0:
            return EvalOutcome(
                status=ControlStatus.PASS,
                reason=f"No {rule_id} findings detected across {len(files_scanned)} scanned Kubernetes manifest(s).",
                remediation="Re-scan after manifest changes to keep evidence fresh.",
                evidence_sources=sources,
                confidence="high",
            )
        sample_files: list[str] = []
        for f in data.get("findings", []) or []:
            if isinstance(f, dict) and f.get("rule_id") == rule_id:
                file_ = f.get("file")
                if isinstance(file_, str) and file_ and file_ not in sample_files:
                    sample_files.append(file_)
            if len(sample_files) >= 3:
                break
        files_hint = f" Sources: {', '.join(sample_files)}." if sample_files else ""
        return EvalOutcome(
            status=ControlStatus.FAIL,
            reason=f"{rule_id} ({summary}) raised {count} finding(s) on the scanned Kubernetes manifests.{files_hint}",
            remediation=(
                "Review evaluation-report.md for details and remediate the listed manifests, "
                "or document an explicit waiver in waivers.yaml with owner, reason, and expires_on."
            ),
            evidence_sources=sources,
            confidence="high",
        )

    _eval.__name__ = f"eval_k8s_{rule_id.split('-', 1)[1].replace('-', '_').lower()}"
    _eval.__doc__ = f"{rule_id}: {summary} (reads k8s-baseline.json evidence)."
    return _eval


K8S_RULES: tuple[tuple[str, str], ...] = (
    ("K8S-PSS-001", "Privileged container"),
    ("K8S-PSS-002", "Pod uses hostPID=true"),
    ("K8S-PSS-003", "Pod uses hostNetwork=true"),
    ("K8S-PSS-004", "Pod mounts hostPath volume"),
    ("K8S-PSS-005", "Container adds Linux capabilities"),
    ("K8S-PSS-006", "Container may run as root (runAsNonRoot/runAsUser not pinned)"),
    ("K8S-PSS-007", "Container allowPrivilegeEscalation not set to false"),
    ("K8S-PSS-008", "Container readOnlyRootFilesystem not true"),
    ("K8S-PSS-009", "Pod automountServiceAccountToken not pinned"),
    ("K8S-PSS-010", "Container image uses latest / unpinned tag"),
    ("K8S-RBAC-001", "Role / ClusterRole grants wildcard verb '*'"),
    ("K8S-RBAC-002", "RoleBinding / ClusterRoleBinding binds to cluster-admin"),
    ("K8S-RBAC-003", "Workload uses default ServiceAccount in default namespace"),
    ("K8S-RBAC-004", "ClusterRole grants wildcard resource '*'"),
    ("K8S-RBAC-005", "Role / ClusterRole grants broad read on secrets"),
    ("K8S-NETPOL-001", "Namespace with workloads but no NetworkPolicy"),
)


def build_k8s_evaluators() -> dict[str, Callable[[Any], EvalOutcome]]:
    """Return ``{control_id: evaluator}`` for every K8S-* rule."""

    return {rule_id: _make_k8s_evaluator(rule_id, summary) for rule_id, summary in K8S_RULES}
