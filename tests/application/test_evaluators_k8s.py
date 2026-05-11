"""Tests for the v5.6 K8S-* controls (Kubernetes manifest posture)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators_k8s import K8S_RULES, build_k8s_evaluators
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.k8s.scanner import (
    EVIDENCE_FILENAME,
    EVIDENCE_SCHEMA_VERSION,
    all_rule_ids,
    render_evidence_payload,
    run_scan,
    write_evidence,
)

# ---------------------------------------------------------------------------
# Catalog + registry + profile wiring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id,_summary", list(K8S_RULES))
def test_k8s_rule_in_catalog(rule_id: str, _summary: str) -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    assert rule_id in catalog
    spec = catalog[rule_id]
    assert spec.lifecycle == "experimental"
    assert spec.assurance == "evidence-backed"
    assert spec.category == "kubernetes"


@pytest.mark.parametrize("rule_id,_summary", list(K8S_RULES))
def test_k8s_rule_registered(rule_id: str, _summary: str) -> None:
    assert rule_id in EVALUATOR_REGISTRY


def test_kubernetes_baseline_1_loads_with_full_pack() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "kubernetes-baseline-1")
    assert spec.id == "kubernetes-baseline-1"
    pack_ids = {rid for rid, _ in K8S_RULES}
    bundled_pack = pack_ids & set(spec.control_ids)
    assert bundled_pack == pack_ids
    assert build_k8s_evaluators().keys() == pack_ids
    assert set(all_rule_ids()) == pack_ids


# ---------------------------------------------------------------------------
# Evidence schema + status invariants
# ---------------------------------------------------------------------------


def test_run_scan_on_empty_repo_writes_ok_evidence(tmp_path: Path) -> None:
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    saved = (tmp_path / ".oss-policy-kit" / "evidence" / EVIDENCE_FILENAME).read_text(encoding="utf-8")
    parsed = json.loads(saved)
    assert parsed["schema_version"] == EVIDENCE_SCHEMA_VERSION
    assert parsed["status"] == "ok"
    assert parsed["findings_total"] == 0
    assert set(parsed["findings_by_rule"].keys()) == set(all_rule_ids())


def test_helm_template_files_are_skipped(tmp_path: Path) -> None:
    chart_dir = tmp_path / "charts" / "templates"
    chart_dir.mkdir(parents=True)
    (chart_dir / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Values.name }}\nspec: {}\n",
        encoding="utf-8",
    )
    outcome = run_scan(tmp_path)
    assert any("templates/deployment.yaml" in p for p in outcome.helm_templates_skipped)
    assert not outcome.findings


# ---------------------------------------------------------------------------
# Per-rule fixtures (vulnerable + hardened pairs)
# ---------------------------------------------------------------------------


_VULNERABLE_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
  namespace: default
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      volumes:
        - name: host
          hostPath:
            path: /
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
            capabilities:
              add: ["NET_ADMIN"]
"""

_HARDENED_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
  namespace: prod
spec:
  template:
    spec:
      automountServiceAccountToken: false
      serviceAccountName: app-sa
      containers:
        - name: app
          image: nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
"""


def _write(tmp_path: Path, name: str, body: str) -> None:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_vulnerable_deployment_triggers_pss_rules(tmp_path: Path) -> None:
    _write(tmp_path, "k8s/bad.yaml", _VULNERABLE_DEPLOYMENT)
    outcome = run_scan(tmp_path)
    triggered = {f.rule_id for f in outcome.findings}
    expected = {
        "K8S-PSS-001",
        "K8S-PSS-002",
        "K8S-PSS-003",
        "K8S-PSS-004",
        "K8S-PSS-005",
        "K8S-PSS-006",
        "K8S-PSS-007",
        "K8S-PSS-008",
        "K8S-PSS-009",
        "K8S-PSS-010",
        "K8S-RBAC-003",
        "K8S-NETPOL-001",
    }
    assert expected <= triggered, f"missing rules: {expected - triggered}"


def test_hardened_deployment_only_triggers_netpol(tmp_path: Path) -> None:
    _write(tmp_path, "k8s/good.yaml", _HARDENED_DEPLOYMENT)
    outcome = run_scan(tmp_path)
    triggered = {f.rule_id for f in outcome.findings}
    # Hardened workload still triggers K8S-NETPOL-001 (no NetworkPolicy declared) by design.
    assert triggered == {"K8S-NETPOL-001"}


_DENY_ALL_NETPOL = (
    "apiVersion: networking.k8s.io/v1\n"
    "kind: NetworkPolicy\n"
    "metadata:\n"
    "  name: deny-all\n"
    "  namespace: prod\n"
    "spec:\n"
    "  podSelector: {}\n"
    "  policyTypes: [Ingress]\n"
)


def test_netpol_present_silences_netpol_001(tmp_path: Path) -> None:
    _write(tmp_path, "k8s/good.yaml", _HARDENED_DEPLOYMENT)
    _write(tmp_path, "k8s/netpol.yaml", _DENY_ALL_NETPOL)
    outcome = run_scan(tmp_path)
    triggered = {f.rule_id for f in outcome.findings}
    assert "K8S-NETPOL-001" not in triggered


_RBAC_WILDCARD_ROLE = (
    "apiVersion: rbac.authorization.k8s.io/v1\n"
    "kind: Role\n"
    "metadata:\n"
    "  name: r\n"
    "  namespace: dev\n"
    "rules:\n"
    '  - apiGroups: [""]\n'
    "    resources: [pods]\n"
    '    verbs: ["*"]\n'
)
_CLUSTER_ADMIN_BINDING = (
    "apiVersion: rbac.authorization.k8s.io/v1\n"
    "kind: ClusterRoleBinding\n"
    "metadata:\n"
    "  name: bad\n"
    "roleRef:\n"
    "  apiGroup: rbac.authorization.k8s.io\n"
    "  kind: ClusterRole\n"
    "  name: cluster-admin\n"
    "subjects:\n"
    "  - kind: ServiceAccount\n"
    "    name: app\n"
    "    namespace: prod\n"
)
_SECRETS_LEAK_ROLE = (
    "apiVersion: rbac.authorization.k8s.io/v1\n"
    "kind: ClusterRole\n"
    "metadata:\n"
    "  name: leak\n"
    "rules:\n"
    '  - apiGroups: [""]\n'
    "    resources: [secrets]\n"
    "    verbs: [get, list, watch]\n"
)


def test_rbac_wildcard_verb_triggers_rbac_001(tmp_path: Path) -> None:
    _write(tmp_path, "rbac.yaml", _RBAC_WILDCARD_ROLE)
    outcome = run_scan(tmp_path)
    triggered = {f.rule_id for f in outcome.findings}
    assert "K8S-RBAC-001" in triggered


def test_rbac_cluster_admin_binding_triggers_rbac_002(tmp_path: Path) -> None:
    _write(tmp_path, "binding.yaml", _CLUSTER_ADMIN_BINDING)
    outcome = run_scan(tmp_path)
    triggered = {f.rule_id for f in outcome.findings}
    assert "K8S-RBAC-002" in triggered


def test_rbac_secrets_broad_read_triggers_rbac_005(tmp_path: Path) -> None:
    _write(tmp_path, "secrets-role.yaml", _SECRETS_LEAK_ROLE)
    outcome = run_scan(tmp_path)
    triggered = {f.rule_id for f in outcome.findings}
    assert "K8S-RBAC-005" in triggered


# ---------------------------------------------------------------------------
# Evaluator contract
# ---------------------------------------------------------------------------


def test_evaluator_returns_manual_review_when_evidence_missing(tmp_path: Path) -> None:
    eval_fn = EVALUATOR_REGISTRY["K8S-PSS-001"]
    out = eval_fn(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "scan-k8s" in out.remediation


def test_evaluator_returns_not_applicable_when_no_manifests(tmp_path: Path) -> None:
    """Empty repo -> scan writes evidence with files_scanned=[] -> NA, not PASS."""
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    eval_fn = EVALUATOR_REGISTRY["K8S-PSS-001"]
    out = eval_fn(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_evaluator_passes_when_zero_findings_with_scanned_files(tmp_path: Path) -> None:
    """Repo with manifests but no findings for this rule -> PASS."""
    _write(tmp_path, "k8s/good.yaml", _HARDENED_DEPLOYMENT)
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    eval_fn = EVALUATOR_REGISTRY["K8S-PSS-001"]
    out = eval_fn(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.PASS


def test_evaluator_fails_when_findings_present(tmp_path: Path) -> None:
    _write(tmp_path, "k8s/bad.yaml", _VULNERABLE_DEPLOYMENT)
    outcome = run_scan(tmp_path)
    payload = render_evidence_payload(outcome, target=tmp_path)
    write_evidence(payload, repo_root=tmp_path, filename=EVIDENCE_FILENAME)
    eval_fn = EVALUATOR_REGISTRY["K8S-PSS-001"]
    out = eval_fn(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.FAIL
