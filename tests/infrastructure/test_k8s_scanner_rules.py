"""Rule-detection coverage for the Kubernetes manifest scanner (PSS + RBAC + NetworkPolicy)."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.k8s import scanner as k8s

_BAD_DEPLOYMENT = """\
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
        - name: h
          hostPath:
            path: /
      containers:
        - name: c
          image: nginx:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            capabilities:
              add: [NET_ADMIN]
"""

_CLUSTER_ROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-role
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""

_CLUSTER_ROLE_BINDING = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind-admin
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: default
"""

_SECRETS_ROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
"""


def _rule_ids(outcome: k8s.K8sScanOutcome) -> set[str]:
    return {f.rule_id for f in outcome.findings}


def test_k8s_rules_fire(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(_BAD_DEPLOYMENT, encoding="utf-8")
    (tmp_path / "clusterrole.yaml").write_text(_CLUSTER_ROLE, encoding="utf-8")
    (tmp_path / "binding.yaml").write_text(_CLUSTER_ROLE_BINDING, encoding="utf-8")
    (tmp_path / "secretrole.yaml").write_text(_SECRETS_ROLE, encoding="utf-8")
    outcome = k8s.run_scan(tmp_path)
    assert outcome.status == "ok"
    fired = _rule_ids(outcome)
    expected_pss = {f"K8S-PSS-{n:03d}" for n in range(1, 11)}
    assert expected_pss <= fired, f"missing PSS: {sorted(expected_pss - fired)}"
    for rbac in ("K8S-RBAC-001", "K8S-RBAC-002", "K8S-RBAC-004", "K8S-RBAC-005"):
        assert rbac in fired, f"{rbac} did not fire"
    assert "K8S-NETPOL-001" in fired  # workload namespace with no NetworkPolicy


def test_k8s_default_sa_rbac_003(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(_BAD_DEPLOYMENT, encoding="utf-8")
    outcome = k8s.run_scan(tmp_path)
    assert "K8S-RBAC-003" in _rule_ids(outcome)  # default ns + default SA


def test_k8s_evidence_payload(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(_BAD_DEPLOYMENT, encoding="utf-8")
    outcome = k8s.run_scan(tmp_path)
    payload = k8s.render_evidence_payload(outcome, target=tmp_path)
    assert payload["findings_total"] == len(outcome.findings)


def test_k8s_clean_no_files(tmp_path: Path) -> None:
    outcome = k8s.run_scan(tmp_path)
    assert outcome.status == "ok"
    assert outcome.findings == []


def test_k8s_grants_broad_secret_read_helper() -> None:
    assert k8s._grants_broad_secret_read({"resources": ["secrets"], "verbs": ["get"]})
    assert k8s._grants_broad_secret_read({"resources": ["*"], "verbs": ["*"]})
    assert not k8s._grants_broad_secret_read({"resources": ["pods"], "verbs": ["get"]})
    assert not k8s._grants_broad_secret_read("notdict")


def test_k8s_container_runs_as_root_helper() -> None:
    assert k8s._container_runs_as_root({}, {})  # nothing rules out root
    assert not k8s._container_runs_as_root({"runAsNonRoot": True}, {})
    assert not k8s._container_runs_as_root({"runAsUser": 1000}, {})
