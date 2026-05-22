"""Kubernetes manifest rule pack and evidence writer.

Mirrors the design of ``infrastructure/iac/scanner.py``:

- discover ``*.yaml`` / ``*.yml`` files under the clone (skipping noisy
  dirs and Helm templates that contain ``{{ ... }}`` markers);
- parse every YAML document via PyYAML's ``safe_load_all`` (PyYAML is a
  hard dependency of the kit, so no ``status: not_available`` path is
  needed here, unlike the IaC scanner);
- run the 16 bundled rules and aggregate findings;
- write evidence under ``.oss-policy-kit/evidence/k8s-baseline.json``
  (schema ``oss-policy-kit/evidence/k8s-baseline/v1``).

Each ``K8S-*`` evaluator is a thin reader of that JSON.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

import yaml

from oss_policy_kit.infrastructure.fs_walk import walk_matching_files

EVIDENCE_SCHEMA_VERSION = "oss-policy-kit/evidence/k8s-baseline/v1"
EVIDENCE_FILENAME = "k8s-baseline.json"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_INCLUDE_GLOBS: tuple[str, ...] = ("**/*.yaml", "**/*.yml")

_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", ".terraform", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".oss-policy-kit"}
)

_HELM_TEMPLATE_MARKER = re.compile(r"\{\{[^}]+\}\}")
_LATEST_TAG_RE = re.compile(r":(latest)?$|^[A-Za-z0-9./-]+(?<!\.)$")
_K8S_KINDS_WORKLOAD: frozenset[str] = frozenset(
    {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}
)
_K8S_KINDS_RBAC_BIND: frozenset[str] = frozenset({"RoleBinding", "ClusterRoleBinding"})
_K8S_KINDS_RBAC_RULE: frozenset[str] = frozenset({"Role", "ClusterRole"})


@dataclass(slots=True)
class K8sFinding:
    """One normalized Kubernetes finding embedded in the evidence JSON."""

    rule_id: str
    severity: str
    message: str
    file: str
    kind: str
    namespace: str
    name: str


@dataclass(slots=True)
class K8sManifest:
    """One parsed YAML document treated as a Kubernetes manifest."""

    file: Path
    api_version: str
    kind: str
    namespace: str
    name: str
    body: dict[str, Any]


@dataclass(slots=True)
class K8sScanOutcome:
    """Structured outcome of one ``scan-k8s`` run."""

    status: str
    tool_version: str | None
    files_scanned: list[str] = field(default_factory=list)
    helm_templates_skipped: list[str] = field(default_factory=list)
    parse_errors: list[dict[str, str]] = field(default_factory=list)
    findings: list[K8sFinding] = field(default_factory=list)
    scanned_at: str = ""
    diagnostics: str = ""
    helm_render_attempted: bool = False
    helm_available: bool = False
    helm_version: str | None = None
    helm_charts_discovered: list[str] = field(default_factory=list)
    helm_charts_rendered: list[str] = field(default_factory=list)
    helm_render_errors: list[dict[str, str]] = field(default_factory=list)


def _kit_version() -> str:
    from oss_policy_kit import __version__ as _src_version

    try:
        installed = _pkg_version("oss-policy-kit")
    except PackageNotFoundError:  # pragma: no cover - dev-only fallback
        return _src_version
    if installed != _src_version:
        return _src_version
    return installed


def _utc_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_target(repo_root: Path, p: Path) -> str:
    try:
        return p.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return p.resolve().as_posix()


def _walk_yaml_files(
    repo_root: Path,
    include_globs: Iterable[str],
    exclude_globs: Iterable[str] | None,
) -> list[Path]:
    return walk_matching_files(repo_root, include_globs, exclude_globs, _SKIP_DIRS)


def _looks_like_kubernetes(doc: Any) -> bool:
    return isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc


def _manifest_from_doc(doc: Any, path: Path) -> K8sManifest | None:
    """Build a :class:`K8sManifest` from one parsed YAML doc, or None if it is not a manifest."""

    if not _looks_like_kubernetes(doc):
        return None
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    return K8sManifest(
        file=path,
        api_version=str(doc.get("apiVersion", "")),
        kind=str(doc.get("kind", "")),
        namespace=str((metadata or {}).get("namespace", "default") or "default"),
        name=str((metadata or {}).get("name", "")),
        body=doc,
    )


def _index_manifests(
    repo_root: Path,
    files: list[Path],
) -> tuple[list[K8sManifest], list[str], list[dict[str, str]]]:
    """Return ``(manifests, helm_templates_skipped, parse_errors)``."""

    manifests: list[K8sManifest] = []
    helm_skipped: list[str] = []
    parse_errors: list[dict[str, str]] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            parse_errors.append({"file": _normalize_target(repo_root, path), "error": str(exc)})
            continue
        if _HELM_TEMPLATE_MARKER.search(text):
            helm_skipped.append(_normalize_target(repo_root, path))
            continue
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            parse_errors.append({"file": _normalize_target(repo_root, path), "error": str(exc)})
            continue
        for doc in docs:
            manifest = _manifest_from_doc(doc, path)
            if manifest is not None:
                manifests.append(manifest)
    return manifests, helm_skipped, parse_errors


# ---------------------------------------------------------------------------
# Per-rule helpers
# ---------------------------------------------------------------------------


def _dig(d: Any, *keys: str) -> dict[str, Any]:
    """Walk nested ``dict.get`` chain; return the final dict, or ``{}`` if any hop is not a dict."""

    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return {}
        cur = cur.get(k, {})
    return cur if isinstance(cur, dict) else {}


def _pod_specs(m: K8sManifest) -> list[dict[str, Any]]:
    """Return the list of pod-spec dicts inside a workload manifest."""

    if m.kind == "Pod":
        return [_dig(m.body, "spec")]
    if m.kind == "CronJob":
        ps = _dig(m.body, "spec", "jobTemplate", "spec", "template", "spec")
        return [ps] if ps else []
    ps = _dig(m.body, "spec", "template", "spec")
    return [ps] if ps else []


def _iter_workload_pod_specs(manifests: list[K8sManifest]) -> Iterator[tuple[K8sManifest, dict[str, Any]]]:
    """Yield ``(manifest, pod_spec)`` for every workload-kind manifest."""

    for m in manifests:
        if m.kind not in _K8S_KINDS_WORKLOAD:
            continue
        for ps in _pod_specs(m):
            yield m, ps


def _iter_workload_containers(
    manifests: list[K8sManifest],
) -> Iterator[tuple[K8sManifest, dict[str, Any], dict[str, Any]]]:
    """Yield ``(manifest, pod_spec, container)`` for every container in every workload."""

    for m, ps in _iter_workload_pod_specs(manifests):
        for c in _all_containers(ps):
            yield m, ps, c


def _all_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        seq = pod_spec.get(key)
        if isinstance(seq, list):
            for c in seq:
                if isinstance(c, dict):
                    out.append(c)
    return out


def _finding(rule_id: str, severity: str, message: str, m: K8sManifest, repo_root: Path) -> K8sFinding:
    return K8sFinding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        file=_normalize_target(repo_root, m.file),
        kind=m.kind,
        namespace=m.namespace,
        name=m.name,
    )


def _rule_pss_001_privileged(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    """K8S-PSS-001 privileged container."""

    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_WORKLOAD:
            continue
        for ps in _pod_specs(m):
            for c in _all_containers(ps):
                sc = c.get("securityContext", {})
                if isinstance(sc, dict) and sc.get("privileged") is True:
                    out.append(
                        _finding("K8S-PSS-001", "HIGH", f"container '{c.get('name', '?')}' is privileged", m, repo_root)
                    )
    return out


def _rule_pss_002_host_pid(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_WORKLOAD:
            continue
        for ps in _pod_specs(m):
            if ps.get("hostPID") is True:
                out.append(_finding("K8S-PSS-002", "HIGH", "podSpec.hostPID=true", m, repo_root))
    return out


def _rule_pss_003_host_network(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_WORKLOAD:
            continue
        for ps in _pod_specs(m):
            if ps.get("hostNetwork") is True:
                out.append(_finding("K8S-PSS-003", "HIGH", "podSpec.hostNetwork=true", m, repo_root))
    return out


def _rule_pss_004_host_path(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_WORKLOAD:
            continue
        for ps in _pod_specs(m):
            for v in ps.get("volumes", []) or []:
                if isinstance(v, dict) and isinstance(v.get("hostPath"), dict):
                    out.append(
                        _finding("K8S-PSS-004", "HIGH", f"hostPath volume '{v.get('name', '?')}' mounted", m, repo_root)
                    )
    return out


def _rule_pss_005_capabilities_add(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m, _ps, c in _iter_workload_containers(manifests):
        sc = c.get("securityContext", {})
        caps = sc.get("capabilities", {}) if isinstance(sc, dict) else {}
        added = caps.get("add", []) if isinstance(caps, dict) else []
        if isinstance(added, list) and added:
            out.append(
                _finding(
                    "K8S-PSS-005",
                    "MEDIUM",
                    f"container '{c.get('name', '?')}' adds capabilities {added}",
                    m,
                    repo_root,
                )
            )
    return out


def _container_runs_as_root(sc: dict[str, Any], pod_sc: dict[str, Any]) -> bool:
    """True when neither container nor pod securityContext rules out running as root."""

    run_non_root = sc.get("runAsNonRoot")
    if run_non_root is None:
        run_non_root = pod_sc.get("runAsNonRoot")
    run_as_user = sc.get("runAsUser")
    if run_as_user is None:
        run_as_user = pod_sc.get("runAsUser")
    if run_non_root is True:
        return False
    return not (isinstance(run_as_user, int) and run_as_user != 0)


def _rule_pss_006_run_as_root(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m, ps, c in _iter_workload_containers(manifests):
        pod_sc = ps.get("securityContext", {}) if isinstance(ps.get("securityContext"), dict) else {}
        sc = c.get("securityContext", {}) if isinstance(c.get("securityContext"), dict) else {}
        if _container_runs_as_root(sc, pod_sc):
            msg = f"container '{c.get('name', '?')}' may run as root (runAsNonRoot not true; runAsUser not non-zero)"
            out.append(_finding("K8S-PSS-006", "HIGH", msg, m, repo_root))
    return out


def _rule_pss_007_priv_escalation(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m, _ps, c in _iter_workload_containers(manifests):
        sc = c.get("securityContext", {}) if isinstance(c.get("securityContext"), dict) else {}
        if sc.get("allowPrivilegeEscalation") is not False:
            out.append(
                _finding(
                    "K8S-PSS-007",
                    "MEDIUM",
                    f"container '{c.get('name', '?')}' allowPrivilegeEscalation not set to false",
                    m,
                    repo_root,
                )
            )
    return out


def _rule_pss_008_readonly_rootfs(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m, _ps, c in _iter_workload_containers(manifests):
        sc = c.get("securityContext", {}) if isinstance(c.get("securityContext"), dict) else {}
        if sc.get("readOnlyRootFilesystem") is not True:
            out.append(
                _finding(
                    "K8S-PSS-008",
                    "MEDIUM",
                    f"container '{c.get('name', '?')}' readOnlyRootFilesystem not true",
                    m,
                    repo_root,
                )
            )
    return out


def _rule_pss_009_automount_sa(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_WORKLOAD:
            continue
        for ps in _pod_specs(m):
            if ps.get("automountServiceAccountToken") is None:
                out.append(
                    _finding(
                        "K8S-PSS-009",
                        "LOW",
                        "podSpec.automountServiceAccountToken not pinned (defaults to true)",
                        m,
                        repo_root,
                    )
                )
    return out


def _rule_pss_010_image_tag_latest(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m, _ps, c in _iter_workload_containers(manifests):
        image = str(c.get("image", ""))
        if not image or "@sha256:" in image:
            continue
        # Treat 'latest' or any image without an explicit tag as drift.
        tag = image.split(":", 1)[1] if ":" in image else "latest"
        if tag in ("", "latest"):
            out.append(
                _finding(
                    "K8S-PSS-010",
                    "MEDIUM",
                    f"container '{c.get('name', '?')}' uses floating tag '{image}'",
                    m,
                    repo_root,
                )
            )
    return out


def _rule_rbac_001_wildcard_verbs(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_RBAC_RULE:
            continue
        for r in m.body.get("rules", []) or []:
            if not isinstance(r, dict):
                continue
            verbs = r.get("verbs", [])
            if isinstance(verbs, list) and "*" in verbs:
                out.append(_finding("K8S-RBAC-001", "HIGH", f"{m.kind} grants wildcard verb '*'", m, repo_root))
                break
    return out


def _rule_rbac_002_cluster_admin(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_RBAC_BIND:
            continue
        role_ref = m.body.get("roleRef", {})
        if not isinstance(role_ref, dict):
            continue
        if str(role_ref.get("name", "")) == "cluster-admin":
            out.append(_finding("K8S-RBAC-002", "HIGH", f"{m.kind} binds to cluster-admin", m, repo_root))
    return out


def _rule_rbac_003_default_sa(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_WORKLOAD:
            continue
        for ps in _pod_specs(m):
            sa = ps.get("serviceAccountName")
            if sa in (None, "default") and m.namespace == "default":
                out.append(
                    _finding(
                        "K8S-RBAC-003",
                        "LOW",
                        "workload runs in 'default' namespace with the default ServiceAccount",
                        m,
                        repo_root,
                    )
                )
    return out


def _rule_rbac_004_cluster_role_no_namespace(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    """ClusterRoleBinding granting a ClusterRole with broad `*` resources."""

    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind != "ClusterRole":
            continue
        for r in m.body.get("rules", []) or []:
            if not isinstance(r, dict):
                continue
            resources = r.get("resources", [])
            if isinstance(resources, list) and "*" in resources:
                out.append(
                    _finding(
                        "K8S-RBAC-004",
                        "MEDIUM",
                        "ClusterRole grants wildcard resource '*' (cluster-scoped, no namespace boundary)",
                        m,
                        repo_root,
                    )
                )
                break
    return out


def _grants_broad_secret_read(r: Any) -> bool:
    """True when an RBAC policy rule grants get/list/watch/* on secrets (or *)."""

    if not isinstance(r, dict):
        return False
    resources = r.get("resources", []) or []
    verbs = r.get("verbs", []) or []
    if not isinstance(resources, list) or not isinstance(verbs, list):
        return False
    if "secrets" not in resources and "*" not in resources:
        return False
    return any(v in {"get", "list", "watch", "*"} for v in verbs)


def _rule_rbac_005_secrets_all_read(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    out: list[K8sFinding] = []
    for m in manifests:
        if m.kind not in _K8S_KINDS_RBAC_RULE:
            continue
        for r in m.body.get("rules", []) or []:
            if _grants_broad_secret_read(r):
                verbs = r.get("verbs", []) or []
                out.append(
                    _finding(
                        "K8S-RBAC-005",
                        "HIGH",
                        f"{m.kind} grants broad read on secrets (verbs={verbs})",
                        m,
                        repo_root,
                    )
                )
                break
    return out


def _rule_netpol_001_no_netpol(repo_root: Path, manifests: list[K8sManifest]) -> list[K8sFinding]:
    """Namespace has no NetworkPolicy at all."""

    workload_namespaces: set[str] = set()
    netpol_namespaces: set[str] = set()
    sample_workload: dict[str, K8sManifest] = {}
    for m in manifests:
        if m.kind == "NetworkPolicy":
            netpol_namespaces.add(m.namespace)
        elif m.kind in _K8S_KINDS_WORKLOAD:
            workload_namespaces.add(m.namespace)
            sample_workload.setdefault(m.namespace, m)
    out: list[K8sFinding] = []
    for ns in sorted(workload_namespaces - netpol_namespaces):
        anchor = sample_workload.get(ns)
        if anchor is None:
            continue
        out.append(
            _finding(
                "K8S-NETPOL-001",
                "MEDIUM",
                f"namespace '{ns}' has workloads but no NetworkPolicy declared",
                anchor,
                repo_root,
            )
        )
    return out


_RuleFn = Callable[[Path, list[K8sManifest]], list[K8sFinding]]

_RULES: tuple[tuple[str, _RuleFn], ...] = (
    ("K8S-PSS-001", _rule_pss_001_privileged),
    ("K8S-PSS-002", _rule_pss_002_host_pid),
    ("K8S-PSS-003", _rule_pss_003_host_network),
    ("K8S-PSS-004", _rule_pss_004_host_path),
    ("K8S-PSS-005", _rule_pss_005_capabilities_add),
    ("K8S-PSS-006", _rule_pss_006_run_as_root),
    ("K8S-PSS-007", _rule_pss_007_priv_escalation),
    ("K8S-PSS-008", _rule_pss_008_readonly_rootfs),
    ("K8S-PSS-009", _rule_pss_009_automount_sa),
    ("K8S-PSS-010", _rule_pss_010_image_tag_latest),
    ("K8S-RBAC-001", _rule_rbac_001_wildcard_verbs),
    ("K8S-RBAC-002", _rule_rbac_002_cluster_admin),
    ("K8S-RBAC-003", _rule_rbac_003_default_sa),
    ("K8S-RBAC-004", _rule_rbac_004_cluster_role_no_namespace),
    ("K8S-RBAC-005", _rule_rbac_005_secrets_all_read),
    ("K8S-NETPOL-001", _rule_netpol_001_no_netpol),
)


def all_rule_ids() -> tuple[str, ...]:
    return tuple(rid for rid, _ in _RULES)


@dataclass(slots=True)
class _HelmState:
    """Mutable bookkeeping for an optional ``helm template`` render pass."""

    attempted: bool = False
    available: bool = False
    version: str | None = None
    charts_discovered: list[str] = field(default_factory=list)
    charts_rendered: list[str] = field(default_factory=list)
    render_errors: list[dict[str, str]] = field(default_factory=list)
    tmp_root: Path | None = None


def _strip_rendered_from_skipped(helm_skipped: list[str], charts_rendered: list[str]) -> list[str]:
    """Drop chart paths from ``helm_skipped`` once we know they were rendered."""

    rendered_chart_dirs = {Path(c) for c in charts_rendered}
    remaining: list[str] = []
    for skipped in helm_skipped:
        skip_path = Path(skipped)
        if any(rcd == skip_path or rcd in skip_path.parents for rcd in rendered_chart_dirs):
            continue
        remaining.append(skipped)
    return remaining


def _apply_helm_render(
    repo_root: Path,
    manifests: list[K8sManifest],
    helm_skipped: list[str],
    parse_errors: list[dict[str, str]],
) -> tuple[_HelmState, list[str]]:
    """Render Helm charts, merge their manifests, and return ``(state, updated_helm_skipped)``."""

    from oss_policy_kit.infrastructure.k8s.helm_renderer import render_charts

    rendered = render_charts(repo_root)
    state = _HelmState(
        attempted=True,
        available=rendered.available,
        version=rendered.helm_version,
        charts_discovered=list(rendered.charts_discovered),
        charts_rendered=list(rendered.charts_rendered),
        render_errors=list(rendered.render_errors),
        tmp_root=rendered.tmp_root,
    )
    if rendered.rendered_manifest_paths:
        extra_manifests, _extra_skipped, extra_parse_errors = _index_manifests(
            repo_root, rendered.rendered_manifest_paths
        )
        manifests.extend(extra_manifests)
        parse_errors.extend(extra_parse_errors)
        helm_skipped = _strip_rendered_from_skipped(helm_skipped, rendered.charts_rendered)
    return state, helm_skipped


def run_scan(
    repo_root: Path,
    *,
    include_globs: Iterable[str] = DEFAULT_INCLUDE_GLOBS,
    exclude_globs: Iterable[str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    helm_render: bool = False,
) -> K8sScanOutcome:
    """Discover Kubernetes manifests, run every bundled rule, return a structured outcome.

    When ``helm_render=True``, the scanner first invokes ``helm template``
    via :mod:`oss_policy_kit.infrastructure.k8s.helm_renderer` on every
    discovered ``Chart.yaml`` and merges the rendered manifests into the
    scan. Charts that fail to render are recorded in
    ``helm_render_errors``; the scan continues with what it could parse.
    Helm-rendered manifests do **not** appear in ``helm_templates_skipped``
    (that list is reserved for unrendered ``{{ ... }}`` templates).
    """

    _ = timeout_seconds
    files = _walk_yaml_files(repo_root, include_globs, exclude_globs)
    manifests, helm_skipped, parse_errors = _index_manifests(repo_root, files)

    helm = _HelmState()
    if helm_render:
        helm, helm_skipped = _apply_helm_render(repo_root, manifests, helm_skipped, parse_errors)
    helm_attempted = helm.attempted
    helm_available_flag = helm.available
    helm_version_str = helm.version
    helm_charts_discovered = helm.charts_discovered
    helm_charts_rendered = helm.charts_rendered
    helm_render_errors = helm.render_errors
    helm_tmp_root = helm.tmp_root

    try:
        findings: list[K8sFinding] = []
        try:
            for _rid, fn in _RULES:
                findings.extend(fn(repo_root, manifests))
        except Exception as exc:  # noqa: BLE001 - one bad rule should not crash the scan
            return K8sScanOutcome(
                status="error",
                tool_version=_kit_version(),
                files_scanned=[_normalize_target(repo_root, p) for p in files],
                helm_templates_skipped=helm_skipped,
                parse_errors=parse_errors,
                findings=[],
                scanned_at=_utc_iso(),
                diagnostics=f"rule engine raised {type(exc).__name__}: {exc}",
                helm_render_attempted=helm_attempted,
                helm_available=helm_available_flag,
                helm_version=helm_version_str,
                helm_charts_discovered=helm_charts_discovered,
                helm_charts_rendered=helm_charts_rendered,
                helm_render_errors=helm_render_errors,
            )
        return K8sScanOutcome(
            status="ok",
            tool_version=_kit_version(),
            files_scanned=[_normalize_target(repo_root, p) for p in files],
            helm_templates_skipped=helm_skipped,
            parse_errors=parse_errors,
            findings=findings,
            scanned_at=_utc_iso(),
            helm_render_attempted=helm_attempted,
            helm_available=helm_available_flag,
            helm_version=helm_version_str,
            helm_charts_discovered=helm_charts_discovered,
            helm_charts_rendered=helm_charts_rendered,
            helm_render_errors=helm_render_errors,
        )
    finally:
        if helm_tmp_root is not None:
            shutil.rmtree(helm_tmp_root, ignore_errors=True)


def render_evidence_payload(outcome: K8sScanOutcome, *, target: Path) -> dict[str, Any]:
    """Build the on-disk evidence dict consumed by every ``K8S-*`` evaluator."""

    by_rule: dict[str, int] = dict.fromkeys(all_rule_ids(), 0)
    by_severity: dict[str, int] = {}
    for f in outcome.findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "tool": "oss-policy-kit-k8s-parser",
        "tool_version": outcome.tool_version,
        "status": outcome.status,
        "target": str(target.resolve()),
        "scanned_at": outcome.scanned_at,
        "attested_at": outcome.scanned_at,
        "attested_by": "oss-policy-kit scan-k8s",
        "files_scanned": outcome.files_scanned,
        "files_failed": [pe["file"] for pe in outcome.parse_errors],
        "helm_templates_skipped": outcome.helm_templates_skipped,
        "helm_render_attempted": outcome.helm_render_attempted,
        "helm_available": outcome.helm_available,
        "helm_version": outcome.helm_version,
        "helm_charts_discovered": outcome.helm_charts_discovered,
        "helm_charts_rendered": outcome.helm_charts_rendered,
        "helm_render_errors": outcome.helm_render_errors,
        "findings_total": len(outcome.findings),
        "findings_by_rule": by_rule,
        "findings_by_severity": by_severity,
        "findings": [asdict(f) for f in outcome.findings],
        "diagnostics": {
            "parse_errors": outcome.parse_errors,
            "raw_message": outcome.diagnostics,
        },
    }


def write_evidence(payload: dict[str, Any], *, repo_root: Path, filename: str = EVIDENCE_FILENAME) -> Path:
    import json

    target_dir = repo_root / ".oss-policy-kit" / "evidence"
    target_dir.mkdir(parents=True, exist_ok=True)
    out = target_dir / filename
    out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return out.resolve()
