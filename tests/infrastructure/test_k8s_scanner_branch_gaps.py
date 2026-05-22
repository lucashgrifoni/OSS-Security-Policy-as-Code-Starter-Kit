"""Branch-coverage gaps for the Kubernetes manifest scanner."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.k8s import scanner as sc
from oss_policy_kit.infrastructure.k8s.helm_renderer import HelmRenderOutcome
from oss_policy_kit.infrastructure.k8s.scanner import K8sManifest


def _m(kind: str, body: dict, *, namespace: str = "default", name: str = "x") -> K8sManifest:
    return K8sManifest(
        file=Path("m.yaml"),
        api_version="v1",
        kind=kind,
        namespace=namespace,
        name=name,
        body=body,
    )


# --------------------------------------------------------------------------- #
# _normalize_target — non-relative path (lines 115-116)
# --------------------------------------------------------------------------- #


def test_normalize_target_outside_repo(tmp_path: Path) -> None:
    other = tmp_path.parent / "elsewhere" / "f.yaml"
    out = sc._normalize_target(tmp_path / "repo", other)
    assert out.endswith("f.yaml")


# --------------------------------------------------------------------------- #
# _manifest_from_doc — non-kubernetes doc (line 135)
# --------------------------------------------------------------------------- #


def test_manifest_from_doc_returns_none_for_non_k8s() -> None:
    assert sc._manifest_from_doc({"just": "data"}, Path("x.yaml")) is None


# --------------------------------------------------------------------------- #
# _index_manifests — read error + YAML error (lines 159-161, 167-169)
# --------------------------------------------------------------------------- #


def test_index_manifests_records_read_error(tmp_path: Path) -> None:
    a_dir = tmp_path / "is_a_dir.yaml"
    a_dir.mkdir()  # reading a directory raises OSError
    manifests, skipped, errors = sc._index_manifests(tmp_path, [a_dir])
    assert manifests == [] and any("is_a_dir" in e["file"] for e in errors)


def test_index_manifests_records_yaml_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("key: : : [unbalanced\n  - {", encoding="utf-8")
    _manifests, _skipped, errors = sc._index_manifests(tmp_path, [bad])
    assert any("bad.yaml" in e["file"] for e in errors)


# --------------------------------------------------------------------------- #
# _dig — non-dict hop (line 188)
# --------------------------------------------------------------------------- #


def test_dig_non_dict_hop() -> None:
    assert sc._dig({"spec": "not-a-dict"}, "spec", "deeper") == {}


# --------------------------------------------------------------------------- #
# _pod_specs — Pod and CronJob kinds (lines 197, 199-200)
# --------------------------------------------------------------------------- #


def test_pod_specs_pod_kind() -> None:
    specs = sc._pod_specs(_m("Pod", {"spec": {"containers": []}}))
    assert specs == [{"containers": []}]


def test_pod_specs_cronjob_kind() -> None:
    body = {"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": []}}}}}}
    specs = sc._pod_specs(_m("CronJob", body))
    assert specs == [{"containers": []}]


def test_pod_specs_cronjob_empty_when_missing() -> None:
    assert sc._pod_specs(_m("CronJob", {"spec": {}})) == []


# --------------------------------------------------------------------------- #
# RBAC rule helpers — malformed-entry guards (lines 426, 441, 476, 500)
# --------------------------------------------------------------------------- #


def test_rbac_001_skips_non_dict_rule() -> None:
    m = _m("Role", {"rules": ["not-a-dict", 42]})
    assert sc._rule_rbac_001_wildcard_verbs(Path("."), [m]) == []


def test_rbac_002_skips_non_dict_role_ref() -> None:
    m = _m("ClusterRoleBinding", {"roleRef": "not-a-dict"})
    assert sc._rule_rbac_002_cluster_admin(Path("."), [m]) == []


def test_rbac_004_skips_non_dict_rule() -> None:
    m = _m("ClusterRole", {"rules": [None, 7]})
    assert sc._rule_rbac_004_cluster_role_no_namespace(Path("."), [m]) == []


def test_grants_broad_secret_read_non_list_resources() -> None:
    assert sc._grants_broad_secret_read({"resources": "secrets", "verbs": "get"}) is False


def test_grants_broad_secret_read_non_dict_rule() -> None:
    assert sc._grants_broad_secret_read("not-a-dict") is False


def test_rbac_004_fires_on_wildcard_resources() -> None:
    m = _m("ClusterRole", {"rules": [{"resources": ["*"], "verbs": ["get"]}]})
    findings = sc._rule_rbac_004_cluster_role_no_namespace(Path("."), [m])
    assert len(findings) == 1 and findings[0].rule_id == "K8S-RBAC-004"


# --------------------------------------------------------------------------- #
# _strip_rendered_from_skipped (lines 598-605)
# --------------------------------------------------------------------------- #


def test_strip_rendered_from_skipped_drops_rendered_chart_dirs() -> None:
    skipped = ["charts/app/templates/deploy.yaml", "other/raw.yaml"]
    remaining = sc._strip_rendered_from_skipped(skipped, ["charts/app"])
    assert remaining == ["other/raw.yaml"]


# --------------------------------------------------------------------------- #
# run_scan — rule engine raises (lines 677-678)
# --------------------------------------------------------------------------- #


def test_run_scan_rule_engine_error(tmp_path: Path, monkeypatch) -> None:
    def _boom(_repo: Path, _manifests: list) -> list:
        raise RuntimeError("boom")

    monkeypatch.setattr(sc, "_RULES", [("K8S-BAD-999", _boom)])
    out = sc.run_scan(tmp_path)
    assert out.status == "error"
    assert "RuntimeError" in out.diagnostics


# --------------------------------------------------------------------------- #
# run_scan with helm render — merges manifests + cleans tmp_root
# (lines 628-634, 711)
# --------------------------------------------------------------------------- #


def test_run_scan_helm_render_merges_and_cleans(tmp_path: Path, monkeypatch) -> None:
    # A real rendered manifest the scanner will index and clean up afterwards.
    helm_tmp = tmp_path / "helm-out"
    chart_dir = helm_tmp / "app"
    chart_dir.mkdir(parents=True)
    rendered = chart_dir / "rendered.yaml"
    rendered.write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  hostNetwork: true\n  containers: []\n",
        encoding="utf-8",
    )

    def _fake_render_charts(_repo: Path) -> HelmRenderOutcome:
        return HelmRenderOutcome(
            available=True,
            helm_version="v3.99.0",
            charts_discovered=["app"],
            charts_rendered=["app"],
            rendered_manifest_paths=[rendered],
            tmp_root=helm_tmp,
        )

    monkeypatch.setattr(
        "oss_policy_kit.infrastructure.k8s.helm_renderer.render_charts",
        _fake_render_charts,
    )
    out = sc.run_scan(tmp_path, helm_render=True)
    assert out.status == "ok"
    assert out.helm_render_attempted is True
    assert out.helm_charts_rendered == ["app"]
    # tmp_root removed in the finally block.
    assert not helm_tmp.exists()
