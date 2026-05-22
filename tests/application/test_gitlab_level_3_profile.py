"""gitlab-level-3: completes the GitLab CI ladder (L3 ⊇ L2 + platform-agnostic hard-gate)."""

from __future__ import annotations

import json
import subprocess
import sys

from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id


def test_gitlab_level_3_loads_and_controls_resolve() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "gitlab-level-3")
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    assert spec.id == "gitlab-level-3"
    assert len(spec.control_ids) == len(set(spec.control_ids)), "duplicate control IDs"
    for cid in spec.control_ids:
        assert cid in catalog, f"Control '{cid}' missing from catalog."


def test_gitlab_level_3_is_superset_of_level_2() -> None:
    l2 = set(load_profile_by_id(bundled_kit_root(), "gitlab-level-2").control_ids)
    l3 = set(load_profile_by_id(bundled_kit_root(), "gitlab-level-3").control_ids)
    assert l2.issubset(l3), f"ladder broken: L2 controls missing from L3: {sorted(l2 - l3)}"
    # L3 adds the platform-agnostic hard-gate controls.
    assert {"ORG-MFA-001", "AUDIT-STREAM-060", "PROV-VERIFY-061", "PLAT-BRPROT-015"}.issubset(l3 - l2)


def test_gitlab_level_3_excludes_github_specific_controls() -> None:
    l3 = set(load_profile_by_id(bundled_kit_root(), "gitlab-level-3").control_ids)
    assert not any(c.startswith("GH-PLAT-") for c in l3)
    assert "CI-WFCALLSHA-055" not in l3


def test_gitlab_level_3_listed_in_profiles_json() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "profiles", "--format", "json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    row = next((p for p in data["profiles"] if p["profile_id"] == "gitlab-level-3"), None)
    assert row is not None
    assert row["family"] == "gitlab"
