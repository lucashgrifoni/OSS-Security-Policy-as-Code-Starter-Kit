"""cra-eu-ready-1: first non-platform-prefixed profile loads, lists with family=multi, controls resolve."""

from __future__ import annotations

import json
import subprocess
import sys

from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)


def test_cra_eu_ready_1_profile_loads() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "cra-eu-ready-1")
    assert spec.id == "cra-eu-ready-1"
    assert len(spec.control_ids) == 12


def test_cra_eu_ready_1_controls_all_resolve_in_catalog() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "cra-eu-ready-1")
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for cid in spec.control_ids:
        assert cid in catalog, f"Control '{cid}' referenced by cra-eu-ready-1 missing from catalog."


def test_cra_eu_ready_1_includes_v51_v52_controls() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "cra-eu-ready-1")
    expected = {"AUDIT-STREAM-060", "PROV-VERIFY-061", "RELEASE-ARCHIVE-063"}
    assert expected.issubset(set(spec.control_ids))


def test_profiles_format_json_includes_cra_eu_ready_with_family_multi() -> None:
    """`profiles --format json` emits family=multi and posture=framework_aligned_advisory for CRA profile."""

    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "profiles", "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout)
    assert payload["schema_version"] == "oss-policy-kit/profile-list/v2"
    cra = next((p for p in payload["profiles"] if p["profile_id"] == "cra-eu-ready-1"), None)
    assert cra is not None, "cra-eu-ready-1 missing from profile-list/v2 output"
    assert cra["family"] == "multi"
    assert cra["posture"] == "framework_aligned_advisory"
    assert cra["live_signal_posture"] == "regulatory_mapping_no_release_gate"
    assert cra["platform"] == "Multi"


def test_recommend_profile_does_not_suggest_cra_eu_ready(tmp_path) -> None:
    """recommend-profile should not surface cra-eu-ready-1 from a typical github fixture."""

    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text(
        "name: ci\non: push\nperms: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: echo ok}]\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "recommend-profile", "--target", str(tmp_path), "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout)
    suggested_ids = [s.get("profile_id") for s in payload.get("suggestions", [])]
    assert "cra-eu-ready-1" not in suggested_ids
