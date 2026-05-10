"""Guards for bundled profile + catalog policy (no new controls or profiles)."""

from __future__ import annotations

import pytest

from oss_policy_kit.application.loader import (
    REMOVED_CONTROL_IDS,
    bundled_kit_root,
    load_catalog,
    load_profile,
    load_profile_by_id,
)


def test_bundled_profiles_exclude_deprecated_audit_and_sbom_controls() -> None:
    root = bundled_kit_root()
    for path in sorted((root / "profiles").iterdir()):
        if not path.is_dir():
            continue
        pfile = path / "profile.yaml"
        if not pfile.is_file():
            continue
        spec = load_profile(pfile)
        bad = REMOVED_CONTROL_IDS.intersection(spec.control_ids)
        assert not bad, f"{spec.id} must not list {bad}"


def test_build_sbom_qual_catalog_stable() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    assert catalog["BUILD-SBOM-QUAL-003"].lifecycle == "stable"


@pytest.mark.parametrize("profile_id", ("github-azure-level-2", "github-aws-level-2"))
def test_github_hybrid_profiles_document_advisory_only(profile_id: str) -> None:
    spec = load_profile_by_id(bundled_kit_root(), profile_id)
    blob = (spec.title + "\n" + spec.description).lower()
    assert "advisory-only" in blob or ("advisory" in blob and "not a hard gate" in blob)
