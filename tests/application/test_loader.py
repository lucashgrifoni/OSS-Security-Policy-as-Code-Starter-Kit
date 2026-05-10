"""Catalog and profile loading."""

from pathlib import Path

import pytest

from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)
from oss_policy_kit.domain.errors import LoadError, ProfileLoadError


def test_load_catalog_and_profiles() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    assert "GOV-SEC-001" in catalog
    p1 = load_profile_by_id(root, "github-level-1")
    assert "PLAT-BRPROT-015" not in p1.control_ids
    p2 = load_profile_by_id(root, "github-release-hardening-1")
    assert "PLAT-BRPROT-015" in p2.control_ids
    # v5.0.0: legacy alias 'github-release-hardening' is rejected with migration text.
    with pytest.raises(LoadError, match="removed in v5.0.0"):
        load_profile_by_id(root, "github-release-hardening")
    p3 = load_profile_by_id(root, "github-level-2")
    assert "GH-WF-018" in p3.control_ids
    p4 = load_profile_by_id(root, "github-level-3")
    assert "GH-PLAT-024" in p4.control_ids
    assert "GH-PROV-023" not in p4.control_ids
    p5 = load_profile_by_id(root, "github-release-hardening-2")
    assert "GH-PLAT-024" in p5.control_ids
    p6 = load_profile_by_id(root, "github-release-hardening-3")
    assert "GH-PLAT-026" in p6.control_ids
    p7 = load_profile_by_id(root, "azure-level-1")
    assert "AZ-PIPE-027" in p7.control_ids
    p8 = load_profile_by_id(root, "azure-level-2")
    assert "AZ-PIPE-030" in p8.control_ids
    p9 = load_profile_by_id(root, "azure-level-3")
    assert "AZ-IDENT-036" in p9.control_ids
    assert "AZ-PLAT-034" in p9.control_ids
    assert "AZ-PLAT-035" in p9.control_ids
    assert "GOV-EVIDFRESH-054" in p9.control_ids
    assert "AZ-SCONN-056" in p9.control_ids
    assert "AZ-WIFEV-057" in p9.control_ids
    assert "AZ-ARTSBOM-058" in p9.control_ids
    assert "AZ-ARTPRV-059" in p9.control_ids
    assert "AZ-SEC-031" not in p9.control_ids
    p10 = load_profile_by_id(root, "azure-release-hardening-1")
    assert "AZ-PLAT-034" in p10.control_ids
    p11 = load_profile_by_id(root, "azure-release-hardening-3")
    assert "AZ-PLAT-035" in p11.control_ids
    assert "GOV-EVIDFRESH-054" in p11.control_ids
    assert "AZ-SEC-031" in p11.control_ids
    assert "AZ-SCONN-056" in p11.control_ids
    p12_rh2 = load_profile_by_id(root, "azure-release-hardening-2")
    assert "GOV-EVIDFRESH-054" in p12_rh2.control_ids
    assert "AZ-SCONN-056" not in p12_rh2.control_ids
    p12 = load_profile_by_id(root, "aws-level-1")
    assert "AWS-CI-037" in p12.control_ids
    p13 = load_profile_by_id(root, "aws-level-2")
    assert "AWS-PIPE-042" in p13.control_ids
    p14 = load_profile_by_id(root, "aws-level-3")
    assert "GOV-EVIDFRESH-054" in p14.control_ids
    assert "AWS-PIPEIAM-056" in p14.control_ids
    assert "AWS-CBIDENT-057" in p14.control_ids
    assert "AWS-SBOMART-058" in p14.control_ids
    assert "AWS-PROVART-059" in p14.control_ids
    assert "AWS-CP-044" in p14.control_ids
    assert "AWS-CB-045" in p14.control_ids
    p15 = load_profile_by_id(root, "aws-release-hardening-1")
    assert "AWS-CP-044" in p15.control_ids
    p16 = load_profile_by_id(root, "aws-release-hardening-3")
    assert "AWS-CB-045" in p16.control_ids
    assert "GOV-EVIDFRESH-054" in p16.control_ids
    assert "AWS-PIPEIAM-056" in p16.control_ids
    assert "AWS-SBOMART-058" in p16.control_ids
    assert "AWS-PROVART-059" in p16.control_ids
    gh_aws = load_profile_by_id(root, "github-aws-level-2")
    assert gh_aws.id == "github-aws-level-2"
    assert "AWS-PIPE-042" in gh_aws.control_ids
    assert "GH-WF-018" in gh_aws.control_ids
    gh_az = load_profile_by_id(root, "github-azure-level-2")
    assert gh_az.id == "github-azure-level-2"
    assert "AZ-PIPE-027" in gh_az.control_ids
    assert "GH-WF-018" in gh_az.control_ids


def test_profile_file_resolution() -> None:
    root = bundled_kit_root()
    assert (root / "profiles" / "github-level-1" / "profile.yaml").is_file()


def test_load_profile_by_id_accepts_external_yaml_path(tmp_path: Path) -> None:
    root = bundled_kit_root()
    bundled = root / "profiles" / "github-level-1" / "profile.yaml"
    ext = tmp_path / "custom-profile.yaml"
    ext.write_bytes(bundled.read_bytes())
    loaded = load_profile_by_id(root, str(ext))
    assert loaded.id == "github-level-1"


def test_load_profile_by_id_external_path_schema_validation(tmp_path: Path) -> None:
    root = bundled_kit_root()
    bad = tmp_path / "bad-profile.yaml"
    bad.write_text("id: x\n", encoding="utf-8")
    with pytest.raises(ProfileLoadError) as excinfo:
        load_profile_by_id(root, str(bad))
    assert "schema validation" in str(excinfo.value.message).lower()
