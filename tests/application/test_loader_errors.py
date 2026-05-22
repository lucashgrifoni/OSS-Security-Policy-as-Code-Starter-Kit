"""Error-path coverage for ``application.loader`` (catalog/profile validation, removed ids, kit root)."""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application import loader
from oss_policy_kit.domain.errors import LoadError, ProfileLoadError


def _yaml(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# load_catalog
# --------------------------------------------------------------------------- #


def test_load_catalog_bad_yaml(tmp_path: Path) -> None:
    p = _yaml(tmp_path, "c.yaml", ":\n  - [")  # invalid YAML
    with pytest.raises(LoadError, match="Failed to load catalog"):
        loader.load_catalog(p)


def test_load_catalog_root_not_mapping(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="must be a mapping"):
        loader.load_catalog(_yaml(tmp_path, "c.yaml", "- a\n- b\n"))


def test_load_catalog_no_controls_list(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="must contain a 'controls' list"):
        loader.load_catalog(_yaml(tmp_path, "c.yaml", "other: 1\n"))


def test_load_catalog_invalid_assurance(tmp_path: Path) -> None:
    src = "controls:\n  - id: X-1\n    assurance: bogus\n"
    with pytest.raises(LoadError, match="invalid assurance"):
        loader.load_catalog(_yaml(tmp_path, "c.yaml", src))


def test_load_catalog_empty(tmp_path: Path) -> None:
    # Items present but none with a valid id -> no controls.
    src = "controls:\n  - notid: 1\n  - {}\n"
    with pytest.raises(LoadError, match="no controls"):
        loader.load_catalog(_yaml(tmp_path, "c.yaml", src))


def test_load_catalog_ok_weight_clamped(tmp_path: Path) -> None:
    src = "controls:\n  - id: X-1\n    weight: 99\n  - id: X-2\n    weight: notanint\n"
    cat = loader.load_catalog(_yaml(tmp_path, "c.yaml", src))
    assert cat["X-1"].weight == 3  # clamped to max 3
    assert cat["X-2"].weight == 1  # invalid -> default 1


# --------------------------------------------------------------------------- #
# load_profile
# --------------------------------------------------------------------------- #


def test_load_profile_root_not_mapping(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="root must be a mapping"):
        loader.load_profile(_yaml(tmp_path, "p.yaml", "- a\n"))


def test_load_profile_missing_id(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="missing id"):
        loader.load_profile(_yaml(tmp_path, "p.yaml", "title: X\ncontrols: [A]\n"))


def test_load_profile_no_controls(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="no controls"):
        loader.load_profile(_yaml(tmp_path, "p.yaml", "id: x\ntitle: X\n"))


def test_load_profile_removed_control(tmp_path: Path) -> None:
    src = "id: x\ntitle: X\ncontrols: [SEC-AUDIT-016]\n"
    with pytest.raises(ProfileLoadError, match="removed in v4.0.0"):
        loader.load_profile(_yaml(tmp_path, "p.yaml", src))


def test_load_profile_external_schema_missing_id(tmp_path: Path) -> None:
    src = "title: X\ncontrols: [GOV-SEC-001]\n"  # no id -> schema fail with hint
    with pytest.raises(ProfileLoadError, match="schema validation"):
        loader.load_profile(_yaml(tmp_path, "p.yaml", src), validate_external_schema=True)


def test_load_profile_ok(tmp_path: Path) -> None:
    src = "id: my-profile\ntitle: My\ndescription: d\naudience: a\ncontrols: [GOV-SEC-001, CI-WF-005]\n"
    spec = loader.load_profile(_yaml(tmp_path, "p.yaml", src))
    assert spec.id == "my-profile"
    assert spec.control_ids == ("GOV-SEC-001", "CI-WF-005")


# --------------------------------------------------------------------------- #
# resolve_profile_file / merge_kit_root
# --------------------------------------------------------------------------- #


def test_resolve_profile_removed_id(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="removed in v5.0.0"):
        loader.resolve_profile_file(tmp_path, "github-release-hardening")


def test_resolve_profile_unknown(tmp_path: Path) -> None:
    with pytest.raises(LoadError, match="Unknown profile"):
        loader.resolve_profile_file(tmp_path, "no-such-profile")


def test_merge_kit_root_not_dir(tmp_path: Path) -> None:
    f = tmp_path / "afile"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(LoadError, match="not a directory"):
        loader.merge_kit_root(f)


def test_merge_kit_root_default_and_override(tmp_path: Path) -> None:
    assert loader.merge_kit_root(None) == loader.bundled_kit_root()
    assert loader.merge_kit_root(tmp_path) == tmp_path.resolve()


def test_raise_if_removed_controls_referenced_clean() -> None:
    # No removed controls -> no raise.
    loader._raise_if_removed_controls_referenced(("GOV-SEC-001",), "ctx")
