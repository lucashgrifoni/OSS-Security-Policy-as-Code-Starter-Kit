"""Schema-style validation for the bundled profiles.

These tests do not introduce a JSON schema file; they use Python assertions
to verify the structural integrity of every ``profile.yaml`` under
``src/oss_policy_kit/data/profiles/`` against the catalog. They catch typos
and structural regressions early without requiring schema tooling.

Coverage:

- Each profile must declare ``id``, ``title``, ``description``, ``audience``,
  and ``controls``.
- Each control_id in ``controls:`` must exist in ``catalog.yaml``.
- No control_id may appear twice in the same profile.
- The profile ``id`` must equal its directory name.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
import yaml

PROFILES_DIR = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "data" / "profiles"
CATALOG_PATH = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "data" / "controls" / "catalog.yaml"

REQUIRED_FIELDS: tuple[str, ...] = ("id", "title", "description", "audience", "controls")


def _load_catalog_ids() -> set[str]:
    """Return the set of control IDs declared in the catalog."""

    raw = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, dict), f"catalog.yaml root must be a mapping; got {type(raw).__name__}"
    controls = raw.get("controls", [])
    assert isinstance(controls, list), "catalog.yaml: 'controls:' must be a list"
    ids: set[str] = set()
    for entry in controls:
        assert isinstance(entry, dict), "catalog.yaml: each control must be a mapping"
        cid = entry.get("id")
        assert isinstance(cid, str) and cid.strip(), f"catalog.yaml: missing 'id' in {entry!r}"
        ids.add(cid)
    return ids


def _profile_files() -> list[Path]:
    """Return every bundled profile.yaml path. Skipping non-directories defensively."""

    return sorted(p / "profile.yaml" for p in PROFILES_DIR.iterdir() if p.is_dir())


@pytest.fixture(scope="module")
def catalog_ids() -> set[str]:
    """Cache the catalog IDs once per test module."""

    return _load_catalog_ids()


@pytest.mark.parametrize("profile_path", _profile_files(), ids=lambda p: p.parent.name)
def test_profile_has_required_fields(profile_path: Path) -> None:
    """Each profile must declare all required top-level fields."""

    data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{profile_path}: root must be a mapping"
    for field in REQUIRED_FIELDS:
        assert field in data, f"{profile_path.parent.name}: missing required field '{field}'"
        value = data[field]
        if field == "controls":
            assert isinstance(value, list) and value, f"{profile_path}: 'controls:' must be a non-empty list"
        else:
            assert isinstance(value, str) and value.strip(), f"{profile_path}: '{field}' must be a non-empty string"


@pytest.mark.parametrize("profile_path", _profile_files(), ids=lambda p: p.parent.name)
def test_profile_id_matches_directory_name(profile_path: Path) -> None:
    """Profile id must equal the directory name (filesystem and YAML must agree)."""

    data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    assert data["id"] == profile_path.parent.name, (
        f"{profile_path.parent.name}: declared id {data['id']!r} differs from directory name"
    )


@pytest.mark.parametrize("profile_path", _profile_files(), ids=lambda p: p.parent.name)
def test_profile_controls_exist_in_catalog(profile_path: Path, catalog_ids: set[str]) -> None:
    """Every control_id used in a profile must exist in the catalog."""

    data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    controls = data["controls"]
    missing = [c for c in controls if c not in catalog_ids]
    assert not missing, (
        f"{profile_path.parent.name}: control IDs not present in catalog.yaml: {missing}"
    )


@pytest.mark.parametrize("profile_path", _profile_files(), ids=lambda p: p.parent.name)
def test_profile_has_no_duplicate_controls(profile_path: Path) -> None:
    """A profile must not list the same control_id twice."""

    data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    counts = Counter(data["controls"])
    duplicates = [cid for cid, n in counts.items() if n > 1]
    assert not duplicates, (
        f"{profile_path.parent.name}: duplicate control IDs in 'controls:': {duplicates}"
    )


def test_at_least_21_bundled_profiles_exist() -> None:
    """Sanity floor: the kit must continue shipping its full bundled catalog of profiles."""

    files = _profile_files()
    assert len(files) >= 21, f"Expected at least 21 bundled profiles; found {len(files)}"
