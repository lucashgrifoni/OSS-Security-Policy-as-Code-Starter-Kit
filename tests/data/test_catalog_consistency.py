"""Catalog-wide invariant tests for ``data/controls/catalog.yaml``.

Complements ``tests/application/test_catalog_assurance.py`` (which only
asserts the ``assurance`` field). This module covers every other field
the catalog declares for each control entry, plus uniqueness and enum
membership invariants.

Coverage:

- Every control entry exposes the full required field set
  (``id``, ``title``, ``category``, ``automation``, ``lifecycle``,
  ``assurance``, ``weight``).
- Each ``category``, ``lifecycle``, ``assurance``, ``automation``, and
  ``weight`` is a member of its allowed set.
- No duplicate ``id`` across the catalog.
- ``title`` is a non-empty trimmed string.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

CATALOG_PATH = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit" / "data" / "controls" / "catalog.yaml"

REQUIRED_FIELDS: tuple[str, ...] = (
    "id",
    "title",
    "category",
    "automation",
    "lifecycle",
    "assurance",
    "weight",
)

ALLOWED_CATEGORIES: frozenset[str] = frozenset(
    {
        "governance",
        "ci_cd",
        "supply_chain",
        "vulnerability_management",
        "release",
        "platform",
        "iac",
        "container",
        "kubernetes",
        "secure_development",
    }
)

ALLOWED_LIFECYCLES: frozenset[str] = frozenset({"stable", "experimental", "deprecated"})

ALLOWED_ASSURANCE: frozenset[str] = frozenset({"deterministic", "signal", "evidence-backed"})

ALLOWED_AUTOMATION: frozenset[str] = frozenset(
    {
        "automated",
        "partially_observable",
        "human_or_policy",
        "not_observable_locally",
        "deterministic",
    }
)

ALLOWED_WEIGHTS: frozenset[int] = frozenset({1, 2, 3})


def _load_controls() -> list[dict[str, Any]]:
    raw = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, dict), "catalog.yaml root must be a mapping"
    controls = raw.get("controls", [])
    assert isinstance(controls, list) and controls, "catalog.yaml: 'controls:' must be a non-empty list"
    for c in controls:
        assert isinstance(c, dict), f"catalog.yaml: each control must be a mapping; got {type(c).__name__}"
    return controls


CONTROLS: list[dict[str, Any]] = _load_controls()


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: str(c.get("id", "<no-id>")))
def test_control_has_required_fields(control: dict[str, Any]) -> None:
    """Every catalog control entry must expose the required field set."""

    cid = control.get("id", "<no-id>")
    for field in REQUIRED_FIELDS:
        assert field in control, f"{cid}: missing required field '{field}'"


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: str(c.get("id", "<no-id>")))
def test_control_title_is_non_empty_string(control: dict[str, Any]) -> None:
    cid = control["id"]
    title = control.get("title")
    assert isinstance(title, str) and title.strip(), f"{cid}: 'title' must be a non-empty string"


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: str(c.get("id", "<no-id>")))
def test_control_category_is_allowed(control: dict[str, Any]) -> None:
    cid = control["id"]
    assert control["category"] in ALLOWED_CATEGORIES, (
        f"{cid}: category={control['category']!r} not in {sorted(ALLOWED_CATEGORIES)}"
    )


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: str(c.get("id", "<no-id>")))
def test_control_lifecycle_is_allowed(control: dict[str, Any]) -> None:
    cid = control["id"]
    assert control["lifecycle"] in ALLOWED_LIFECYCLES, (
        f"{cid}: lifecycle={control['lifecycle']!r} not in {sorted(ALLOWED_LIFECYCLES)}"
    )


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: str(c.get("id", "<no-id>")))
def test_control_assurance_is_allowed(control: dict[str, Any]) -> None:
    cid = control["id"]
    assert control["assurance"] in ALLOWED_ASSURANCE, (
        f"{cid}: assurance={control['assurance']!r} not in {sorted(ALLOWED_ASSURANCE)}"
    )


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: str(c.get("id", "<no-id>")))
def test_control_automation_is_allowed(control: dict[str, Any]) -> None:
    cid = control["id"]
    assert control["automation"] in ALLOWED_AUTOMATION, (
        f"{cid}: automation={control['automation']!r} not in {sorted(ALLOWED_AUTOMATION)}"
    )


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: str(c.get("id", "<no-id>")))
def test_control_weight_is_allowed(control: dict[str, Any]) -> None:
    cid = control["id"]
    assert control["weight"] in ALLOWED_WEIGHTS, f"{cid}: weight={control['weight']!r} not in {sorted(ALLOWED_WEIGHTS)}"


def test_no_duplicate_control_ids() -> None:
    """Catalog must not declare the same control id twice."""

    counts = Counter(c["id"] for c in CONTROLS)
    duplicates = sorted(cid for cid, n in counts.items() if n > 1)
    assert not duplicates, f"catalog.yaml: duplicate control IDs: {duplicates}"


def test_at_least_120_controls_in_catalog() -> None:
    """Sanity floor: catalog must continue to expose its full control set."""

    assert len(CONTROLS) >= 120, f"Expected at least 120 catalog controls; found {len(CONTROLS)}"
