"""Property-based tests for control catalog deserialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from oss_policy_kit.application.loader import load_catalog

control_id_strategy = st.from_regex(r"[A-Z]{2,8}-[A-Z0-9]{2,12}-\d{3}", fullmatch=True)
assurance_strategy = st.sampled_from(["deterministic", "signal", "evidence-backed"])
lifecycle_strategy = st.sampled_from(["stable", "experimental", "deprecated"])
weight_strategy = st.one_of(st.integers(min_value=-10, max_value=10), st.text(alphabet="abc123", max_size=6), st.none())


@st.composite
def control_dicts(draw: Any) -> dict[str, Any]:
    cid = draw(control_id_strategy)
    return {
        "id": cid,
        "title": f"Control {cid}",
        "category": draw(st.sampled_from(["governance", "ci-cd", "supply-chain", "appsec"])),
        "automation": draw(st.sampled_from(["deterministic", "manual", "evidence"])),
        "lifecycle": draw(lifecycle_strategy),
        "assurance": draw(assurance_strategy),
        "weight": draw(weight_strategy),
    }


@given(controls=st.lists(control_dicts(), min_size=1, max_size=40, unique_by=lambda c: c["id"]))
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_catalog_loader_preserves_controls_and_clamps_weight(
    controls: list[dict[str, Any]],
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump({"controls": controls}), encoding="utf-8")

    catalog = load_catalog(path)

    assert set(catalog) == {c["id"] for c in controls}
    for spec in catalog.values():
        assert spec.assurance in {"deterministic", "signal", "evidence-backed"}
        assert 1 <= spec.weight <= 3


@given(lifecycle=lifecycle_strategy, assurance=assurance_strategy, weight=st.integers(min_value=1, max_value=3))
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_control_spec_core_fields_roundtrip(lifecycle: str, assurance: str, weight: int, tmp_path: Path) -> None:
    path = tmp_path / "catalog.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "controls": [
                    {
                        "id": "GOV-SEC-001",
                        "title": "Security policy",
                        "category": "governance",
                        "automation": "deterministic",
                        "lifecycle": lifecycle,
                        "assurance": assurance,
                        "weight": weight,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    spec = load_catalog(path)["GOV-SEC-001"]
    assert spec.lifecycle == lifecycle
    assert spec.assurance == assurance
    assert spec.weight == weight
