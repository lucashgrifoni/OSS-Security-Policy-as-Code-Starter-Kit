"""Property-based tests for ProfileSpec deserialization."""

from __future__ import annotations

from pathlib import Path

import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from oss_policy_kit.application.loader import load_profile

control_id_strategy = st.from_regex(r"[A-Z]{2,8}-[A-Z0-9]{2,12}-\d{3}", fullmatch=True)


@given(controls=st.lists(control_id_strategy, min_size=1, max_size=30, unique=True))
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_external_profile_yaml_roundtrip_preserves_control_ids(controls: list[str], tmp_path: Path) -> None:
    path = tmp_path / "profile.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "id": "test-profile",
                "title": "Test profile",
                "description": "Generated profile",
                "audience": "property tests",
                "controls": controls,
            }
        ),
        encoding="utf-8",
    )

    spec = load_profile(path, validate_external_schema=True)
    assert spec.id == "test-profile"
    assert spec.control_ids == tuple(controls)


@given(
    controls=st.lists(
        st.text(alphabet=" ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789", min_size=1, max_size=40),
        min_size=1,
        max_size=20,
    )
)
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_profile_loader_trims_non_empty_control_ids(controls: list[str], tmp_path: Path) -> None:
    expected = tuple(str(c).strip() for c in controls if str(c).strip())
    path = tmp_path / "profile.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "id": "test-profile",
                "title": "Test profile",
                "description": "Generated profile",
                "audience": "property tests",
                "controls": controls,
            }
        ),
        encoding="utf-8",
    )

    spec = load_profile(path, validate_external_schema=False)
    assert spec.control_ids == expected
