"""Property-based tests for waiver expiry semantics."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.domain.models import utc_today


@given(expires_at=st.dates(min_value=date(2020, 1, 1), max_value=date(2030, 12, 31)))
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_waiver_expiry_date_controls_application(expires_at: date, tmp_path: Path) -> None:
    path = tmp_path / "waivers.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "waivers": [
                    {
                        "control_id": "GOV-SEC-001",
                        "justification": "temporary accepted risk",
                        "owner": "security@example.com",
                        "expires_at": expires_at.isoformat(),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    outcome = parse_waivers_file(path)
    if expires_at < utc_today():
        assert "GOV-SEC-001" not in outcome.by_control
        assert outcome.warnings
    else:
        assert outcome.by_control["GOV-SEC-001"].expires_at == expires_at


@given(days=st.integers(min_value=0, max_value=3650))
@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_waiver_datetime_string_roundtrip_keeps_date(days: int, tmp_path: Path) -> None:
    expires_on = utc_today() + timedelta(days=days)
    iso = f"{expires_on.isoformat()}T12:34:56+00:00"
    path = tmp_path / "waivers.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "waivers": [
                    {
                        "control_id": "GOV-SEC-001",
                        "justification": "temporary accepted risk",
                        "owner": "security@example.com",
                        "expires_at": iso,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    outcome = parse_waivers_file(path)
    assert outcome.by_control["GOV-SEC-001"].expires_at == expires_on


@given(value=st.text(min_size=1, max_size=40).filter(lambda s: s[:10].count("-") != 2))
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_invalid_waiver_dates_are_skipped_with_warning(value: str, tmp_path: Path) -> None:
    path = tmp_path / "waivers.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "waivers": [
                    {
                        "control_id": "GOV-SEC-001",
                        "justification": "temporary accepted risk",
                        "owner": "security@example.com",
                        "expires_at": value,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    outcome = parse_waivers_file(path)
    assert "GOV-SEC-001" not in outcome.by_control
    assert outcome.warnings
