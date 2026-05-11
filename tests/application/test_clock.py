"""Tests for ``application/clock.py``.

Verifies that ``SOURCE_DATE_EPOCH`` is honoured for reproducible builds and
that malformed / missing values fall back cleanly to the wall clock.
"""

from __future__ import annotations

import re

import pytest

from oss_policy_kit.application.clock import report_generated_at

_ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")


def test_report_generated_at_uses_wall_clock_when_env_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    out = report_generated_at()
    assert _ISO_UTC_RE.match(out), out


def test_report_generated_at_honours_source_date_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    assert report_generated_at() == "2023-11-14T22:13:20+00:00"


def test_report_generated_at_strips_microseconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    out = report_generated_at()
    assert "." not in out.split("+")[0]


@pytest.mark.parametrize("bad_value", ["", "not-a-number", "-1", "abc123"])
def test_report_generated_at_falls_back_on_bad_input(monkeypatch: pytest.MonkeyPatch, bad_value: str) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", bad_value)
    out = report_generated_at()
    assert _ISO_UTC_RE.match(out), (bad_value, out)


def test_report_generated_at_accepts_zero_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    assert report_generated_at() == "1970-01-01T00:00:00+00:00"
