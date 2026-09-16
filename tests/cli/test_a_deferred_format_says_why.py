"""Asking for a format the kit deliberately does not emit should get the reason.

`osps-coverage --format osps` used to answer "--format must be human or json", which is true
and tells the reader nothing. The renderer is deferred on purpose: it would have to match the
Scorecard v6 OSPS conformance wire shape, which is still a proposal rather than a released
format, and emitting a guess at it would be a conformance claim the kit cannot keep.

That reasoning existed only in ADR-018 and in the second half of a documentation page, so the
one person guaranteed to want it -- someone who just typed the flag -- was the one least
likely to find it. These tests hold the message at the point of use, and hold its two written
sources in place so it cannot outlive its own explanation.

Asserted in-process rather than through a subprocess: Rich hard-wraps stderr at the terminal
width, which splits a long message mid-phrase and makes a substring assertion pass on one
machine and fail on another.
"""

from __future__ import annotations

import pytest
from tests.conftest import ROOT

from oss_policy_kit.cli.osps_coverage import _run_osps_coverage
from oss_policy_kit.domain.errors import InvalidInputError

_ADR = ROOT / "docs" / "decisions" / "adr-018-osps-baseline-2026-scorecard-v6.md"
_COVERAGE_DOC = ROOT / "docs" / "osps-baseline-2026-coverage.md"


def test_the_deferred_format_names_its_reason_and_its_trigger() -> None:
    with pytest.raises(InvalidInputError) as caught:
        _run_osps_coverage("osps")

    message = caught.value.message
    assert "deliberately" in message
    assert "ADR-018" in message
    assert "proposal rather than a released format" in message


def test_the_deferred_format_points_at_the_half_that_is_shipped() -> None:
    """The consuming side exists, and a reader who wanted `osps` probably wants to hear it."""

    with pytest.raises(InvalidInputError) as caught:
        _run_osps_coverage("osps")

    message = caught.value.message
    assert "OSPS-SCORECARD-V6-001" in message
    assert ".oss-policy-kit/evidence/scorecard-osps.json" in message


def test_an_ordinary_unknown_format_keeps_the_short_answer() -> None:
    """Only the deferred name earns the long message; a typo still gets the two valid values."""

    with pytest.raises(InvalidInputError) as caught:
        _run_osps_coverage("nonsense")

    assert caught.value.message == "--format must be human or json."


@pytest.mark.parametrize("fmt", ["osps", "OSPS", "  osps  "])
def test_the_deferred_name_is_matched_the_way_every_other_format_is(fmt: str) -> None:
    """Case and surrounding space are normalized before the lookup, as for human and json."""

    with pytest.raises(InvalidInputError) as caught:
        _run_osps_coverage(fmt)

    assert "ADR-018" in caught.value.message


@pytest.mark.parametrize("fmt", ["human", "json"])
def test_the_formats_that_do_work_still_work(fmt: str) -> None:
    _run_osps_coverage(fmt)


def test_the_deferral_is_still_written_down_where_the_message_sends_the_reader() -> None:
    """The message cites two documents. If either stops explaining it, the message is a dead end.

    Checked by content rather than by the file existing: a page that no longer mentions the
    deferral would still open.
    """

    adr = _ADR.read_text(encoding="utf-8")
    coverage = _COVERAGE_DOC.read_text(encoding="utf-8")

    assert "--format=osps" in adr, "ADR-018 no longer mentions the format it defers"
    assert "reaches GA" in adr, "ADR-018 no longer states the condition that ends the deferral"
    assert "intentionally deferred" in coverage, "the coverage page no longer records the deferral"
