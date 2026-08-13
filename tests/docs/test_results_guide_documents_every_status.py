"""``docs/results-guide.md`` must document every state the CLI can actually emit.

The status table shipped seven of the nine ``ControlStatus`` members. ``attested`` and
``not-evaluated`` were missing, and both are reached on ordinary runs with stock bundled
profiles and no flags -- ``OSS-SCORECARD-001`` without ``--scorecard-json`` is
``not-evaluated``, ``PROV-VERIFY-061`` with a verified provenance record is ``attested``.
A reader who hit either had nowhere to look it up.

String-presence checks would not have caught that and will not catch the next one, so both
guards below are derived from the source of truth rather than from a hardcoded list:

- every :class:`ControlStatus` member has a row, so a tenth state fails this test in the
  commit that adds it;
- each row's ``reports/2.0`` cell matches :data:`REPORTS_V2_STATUS_MAP`, so the projection
  the page teaches cannot drift from the projection the reporter performs. That mapping is
  the confusing part -- five domain states collapse into ``UNKNOWN`` and only ``reason``
  separates them -- which is exactly why it needs a guard.
"""

from __future__ import annotations

import re
from pathlib import Path

from oss_policy_kit.application.reporting import REPORTS_V2_STATUS_MAP
from oss_policy_kit.domain.models import ControlStatus

_GUIDE = Path(__file__).resolve().parents[2] / "docs" / "results-guide.md"
_HEADER = "| Status | Meaning | In `reports/2.0` |"


def _status_table_rows() -> dict[str, str]:
    """Map each documented status to the raw text of its ``reports/2.0`` cell."""

    lines = _GUIDE.read_text(encoding="utf-8").splitlines()
    assert _HEADER in lines, f"status table header not found in {_GUIDE.name}"
    rows: dict[str, str] = {}
    # Skip the header and the `| --- |` separator, then take rows until the table ends.
    for line in lines[lines.index(_HEADER) + 2 :]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == 3, f"malformed status-table row: {line}"
        rows[cells[0].strip("`")] = cells[2]
    return rows


def _expected_projection_tokens(status: ControlStatus) -> list[str]:
    """The backtick-quoted tokens the ``reports/2.0`` cell must carry for *status*."""

    state, reason = REPORTS_V2_STATUS_MAP[status.value]
    if reason is None:
        return [state]
    return [state, f"reason: {reason}"]


def test_status_table_documents_every_control_status() -> None:
    documented = set(_status_table_rows())
    emitted = {s.value for s in ControlStatus}
    assert emitted - documented == set(), "ControlStatus members with no row in the status table"
    assert documented - emitted == set(), "status-table rows naming a state ControlStatus cannot emit"


def test_status_table_projection_column_matches_the_reporter() -> None:
    rows = _status_table_rows()
    for status in ControlStatus:
        cell = rows[status.value]
        assert re.findall(r"`([^`]+)`", cell) == _expected_projection_tokens(status), (
            f"{status.value}: reports/2.0 cell disagrees with REPORTS_V2_STATUS_MAP"
        )


def test_scaffold_templates_are_not_described_as_self_attested() -> None:
    """Unfilled ``scaffold-evidence`` templates are ``not-evaluated``, on every control.

    The page used to promise ``self-attested`` (or ``manual-review-required`` for empty
    fields), which credits a template nobody filled in with a state that scores as a pass.
    """

    text = _GUIDE.read_text(encoding="utf-8")
    section = text.split("## Evidence templates vs. real evidence", 1)[1].split("\n## ", 1)[0]
    assert "`not-evaluated`" in section
    assert "never as `self-attested`" in section
