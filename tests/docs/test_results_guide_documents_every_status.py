"""``docs/results-guide.md`` must document every state the CLI can actually emit.

The status table shipped seven of the nine ``ControlStatus`` members. ``attested`` and
``not-evaluated`` were missing, and both are reached on ordinary runs with stock bundled
profiles and no flags -- ``OSS-SCORECARD-001`` without ``--scorecard-json`` is
``not-evaluated``, ``PROV-VERIFY-061`` with a verified provenance record is ``attested``.
A reader who hit either had nowhere to look it up.

String-presence checks would not have caught that and will not catch the next one, so every
guard below is derived from the source of truth rather than from a hardcoded list:

- every :class:`ControlStatus` member has a row, so a tenth state fails this test in the
  commit that adds it;
- the rows sit in :data:`STATUS_ORDER`, the order the page claims for them;
- each row's ``reports/2.0`` cell matches :data:`REPORTS_V2_STATUS_MAP`, so the projection
  the page teaches cannot drift from the projection the reporter performs. That mapping is
  the confusing part -- five domain states collapse into ``UNKNOWN`` and only ``reason``
  separates them -- which is exactly why it needs a guard.

The table was all those guards saw. The prose is where the page claimed ``OSS-SCORECARD-001``
reaches ``not-evaluated`` "on any profile from ``github-level-2`` up" -- which omits the three
``s2c2f-*`` profiles that carry the control and sweeps in ``github-release-hardening-1``, which
does not. So two guards read the prose as well:

- the profiles the ``OSS-SCORECARD-001`` bullet names are exactly the bundled profiles whose
  ``profile.yaml`` lists that control;
- every hyphenated inline-code token spelled only from status words is a real state, which
  catches a ``manual-review`` or a ``not-attested`` written into a sentence. A coinage that
  brings in a word the enum never uses (``not-evaluated-yet``) reads as ordinary prose and
  slips past it; the row guards above are what catch a state that disappears.
"""

from __future__ import annotations

import re
from pathlib import Path

from oss_policy_kit.application.cli_output import STATUS_ORDER
from oss_policy_kit.application.loader import bundled_kit_root, load_profile_by_id
from oss_policy_kit.application.reporting import REPORTS_V2_STATUS_MAP
from oss_policy_kit.domain.models import ControlStatus

_GUIDE = Path(__file__).resolve().parents[2] / "docs" / "results-guide.md"
_HEADER = "| Status | Meaning | In `reports/2.0` |"
#: The words the nine status values are spelled from. A hyphenated token built only out of
#: these names a state; `all-pass` and `collect-evidence` each bring a word the enum never
#: uses, so they read as prose.
_STATUS_WORDS = frozenset(word for status in ControlStatus for word in status.value.split("-"))


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


def _prose() -> str:
    """The page without its fenced blocks, so sample output is not mined for claims."""

    return re.sub(r"^```.*?^```", "", _GUIDE.read_text(encoding="utf-8"), flags=re.S | re.M)


def _inline_code(text: str) -> list[str]:
    """Every single-backtick span in *text*."""

    return re.findall(r"`([^`\n]+)`", text)


def _bullet(prefix: str) -> str:
    """The one list item starting with *prefix*, indented continuation lines folded in."""

    lines = _prose().splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith(prefix)]
    assert len(starts) == 1, f"expected exactly one bullet starting {prefix!r}, found {len(starts)}"
    body = [lines[starts[0]]]
    for line in lines[starts[0] + 1 :]:
        if not line.startswith("  "):
            break
        body.append(line)
    return " ".join(body)


def _bundled_profile_ids() -> set[str]:
    """Every profile id shipped under ``data/profiles/``."""

    return {path.parent.name for path in (bundled_kit_root() / "profiles").glob("*/profile.yaml")}


def _profiles_carrying(control_id: str) -> set[str]:
    """The bundled profiles whose control list includes *control_id*."""

    root = bundled_kit_root()
    return {pid for pid in _bundled_profile_ids() if control_id in load_profile_by_id(root, pid).control_ids}


def _names_a_status(token: str) -> bool:
    """True when *token* is a hyphenated phrase spelled entirely from status words."""

    return re.fullmatch(r"[a-z]+(?:-[a-z]+)+", token) is not None and set(token.split("-")) <= _STATUS_WORDS


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


def test_status_table_rows_are_in_the_order_the_cli_prints() -> None:
    """The page introduces the table as "the order the CLI summary prints them"."""

    assert tuple(_status_table_rows()) == STATUS_ORDER, "status-table row order disagrees with STATUS_ORDER"


def test_status_table_projection_column_matches_the_reporter() -> None:
    rows = _status_table_rows()
    for status in ControlStatus:
        cell = rows[status.value]
        assert re.findall(r"`([^`]+)`", cell) == _expected_projection_tokens(status), (
            f"{status.value}: reports/2.0 cell disagrees with REPORTS_V2_STATUS_MAP"
        )


def test_prose_names_no_state_the_table_does_not_document() -> None:
    named = {token for token in _inline_code(_prose()) if _names_a_status(token)}
    assert named <= set(_status_table_rows()), "prose names a state with no row in the status table"


def test_scorecard_bullet_names_the_profiles_that_carry_the_control() -> None:
    """`OSS-SCORECARD-001` is on three `s2c2f-*` profiles too, not only the GitHub ladder."""

    named = {token for token in _inline_code(_bullet("- `OSS-SCORECARD-001`")) if token in _bundled_profile_ids()}
    assert named == _profiles_carrying("OSS-SCORECARD-001"), "the bullet's profile list disagrees with data/profiles"


def test_scaffold_templates_are_not_described_as_self_attested() -> None:
    """Unfilled ``scaffold-evidence`` templates are ``not-evaluated``, on every control.

    The page used to promise ``self-attested`` (or ``manual-review-required`` for empty
    fields), which credits a template nobody filled in with a state that scores as a pass.
    """

    text = _GUIDE.read_text(encoding="utf-8")
    section = text.split("## Evidence templates vs. real evidence", 1)[1].split("\n## ", 1)[0]
    assert "`not-evaluated`" in section
    assert "never as `self-attested`" in section
