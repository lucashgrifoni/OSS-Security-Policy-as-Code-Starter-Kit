"""The release-hardening guide must name the vocabulary the code emits.

`docs/release-hardening-workflow.md` tells an operator how to read
`evaluation-report.json`. It restated the contract instead of pointing at it, and the
restatement was the pre-2.0 one: a `results` array that does not exist and lowercase
state names the report never writes. Someone writing a parser from that page gets
`KeyError: 'results'` on the first line, and after fixing that never matches a state,
because they are comparing `pass` against `PASS`.

These tests derive the expected vocabulary from `REPORTS_V2_STATUS_MAP`, the map the
renderer itself uses. A state added or renamed there fails this file until the guide
follows, which is the property the previous wording lacked.
"""

from __future__ import annotations

import re

import pytest

from oss_policy_kit.application.reporting import REPORTS_V2_STATUS_MAP
from tests.conftest import ROOT

_GUIDE = ROOT / "docs" / "release-hardening-workflow.md"

#: The wire states, and the sub-codes that refine `UNKNOWN`, exactly as the renderer maps
#: them. Deriving both from one map keeps this file from becoming the second stale copy.
_STATES = sorted({state for state, _ in REPORTS_V2_STATUS_MAP.values()})
_REASONS = sorted({reason for _, reason in REPORTS_V2_STATUS_MAP.values() if reason})


def _guide() -> str:
    return _GUIDE.read_text(encoding="utf-8")


@pytest.mark.parametrize("state", _STATES)
def test_the_guide_names_every_state_the_report_can_carry(state: str) -> None:
    assert f"`{state}`" in _guide(), (
        f"`{state}` is a state the report emits and the reading guide never mentions it. "
        "An operator following this page will not recognise it in their own output."
    )


@pytest.mark.parametrize("reason", _REASONS)
def test_the_guide_names_every_reason_that_refines_unknown(reason: str) -> None:
    assert f"`{reason}`" in _guide(), (
        f"`UNKNOWN` can carry `reason: {reason!r}`, and the guide's list omits it. That list "
        "is presented as complete, so an omission reads as 'this value cannot occur'."
    )


def test_the_guide_does_not_name_the_array_the_report_stopped_writing() -> None:
    """`results` was the pre-2.0 name. The report writes `controls`.

    Asserted on the section rather than the file so an explicit migration note elsewhere
    on the page could still say the old name out loud.
    """

    section = _guide().split("## Reading the report", 1)[1].split("\n## ", 1)[0]
    assert "`results`" not in section
    assert "`controls`" in section


def test_the_guide_does_not_present_a_lowercase_state_as_a_state() -> None:
    """The old vocabulary survives as `reason` values, so a bare lowercase `pass` is wrong.

    `waived` and `not-evaluated` are still real — as sub-codes — which is why this checks
    only the names that became states and kept no lowercase meaning.
    """

    section = _guide().split("## Reading the report", 1)[1].split("\n## ", 1)[0]
    retired = [name for name in ("pass", "fail", "not-applicable", "self-attested", "attested")]
    found = [name for name in retired if re.search(rf"^- `{re.escape(name)}`", section, re.MULTILINE)]
    assert not found, (
        f"these are listed as states in their pre-2.0 lowercase spelling: {found}. "
        "The report writes them uppercase, so a consumer comparing against this page never matches."
    )
