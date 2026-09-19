"""Text a scanned repository chooses must not give the report a destination to fetch.

The report prints a control's reason and remediation, the operational warnings, and a
waiver's owner and justification as prose. The target chooses more of that text than it
looks: `evaluators/ai.py` alone interpolates `{p.name}` and `{rel}` into a dozen reasons,
so a file named `[click](http://somewhere)` inside a scanned repository reaches the page.

Measured against a rendered report before the fix, three shapes worked. An inline link and
an autolink each produced a clickable `<a href>`. An image produced an `<img src>`, and
that one is the reason this is not only about clickable links: an image needs no click, so
opening the report reaches out to whoever wrote the filename.

Reference-style links and bare URLs did not work, the first because the newline that would
carry the definition is flattened and the second because CommonMark does not linkify bare
text. They are left alone rather than defended against, and the cases below record that
they were checked.

What the fix leaves reachable is deliberate. Emphasis still works: a `*` turns text italic
and gives nobody an address. Backticks still work, because three catalog controls quote
filenames with them. A bare `[` still works, because a shipped remediation reads
``runs-on: [self-hosted, ephemeral]`` and escaping it would show the reader a backslash.
"""

from __future__ import annotations

import re

import pytest
from markdown_it import MarkdownIt

from oss_policy_kit.application.reporting import _markdown_report_text
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

#: Anything a reader's browser would follow or fetch, clicked or not.
_DESTINATION = re.compile(r"<a href|<img[^>]*src")

#: Shapes that were measured producing a destination before the fix.
_WORKING_VECTORS = [
    pytest.param("[click](http://evil.invalid)", id="inline-link"),
    pytest.param("![i](http://evil.invalid/beacon.png)", id="image-beacon"),
    pytest.param("<http://evil.invalid>", id="autolink-http"),
    pytest.param("<mailto:someone@evil.invalid>", id="autolink-mailto"),
    pytest.param("<someone@evil.invalid>", id="autolink-bare-email"),
]

#: Text the kit itself writes. Every one of these has to survive byte for byte.
_LEGITIMATE = [
    pytest.param("`SECURITY.md` not found at repository root.", id="backticks"),
    pytest.param("Add `ephemeral` to the list (e.g. `runs-on: [self-hosted, ephemeral]`)", id="bare-brackets"),
    pytest.param("the value must be < 80 characters", id="bare-less-than"),
    pytest.param("SBOM-like file(s) found but format not confirmed: a.json, b.json.", id="parentheses"),
]


def _report(*, reason: str = "r", remediation: str = "x", warning: str | None = None) -> ExecutionReport:
    result = ControlResult(
        control_id="GOV-SEC-001",
        title="Security policy present",
        category="governance",
        status=ControlStatus.FAIL,
        profile="github-level-1",
        evidence_sources=[],
        confidence="high",
        reason=reason,
        remediation=remediation,
    )
    return ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-09-19T00:00:00Z",
        kit_version="10.0.24",
        target_path="repo",
        profile_id="github-level-1",
        profile_title="GitHub level 1",
        summary_by_status={"fail": 1},
        results=[result],
        operational_warnings=[warning] if warning else [],
    )


def _rendered(report: ExecutionReport) -> str:
    return MarkdownIt("commonmark").render(_markdown_report_text(report))


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_a_reason_cannot_give_the_report_a_destination(payload: str) -> None:
    html = _rendered(_report(reason=payload))

    assert not _DESTINATION.search(html), (
        f"a reason of {payload!r} put a destination in the report. The reason carries file "
        "names read out of the scanned repository, so the repository chose that address."
    )


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_a_remediation_cannot_give_the_report_a_destination(payload: str) -> None:
    assert not _DESTINATION.search(_rendered(_report(remediation=payload)))


@pytest.mark.parametrize("payload", _WORKING_VECTORS)
def test_an_operational_warning_cannot_give_the_report_a_destination(payload: str) -> None:
    """Warnings name the file that raised them, so their wording comes from the target too."""

    assert not _DESTINATION.search(_rendered(_report(warning=payload)))


@pytest.mark.parametrize("payload", _LEGITIMATE)
def test_the_text_the_kit_writes_is_unchanged(payload: str) -> None:
    """The other half. A fix that escaped everything would pass every case above it."""

    markdown = _markdown_report_text(_report(reason=payload))

    assert payload in markdown, (
        f"{payload!r} came back altered. This is text the kit itself writes, and a reader "
        "would see the escaping rather than the sentence."
    )


def test_the_vectors_that_do_not_work_are_recorded_as_checked() -> None:
    """Anti-drift: if CommonMark or the flattening changes, these stop being safe by luck."""

    assert not _DESTINATION.search(_rendered(_report(reason="http://evil.invalid")))
    assert not _DESTINATION.search(_rendered(_report(reason="[click][r]\n\n[r]: http://evil.invalid")))
