"""The sample reports checked into ``docs/`` must be what the current CLI writes.

``docs/sample-reports/`` is offered in the README as the way to see a report without
running anything, so it is read as a specification. Nothing verified it: the files sat
on the pre-2.0 shape (``results[]`` / ``schema_version``, no ``contract_version``) from
2026-05-19 through v9.0.0, which removed that contract, and v10.0.0, which rebuilt the
surface around it. A 4600-test suite stayed green the whole time because no test ever
opened them.

They also carried the defect the positional redaction had: an evidence reference marked
``"redacted": true`` still spelled out the directory chain of the machine that produced
it, which is the failure mode where a label stops a reviewer from looking.

These checks are cheap and they fail loudly the next time either drifts.
"""

from __future__ import annotations

import json
import re
from typing import Any

import jsonschema
import pytest

from oss_policy_kit.application.reporting import REPORTS_V2_STATUS_MAP
from tests.conftest import ROOT

SAMPLES = ROOT / "docs" / "sample-reports"
SCHEMA_2_0 = ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "reports" / "2.0.json"
LABS = ("hardened", "vulnerable")

# A redacted value that still contains a separator kept part of the host's directory
# chain. The marker itself ends in one, so it is stripped before the check.
_MARKER = "<redacted-absolute>"


def _report(lab: str) -> dict[str, Any]:
    return json.loads((SAMPLES / lab / "evaluation-report.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("lab", LABS)
def test_sample_report_is_on_the_only_contract_the_kit_emits(lab: str) -> None:
    payload = _report(lab)

    assert payload.get("contract_version") == "reports/2.0", (
        "the shipped sample is not on the contract the CLI writes; regenerate it (see docs/sample-reports/README.md)"
    )
    assert "controls" in payload, "sample uses the removed pre-2.0 'results[]' shape"
    assert "results" not in payload


@pytest.mark.parametrize("lab", LABS)
def test_sample_report_was_produced_by_the_kit_that_ships_with_it(lab: str) -> None:
    """The version stamp is part of "what the current CLI writes", and nothing was reading it.

    The four guards here checked contract, schema, redaction and JSON/MD agreement, and the
    samples still drifted: they carried `kit_version 10.0.5` while the kit shipped 10.0.15, ten
    patch releases later. A reader is told these files are the way to see a report without running
    anything, so a stale stamp says the kit last produced this a version it did not.

    Regenerating showed the drift was exactly one line per file and nothing else -- the verdicts,
    reasons and remediation text were identical across those ten releases. That is a good sign
    about contract stability and a bad one about this guard: the only field that moved was the
    only field nobody compared.

    Both formats are checked. The Markdown is what most readers open, and it carries its own copy
    of the stamp, so a JSON-only assertion would leave half the samples able to drift.
    """

    from oss_policy_kit import __version__

    assert _report(lab)["kit_version"] == __version__, (
        f"docs/sample-reports/{lab}/evaluation-report.json was produced by kit "
        f"{_report(lab)['kit_version']}, and this tree is {__version__}. Regenerate both labs with "
        "the commands in docs/sample-reports/README.md, with SOURCE_DATE_EPOCH exported -- never "
        "by editing the version string, which would claim a freshness the file does not have."
    )

    markdown = (SAMPLES / lab / "evaluation-report.md").read_text(encoding="utf-8")
    assert f"`{__version__}`" in markdown, (
        f"docs/sample-reports/{lab}/evaluation-report.md does not name kit {__version__}"
    )


@pytest.mark.parametrize("lab", LABS)
def test_sample_report_validates_against_the_published_schema(lab: str) -> None:
    schema = json.loads(SCHEMA_2_0.read_text(encoding="utf-8"))

    jsonschema.validate(_report(lab), schema)


@pytest.mark.parametrize("lab", LABS)
def test_sample_report_keeps_no_host_directory_chain(lab: str) -> None:
    """A reference labelled redacted must carry the leaf and nothing above it."""

    text = (SAMPLES / lab / "evaluation-report.json").read_text(encoding="utf-8")
    kept: list[str] = []
    for value in re.findall(rf'"{re.escape(_MARKER)}[^"]*"', text):
        tail = value.strip('"')[len(_MARKER) :].lstrip("/\\")
        if "/" in tail or "\\" in tail:
            kept.append(value)

    assert not kept, f"{lab}: redacted references still carry a directory chain: {kept[:3]}"


@pytest.mark.parametrize("lab", LABS)
def test_sample_markdown_and_json_agree_on_the_verdict(lab: str) -> None:
    """The two artifacts come from one run and must not tell a reader different stories.

    They deliberately speak different vocabularies -- the JSON carries the ``reports/2.0``
    state enum (``FAIL``), the Markdown the human status it was rendered from (``fail``,
    ``manual-review-required``) -- so the counts are compared through the kit's own map
    rather than by matching strings across the two surfaces.
    """

    payload = _report(lab)
    markdown = (SAMPLES / lab / "evaluation-report.md").read_text(encoding="utf-8")

    from_markdown: dict[str, int] = {}
    for status, count in re.findall(r"^\| `([a-z-]+)` \| (\d+) \|$", markdown, re.MULTILINE):
        state, _detail = REPORTS_V2_STATUS_MAP[status]
        from_markdown[state] = from_markdown.get(state, 0) + int(count)

    assert from_markdown, "the Markdown summary table was not found, so nothing was compared"
    assert from_markdown == payload["summary_by_status"], (
        f"{lab}: the two sample artifacts disagree on the outcome of the same run"
    )
