"""The rebuild promise named the backend and stopped there. The backend is not enough.

`docs/supply-chain-verification.md` used to tell a verifier the wheel hash matches "when
the build backend matches". Measured at tag v10.0.24 on Windows 11 against the published
wheel, with `SOURCE_DATE_EPOCH` from the release commit and `Generator: setuptools
(84.0.0)` in both artifacts, so that condition was met:

    229 of 231 entries        byte for byte identical
    dist-info/METADATA        13,637 bytes against 13,384; 253 CRLF lines against 253 LF
                              lines, and nothing else
    dist-info/RECORD          differs because it carries METADATA's hash

A verifier following the old sentence from Windows gets two mismatches, one of them in
RECORD, and RECORD mismatching is what tampering looks like. That is the expensive
failure here: not a missing guarantee, a guarantee that makes an honest rebuild look
dishonest.

The mechanism is worth stating because it tells the verifier what to do. setuptools
generates METADATA, and on Windows writes it with CRLF. `.gitattributes` normalises files
as they are checked out and cannot reach one the build writes, which is why the catch-all
that fixed LICENSE and NOTICE left this behind.

This is a documentation guard. It asserts the page still carries the platform condition
and the mechanism, because the sentence it replaced was itself a correction that did not
go far enough, and the same paragraph has now been wrong twice in two different ways.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

DOC = Path(__file__).resolve().parents[2] / "docs" / "supply-chain-verification.md"
PUBLISH = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "publish-pypi.yml"


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def test_the_expectations_row_does_not_promise_the_backend_alone() -> None:
    """ "When the build backend matches" was measured insufficient; it must not come back."""

    body = _text()
    row = next((line for line in body.splitlines() if "Anything published after v10.0.20" in line), "")
    assert row, "the expectations table lost its post-v10.0.20 row"
    assert "Linux" in row, f"the wheel row no longer names the platform condition: {row}"
    assert not re.search(r"Identical hash, when the build backend matches\s*\(see below\)\s*\|", row), (
        "the row is back to promising the backend alone, which a Windows rebuild disproves"
    )


def test_the_page_states_what_a_windows_rebuild_actually_produces() -> None:
    """The numbers are the point. Without them the reader cannot tell a match from tampering."""

    body = _text()
    for fragment in ("229 of 231", "METADATA", "RECORD", "CRLF"):
        assert fragment in body, f"the page no longer states {fragment!r}"


def test_the_page_says_why_gitattributes_cannot_fix_it() -> None:
    """A verifier who does not know METADATA is generated will look for it in .gitattributes."""

    body = _text().lower()
    assert "generates metadata" in body or "metadata is written" in body or "setuptools generates" in body, (
        "the page states the difference without the mechanism, so the reader cannot act on it"
    )
    assert "gitattributes" in body, "the page no longer explains why the checkout rule does not reach this"


def test_the_page_tells_a_windows_verifier_what_to_do() -> None:
    """Naming a difference without the remedy leaves the verifier with a failed check."""

    body = _text()
    assert "Rebuild on Linux" in body, "the page no longer gives the remedy for the hash to match"
    assert "entry by entry" in body, "the page no longer tells a Windows verifier how to compare"


def test_the_published_wheel_is_built_where_the_page_says_to_rebuild() -> None:
    """The promise has two ends. "Rebuild on Linux" matches only a wheel built on Linux.

    Nothing pinned the other end. A publish job moved to a Windows runner would ship
    METADATA with CRLF, every Linux rebuild the page recommends would then differ in
    METADATA and RECORD, and the identical hash the page promises would not exist.
    """

    workflow = yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))
    runner = str(workflow["jobs"]["build"]["runs-on"])

    assert runner.startswith("ubuntu-"), f"the published wheel is built on {runner}, and the page promises Linux"
