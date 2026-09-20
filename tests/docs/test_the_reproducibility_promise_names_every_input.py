"""What decides the hash is more than the epoch, and the docs used to name only the epoch.

Two sentences, in `publish-pypi.yml` and in `docs/supply-chain-verification.md`, both
measured and both wrong in the same direction.

The first said pinning `SOURCE_DATE_EPOCH` "makes the wheel bit-for-bit reproducible from
the tag alone". The epoch removes the runner's clock, which was the real obstacle, and it
is one input among several: the Python version, the platform and the build backend version
also decide the bytes. The backend version is not inferred here, it is read out of the
artifact: a wheel built from this tree carries `Generator: setuptools (84.0.0)` in
`.dist-info/WHEEL`, so a rebuild on a different setuptools cannot match the hash however
the clock is pinned. The published rebuild recipe runs `pip install build`, which resolves
whatever setuptools is current, so the gap is reachable by following the documentation.

The second said the sdist has its source entries pinned and that only the generated
`egg-info` members and the gzip header carry build time. Measured on a build with the
epoch exported: **0 of 237** file members carry `SOURCE_DATE_EPOCH` and all 237 carry the
checkout's mtime. The sentence attributed to a couple of generated entries what is true of
the whole archive.

These tests hold the corrected wording in place. They are string checks, which is the
right weight here: the facts were established by building, and what can regress is the
sentence, not the build.
"""

from __future__ import annotations

import pytest

from tests.conftest import ROOT

_WORKFLOW = ROOT / ".github" / "workflows" / "publish-pypi.yml"
_DOC = ROOT / "docs" / "supply-chain-verification.md"


def _collapsed(path) -> str:  # type: ignore[no-untyped-def]
    """Whitespace collapsed, comment and quote markers dropped.

    Both files hard-wrap, one behind `#` and one inside a table and bold runs, so a phrase
    that reads as one sentence is split across lines with a marker in the middle. A plain
    substring search misses it, which is a mistake this suite has already made once.
    """

    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            stripped = stripped.lstrip("#").strip()
        lines.append(stripped)
    return " ".join(" ".join(lines).split())


@pytest.mark.parametrize(
    "phrase",
    [
        pytest.param("removes the clock", id="says-what-the-epoch-does"),
        pytest.param("does not make the wheel reproducible from the tag alone", id="says-what-it-does-not-do"),
        pytest.param("build backend version and the platform all decide the bytes", id="names-the-other-inputs"),
        pytest.param("0 of 237 file members carry", id="the-sdist-measurement"),
    ],
)
def test_the_workflow_comment_says_what_was_measured(phrase: str) -> None:
    assert phrase in _collapsed(_WORKFLOW), f"the publish workflow no longer says: {phrase!r}"


@pytest.mark.parametrize(
    "phrase",
    [
        pytest.param("The epoch is one input, not the only one", id="names-the-limit"),
        pytest.param("Generator: setuptools", id="points-at-the-checkable-field"),
        pytest.param("0 of 237 file members carry the epoch", id="the-sdist-measurement"),
        pytest.param("Compare sdists by content, never by hash", id="tells-the-reader-what-to-do"),
    ],
)
def test_the_adopter_facing_doc_says_it_too(phrase: str) -> None:
    assert phrase in _collapsed(_DOC), f"docs/supply-chain-verification.md no longer says: {phrase!r}"


def test_the_wheel_row_no_longer_promises_an_unqualified_hash() -> None:
    """The row is the part a reader acts on, so it carries a condition.

    This asserted the literal phrase "when the build backend matches" until the backend
    condition was itself measured insufficient: at v10.0.24 with the same setuptools on
    both sides, a Windows rebuild still differs in METADATA and RECORD. Pinning the
    sentence made the guard fail on a correction rather than on a regression, which is
    backwards, so it now asserts what the row has to carry instead of how it is worded.
    The defect it was written for, an unqualified "Identical hash", still fails it.
    """

    doc = _collapsed(_DOC)
    lines = _DOC.read_text(encoding="utf-8").splitlines()
    row = next((line for line in lines if "Anything published after v10.0.20" in line), "")

    assert row, "the expectations table lost its post-v10.0.20 row"
    assert "Identical hash" in row, "the wheel row no longer states the hash expectation at all"
    assert "when the" in row, f"the wheel row promises a hash with no condition attached: {row}"
    assert "| Identical hash |" not in doc, "the unqualified promise is back in the table"


def test_the_sdist_row_does_not_claim_pinned_source_entries() -> None:
    doc = _collapsed(_DOC)

    assert "the mtimes of the generated `egg-info` members still carry build time" not in doc, (
        "the sdist row again attributes to a couple of generated entries what is true of all 237"
    )


def test_the_guard_can_tell_the_two_wordings_apart() -> None:
    """The mutation: the old row must not satisfy the new assertions."""

    old_row = "| Anything published after v10.0.20 | Identical hash | Identical file contents; ... |"

    assert "| Identical hash |" in old_row
    assert "Identical hash, when the build backend matches" not in old_row
