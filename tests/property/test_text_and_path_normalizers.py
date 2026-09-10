"""Properties of the four pure normalizers that decide what reaches a shareable artifact.

Every one of these was added or reshaped in the v10.0.18 cycle, and every one was tested
by example: the spellings someone thought of, the control byte someone remembered. Four of
that cycle's guards were found to assert less than they claimed -- by mutation, not by the
suite -- and all four were example tests. These functions are pure, total and cheap, with a
domain far larger than a person enumerates, which is exactly what property testing is for.

Each property is stated as an invariant the rest of the kit relies on:

- `normalize_path_spelling`  -- idempotent; folds separators; keeps `..`; leaves URIs alone.
- `without_control_characters` -- idempotent; removes, never rewrites; keeps whitespace.
- `normalize_confidence`     -- total onto the four-word enum; idempotent; case-blind.
- `_sanitize_embedded_path_in_text` -- idempotent; never lengthens; leaves prose alone.

`deadline=None`, as in every other file under `tests/property/`. This file was the one holdout,
0 of 16 against 2-of-2 to 5-of-5 everywhere else, and it is the file that pays for it: the
default 200ms deadline is a wall-clock assertion about a single generated example, sitting
inside a test whose subject is correctness. It fired at about 1.6% of runs, and it was right
to -- a generated token shaped like `\\\\server\\share` sent `_sanitize_embedded_path_in_text`
to the network and it blocked for 2.7 seconds.

That defect is fixed at the source, and the guard that holds it now is deterministic: see
`tests/application/test_a_report_does_not_dial_a_destination_the_evidence_chose.py`, which
makes `Path.resolve` raise rather than measuring how long it took. So the signal this deadline
carried is kept in a form somebody can act on, and the deadline itself goes the way of the
other seven. What it would catch from here is a loaded machine, which is not a defect in the
normalizers.
"""

from __future__ import annotations

import string
import unicodedata

from hypothesis import given, settings
from hypothesis import strategies as st

from oss_policy_kit.application.reporting import _sanitize_embedded_path_in_text
from oss_policy_kit.domain.findings import normalize_path_spelling
from oss_policy_kit.domain.models import normalize_confidence, without_control_characters

_CONFIDENCE_ENUM = {"high", "medium", "low", "none"}
_KEPT_WHITESPACE = {"\t", "\n", "\r"}

# Path-shaped text: separators of both styles, dots, drive letters, ordinary segments.
_path_text = st.text(alphabet=string.ascii_letters + string.digits + "/\\.:_- ~", min_size=1, max_size=60)

# Anything at all, including control and format characters -- the categories the cleaner
# is meant to remove, plus the whitespace it is meant to keep.
_any_text = st.text(max_size=80)

# Prose with no path separator and no drive-letter shape in it.
_prose = st.text(alphabet=string.ascii_letters + string.digits + " ,;.", max_size=80)


# --------------------------------------------------------------------------- #
# normalize_path_spelling
# --------------------------------------------------------------------------- #


@given(_path_text)
@settings(deadline=None)
def test_path_spelling_is_idempotent(value: str) -> None:
    once = normalize_path_spelling(value)
    assert normalize_path_spelling(once) == once


@given(_path_text)
@settings(deadline=None)
def test_path_spelling_folds_every_separator_to_one_style(value: str) -> None:
    out = normalize_path_spelling(value)
    if "://" in value:
        assert out == value, "a URI is a different kind of reference and is left exactly as written"
        return
    assert "\\" not in out
    body = out[2:] if out.startswith("//") else out
    assert "//" not in body, "a doubled separator survives only as a UNC prefix"
    assert "/./" not in out
    assert not out.endswith("/.")
    assert out != "/."


@given(_path_text)
@settings(deadline=None)
def test_path_spelling_never_resolves_a_parent_segment(value: str) -> None:
    """`..` is a claim about the filesystem; this layer only reads a document."""

    if "://" in value:
        return
    before = [s for s in value.replace("\\", "/").split("/") if s == ".."]
    after = [s for s in normalize_path_spelling(value).split("/") if s == ".."]
    assert len(after) == len(before)


@given(_path_text)
@settings(deadline=None)
def test_path_spelling_keeps_every_named_segment_in_order(value: str) -> None:
    """Only separators and `.` segments are touched; nothing that names a file is lost."""

    if "://" in value:
        return
    named = [s for s in value.replace("\\", "/").split("/") if s and s != "."]
    out = normalize_path_spelling(value)
    kept = [s for s in out.split("/") if s and s != "."]
    assert kept == named or (not named and out == value)


# --------------------------------------------------------------------------- #
# without_control_characters
# --------------------------------------------------------------------------- #


@given(_any_text)
@settings(deadline=None)
def test_control_cleaning_is_idempotent(value: str) -> None:
    once = without_control_characters(value)
    assert without_control_characters(once) == once


@given(_any_text)
@settings(deadline=None)
def test_control_cleaning_only_removes_and_never_rewrites(value: str) -> None:
    """The output is a subsequence of the input: characters go, nothing is substituted."""

    out = without_control_characters(value)
    it = iter(value)
    assert all(ch in it for ch in out), f"{out!r} is not a subsequence of {value!r}"


@given(_any_text)
@settings(deadline=None)
def test_control_cleaning_leaves_nothing_invisible_but_whitespace(value: str) -> None:
    for ch in without_control_characters(value):
        assert ch in _KEPT_WHITESPACE or unicodedata.category(ch) not in {"Cc", "Cf"}, (
            f"{ch!r} (category {unicodedata.category(ch)}) reached the output"
        )


@given(_any_text)
@settings(deadline=None)
def test_control_cleaning_keeps_the_whitespace_the_markdown_writer_folds(value: str) -> None:
    out = without_control_characters(value)
    for ch in _KEPT_WHITESPACE:
        assert out.count(ch) == value.count(ch)


@given(st.text(alphabet=string.printable.replace("\x0b", "").replace("\x0c", ""), max_size=80))
@settings(deadline=None)
def test_printable_text_passes_through_untouched(value: str) -> None:
    assert without_control_characters(value) == value


# --------------------------------------------------------------------------- #
# normalize_confidence
# --------------------------------------------------------------------------- #


@given(st.one_of(st.none(), st.text(max_size=40)))
@settings(deadline=None)
def test_confidence_is_total_onto_the_enum(value: str | None) -> None:
    assert normalize_confidence(value) in _CONFIDENCE_ENUM


@given(st.text(max_size=40))
@settings(deadline=None)
def test_confidence_is_idempotent(value: str) -> None:
    once = normalize_confidence(value)
    assert normalize_confidence(once) == once


@given(st.text(alphabet=string.ascii_letters + "-_/ ", max_size=40))
@settings(deadline=None)
def test_confidence_is_blind_to_case_and_surrounding_whitespace(value: str) -> None:
    assert normalize_confidence(value.upper()) == normalize_confidence(value.lower())
    assert normalize_confidence(f"  {value}\t") == normalize_confidence(value)


# --------------------------------------------------------------------------- #
# _sanitize_embedded_path_in_text
# --------------------------------------------------------------------------- #


@settings(deadline=None, max_examples=200)
@given(st.text(alphabet=string.ascii_letters + string.digits + "/\\.:_- ~,", max_size=120))
def test_embedded_path_redaction_is_idempotent(value: str) -> None:
    once = _sanitize_embedded_path_in_text(value, include_absolute=False)
    assert _sanitize_embedded_path_in_text(once, include_absolute=False) == once


@given(st.text(alphabet=string.ascii_letters + string.digits + "/\\.:_- ~,", max_size=120))
@settings(deadline=None)
def test_embedded_path_redaction_never_lengthens_the_text(value: str) -> None:
    """Redaction replaces a directory chain with a basename; it has nothing to add."""

    assert len(_sanitize_embedded_path_in_text(value, include_absolute=False)) <= len(value)


@given(_prose)
@settings(deadline=None)
def test_prose_without_a_path_in_it_is_untouched(value: str) -> None:
    assert _sanitize_embedded_path_in_text(value, include_absolute=False) == value


@given(st.text(alphabet=string.ascii_letters + string.digits + "/\\.:_- ~,", max_size=120))
@settings(deadline=None)
def test_include_absolute_is_the_identity(value: str) -> None:
    """The flag exists for operators who want the full path; redaction must not override it."""

    assert _sanitize_embedded_path_in_text(value, include_absolute=True) == value
