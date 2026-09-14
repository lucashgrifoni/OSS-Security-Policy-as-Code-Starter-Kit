"""The depth budget counted brackets, and block-style YAML has none.

`too_deep_reason` measured bracket nesting only, so a YAML document nested by indentation
had a measured depth of 1 at any real depth and the documented 200-level budget never
applied to it. The note beside `MAX_JSON_DEPTH` called `RecursionError` the backstop for
that case. It is not one, because whether it fires depends on `sys.getrecursionlimit()`,
which is global state any library may raise. Measured on a 500-level block document before
the fix:

    recursion limit 1000, the default    RecursionError, refused
    recursion limit 1500 and above       accepted, "valid": true, no refusal at all

`hypothesis` raises that limit when it is imported, which is why the regression test in
`tests/cli/test_v10_0_7_insights_and_ingest.py` passed alone and failed in a full
`tests/cli` run. That flaky test was the symptom. The defect was that an adopter whose
application raises the limit had no depth guard on block-style YAML at all, and no test
here could see it, because the suite's own limit decided the answer.

The tests below therefore assert two different things: that the depth is measured, and that
the measurement does not consult the interpreter.
"""

from __future__ import annotations

import sys

import pytest

from oss_policy_kit.application.input_limits import (
    MAX_JSON_DEPTH,
    max_block_nesting_depth,
    max_json_nesting_depth,
    too_deep_reason,
)


def _block(depth: int) -> str:
    """A document nested *depth* levels by indentation alone, with no bracket anywhere."""

    lines = ["nested:"]
    lines += ["  " * (index + 1) + "a:" for index in range(depth)]
    lines.append("  " * (depth + 1) + "1")
    return "\n".join(lines) + "\n"


# --- the defect ------------------------------------------------------------------------------


def test_a_block_nested_document_is_refused() -> None:
    """The case that shipped: 500 levels, bracket depth 1."""

    raw = _block(500)
    assert max_json_nesting_depth(raw) <= 1, "no brackets, which is why the old measure missed it"

    assert too_deep_reason(raw, label="X") is not None


@pytest.mark.parametrize("limit", [1000, 1500, 3000, 10_000])
def test_the_refusal_does_not_depend_on_the_recursion_limit(limit: int, monkeypatch: pytest.MonkeyPatch) -> None:
    """The heart of it. Before the fix this passed at 1000 and failed at every value above.

    `monkeypatch` restores the limit afterwards, so raising it here cannot leak into the rest
    of the session -- which is precisely the kind of leak that produced the original symptom.
    """

    original = sys.getrecursionlimit()
    monkeypatch.setattr(sys, "setrecursionlimit", sys.setrecursionlimit)
    sys.setrecursionlimit(limit)
    try:
        assert too_deep_reason(_block(500), label="X") is not None
    finally:
        sys.setrecursionlimit(original)


def test_an_ordinary_document_is_not_refused() -> None:
    """The other direction, and the reason this is a budget rather than a ban.

    The deepest YAML or JSON file in this repository measures 9. A guard that refused honest
    documents would be a worse defect than the one it replaced.
    """

    assert too_deep_reason(_block(8), label="X") is None
    assert max_block_nesting_depth(_block(8)) < MAX_JSON_DEPTH


# --- what counts as a level, and what does not -------------------------------------------------


def test_indentation_depth_is_counted_from_the_columns() -> None:
    assert max_block_nesting_depth("a:\n  b:\n    c: 1\n") == 3
    assert max_block_nesting_depth("a: 1\nb: 2\n") == 1
    assert max_block_nesting_depth("") == 0


def test_closing_a_level_pops_every_column_at_or_beyond_it() -> None:
    """Depth is how deep the document goes, not how many indented lines it has."""

    deep_then_shallow = "a:\n  b:\n    c: 1\nd:\n  e: 2\n"

    assert max_block_nesting_depth(deep_then_shallow) == 3


def test_blank_lines_and_comments_are_not_structure() -> None:
    """A comment may sit at any column, including one no key ever uses."""

    assert max_block_nesting_depth("a:\n\n  b: 1\n") == 2
    assert max_block_nesting_depth("a:\n" + " " * 400 + "# a very indented note\n  b: 1\n") == 2


def test_the_text_inside_a_block_scalar_is_not_structure() -> None:
    """`script: |` introduces text, and text may carry any indentation at all.

    Counting it would refuse an ordinary GitHub Actions workflow with a long `run:` block,
    which is the false positive this whole guard must not produce.
    """

    scalar = "steps:\n  - run: |\n" + "".join(" " * (8 + index) + f"echo {index}\n" for index in range(300))

    assert max_block_nesting_depth(scalar) < MAX_JSON_DEPTH
    assert too_deep_reason(scalar, label="workflow") is None


@pytest.mark.parametrize("header", ["|", ">", "|-", ">-", "|+", ">+", "|2", "|2-"])
def test_every_block_scalar_header_form_is_recognised(header: str) -> None:
    raw = f"a:\n  b: {header}\n" + "".join(" " * (4 + index) + "text\n" for index in range(250))

    assert max_block_nesting_depth(raw) < MAX_JSON_DEPTH


def test_structure_after_a_block_scalar_counts_again() -> None:
    """The skip must end when the text does, or everything after one `run:` goes uncounted."""

    raw = "a:\n  b: |\n    text\n    more text\n  c:\n    d:\n      e: 1\n"

    assert max_block_nesting_depth(raw) == 4


def test_a_blank_line_inside_a_block_scalar_does_not_end_it() -> None:
    """Blank lines are legal inside a scalar and must not be read as leaving it."""

    raw = "a:\n  b: |\n    text\n\n" + " " * 300 + "still text\n"

    assert max_block_nesting_depth(raw) < MAX_JSON_DEPTH


# --- the two measures together -----------------------------------------------------------------


def test_the_larger_of_the_two_measurements_decides() -> None:
    """A document may nest either way, and the budget is about depth, not about syntax."""

    flow = "nested: " + ("{a: " * 500) + "1" + ("}" * 500) + "\n"
    assert max_block_nesting_depth(flow) <= 2, "one line, so indentation says almost nothing"
    assert too_deep_reason(flow, label="X") is not None, "the bracket measure still carries this one"

    block = _block(500)
    assert max_json_nesting_depth(block) <= 1
    assert too_deep_reason(block, label="X") is not None, "and the indentation measure carries this one"
