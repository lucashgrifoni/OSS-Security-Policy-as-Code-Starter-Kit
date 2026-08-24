"""Stripping HTML comments is linear in the document, not quadratic in its `<!--` count.

`_markdown_sections` removes HTML comments before it reads anything, because a commented-out
heading is a draft rather than a published section. It did that with ``re.sub(r"<!--.*?-->")``,
and a non-greedy scan that never finds its terminator restarts from the next `<!--` and runs to
end-of-file again. A document that opens comments without closing them therefore costs
O(comments x length), and an adopter's `SECURITY.md` is attacker-controlled input to a CI gate.

Measured on the real CLI against a 128 KiB `SECURITY.md` of unclosed `<!--`, before the fix:

    profile appsec-llm-ssdf-218a-1   HEAD 0.98s -> 14.60s
    profile cra-eu-ai-act-art11-1    HEAD 0.98s -> 45.72s

The CRA profile is worse because more of its controls read the document, and each one re-parses
it. Both profiles ship, so this is reachable, and at 352 KiB the second is minutes.

The budget below is deliberately loose. It is not a benchmark and it must not fail on a slow
runner: the quadratic version needs roughly a minute for this input, so anything under a couple
of seconds separates the two by more than an order of magnitude.
"""

from __future__ import annotations

import time

from oss_policy_kit.application.evaluators._shared import _markdown_sections

#: 1 MiB of opened, never closed comments -- the worst case, since every `<!--` starts a scan that
#: reaches end-of-file.
#:
#: The size is chosen against the CHEAPEST wrong implementation, not the one that shipped. Two
#: were measured at doubling sizes:
#:
#:     re.sub(r"<!--.*?-->")          256 KiB -> 58.7s
#:     str.find restarting the scan   256 KiB ->  0.78s, growing 3.9x per doubling
#:
#: A first version of this test used 256 KiB and a 2s budget. It caught the regex and MISSED the
#: `find` variant by a factor of three, so it pinned "not as slow as the regex" while its name
#: claimed to pin the complexity class -- found by mutating the fix and watching the test stay
#: green. At 1 MiB the same variant costs ~12s against a linear cost that does not register.
_UNCLOSED = "<!-- " * (1024 * 1024 // 5)

#: Seconds. Roughly 6x under the cheapest quadratic implementation and far above the linear one,
#: which returns before it has read the second comment.
_BUDGET_SECONDS = 2.0


def test_unclosed_comments_do_not_make_the_parser_quadratic() -> None:
    started = time.perf_counter()

    _markdown_sections(_UNCLOSED)

    elapsed = time.perf_counter() - started
    assert elapsed < _BUDGET_SECONDS, (
        f"stripping comments from a {len(_UNCLOSED) // 1024} KiB document of unclosed `<!--` took "
        f"{elapsed:.1f}s. This input is an adopter's SECURITY.md and it gates their CI."
    )


def test_the_stripping_still_removes_what_it_used_to_remove() -> None:
    """The counterpart: a faster strip that strips differently is a different bug.

    Every shape the regex handled has to survive -- a closed comment goes, an UNCLOSED one stays
    as ordinary text (the previous release read it that way, and reading less is not allowed),
    and a nested opener is consumed by the first terminator exactly as a non-greedy match was.
    """

    assert _markdown_sections("<!--\n## Draft\nbody\n-->\n") == []

    kept = dict(_markdown_sections("## Real\nbody\n<!-- ## Draft -->\n"))
    assert "real" in kept
    assert "draft" not in kept

    # Unterminated: not a comment, so the heading is still published.
    unterminated = dict(_markdown_sections("<!-- unterminated\n## Real\nbody\n"))
    assert "real" in unterminated

    # A second opener inside a comment is consumed with it, because the first `-->` closes both.
    nested = dict(_markdown_sections("<!-- a <!-- b -->\n## Real\nbody\n"))
    assert "real" in nested
    assert nested["real"].strip() == "body"


#: Headings, not comments. The comment case above is one way to make this function expensive;
#: the section walk is another, and a guard that only covers the first is a guard that watched
#: the wrong door.
#:
#: A section's body runs to the next heading of the SAME OR SHALLOWER level. The first version of
#: that rule searched forward with `heads[position + 1:]`, which COPIES the tail of the list on
#: every iteration even though the loop breaks on its first element -- O(headings^2). Measured on
#: `_markdown_sections` directly:
#:
#:     document      before the section rule      with the slicing version
#:     256 KiB              0.031s                        0.338s
#:     512 KiB              0.024s                        2.313s
#:       1 MiB              0.049s                       14.255s
#:
#: An adversarial review caught it: the fix for one denial of service had recreated the class in
#: the same function, and the comment-based guard next to it could not see it.
_HEADING_DOC_KIB = 256


def _headings(kib: int) -> str:
    return "# limitations\n" * (kib * 1024 // 14)


def test_doubling_the_headings_does_not_quadruple_the_work() -> None:
    """Ratio, not a clock -- the same reason as the SARIF walker: the suite runs under coverage."""

    small, large = _headings(_HEADING_DOC_KIB), _headings(_HEADING_DOC_KIB * 2)

    _markdown_sections(small)  # warm-up
    started = time.perf_counter()
    _markdown_sections(small)
    at_n = time.perf_counter() - started
    started = time.perf_counter()
    _markdown_sections(large)
    at_2n = time.perf_counter() - started

    ratio = at_2n / at_n
    assert ratio < 3.0, (
        f"doubling a {_HEADING_DOC_KIB} KiB document of headings multiplied the work by "
        f"{ratio:.2f}x ({at_n:.3f}s -> {at_2n:.3f}s). Linear is ~2x; ~4x or more is a per-heading "
        "scan over the remaining headings, and SECURITY.md is attacker-controlled input to a gate."
    )


def test_the_section_rule_still_holds_after_the_walk_is_made_linear() -> None:
    """The counterpart, so speed cannot be bought by dropping the nesting rule it exists for."""

    nested = dict(_markdown_sections("## Parent\n### Child\nreal content\n"))
    assert nested["parent"].strip() != "", "a subsection's content is still the parent's content"

    siblings = dict(_markdown_sections("## First\n\n## Second\nbody\n"))
    assert siblings["first"].strip() == "", "a sibling heading still ends the section"

    outdent = dict(_markdown_sections("### Deep\ndeep body\n# Top\ntop body\n"))
    assert outdent["deep"].strip() == "deep body"
    assert outdent["top"].strip() == "top body"
