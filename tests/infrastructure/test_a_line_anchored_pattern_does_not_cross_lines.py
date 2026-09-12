"""A pattern run over text the audited repository wrote must cost linear time.

Three sweeps have now looked for this class. The first two reported zero while defects were
live, and they failed in different ways, which is the reason this file no longer decides by
recognising a shape:

* the first searched for ``\\s`` in a non-raw string, so the needle was a literal space and it
  flagged the CORRECT patterns instead of the broken ones;
* the second looked only at ``re.compile`` calls carrying a ``MULTILINE`` argument, and the
  worst site used the inline flag ``(?m)`` with a bare ``re.search``;
* the third -- the previous version of this file -- filtered on MULTILINE too, and then only
  examined branches beginning with ``^``. It missed ``(^|\\n)\\s*release\\s*:``, which carries
  no flag at all and puts the quantifier AFTER an explicit newline alternation, and it missed
  ``uses:[^\\n#]*bandit``, which is not line-anchored in any way: it anchors on a repeatable
  literal and walks the rest of the line from every occurrence.

Measured before the fix, CPU time for one search:

    (^|\\n)\\s*release\\s*:      64000 blank lines     7156.25 ms    x3.98 per doubling
    uses:[^\\n#]*bandit         64000 chars one line   593.75 ms    x7.03 per doubling

The rule below quadruples the input rather than doubling it, because the doubling version
failed once on its own canary under full-suite load. See :data:`MAX_GROWTH`.

End to end the first was roughly 648 seconds for a 900 KiB workflow -- inside the 1 MiB cap,
because quadratic cost arrives long before a size limit does. Both are bounded now.

So the rule this file enforces is no longer "the pattern does not have a bad shape". It is
**the pattern does not grow faster than its input**, measured on documents built to stress it,
including one built from the pattern's own literal prefix. A guard that names shapes can only
ever catch the shapes somebody thought of; three sweeps proved that the hard way.

The static rule is kept alongside, because when it does fire it names the offending site and
the reason, which a timing failure cannot.

Sizing note, from the memory of a guard that hung rather than failed: an earlier ReDoS guard
used a 200k-char input and made a mutation run take 400 seconds instead of failing. The sizes
here are picked from measurement so that a quadratic pattern is unmistakable within about a
tenth of a second, and a linear one costs nothing.
"""

from __future__ import annotations

import ast
import re
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit"

#: Every ``re`` entry point that takes a pattern, not just ``compile`` -- the site that cost
#: 599 seconds was a bare ``re.search``.
REGEX_ENTRY_POINTS = frozenset(
    {"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split"}
)

#: ``(?m)``, ``(?im)``, ``(?mi)``... MULTILINE can arrive inline as well as by argument.
_INLINE_MULTILINE = re.compile(r"^\(\?[aiLmsux]*m[aiLmsux]*\)")

#: The input grows by four, not by two, and the threshold sits halfway between the two answers
#: that matter: a linear pattern costs 4x more, a quadratic one 16x.
#:
#: Doubling was tried first and the margin was too thin to leave switched on. Ten runs of the
#: same canary spread from x3.32 to x5.17 against a threshold of 3.0, which is ten per cent of
#: headroom at the bottom, and a full-suite run duly went under and failed the guard on its own
#: canary. The residual spread is scheduling and processor boost; repeating the measurement
#: narrows it and never removes it. Quadrupling the input moves the signal away from the noise
#: instead, and buys a factor of two of headroom on each side.
MAX_GROWTH = 8.0

#: Sizes for the growth measurement, kept as small as the separation allows. The factor of four
#: between them is what matters; the absolute sizes only decide how long a broken pattern takes
#: to prove itself. At 8000 and 32000 the two known defects cost 110 ms / 1797 ms and 4 ms /
#: 148 ms, which is unmistakable at a tenth of the cost of running them at 64000.
SMALL, LARGE = 8_000, 32_000

#: The screen, as total CPU seconds for :data:`SCREEN_REPS` searches. Only patterns above it
#: get measured properly.
#:
#: The first version of this guard had no screen: it measured the ratio for all 135 regex
#: literals in the package, and the accumulation loop that makes a measurement stable needs
#: MORE repetitions the FASTER the pattern is -- about 300k searches for a microsecond pattern.
#: The suite ran past two minutes and was killed. That is the failure this project has already
#: recorded once: a guard that hangs is not a guard, because nobody leaves it switched on.
#:
#: A linear pattern costs 0.3-2 ms on these documents and a broken one costs 148-1797 ms, so
#: the screen separates them by two orders of magnitude and does not need to be precise -- the
#: ratio measurement below decides. On a green tree nothing reaches it.
#:
#: Repeated rather than single, and that is not a detail. `process_time` ticks at about 15.6 ms
#: on Windows, so one search of a pattern costing 10 ms reads as either 0 or 15.6 ms -- and a
#: pattern costing 10 ms over 32000 characters costs roughly 16 seconds over a 1 MiB file. A
#: single-search screen could therefore skip a real defect, which is the failure this guard
#: exists to prevent.
SCREEN_REPS = 8
SCREEN_CEILING_SECONDS = 0.060


def _has_multiline(pattern: str, flags_source: str) -> bool:
    return "MULTILINE" in flags_source or bool(_INLINE_MULTILINE.match(pattern))


def _crosses_a_line(pattern: str) -> str | None:
    """Why this anchored pattern can scan past its own line, or None when it cannot."""

    inline = _INLINE_MULTILINE.match(pattern)
    body = pattern[inline.end() :] if inline else pattern

    # An alternation can hide the anchored branch: `(?m)(^\s*x:\s*$|literal|literal)`.
    branches = [body]
    if body.startswith("("):
        branches += re.split(r"\|", body[1:])

    for branch in branches:
        stripped = branch.lstrip("(")
        if not stripped.startswith("^"):
            continue
        rest = stripped[1:]
        if rest.startswith((r"\s", r"\W")):
            return f"^{rest[:2]} matches a newline"
        if rest.startswith("[^"):
            close = rest.find("]")
            negated = rest[2:close] if close > 0 else ""
            if r"\n" not in negated:
                return f"^{rest[: close + 1]} does not exclude a newline"
    return None


def _regex_literals(path: Path):
    """(line, pattern, flags-source) for every ``re.<fn>(<literal>, ...)`` in a file."""

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:  # pragma: no cover - a file that will not parse fails elsewhere
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in REGEX_ENTRY_POINTS:
            continue
        if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "re"):
            continue
        if not node.args:
            continue
        try:
            pattern = ast.literal_eval(node.args[0])
        except (ValueError, SyntaxError):
            continue
        if not isinstance(pattern, str):
            continue
        flags = " ".join(ast.unparse(a) for a in node.args[1:])
        flags += " " + " ".join(ast.unparse(k.value) for k in node.keywords if k.arg == "flags")
        yield node.lineno, pattern, flags


def _literal_prefix(pattern: str) -> str:
    """The leading run of ordinary characters, which is what the engine anchors on.

    This is what turns a harmless-looking pattern into a quadratic one: ``uses:[^\\n#]*bandit``
    is cheap on a document with one ``uses:`` and ruinous on a line carrying a thousand, because
    the engine restarts the walk at each. A document built from the pattern's own prefix is
    therefore the adversarial document for that pattern, and no generic input finds it.
    """

    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch in "\\^$.|?*+()[]{}":
            break
        # A literal followed by a quantifier belongs to the quantifier, not to the prefix.
        if i + 1 < len(pattern) and pattern[i + 1] in "?*+{":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def _adversarial_documents(pattern: str, size: int) -> dict[str, str]:
    """Documents built to make *pattern* work hard, keyed by the shape they exercise."""

    docs = {
        "linhas em branco": "\n" * size,
        "espacos": " " * size,
        "linhas so com espacos": (" " * 9 + "\n") * (size // 10),
    }
    prefix = _literal_prefix(pattern)
    if len(prefix) >= 2:
        # No newline and no `#`: both would let a line-bounded class stop early, and the point
        # is to measure the walk, not to prove the class terminates.
        filler = "x" * 20
        unit = prefix + filler
        docs["prefixo do proprio padrao"] = unit * max(1, size // len(unit))
    return docs


def _one_search_seconds(compiled: re.Pattern[str], document: str) -> float:
    """Total CPU seconds for :data:`SCREEN_REPS` searches. Cheap, coarse, used only to screen.

    ``process_time`` and not ``perf_counter``: the suite may run beside other work and wall
    clock would measure the neighbours instead of the pattern.

    Repeated because one search of a fast pattern lands below the clock's granularity and is
    indistinguishable from one of a moderately slow one. Eight searches put anything worth
    measuring above the tick while leaving a linear pattern at a few milliseconds.

    It stops as soon as it is over the ceiling, and that is not an optimisation. Without the
    break, a pattern whose single search costs 7 s paid 56 s to answer a question the first
    search had already settled, and the screen exists precisely so that the expensive
    measurement is reached rarely. Measured: 173 s for this file, against 35 s with the break.
    """

    start = time.process_time()
    for _ in range(SCREEN_REPS):
        compiled.search(document)
        elapsed = time.process_time() - start
        if elapsed > SCREEN_CEILING_SECONDS:
            return elapsed
    return time.process_time() - start


def _steady_seconds(compiled: re.Pattern[str], document: str) -> float:
    """CPU seconds per search, accumulated past the clock's granularity.

    On Windows the CPU clock ticks at about 15.6 ms, so a single fast search measures zero or
    one tick and a ratio between two of those is quantisation, not growth -- that mistake
    already produced a "linear" verdict in this session on a pattern later measured at x7.03.
    Accumulating fixes it, but costs more the FASTER the pattern is, which is why only patterns
    the screen has already flagged reach this function.

    The target is twenty ticks, not three. At three the measurement carries about a third of
    error and the ratio between two of them up to two thirds: eight consecutive runs of the
    same canary spread from x3.57 to x5.33 against a threshold of 3.0, and under the load of a
    full-suite run one of them went under and failed the guard on its own canary. A guard that
    reports a quadratic pattern as linear once in a while is worse than no guard, because the
    next person switches it off.
    """

    reps = 1
    while reps <= 100_000:
        start = time.process_time()
        for _ in range(reps):
            compiled.search(document)
        elapsed = time.process_time() - start
        if elapsed > 0.30:
            return elapsed / reps
        reps *= 8
    return 0.0  # pragma: no cover - a pattern this fast never reaches here


def _compile(pattern: str, flags_source: str) -> re.Pattern[str] | None:
    flags = re.MULTILINE if "MULTILINE" in flags_source else 0
    if "IGNORECASE" in flags_source:
        flags |= re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except re.error:  # pragma: no cover - a pattern that will not compile fails elsewhere
        return None


def _slow_shapes(pattern: str, flags_source: str) -> list[str]:
    """Shapes on which one search already costs more than the screen allows."""

    compiled = _compile(pattern, flags_source)
    if compiled is None:
        return []
    docs = _adversarial_documents(pattern, LARGE)
    return [shape for shape, doc in docs.items() if _one_search_seconds(compiled, doc) > SCREEN_CEILING_SECONDS]


def _worst_growth(pattern: str, flags_source: str) -> tuple[float, str]:
    """(worst growth factor, the shape that produced it), measured only where the screen fired.

    Returns ``(0.0, "")`` when no shape is slow enough to be worth measuring, which is the
    ordinary answer for a linear pattern and costs one screening pass.

    Stops at the first shape that exceeds :data:`MAX_GROWTH` rather than finding the true worst.
    Every caller only asks whether the threshold was crossed, and measuring the remaining shapes
    of an already-condemned pattern is the expensive half: the two blank-line canaries took 67 s
    and 65 s finding a worse number for a verdict that was already settled, against 8 s once they
    stop at the first one. What the caller loses is that the reported shape is the first that
    crossed, not necessarily the worst, which the message says.
    """

    compiled = _compile(pattern, flags_source)
    if compiled is None:
        return 0.0, ""

    worst, worst_shape = 0.0, ""
    for shape in _slow_shapes(pattern, flags_source):
        small_cost = _steady_seconds(compiled, _adversarial_documents(pattern, SMALL)[shape])
        if small_cost <= 0:
            continue
        growth = _steady_seconds(compiled, _adversarial_documents(pattern, LARGE)[shape]) / small_cost
        if growth > worst:
            worst, worst_shape = growth, shape
        if worst > MAX_GROWTH:
            return worst, worst_shape
    return worst, worst_shape


def _package_patterns() -> list[tuple[str, int, str, str]]:
    return [
        (path.relative_to(SRC).as_posix(), lineno, pattern, flags)
        for path in sorted(SRC.rglob("*.py"))
        for lineno, pattern, flags in _regex_literals(path)
    ]


# --------------------------------------------------------------------------------------
# The measured rule. This is the one that would have caught both real defects.
# --------------------------------------------------------------------------------------


def test_no_pattern_in_the_package_grows_faster_than_its_input() -> None:
    """Double the document, and the cost may not more than double.

    Shape-based rules catch the shapes somebody thought of. This one catches the behaviour,
    which is what actually costs an operator a scan.
    """

    offenders: list[str] = []
    for rel, lineno, pattern, flags in _package_patterns():
        growth, shape = _worst_growth(pattern, flags)
        if growth > MAX_GROWTH:
            offenders.append(f"{rel}:{lineno}: x{growth:.2f} for 4x input on {shape} -- {pattern[:70]!r}")

    assert not offenders, (
        "these patterns cost more than linear time in the size of a document the audited "
        f"repository wrote: the input grew 4x, from {SMALL} to {LARGE} characters, and the cost "
        "grew more than 8x. Bound the repetition "
        "rather than widening the class, and record the numbers beside the pattern:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    ("label", "pattern", "flags"),
    [
        # Exactly as they were on disk when end-user validation found them.
        ("release key, no flag, quantifier after a newline alternation", r"(^|\n)\s*release\s*:", ""),
        ("uses: detector, anchored on a repeatable literal", r"uses:[^\n#]*bandit", ""),
        # The shape the first version of this file was written for.
        ("line-anchored under MULTILINE", r"^\s*uses:\s*([^\s#]+)", "re.MULTILINE"),
    ],
)
def test_the_measured_rule_sees_a_pattern_that_breaks_it(label: str, pattern: str, flags: str) -> None:
    """Canaries. A green sweep means nothing unless the sweep can produce a red one.

    Each of these is a real pattern that shipped, and each was reported clean by some earlier
    version of this guard.
    """

    growth, shape = _worst_growth(pattern, flags)

    assert growth > MAX_GROWTH, f"{label}: measured only x{growth:.2f} on {shape or 'nothing'}"


@pytest.mark.parametrize(
    ("label", "pattern", "flags"),
    [
        ("release key, bounded", r"(?m)^[^\S\n]{0,40}release[^\S\n]{0,20}:", ""),
        ("uses: detector, bounded", r"uses:[^\n#]{0,1000}bandit", ""),
        ("whitespace-minus-newline under MULTILINE", r"^[^\S\n]*uses:\s*([^\s#]+)", "re.MULTILINE"),
        ("possessive leading run", r"^[ \t]*+FROM[ \t]+([^\n]+)$", "re.MULTILINE"),
        ("not anchored, no unbounded class", r"\bsemgrep\s+(scan|ci)\b", ""),
    ],
)
def test_the_measured_rule_leaves_a_linear_pattern_alone(label: str, pattern: str, flags: str) -> None:
    """The other direction: a rule that failed everything would also pass the canaries.

    The last two are deliberately patterns nobody changed -- if the rule flags those, the
    threshold is wrong rather than the code.
    """

    growth, _ = _worst_growth(pattern, flags)

    assert growth <= MAX_GROWTH, f"{label}: measured x{growth:.2f}"


# --------------------------------------------------------------------------------------
# The static rule, kept because a timing failure cannot say WHY.
# --------------------------------------------------------------------------------------


def test_no_line_anchored_pattern_can_scan_past_its_line() -> None:
    """The shape rule, across the package. Narrower than the measured one, and more legible."""

    offenders: list[str] = []
    for rel, lineno, pattern, flags in _package_patterns():
        if not _has_multiline(pattern, flags):
            continue
        reason = _crosses_a_line(pattern)
        if reason:
            offenders.append(f"{rel}:{lineno}: {reason} -- {pattern[:60]!r}")

    assert not offenders, (
        "these patterns are anchored at a line start and can scan past it, which is "
        "quadratic in the number of lines of a file the audited repository wrote:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    ("pattern", "flags"),
    [
        # The plain shape.
        (r"^\s*uses:\s*([^\s#]+)", "re.MULTILINE"),
        # The shape that cost 599 seconds: inline flag, and the anchor inside an alternation.
        (r"(?m)(^\s*merge_group:\s*$|merge-queue)", ""),
        # A negated class that forgets to exclude the newline.
        (r"(?m)^[^a-z]*FROM", ""),
    ],
)
def test_the_static_sweep_sees_a_pattern_that_breaks_the_rule(pattern: str, flags: str) -> None:
    """Canaries for the shape rule. Each was reported clean by an earlier version of it."""

    assert _has_multiline(pattern, flags)
    assert _crosses_a_line(pattern) is not None


@pytest.mark.parametrize(
    "pattern",
    [
        r"^[^\S\n]*uses:\s*([^\s#]+)",
        r"^[ \t]*+FROM[ \t]+([^\n]+)$",
        r"(?m)^[^\S\n]*merge_group:[^\S\n]*$",
        r"uses:\s*([^\s#]+)",  # not anchored at all
    ],
)
def test_the_static_sweep_leaves_a_compliant_pattern_alone(pattern: str) -> None:
    """A sweep that flagged everything would also pass the canaries."""

    assert _crosses_a_line(pattern) is None


def test_the_sweep_actually_reads_the_package() -> None:
    """An empty file list would make both rules vacuous rather than satisfied."""

    seen = len(_package_patterns())

    assert seen > 50, f"only {seen} regex literals found; the sweep is not reaching the package"


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"uses:[^\n#]{0,1000}bandit", "uses:"),
        (r"(^|\n)\s*release\s*:", ""),
        (r"\bsemgrep\s+(scan|ci)\b", ""),
        (r"github/codeql-action/\w+", "github/codeql-action/"),
        (r"abc*def", "ab"),  # the `c` belongs to the quantifier, not to the prefix
    ],
)
def test_the_prefix_extractor_finds_what_the_engine_anchors_on(pattern: str, expected: str) -> None:
    """The adversarial document for a pattern is built from this, so it has to be right.

    Without the prefix shape, ``uses:[^\\n#]*bandit`` measures linear on every generic document
    and the guard reports clean -- which is precisely what happened.
    """

    assert _literal_prefix(pattern) == expected


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (r"^\s*uses:\s*([^\s#]+)", r"^[^\S\n]*uses:\s*([^\s#]+)"),
        (r"^\s*USER\s+(root|0)\s*$", r"^[^\S\n]*USER\s+(root|0)[^\S\n]*$"),
        (r"^\s*HEALTHCHECK\b", r"^[^\S\n]*HEALTHCHECK\b"),
        (r"(^|\n)\s*release\s*:", r"(?m)^[^\S\n]{0,40}release[^\S\n]{0,20}:"),
    ],
)
def test_refusing_to_cross_a_line_does_not_lose_a_match(old: str, new: str) -> None:
    """The safety half: the cheaper pattern finds exactly what the expensive one found.

    The alphabet deliberately includes form feed, vertical tab and a non-breaking space. A
    narrower fix -- ``[ \\t]*``, which is what the neighbouring ``_DOCKER_FROM_RE`` uses --
    would diverge on those, and for ``USER root`` a lost match is a lost finding.

    The comparison is on END positions rather than on the matched text. The ``release`` pair
    differs in where each match STARTS -- the old form consumes the newline it anchors on, the
    new one anchors after it -- while both end on the same colon. Ends are what identify the
    finding; starts are an artefact of how the anchor is written.
    """

    import random

    alphabet = "abcdefghijklmnopqrstuvwxyzUSERHALTCHK0123456789 \t\n\f\v\r:#/@.-\u00a0\u2003"
    rnd = random.Random(20260911)
    old_re = re.compile(old, re.MULTILINE | re.IGNORECASE)
    new_re = re.compile(new, re.MULTILINE | re.IGNORECASE)

    for _ in range(2000):
        document = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(10, 200)))
        assert [m.end() for m in old_re.finditer(document)] == [m.end() for m in new_re.finditer(document)], (
            f"divergence on {document!r}"
        )
