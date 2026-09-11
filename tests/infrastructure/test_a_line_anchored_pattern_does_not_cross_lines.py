"""A pattern anchored at a line start must not be able to scan past that line.

`^\\s*` under `re.MULTILINE` is quadratic. `\\s` matches a newline, so on a document of N lines
the engine tries the anchor at each of N line starts and each attempt can walk the whitespace of
every line before it. Measured on this tree, on blank-line-heavy workflow YAML:

    4000 lines   0.0338s      8000 lines   0.1342s
   16000 lines   0.5402s     32000 lines   2.2052s        x3.97 per doubling

End to end that was 599 seconds for 256 KiB of blank lines, inside a file under the 1 MiB cap --
so the cap did not help, because quadratic cost arrives long before a size limit does. The same
shapes now cost 1.6-3.2 seconds at 900 KiB.

`[^\\S\\n]` is whitespace-minus-newline. Since `^` under MULTILINE already anchors at every line
start, refusing to cross a newline cannot lose a match: any `uses:` at a line start is still
reached by the anchor on its own line. That is an exact argument, not a probable one, and the
differential test below holds it over generated documents including exotic whitespace.

The guard is static and derives the rule from the source. Two earlier versions of this sweep
reported zero while the worst site was still there: the first because it searched for `\\s` in a
non-raw string, which matched a literal space and flagged the CORRECT patterns instead; the
second because the site used the inline flag `(?m)` and a bare `re.search`, and the sweep only
looked at `re.compile` calls with a `MULTILINE` argument. Both of those shapes are canaries here.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "oss_policy_kit"

#: Every `re` entry point that takes a pattern, not just `compile` -- the site that cost 599
#: seconds was a bare `re.search`.
REGEX_ENTRY_POINTS = frozenset(
    {"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split"}
)

#: `(?m)`, `(?im)`, `(?mi)`... MULTILINE can arrive inline as well as by argument.
_INLINE_MULTILINE = re.compile(r"^\(\?[aiLmsux]*m[aiLmsux]*\)")


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
    """(line, pattern, flags-source) for every `re.<fn>(<literal>, ...)` in a file."""

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


def test_no_line_anchored_pattern_can_scan_past_its_line() -> None:
    """The rule, across the package."""

    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        for lineno, pattern, flags in _regex_literals(path):
            if not _has_multiline(pattern, flags):
                continue
            reason = _crosses_a_line(pattern)
            if reason:
                rel = path.relative_to(SRC).as_posix()
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
def test_the_sweep_sees_a_pattern_that_breaks_the_rule(pattern: str, flags: str) -> None:
    """Canaries. A zero above means nothing unless the sweep can produce a non-zero.

    Each of these is a shape that a previous version of this sweep reported as clean.
    """

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
def test_the_sweep_leaves_a_compliant_pattern_alone(pattern: str) -> None:
    """The other direction: a sweep that flagged everything would also pass the canaries."""

    assert _crosses_a_line(pattern) is None


def test_the_sweep_actually_reads_the_package() -> None:
    """An empty file list would make the rule vacuous rather than satisfied."""

    seen = sum(1 for path in SRC.rglob("*.py") for _ in _regex_literals(path))

    assert seen > 50, f"only {seen} regex literals found; the sweep is not reaching the package"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (r"^\s*uses:\s*([^\s#]+)", r"^[^\S\n]*uses:\s*([^\s#]+)"),
        (r"^\s*USER\s+(root|0)\s*$", r"^[^\S\n]*USER\s+(root|0)[^\S\n]*$"),
        (r"^\s*HEALTHCHECK\b", r"^[^\S\n]*HEALTHCHECK\b"),
    ],
)
def test_refusing_to_cross_a_line_does_not_lose_a_match(old: str, new: str) -> None:
    """The safety half: the cheaper pattern finds exactly what the expensive one found.

    The alphabet deliberately includes form feed, vertical tab and a non-breaking space. A
    narrower fix -- `[ \\t]*`, which is what the neighbouring `_DOCKER_FROM_RE` uses -- would
    diverge on those, and for `USER root` a lost match is a lost finding.
    """

    import random

    alphabet = "abcdefghijklmnopqrstuvwxyzUSERHALTCHK0123456789 \t\n\f\v\r:#/@.-\u00a0\u2003"
    rnd = random.Random(20260911)
    old_re = re.compile(old, re.MULTILINE | re.IGNORECASE)
    new_re = re.compile(new, re.MULTILINE | re.IGNORECASE)

    for _ in range(2000):
        document = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(10, 200)))
        assert [m.group(0) for m in old_re.finditer(document)] == [m.group(0) for m in new_re.finditer(document)], (
            f"divergence on {document!r}"
        )
