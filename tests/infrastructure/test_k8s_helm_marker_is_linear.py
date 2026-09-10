r"""The Helm-marker test the Kubernetes scanner runs over every scanned YAML file.

Two things are pinned here, and they are different kinds of claim.

The first is EQUIVALENCE. ``_has_helm_template_marker`` replaced
``re.compile(r"\{\{[^}]+\}\}").search(...)``, and a wrong answer is not a slow scan, it is a
wrong verdict: a file classified as an unrendered Helm template is SKIPPED, so a false
positive deletes every finding in a real manifest. The regex is therefore kept here as the
oracle and the two are compared over every string up to length 9 on ``{}x`` and length 7 on
``{}xy``, plus randomised YAML-alphabet strings. Exhaustive enumeration is the point: the
shapes that break this kind of scanner are ``{{}}``, ``{{a}``, ``{{a}}}`` and ``{{{}}}``,
which no hand-written example list reliably contains.

The second is COST, and it is deliberately NOT a wall-clock assertion on the fast path -- a
shared runner makes those flake. It is a ceiling on the pathological input, and the two
numbers it sits between were measured rather than guessed: at 256 KiB of ``{`` the old regex
took 20.7s and the replacement 0.00003s. The ceiling below is 2s at 128 KiB, where the regex
cost about 5.3s. So the guard fails on the old code by a wide margin, passes on the new one by
a wider one, and -- this is the part that matters on a slow runner -- when it does fail it
fails in seconds rather than hanging, because the input is sized to make the quadratic visible
without making it interminable.
"""

from __future__ import annotations

import itertools
import random
import re
import time

import pytest

from oss_policy_kit.infrastructure.k8s.scanner import _has_helm_template_marker

#: The expression the linear scanner replaced. Kept as the oracle, not as production code.
_ORACLE = re.compile(r"\{\{[^}]+\}\}")


def _disagreements(strings: list[str]) -> list[str]:
    return [s for s in strings if bool(_ORACLE.search(s)) != _has_helm_template_marker(s)]


@pytest.mark.parametrize(
    ("alphabet", "max_len"),
    [("{}x", 9), ("{}xy", 7)],
)
def test_it_answers_exactly_what_the_regex_answered(alphabet: str, max_len: int) -> None:
    """Every string over the alphabet that matters, up to a length that covers the edges."""

    disagree: list[str] = []
    for length in range(max_len + 1):
        for tup in itertools.product(alphabet, repeat=length):
            s = "".join(tup)
            if bool(_ORACLE.search(s)) != _has_helm_template_marker(s):
                disagree.append(s)
                if len(disagree) > 5:
                    break
    assert disagree == [], f"linear scanner disagrees with the regex on {disagree}"


def test_it_agrees_with_the_regex_on_randomised_yaml_text() -> None:
    """A fixed seed, so a failure is reproducible rather than a story about one CI run."""

    rng = random.Random(20260909)
    alphabet = "{}xy \n:-'\"$.abcVal"
    strings = ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60))) for _ in range(20000)]
    assert _disagreements(strings) == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("{{ .Values.image }}", True),
        ("image: {{ .Values.repo }}/app:{{ .Values.tag }}", True),
        ("{{ if .x }}\nfoo\n{{ end }}", True),
        # The  after  is not followed by another , so this does NOT match --
        # a shape that reads like a marker and is not one.
        # Reads like a marker and is not one: the `}` after `nested` is not followed by
        # another `}`, and backtracking cannot help because every shorter run of
        # `[^}]+` also ends on a non-`}`.
        ("{{ {nested} }}", False),
        ("a{{b}}c", True),
        ("{{a}}}", True),
        ("{{}}", False),  # `[^}]+` needs at least one character
        ("{{a}", False),  # no closing `}}`
        ("{{x}y}}", False),  # the `}` after x is not followed by `}`
        ("apiVersion: v1\nkind: Pod\n", False),
        ("", False),
        ("{" * 100, False),  # no `}` at all -- the early return
        ("}" * 100, False),  # `}` everywhere, no opener
        ("{}{}", False),
    ],
)
def test_named_shapes(text: str, expected: bool) -> None:
    assert _has_helm_template_marker(text) is expected
    assert bool(_ORACLE.search(text)) is expected


@pytest.mark.parametrize(
    "shape",
    [
        # 128 KiB of `{`: the regex restarts at each one and walks to the end each time.
        "brace-run",
        # The same, with a `}}` present so a "does the file contain }} at all" short-circuit
        # would not help. This is the shape that survives the cheap fixes.
        "brace-run-then-decoy-closer",
    ],
)
def test_a_pathological_file_cannot_stall_the_scan(shape: str) -> None:
    """A repository-controlled ``.yaml`` must not cost seconds in this one predicate.

    ``ScanDeadline`` is checked between files, never inside one, so ``--timeout`` cannot
    interrupt this call once it has started. That is what makes the cost a scan-wide budget
    problem rather than a slow file.

    The payload is built here rather than passed through ``parametrize`` so the test id stays
    readable; a 128 KiB parameter becomes a 128 KiB test id.
    """

    payload = "{" * 131072
    if shape == "brace-run-then-decoy-closer":
        payload += "}a}}"

    start = time.perf_counter()
    result = _has_helm_template_marker(payload)
    elapsed = time.perf_counter() - start

    assert result is False, shape
    assert elapsed < 2.0, f"{shape}: {elapsed:.3f}s -- the quadratic scan is back"
