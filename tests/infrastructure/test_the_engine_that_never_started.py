"""Telling "Semgrep found nothing" apart from "Semgrep never looked".

On Windows the scanner exits 2 before it reads a single file: its Python front end cannot talk
to ``semgrep-core``, so the run ends with ``<ERROR: missing output>`` on stdout and nothing on
stderr. Measured on this repository's own tree with semgrep 1.163.0 and 1.177.0, with a local
rule file and no network, so neither the ruleset nor the registry is the cause.

The command answered that with "see diagnostics in <file>", and the file said
``<ERROR: missing output>``. Both statements were true and neither told the operator that
nothing had been scanned, or what to do instead.

These tests hold the classification only. What the CLI prints once it knows lives in
``tests/cli/test_scan_sast_says_what_broke.py``.
"""

from __future__ import annotations

import pytest

from oss_policy_kit.infrastructure.scanners.semgrep_adapter import (
    SemgrepRunOutcome,
    engine_never_started,
)


def _outcome(*, stdout: str = "", stderr: str = "", code: int | None = 2) -> SemgrepRunOutcome:
    return SemgrepRunOutcome(
        status="error",
        version="1.177.0",
        rulesets=["p/security-audit"],
        raw_stdout=stdout,
        raw_stderr=stderr,
        exit_code=code,
    )


def test_the_marker_a_quiet_run_leaves_on_stdout_is_recognised() -> None:
    """What the adapter's own invocation produces: --quiet empties stderr, stdout has the marker."""

    assert engine_never_started(_outcome(stdout="<ERROR: missing output>\n")) is True


@pytest.mark.parametrize(
    "line",
    [
        "RPC input error: Expected a number, got ''",
        "RPC subprocess exited with code 1",
        "[ERROR] Failed to obtain target files from semgrep-core",
        "semgrep-core rule validation failed (SemgrepError)",
    ],
)
def test_the_lines_a_loud_run_prints_are_recognised(line: str) -> None:
    """Without --quiet the same failure names itself four ways; any one of them is enough."""

    assert engine_never_started(_outcome(stderr=line)) is True


def test_a_real_scanner_error_is_not_read_as_an_engine_failure() -> None:
    """The guard has to stay narrow: a bad ruleset is a different failure with a different fix.

    Widening this predicate would send every Semgrep error to a message about Windows, which is
    worse than the message it replaces because it would be confidently wrong.
    """

    outcome = _outcome(stderr="Invalid rule schema: unknown key 'patern' in rule 'x'")

    assert engine_never_started(outcome) is False


def test_a_successful_run_is_never_an_engine_failure() -> None:
    ok = SemgrepRunOutcome(status="ok", version="1.177.0", rulesets=["p/security-audit"], exit_code=0)

    assert engine_never_started(ok) is False


def test_a_missing_binary_is_not_an_engine_failure() -> None:
    """``not_available`` already has its own message naming the install command."""

    absent = SemgrepRunOutcome(
        status="not_available",
        version=None,
        rulesets=["p/security-audit"],
        raw_stderr="semgrep binary not found on PATH",
    )

    assert engine_never_started(absent) is False


def test_an_error_with_no_diagnostics_at_all_is_not_claimed_as_an_engine_failure() -> None:
    """Saying nothing is not evidence of this failure; the existing pointer at the file is."""

    assert engine_never_started(_outcome()) is False
