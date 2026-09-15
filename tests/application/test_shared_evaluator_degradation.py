"""The degradation paths in the shared evaluator helpers, exercised rather than assumed.

`_shared.py` is imported by every evaluator, and its signal helpers are written to keep
going when a file cannot be read, a document is nonsense, or a scan is unbounded. None of
that was ever executed: the suite only ever fed these helpers well-formed clones, so the
handlers were documentation, not behaviour. A helper that swallowed the wrong thing, or
returned the wrong sentinel, would not have failed a single test.

Each test here forces one such condition and asserts the *stated* degradation -- skip this
file and carry on, refuse with a named status, stop at the documented cap -- so a handler
that stops handling turns the file red.

The OSError injection patches ``Path.read_text`` for one target path only; everything else
still reads normally, so a helper that fails for an unrelated reason is not mistaken for
the branch under test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import _shared
from oss_policy_kit.domain.models import ControlStatus


def _fail_reads_of(monkeypatch: pytest.MonkeyPatch, *targets: Path) -> None:
    """Make every reader raise OSError for *targets* and behave normally elsewhere.

    Both ``read_text`` and ``read_bytes``, not just the one the helper under test happens to
    call today. These readers move between the two whenever an encoding fix lands -- and a test
    that intercepts only one stops testing anything the moment that choice changes, silently,
    because refusing nothing lets the file read fine and the assertion then measures the
    ordinary path. Patching only ``read_text`` is how twelve of these went green against a
    reader that had moved to ``read_bytes``.
    """

    wanted = {p.resolve() for p in targets}
    real_text = Path.read_text
    real_bytes = Path.read_bytes

    def _read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.resolve() in wanted:
            raise OSError(13, "Permission denied")
        return real_text(self, *args, **kwargs)

    def _read_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
        if self.resolve() in wanted:
            raise OSError(13, "Permission denied")
        return real_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _read_text)
    monkeypatch.setattr(Path, "read_bytes", _read_bytes)


# --------------------------------------------------------------------------- #
# unreadable files are skipped, not fatal
# --------------------------------------------------------------------------- #


def test_build_instructions_skips_a_readme_it_cannot_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An unreadable README must not be reported as carrying build instructions."""

    readme = tmp_path / "README.md"
    readme.write_text("## Building from source\n", encoding="utf-8")
    assert _shared._has_build_instructions(tmp_path) is True, "fixture does not reach the branch under test"

    _fail_reads_of(monkeypatch, readme)

    assert _shared._has_build_instructions(tmp_path) is False


@pytest.mark.parametrize(
    ("helper", "relative", "body"),
    [
        ("_audit_stream_signal_match", "RELEASE_OPERATIONS.md", "audit log streaming is enabled"),
        ("_disclosure_sla_signal_match", "SECURITY.md", "we will respond within 3 days"),
        ("_release_archive_signal_match", "RELEASE_ARCHIVAL.md", "retention policy: 7 years"),
    ],
)
def test_signal_helpers_skip_a_document_they_cannot_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    helper: str,
    relative: str,
    body: str,
) -> None:
    """Each keyword-matching signal degrades to "no signal" rather than raising."""

    doc = tmp_path / relative
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text(body, encoding="utf-8")
    fn = getattr(_shared, helper)
    assert fn(tmp_path) is not None, "fixture does not reach the branch under test"

    _fail_reads_of(monkeypatch, doc)

    assert fn(tmp_path) is None


def test_audit_stream_config_yaml_signals_without_a_keyword(tmp_path: Path) -> None:
    """A dedicated config YAML implies intent; unlike a doc file it needs no keyword match."""

    config = tmp_path / ".github" / "audit-log-streaming.yml"
    config.parent.mkdir(parents=True)
    config.write_text("nothing the keyword list would match\n", encoding="utf-8")

    assert _shared._audit_stream_signal_match(tmp_path) == config


def test_audit_stream_config_yaml_signals_nothing_when_it_is_empty(tmp_path: Path) -> None:
    """`touch .github/audit-log-streaming.yml` satisfied three controls. It is not a signal."""

    config = tmp_path / ".github" / "audit-log-streaming.yml"
    config.parent.mkdir(parents=True)
    config.write_bytes(b"")

    assert _shared._audit_stream_signal_match(tmp_path) is None


def test_audit_stream_config_yaml_signals_nothing_when_it_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This assertion used to be its opposite, and the opposite was the defect.

    The old test was named ``..._signals_without_being_read`` and required the match to succeed
    while every read of the file was refused. That makes the control state a positive posture --
    "audit log streaming is configured" -- about a file it could not open.

    Not signalling is the safe direction and costs nothing: the controls reading this matcher
    answer ``manual-review-required`` when they find no signal, so a refused read degrades
    rather than passing or claiming an absence.
    """

    config = tmp_path / ".github" / "audit-log-streaming.yml"
    config.parent.mkdir(parents=True)
    config.write_text("streaming: on\n", encoding="utf-8")

    _fail_reads_of(monkeypatch, config)

    assert _shared._audit_stream_signal_match(tmp_path) is None


# --------------------------------------------------------------------------- #
# malformed evidence is refused with a named status
# --------------------------------------------------------------------------- #


def test_branch_protection_evidence_whose_root_is_not_an_object_is_refused(tmp_path: Path) -> None:
    """A JSON array parses fine and is still not branch-protection evidence."""

    evidence = tmp_path / "branch-protection.json"
    evidence.write_text(json.dumps([{"protections": {}}]), encoding="utf-8")

    outcome = _shared._parse_branch_protection_evidence(evidence)

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "must be a JSON object" in outcome.reason


def test_digest_invalid_outcome_is_not_evaluated_and_says_why(tmp_path: Path) -> None:
    """A placeholder digest is NOT_EVALUATED -- never a pass, and never a silent skip."""

    outcome = _shared._digest_invalid_not_evaluated(tmp_path / "provenance.json")

    assert outcome.status is ControlStatus.NOT_EVALUATED
    assert outcome.reason == _shared._INVALID_DIGEST_REASON


# --------------------------------------------------------------------------- #
# hostile SARIF
# --------------------------------------------------------------------------- #


def test_deeply_nested_sarif_is_reported_not_crashed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A document nested past the interpreter limit must not escape as RecursionError.

    The parser is forced to raise rather than fed genuinely pathological input: the depth
    CPython actually breaks at varies by build and stack size, so a fixture tuned to this
    host would pass here and prove nothing in CI. What is under test is the handler -- that
    the error is turned into a named reason instead of unwinding through the evaluator.
    """

    sarif = tmp_path / "deep.sarif"
    depth = 200
    sarif.write_text("[" * depth + "]" * depth, encoding="utf-8")
    monkeypatch.setattr(_shared.json, "loads", _raise_recursion_error)

    runs, error = _shared._load_sarif_runs(sarif)

    assert runs is None
    assert error is not None
    assert "too deeply nested" in error


def _raise_recursion_error(*_args: Any, **_kwargs: Any) -> Any:
    raise RecursionError("maximum recursion depth exceeded")


def test_oversize_sarif_is_refused_before_it_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The size cap has to be checked first; reading the file to find out defeats it."""

    sarif = tmp_path / "huge.sarif"
    sarif.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(_shared, "MAX_SARIF_BYTES", 1)
    _fail_reads_of(monkeypatch, sarif)

    counts, error = _shared._parse_zizmor_severity_properties(sarif)

    assert counts is None
    assert error is not None


# --------------------------------------------------------------------------- #
# unbounded scans are capped
# --------------------------------------------------------------------------- #


def test_ai_agent_file_scan_stops_at_two_hundred_files(tmp_path: Path) -> None:
    """Without the cap, a monorepo turns one signal lookup into a full-tree walk."""

    for i in range(250):
        (tmp_path / f"mod_{i:03d}.py").write_text("x = 1\n", encoding="utf-8")

    found = _shared._iter_ai_agent_text_files(tmp_path)

    assert len(found) == 200


def test_text_hint_search_stops_at_five_matches(tmp_path: Path) -> None:
    """The evaluator reason lists examples, not an inventory."""

    for i in range(12):
        (tmp_path / f"prompt_{i:02d}.md").write_text("this mentions langchain\n", encoding="utf-8")

    matched = _shared._find_any_text_hint(tmp_path, ("langchain",))

    assert len(matched) == 5


# --------------------------------------------------------------------------- #
# type guards on scanner-supplied data
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "result",
    [
        None,
        "a string",
        42,
        [],
        {"properties": "not-an-object"},
        {"properties": None},
        # The one that would pass silently without the isinstance guard: `in` on a string
        # is a substring test, so this would claim both enrichments are present.
        {"properties": "kev and epss_score, as prose"},
    ],
)
def test_enrichment_probe_survives_a_result_of_any_shape(result: Any) -> None:
    """SARIF comes from third-party scanners; a malformed result must answer, not raise."""

    assert _shared._result_carries_enrichment(result) == (False, False)


def test_enrichment_probe_finds_kev_and_epss_when_present() -> None:
    """The negative cases above only mean something if the positive one still works."""

    assert _shared._result_carries_enrichment({"properties": {"kev": True}}) == (True, False)
    assert _shared._result_carries_enrichment({"properties": {"epss_score": 0.4}}) == (False, True)
    assert _shared._result_carries_enrichment({"properties": {"epss": 0.4}}) == (False, True)


# --------------------------------------------------------------------------- #
# agentic applicability folds in the MCP signals
# --------------------------------------------------------------------------- #


def test_agentic_applicability_includes_what_the_mcp_probe_found(tmp_path: Path) -> None:
    """An MCP config alone makes a repo agentic; the paths it found must reach the caller."""

    mcp_dir = tmp_path / ".mcp"
    mcp_dir.mkdir()

    applicable, found = _shared._agentic_applicable(tmp_path)

    assert applicable is True
    assert mcp_dir in found


def test_a_repo_with_no_agent_signal_at_all_is_not_applicable(tmp_path: Path) -> None:
    """The converse, so the test above cannot pass by always returning True."""

    (tmp_path / "README.md").write_text("an ordinary project\n", encoding="utf-8")

    applicable, found = _shared._agentic_applicable(tmp_path)

    assert applicable is False
    assert found == []


# --------------------------------------------------------------------------- #
# the read that fails on the second attempt, not the first
# --------------------------------------------------------------------------- #


def _fail_reads_after_the_first(monkeypatch: pytest.MonkeyPatch, target: Path) -> list[int]:
    """Let the first read of *target* succeed and raise OSError on every read after it.

    The signal helpers read each candidate twice: `_has_content` reads it to decide whether
    there is anything in the file, and the loop body reads it again to match keywords. A test
    that refuses every read never reaches the second one, because `_has_content` answers False
    and the loop skips the file one branch earlier. That is why the `except OSError` around the
    keyword read looked dead: the only way in is for the file to stop being readable BETWEEN
    the two reads, which is what a deleted file, a revoked permission or a dropped mount does
    while an evaluation is running.

    Returns a single-element list holding the read count, so the caller can assert the second
    read was actually attempted rather than trust that it was.
    """

    wanted = target.resolve()
    real_bytes = Path.read_bytes
    calls = [0]

    def _read_bytes(self: Path, *args: Any, **kwargs: Any) -> bytes:
        if self.resolve() == wanted:
            calls[0] += 1
            if calls[0] > 1:
                raise OSError(5, "Input/output error")
        return real_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    return calls


@pytest.mark.parametrize(
    ("helper", "relative", "body"),
    [
        ("_audit_stream_signal_match", "RELEASE_OPERATIONS.md", "audit log streaming is enabled"),
        ("_release_archive_signal_match", "RELEASE_ARCHIVAL.md", "retention policy: 7 years"),
    ],
)
def test_signal_helpers_survive_a_file_that_stops_being_readable_mid_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    helper: str,
    relative: str,
    body: str,
) -> None:
    """The keyword read fails after the content check passed: answer "no signal", do not raise.

    Both controls reading these helpers PASS only on finding the signal and answer
    manual-review-required without it, so losing the file here withdraws the claim instead of
    inventing one. That is the direction ADR-045 asks for, and it holds here for free rather
    than by a withdrawal written into the helper.
    """

    doc = tmp_path / relative
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text(body, encoding="utf-8")
    fn = getattr(_shared, helper)
    assert fn(tmp_path) is not None, "fixture does not reach the branch under test"

    calls = _fail_reads_after_the_first(monkeypatch, doc)

    assert fn(tmp_path) is None
    assert calls[0] >= 2, (
        "the second read was never attempted, so the branch under test did not run; "
        f"{relative} was read {calls[0]} time(s)"
    )
