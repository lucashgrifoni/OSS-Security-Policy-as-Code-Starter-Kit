"""Regression tests for the v10.0.7 ``diff-reports`` fixes.

Four defects found by clean-room validation of the published v10.0.6 wheel:

1. *exit 3 on hostile reports* — a 3000-level nested JSON array (and a 20000-level
   nested object) blew the C JSON scanner's stack inside ``json.loads``, so
   ``diff-reports`` reported ``Unexpected error: maximum recursion depth exceeded``
   with exit 3. Exit 3 means "defect in the kit"; a bad input file is exit 2. The
   depth ladder mattered: 199/250/400/900/1200/2000 all exited 2 (the shape check
   ran), and only 3000+ crashed, which is exactly the fingerprint of a guard placed
   *after* the parse instead of before it.
2. *M-002 in the published artifact* — ``--format markdown`` (the format the
   command's own EXAMPLES block tells you to paste into a PR comment) and
   ``--format json`` both resolved a relative ``--before``/``--after`` to an
   absolute path purely for display, publishing the auditor's home directory and
   OS account name.
3. *unhelpful parse error* — a malformed ``--before`` and a malformed ``--after``
   produced byte-identical text with no filename and no side.
4. *wrong claim in a rejection message* — ``--report-json-contract 3.0`` (and
   ``two``/``2``/``2.0.0``) claimed the value "was removed in v9.0.0 (ADR-043)".
   Those spellings never named a contract of this kit; only the four that really
   existed may be sent to the migration guide.

Every guard here was mutation-tested: the fix was reverted on purpose and each
test confirmed to fail before being kept.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.engine import report_json_schema_url
from oss_policy_kit.application.input_limits import MAX_JSON_DEPTH
from oss_policy_kit.application.reporting import digest_for_report_payload
from oss_policy_kit.cli import reports as rep
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import LoadError

runner = CliRunner()


def _report(controls: list[dict[str, Any]] | None = None, **extra: Any) -> dict[str, Any]:
    """A minimal ``reports/2.0`` payload — the only contract ``diff-reports`` accepts."""

    payload: dict[str, Any] = {
        "contract_version": "reports/2.0",
        "kit_version": "10.0.7",
        "profile": {"id": "p"},
        "controls": controls if controls is not None else [{"id": "A", "state": "PASS", "title": "t"}],
    }
    payload.update(extra)
    # reports/2.0 requires results_digest and the loader checks it, so a fixture without
    # one is not a minimal report -- it is an incomplete one. `extra` still wins, which is
    # what lets a case supply a deliberately wrong digest.
    payload.setdefault("results_digest", digest_for_report_payload(payload)[0] or "")
    return payload


def _write(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_raw(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _nested_array(depth: int) -> str:
    return "[" * depth + "]" * depth


def _nested_object(depth: int) -> str:
    return '{"a":' * depth + "1" + "}" * depth


def _flat(text: str) -> str:
    """Collapse whitespace so a Rich soft-wrap cannot split an asserted phrase.

    A long ``tmp_path`` wraps the stderr message mid-phrase on one platform and not
    on another; asserting on the flattened text makes the check mean the same thing
    everywhere.
    """

    return re.sub(r"\s+", " ", text)


def _pair(tmp_path: Path) -> tuple[Path, Path]:
    return _write(tmp_path / "before.json", _report()), _write(tmp_path / "after.json", _report())


# --------------------------------------------------------------------------- #
# 1 — hostile documents are exit 2 (bad input), never exit 3 (defect in the kit)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("depth", [250, 1200, 3000, 20_000])
@pytest.mark.parametrize("shape", ["array", "object"])
def test_over_deep_report_on_either_side_exits_2(tmp_path: Path, depth: int, shape: str) -> None:
    """The whole ladder answers the same way — including past the C stack limit.

    3000 (arrays) and 20000 (objects) are the exact depths that crashed v10.0.6; the
    shallower rungs are here so a regression that moves the guard back behind
    ``json.loads`` cannot pass by only fixing the two reported numbers.
    """

    raw = _nested_array(depth) if shape == "array" else _nested_object(depth)
    hostile = _write_raw(tmp_path / "hostile.json", raw)
    ok = _write(tmp_path / "ok.json", _report())

    for flag, other in (("--before", "--after"), ("--after", "--before")):
        res = runner.invoke(app, ["diff-reports", flag, str(hostile), other, str(ok)])
        out = _flat(res.output)
        assert res.exit_code == 2, res.output
        assert "nested too deeply" in out, res.output
        assert f"{flag} report" in out, res.output
        assert "Unexpected error" not in out, res.output
        assert "Traceback" not in out, res.output


def test_two_hostile_reports_still_exit_2(tmp_path: Path) -> None:
    """Reproduced with one valid and one hostile report *as well as* with two."""

    a = _write_raw(tmp_path / "a.json", _nested_array(3000))
    b = _write_raw(tmp_path / "b.json", _nested_object(20_000))

    res = runner.invoke(app, ["diff-reports", "--before", str(a), "--after", str(b)])

    assert res.exit_code == 2, res.output
    assert "nested too deeply" in _flat(res.output), res.output


def test_depth_refusal_names_the_shared_limit(tmp_path: Path) -> None:
    """One vocabulary for one problem: the same wording every other reader uses."""

    hostile = _write_raw(tmp_path / "hostile.json", _nested_array(MAX_JSON_DEPTH + 1))
    ok = _write(tmp_path / "ok.json", _report())

    res = runner.invoke(app, ["diff-reports", "--before", str(hostile), "--after", str(ok)])

    assert res.exit_code == 2, res.output
    assert f"more than {MAX_JSON_DEPTH} levels" in _flat(res.output), res.output


def test_the_depth_check_runs_before_the_parser_is_ever_called(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Placement is the fix, not the message.

    Catching ``RecursionError`` around ``json.loads`` happens to work at 3000 levels
    on this platform, which would let a "the message says nested too deeply" test pass
    with the real guard removed. This one fails unless the document is refused without
    the parser being entered at all — the only version that survives a C-stack
    overflow that never raises anything Python can catch.
    """

    from oss_policy_kit.application import drift as drift_mod
    from oss_policy_kit.domain.errors import InvalidInputError

    class _NoParse:
        @staticmethod
        def loads(_text: str) -> Any:
            raise AssertionError("json.loads must not be reached for an over-deep document")

    hostile = _write_raw(tmp_path / "hostile.json", _nested_array(3000))
    monkeypatch.setattr(drift_mod, "json", _NoParse)

    with pytest.raises(InvalidInputError) as exc:
        drift_mod.load_report_json(hostile, label="--before report")

    assert "nested too deeply" in str(exc.value)


def test_a_legitimately_deep_report_is_still_accepted(tmp_path: Path) -> None:
    """The guard must refuse hostile documents, not merely-nested honest ones.

    A report whose ``extensions`` block nests well below the limit still diffs
    cleanly — otherwise the fix would be a new false refusal.
    """

    deep: dict[str, Any] = {"leaf": 1}
    for _ in range(150):
        deep = {"n": deep}
    before = _write(tmp_path / "before.json", _report(extensions=deep))
    after = _write(tmp_path / "after.json", _report(extensions=deep))

    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after), "-f", "json"])

    assert res.exit_code == 0, res.output


def test_utf16_report_is_a_usage_error_not_a_crash(tmp_path: Path) -> None:
    """A non-UTF-8 report is bad input; it must not reach the exit-3 handler."""

    hostile = tmp_path / "utf16.json"
    hostile.write_bytes(json.dumps(_report()).encode("utf-16"))
    ok = _write(tmp_path / "ok.json", _report())

    res = runner.invoke(app, ["diff-reports", "--before", str(hostile), "--after", str(ok)])
    out = _flat(res.output)

    assert res.exit_code == 2, res.output
    assert "--before report" in out, res.output
    assert "not valid UTF-8" in out, res.output
    assert "Unexpected error" not in out, res.output


# --------------------------------------------------------------------------- #
# 2 — M-002: the shareable output carries a basename, not an absolute path
# --------------------------------------------------------------------------- #


def test_json_format_does_not_publish_an_absolute_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Relative in, relative out. The inputs are relative so the assertion cannot
    pass for the wrong reason on Windows, where the 8.3 short name (``LUCASG~1``)
    hides the account name from a naive "username not in output" check."""

    _pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    res = runner.invoke(app, ["diff-reports", "--before", "before.json", "--after", "after.json", "-f", "json"])
    payload = json.loads(res.output)

    assert res.exit_code == 0, res.output
    assert payload["before_path"] == "before.json"
    assert payload["after_path"] == "after.json"
    assert str(tmp_path) not in res.output


def test_markdown_format_does_not_publish_an_absolute_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The markdown output is the surface the EXAMPLES block tells users to paste
    into a PR comment, so it is the one most likely to be published."""

    _pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    res = runner.invoke(app, ["diff-reports", "--before", "before.json", "--after", "after.json", "-f", "markdown"])

    assert res.exit_code == 0, res.output
    assert "- **Before**: `before.json`" in res.output, res.output
    assert "- **After**: `after.json`" in res.output, res.output
    assert str(tmp_path) not in res.output


def test_an_absolute_input_is_reduced_to_its_basename(tmp_path: Path) -> None:
    """Sanitizing is about the published value, not about what the user typed: an
    absolute ``--before`` must still render as a basename."""

    before, after = _pair(tmp_path)

    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after), "-f", "json"])
    payload = json.loads(res.output)

    assert res.exit_code == 0, res.output
    assert payload["before_path"] == "before.json"
    assert payload["after_path"] == "after.json"


def test_include_absolute_path_opts_back_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The opt-out mirrors ``evaluate --include-absolute-path`` for downstream tooling
    that genuinely wants the full path."""

    _pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    res = runner.invoke(
        app,
        [
            "diff-reports",
            "--before",
            "before.json",
            "--after",
            "after.json",
            "-f",
            "json",
            "--include-absolute-path",
        ],
    )
    payload = json.loads(res.output)

    assert res.exit_code == 0, res.output
    assert Path(payload["before_path"]).is_absolute(), payload["before_path"]
    assert Path(payload["after_path"]).is_absolute(), payload["after_path"]
    assert Path(payload["before_path"]).name == "before.json"


# --------------------------------------------------------------------------- #
# 3 — a parse failure names its side and its file
# --------------------------------------------------------------------------- #


def test_malformed_before_and_after_no_longer_read_identically(tmp_path: Path) -> None:
    """Through v10.0.6 both sides printed the same 'Expecting value: line 1 column 1
    (char 0)' with no filename and no side, so the message could not tell the user
    which file to open."""

    good = _write(tmp_path / "good.json", _report())
    bad = _write_raw(tmp_path / "bad.json", "{not json")

    before_bad = runner.invoke(app, ["diff-reports", "--before", str(bad), "--after", str(good)])
    after_bad = runner.invoke(app, ["diff-reports", "--before", str(good), "--after", str(bad)])

    assert before_bad.exit_code == 2, before_bad.output
    assert after_bad.exit_code == 2, after_bad.output
    assert _flat(before_bad.output) != _flat(after_bad.output)
    assert "--before report 'bad.json'" in _flat(before_bad.output), before_bad.output
    assert "--after report 'bad.json'" in _flat(after_bad.output), after_bad.output


def test_parse_failure_message_carries_no_directory(tmp_path: Path) -> None:
    """The filename is enough to act on; the directory would leak the home path."""

    good = _write(tmp_path / "good.json", _report())
    bad = _write_raw(tmp_path / "bad.json", "{not json")

    res = runner.invoke(app, ["diff-reports", "--before", str(bad), "--after", str(good)])

    assert res.exit_code == 2, res.output
    assert str(tmp_path) not in res.output, res.output


def test_unreadable_report_is_still_exit_2(tmp_path: Path) -> None:
    """A directory passed where a file belongs is an OSError inside ``read_text``;
    it must land on the same exit-2 vocabulary rather than the exit-3 handler."""

    good = _write(tmp_path / "good.json", _report())
    directory = tmp_path / "adir.json"
    directory.mkdir()

    # ``--before`` is checked with ``is_file()`` first, so drive the read failure
    # through the loader directly for the branch that ``is_file()`` cannot cover.
    from oss_policy_kit.application.drift import load_report_json
    from oss_policy_kit.domain.errors import InvalidInputError

    with pytest.raises(InvalidInputError) as exc:
        load_report_json(directory, label="--before report")

    assert "--before report 'adir.json'" in str(exc.value)
    assert str(tmp_path) not in str(exc.value)
    assert good.is_file()


def test_value_error_backstop_still_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ValueError handler stays the backstop for a non-object report root and for
    anything below the loader; it must not become an exit-3 path."""

    before, after = _pair(tmp_path)

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise ValueError("synthetic")

    monkeypatch.setattr(rep, "compute_drift", _boom)
    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after)])

    assert res.exit_code == 2, res.output


# --------------------------------------------------------------------------- #
# 4 — only the contracts that really existed may be called "removed"
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("removed", ["1.0", "0.3", "0.2", "0.1", "v1.0", "reports/1.0", "  0.2  "])
def test_a_genuinely_removed_contract_points_at_the_migration_guide(removed: str) -> None:
    with pytest.raises(LoadError) as exc:
        report_json_schema_url(removed)

    msg = str(exc.value)
    assert "was removed in v9.0.0 (ADR-043)" in msg
    assert "v9.0.0-migration-guide.md" in msg


@pytest.mark.parametrize("unknown", ["3.0", "two", "2", "2.0.0", "banana", "9.9", "reports/2.0"])
def test_an_unknown_contract_is_not_claimed_to_have_been_removed(unknown: str) -> None:
    """These spellings never named a contract of this kit. Telling the user they
    "were removed in v9.0.0" is a false statement about the kit's own history and
    sends them to a migration guide for a version they never used."""

    with pytest.raises(LoadError) as exc:
        report_json_schema_url(unknown)

    msg = str(exc.value)
    assert "not a recognised contract" in msg
    assert "removed" not in msg
    assert "2.0" in msg  # the reader is still told what to pass


def test_the_only_contract_is_still_accepted_and_blank_still_fails_closed() -> None:
    assert report_json_schema_url("2.0").endswith("/reports/2.0")
    with pytest.raises(LoadError):
        report_json_schema_url("")
