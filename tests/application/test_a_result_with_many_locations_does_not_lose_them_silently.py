"""A SARIF result may name several locations; the artifact must not pretend it named one.

SARIF 2.1.0 §3.27.12 defines `result.locations` as *the set of locations where the result was
detected*. `finding_sarif._location()` reads `locations[0]` and returns a single
`FindingLocation`; nothing looks at `locations[1:]`.

Reproduced through the CLI before writing this, with one result naming three files:

    correlate-findings --target <repo> --format json  ->  exit 0
    findings_total: 1, location.file: "service-a/config.py"
    grep -c 'service-b\\|service-c' <artifact>  ->  0
    extensions: {}

Two of the three affected files are absent from every field of the artifact -- not in
`sources[]`, not in `extensions`, nowhere -- and the command exits 0 with no diagnostic. Fix
the first file and a re-exported alert closes while the other two are still vulnerable.

The kit already answers this exact question for its own evidence. The docstring of
`finding_normalization.kit_evidence_partial_scan_warnings` argues it in full: a source the
scanner could not parse is invisible in `findings_total`, `--fail-on-severity` gates pipelines
on that number, `sources_read[].status` is a closed enum with `additionalProperties: false` and
cannot carry the fact, so `extensions` -- the contract's sanctioned free-form block -- carries
it instead. External SARIF locations are the same class of loss and were never covered.

So this asserts the same remedy through the same channel, rather than changing what a finding
is: `findings_total` and the primary location stay exactly as they are, and the artifact stops
being silent about the rest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import finding_sarif
from oss_policy_kit.application.finding_sarif import sarif_partial_location_warnings
from oss_policy_kit.application.findings_report import build_findings_report

_SAST = Path(".oss-policy-kit") / "evidence" / "sast"


def _write_sarif(repo: Path, filename: str, results: list[dict[str, Any]]) -> None:
    directory = repo / _SAST
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": filename.split(".")[0], "version": "1.0.0"}}, "results": results}],
    }
    (directory / filename).write_text(json.dumps(document), encoding="utf-8")


def _result_at(*uris: str) -> dict[str, Any]:
    return {
        "ruleId": "HARDCODED-SECRET",
        "level": "error",
        "message": {"text": "Hardcoded credential shared by three services"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 10 * (i + 1)}}}
            for i, uri in enumerate(uris)
        ],
    }


def test_the_files_beyond_the_first_are_named(tmp_path: Path) -> None:
    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py", "b/y.py", "c/z.py")])

    warnings = sarif_partial_location_warnings(tmp_path)

    assert warnings, "a result naming three files produced no warning at all"
    joined = " ".join(warnings)
    assert "b/y.py" in joined and "c/z.py" in joined, f"the dropped files are still unnamed: {warnings!r}"


def test_a_single_location_result_warns_about_nothing(tmp_path: Path) -> None:
    """The guard must not fire on the ordinary case, which is nearly every result."""

    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py")])

    assert sarif_partial_location_warnings(tmp_path) == []


def test_the_warning_reaches_the_published_artifact(tmp_path: Path) -> None:
    """Not just the helper: the artifact an adopter reads has to carry it."""

    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py", "b/y.py")])

    report = build_findings_report(tmp_path, kit_version="test")

    assert report["findings_total"] == 1, "the fix must not change how many findings there are"
    assert report["findings"][0]["location"]["file"] == "a/x.py", "the primary location must be unchanged"

    warnings = report["extensions"].get("partial_scan_warnings", [])
    assert any("b/y.py" in w for w in warnings), (
        f"the artifact still does not mention the second affected file anywhere: extensions={report['extensions']!r}"
    )


def test_the_artifact_stays_quiet_when_there_is_nothing_to_say(tmp_path: Path) -> None:
    """`extensions` is absent-when-empty, and that has to survive the change."""

    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py")])

    report = build_findings_report(tmp_path, kit_version="test")

    assert "partial_scan_warnings" not in report["extensions"]


# The three assertions below cover the bounds the fix itself introduced. Every one of them
# is target-controlled text on its way into a published artifact, and a mutation run proved
# the length cap was decorative until this existed: deleting it left all four tests green.


def test_a_long_uri_cannot_stretch_the_warning(tmp_path: Path) -> None:
    long_uri = "d/" + ("n" * 500) + ".py"
    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py", long_uri)])

    warning = " ".join(sarif_partial_location_warnings(tmp_path))

    assert long_uri not in warning, "the whole 500-character path was copied in verbatim"
    assert "d/nnnn" in warning, "it was truncated so hard the file is no longer identifiable"
    assert len(warning) < 600, f"the warning grew to {len(warning)} characters"


def test_many_extra_locations_are_summarised_rather_than_listed(tmp_path: Path) -> None:
    extras = [f"svc-{i:02d}/config.py" for i in range(25)]
    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py", *extras)])

    warning = " ".join(sarif_partial_location_warnings(tmp_path))

    assert "svc-00/config.py" in warning, "the first extras must still be named"
    assert "more" in warning, "the remainder was dropped without saying so"
    assert "svc-24/config.py" not in warning, "all 25 were listed; the cap did nothing"


def test_two_results_sharing_an_affected_file_name_it_once(tmp_path: Path) -> None:
    """The dedup that matters is the one ACROSS results, not within one.

    A single result cannot produce a duplicate -- `_extra_location_uris` already collapses
    those -- so the outer check only ever fires here, where two different rules both reach the
    same shared file. Coverage found this: the outer branch was never exercised until this
    test existed, which is the same thing as saying it was untested code.
    """

    first = _result_at("a/x.py", "shared/config.py")
    second = _result_at("b/y.py", "shared/config.py")
    second["ruleId"] = "WEAK-CIPHER"
    _write_sarif(tmp_path, "osv-scanner.sarif.json", [first, second])

    warning = " ".join(sarif_partial_location_warnings(tmp_path))

    assert warning.count("shared/config.py") == 1, "the shared file was named once per result"


def test_a_repeated_file_is_named_once(tmp_path: Path) -> None:
    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py", "b/y.py", "b/y.py")])

    warning = " ".join(sarif_partial_location_warnings(tmp_path))

    assert warning.count("b/y.py") == 1, "the same file was named twice"


@pytest.mark.parametrize(
    "extra,reason",
    [
        ("not-a-dict", "a location entry that is not an object"),
        ({}, "a location with no physicalLocation"),
        ({"physicalLocation": "not-a-dict"}, "a physicalLocation that is not an object"),
        ({"physicalLocation": {}}, "a physicalLocation with no artifactLocation"),
        ({"physicalLocation": {"artifactLocation": {"uri": 42}}}, "a uri that is not a string"),
        ({"physicalLocation": {"artifactLocation": {"uri": "   "}}}, "a uri that is only whitespace"),
    ],
)
def test_a_malformed_extra_location_is_skipped_not_raised(tmp_path: Path, extra: Any, reason: str) -> None:
    """Degrade, never raise -- the rule the whole module is written to.

    Each of these is a shape a real document can carry. Naming nothing is the honest answer;
    an exception here would surface as the exit 3 this command reserves for a kit defect.
    """

    result = _result_at("a/x.py")
    result["locations"].append(extra)
    _write_sarif(tmp_path, "osv-scanner.sarif.json", [result])

    assert sarif_partial_location_warnings(tmp_path) == [], f"warned about {reason}"


def test_an_unparseable_drop_says_nothing_here(tmp_path: Path) -> None:
    """`sources_read` already reports it. Repeating it in a field about a different problem is noise."""

    directory = tmp_path / _SAST
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "osv-scanner.sarif.json").write_text("{ this is not json", encoding="utf-8")

    assert sarif_partial_location_warnings(tmp_path) == []


def test_an_oversize_drop_says_nothing_here(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py", "b/y.py")])
    monkeypatch.setattr(finding_sarif, "MAX_SARIF_BYTES", 4)

    assert sarif_partial_location_warnings(tmp_path) == []


@pytest.mark.parametrize(
    "runs,reason",
    [
        (["not-a-dict"], "a run that is not an object"),
        ([{"tool": {"driver": {"name": "osv"}}, "results": "not-a-list"}], "a results container that is not a list"),
    ],
)
def test_a_malformed_run_is_skipped(tmp_path: Path, runs: list[Any], reason: str) -> None:
    directory = tmp_path / _SAST
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "osv-scanner.sarif.json").write_text(json.dumps({"version": "2.1.0", "runs": runs}), encoding="utf-8")

    assert sarif_partial_location_warnings(tmp_path) == [], f"warned about {reason}"


def test_a_passing_result_is_not_a_finding_and_names_nothing(tmp_path: Path) -> None:
    """`kind: pass` is the tool saying the check succeeded; its locations are not affected files."""

    result = _result_at("a/x.py", "b/y.py")
    result["kind"] = "pass"
    _write_sarif(tmp_path, "osv-scanner.sarif.json", [result])

    assert sarif_partial_location_warnings(tmp_path) == []


def test_control_bytes_in_a_path_do_not_reach_the_artifact(tmp_path: Path) -> None:
    """The target writes this file. An escape sequence in it must not reach a terminal.

    Same class as the ANSI-in-Markdown finding: repository content flowing into an artifact
    a human is meant to read and share.
    """

    _write_sarif(tmp_path, "osv-scanner.sarif.json", [_result_at("a/x.py", "e/\x1b[31mred\x1b[0m.py")])

    warning = " ".join(sarif_partial_location_warnings(tmp_path))

    assert "\x1b" not in warning, "an ESC byte survived into the warning text"
    assert "red" in warning, "the path was scrubbed so thoroughly it names nothing"
