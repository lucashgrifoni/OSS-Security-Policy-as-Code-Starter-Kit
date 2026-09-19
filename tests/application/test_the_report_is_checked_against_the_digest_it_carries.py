"""Every report carries a `results_digest`, and until now nothing read it back.

`compute_results_digest` has hashed six canonical fields of every control since the
contract existed, and `results_digest` is a required property of reports/2.0. No consumer
compared it to anything. A report whose `state` had been edited from `FAIL` to `PASS`
produced a clean drift verdict at exit 0, and `export-evidence` would attest to it.

What this establishes is bounded, and the bound is the point:

* The digest is unkeyed. Recomputing it catches a report somebody edited and did not
  re-hash. It does not catch a forgery, because whoever changed the verdict can run the
  same function. Signing is the answer to that and is not this.
* It covers `control_id`, `profile`, `status`, `lifecycle`, `assurance` and `weight`, and
  nothing else, so an edited `message` still passes. That is the same deliberate choice
  that makes the digest stable across cosmetic refactors, and it is asserted below rather
  than only described.

The inverse is the part that could rot. `REPORTS_V2_STATUS_MAP` projects the statuses onto
six wire states, and recomputing the digest means going back the other way. That works
only because every `(state, reason)` pair is distinct across the statuses `ControlStatus`
actually has. Three keys in that map name no member -- `degraded`, `error`, `skipped` --
and `degraded` is the dangerous one: it maps to `("FAIL", None)`, exactly where `fail`
already sits. The last two tests below are what stands between that and a verifier that
quietly guesses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import ROOT

from oss_policy_kit.application.drift import UNVERIFIED_DIGEST_KEY, load_report_json
from oss_policy_kit.application.reporting import (
    REPORTS_V2_STATUS_MAP,
    _status_from_wire,
    verify_results_digest,
)
from oss_policy_kit.domain.errors import InvalidInputError
from oss_policy_kit.domain.models import ControlStatus

_SAMPLES = [
    pytest.param(ROOT / "docs" / "sample-reports" / "hardened" / "evaluation-report.json", id="hardened"),
    pytest.param(ROOT / "docs" / "sample-reports" / "vulnerable" / "evaluation-report.json", id="vulnerable"),
]


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", _SAMPLES)
def test_a_report_the_kit_wrote_verifies(path: Path) -> None:
    """Both shipped samples, one all-PASS and one carrying FAIL and UNKNOWN."""

    assert verify_results_digest(_load(path)) == ("verified", None)


@pytest.mark.parametrize("path", _SAMPLES)
def test_a_report_the_kit_wrote_still_loads(path: Path) -> None:
    """The check runs inside the loader, so a false positive would break every consumer."""

    assert load_report_json(path, label="--before report")["contract_version"]


def _vulnerable() -> dict[str, Any]:
    return _load(ROOT / "docs" / "sample-reports" / "vulnerable" / "evaluation-report.json")


def _flip_a_fail_to_pass(report: dict[str, Any]) -> None:
    next(c for c in report["controls"] if c["state"] == "FAIL")["state"] = "PASS"


def _raise_a_weight(report: dict[str, Any]) -> None:
    report["controls"][0]["weight"] = 99


def _drop_a_control(report: dict[str, Any]) -> None:
    report["controls"].pop(0)


def _upgrade_assurance(report: dict[str, Any]) -> None:
    report["controls"][0]["assurance"] = "self-attested"


def _rename_a_control(report: dict[str, Any]) -> None:
    report["controls"][0]["id"] = "GOV-SEC-999"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(_flip_a_fail_to_pass, id="a-failing-control-marked-passing"),
        pytest.param(_raise_a_weight, id="a-weight-inflated"),
        pytest.param(_drop_a_control, id="a-control-removed-entirely"),
        pytest.param(_upgrade_assurance, id="assurance-upgraded"),
        pytest.param(_rename_a_control, id="a-control-renamed"),
    ],
)
def test_an_edited_verdict_is_refused(mutate: Any, tmp_path: Path) -> None:
    report = _vulnerable()
    mutate(report)
    path = tmp_path / "evaluation-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(InvalidInputError) as caught:
        load_report_json(path, label="--after report")

    assert "digest" in str(caught.value)


def test_a_report_with_no_digest_loads_and_says_it_was_not_checked(tmp_path: Path) -> None:
    """Not a refusal. ADR-045: not knowing and knowing-it-is-wrong are different answers.

    The first cut of this change refused here, and 81 of the kit's own tests went red.
    That number is evidence about the design, not only about the fixtures: a report with
    no digest has not been shown to be wrong. It has not been shown to be right either,
    which is why the key below travels with the payload instead of the loader staying
    quiet.
    """

    report = _vulnerable()
    del report["results_digest"]
    path = tmp_path / "evaluation-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    loaded = load_report_json(path, label="--after report")

    assert "results_digest" in str(loaded[UNVERIFIED_DIGEST_KEY])


def test_a_verified_report_is_not_marked_unverified(tmp_path: Path) -> None:
    """The other direction: the key must be absent when the digest actually checked out."""

    path = ROOT / "docs" / "sample-reports" / "vulnerable" / "evaluation-report.json"

    assert UNVERIFIED_DIGEST_KEY not in load_report_json(path, label="--before report")


def test_diff_reports_tells_the_operator_a_report_was_not_checked(tmp_path: Path) -> None:
    """A verdict nobody is shown is not a verdict.

    Run as a subprocess with COLUMNS pinned. Rich wraps to the terminal width, and a
    `tmp_path` long enough to push the message over the edge splits the very token this
    asserts on, which passes on one machine and fails on another.
    """

    import os
    import subprocess
    import sys

    report = _vulnerable()
    del report["results_digest"]
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps(report), encoding="utf-8")
    after.write_text(json.dumps(report), encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - fixed argv, shell=False
        [sys.executable, "-m", "oss_policy_kit", "diff-reports", "--before", str(before), "--after", str(after)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "COLUMNS": "200", "NO_COLOR": "1", "PYTHONIOENCODING": "utf-8"},
        check=False,
    )
    combined = " ".join((result.stderr or "").split())

    assert "results_digest" in combined, f"the run said nothing about the unchecked digest: {combined[:300]}"


def test_edited_prose_still_passes_because_the_digest_does_not_cover_it() -> None:
    """The stated limit, asserted. A test suite that only proves the good news lies."""

    report = _vulnerable()
    report["controls"][0]["message"] = "a completely different sentence"
    report["controls"][0]["remediation"] = "and a different remediation"

    assert verify_results_digest(report) == ("verified", None), (
        "the digest started covering free text. That may be an improvement, but it is a "
        "contract change: every digest value in the wild stops matching."
    )


@pytest.mark.parametrize("status", [pytest.param(s, id=s.value) for s in ControlStatus])
def test_every_status_survives_the_round_trip(status: ControlStatus) -> None:
    """Derived from the enum. A tenth status that breaks the inverse fails here."""

    wire, reason = REPORTS_V2_STATUS_MAP[status.value]

    assert _status_from_wire(wire, reason) == status.value, (
        f"{status.value!r} serialises as {(wire, reason)!r} and cannot be read back, so no "
        "report containing this status can have its digest verified."
    )


def test_the_map_keys_that_name_no_status_are_the_only_reason_it_is_invertible() -> None:
    """The guard that matters. Adding `degraded` as a real status breaks the inverse.

    `degraded` maps to `("FAIL", None)`, which is where `fail` already is. While no
    `ControlStatus` carries that value the pair is unambiguous; the moment one does, two
    statuses produce identical bytes on the wire and the verifier can only guess. Better
    to fail here, with the reason, than to guess in a security check.
    """

    real = {member.value for member in ControlStatus}
    dead = sorted(set(REPORTS_V2_STATUS_MAP) - real)

    assert dead == ["degraded", "error", "skipped"], (
        f"the set of map keys naming no ControlStatus changed: {dead}. If one of them "
        "became real, check it does not collide with another status's (state, reason)."
    )

    pairs: dict[tuple[str, str | None], list[str]] = {}
    for value in sorted(real):
        pairs.setdefault(REPORTS_V2_STATUS_MAP[value], []).append(value)
    collisions = {pair: names for pair, names in pairs.items() if len(names) > 1}

    assert not collisions, (
        f"two statuses now serialise identically: {collisions}. The digest cannot be "
        "recomputed from a report containing either, so verify_results_digest would be "
        "guessing. Give one of them a distinct reason in REPORTS_V2_STATUS_MAP."
    )


def test_the_collision_guard_would_notice() -> None:
    """The mutation, run in-process: the check above must fail on a colliding map."""

    colliding = {**REPORTS_V2_STATUS_MAP, "fail": ("FAIL", None), "pass": ("FAIL", None)}
    pairs: dict[tuple[str, str | None], list[str]] = {}
    for value in ("fail", "pass"):
        pairs.setdefault(colliding[value], []).append(value)

    assert {p: n for p, n in pairs.items() if len(n) > 1} == {("FAIL", None): ["fail", "pass"]}


def test_a_state_the_contract_does_not_define_is_named_rather_than_guessed() -> None:
    report = _vulnerable()
    report["controls"][0]["state"] = "PROBABLY_FINE"

    verdict, reason = verify_results_digest(report)

    assert verdict == "unverifiable", "an undefined state is unreadable, not proof of tampering"
    assert reason is not None
    assert "PROBABLY_FINE" in reason, "the reader has to say which value it did not recognise"


def test_export_evidence_reads_the_digest_too() -> None:
    """The second of the two readers. A chokepoint that is not the only door is not one."""

    import inspect

    from oss_policy_kit.cli import export_evidence

    source = inspect.getsource(export_evidence._read_report)

    assert "verify_results_digest" in source, (
        "export-evidence parses the report itself instead of going through "
        "drift.load_report_json, so the check has to be wired in here as well"
    )


# --------------------------------------------------------------------------------------
# The shapes a report can be broken in without being tampered with. Each one is a report
# the digest cannot be recomputed from, which is a different answer from a wrong digest.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("break_it", "expected"),
    [
        pytest.param(lambda r: r.__setitem__("controls", "not a list"), "controls array", id="controls-is-not-a-list"),
        pytest.param(
            lambda r: r["controls"].__setitem__(0, "a string"), "not an object", id="a-control-is-not-an-object"
        ),
        pytest.param(lambda r: r["controls"][0].pop("state"), "has no state", id="a-control-has-no-state"),
        pytest.param(lambda r: r["controls"][0].__setitem__("state", 7), "has no state", id="state-is-not-a-string"),
    ],
)
def test_a_report_the_digest_cannot_be_recomputed_from_is_unverifiable(break_it: Any, expected: str) -> None:
    report = _vulnerable()
    break_it(report)

    verdict, why = verify_results_digest(report)

    assert verdict == "unverifiable", "a malformed report has not been shown to be tampered with"
    assert why is not None and expected in why


def test_export_evidence_refuses_a_report_whose_verdicts_were_edited(tmp_path: Path) -> None:
    """The other reader, on the surface where attesting to a false verdict costs most."""

    import os
    import subprocess
    import sys

    report = _vulnerable()
    _flip_a_fail_to_pass(report)
    path = tmp_path / "evaluation-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    result = subprocess.run(  # noqa: S603 - fixed argv, shell=False
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "export-evidence",
            "--target",
            str(tmp_path),
            "--report",
            str(path),
            "--format",
            "sarif",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "COLUMNS": "200", "NO_COLOR": "1", "PYTHONIOENCODING": "utf-8"},
        check=False,
    )
    combined = " ".join(((result.stderr or "") + " " + (result.stdout or "")).split())

    assert result.returncode == 2, f"an edited report was exported anyway (exit {result.returncode}): {combined[:300]}"
    assert "digest" in combined


def test_the_export_evidence_reader_itself_refuses_a_tampered_report(tmp_path: Path) -> None:
    """In-process, because the subprocess case above is not measured by coverage.

    The subprocess test proves the exit code an operator sees. This one proves the branch
    that produces it, which is the part a later refactor can delete silently.
    """

    from oss_policy_kit.cli.export_evidence import _read_report

    report = _vulnerable()
    _flip_a_fail_to_pass(report)
    path = tmp_path / "evaluation-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(InvalidInputError, match="digest"):
        _read_report(path)


def test_the_export_evidence_reader_warns_on_a_report_it_cannot_check(tmp_path: Path, capsys: Any) -> None:
    """The other branch: exported, with the kit saying it did not check the verdicts."""

    from oss_policy_kit.cli.export_evidence import _read_report

    report = _vulnerable()
    del report["results_digest"]
    path = tmp_path / "evaluation-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    parsed = _read_report(path)

    assert parsed["controls"], "the report still loads; this is a warning, not a refusal"
    assert "results_digest" in " ".join(capsys.readouterr().err.split())


def test_the_export_evidence_reader_passes_a_report_that_verifies(tmp_path: Path, capsys: Any) -> None:
    """The third branch, and the one the other two are measured against.

    `_read_report` was exercised on a tampered report and on an unverifiable one, and
    never on a good one, so the arm that simply returns was unmeasured. A reader that
    only ever ran on bad input is not evidence that good input survives it.
    """

    from oss_policy_kit.cli.export_evidence import _read_report

    path = tmp_path / "evaluation-report.json"
    path.write_text(json.dumps(_vulnerable()), encoding="utf-8")

    parsed = _read_report(path)

    assert parsed["results_digest"] == _vulnerable()["results_digest"]
    assert capsys.readouterr().err == "", "a report that verifies must produce no warning"
