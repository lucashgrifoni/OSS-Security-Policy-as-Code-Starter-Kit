"""Drift must read ``reports/2.0`` — the only contract since v9.0.0 (ADR-043).

Found by end-user validation on 2026-08-05: ``diff-reports`` computed an empty drift for
every report the kit itself produces, so its default CI regression gate could never fire.
A pull request deleting ``SECURITY.md``, ``LICENSE`` and ``CODEOWNERS`` took a repository
from 14/14 PASS to 4 FAIL and the gate still exited 0 with "no status changes".

The cause was that :mod:`oss_policy_kit.application.drift` read the ``reports/1.0`` shape —
``results[]`` with ``control_id``/``status`` in lowercase — while ``reports/2.0`` emits
``controls[]`` with ``id``/``state`` in uppercase. The whole of ``tests/unit/test_drift.py``
was written against that removed shape, which is why a green suite never caught it.

Every test here builds the shape the kit actually writes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.drift import compute_drift, load_report_json
from oss_policy_kit.application.reporting import digest_for_report_payload
from oss_policy_kit.domain.errors import InvalidInputError

CONTRACT = "reports/2.0"


def _control(cid: str, state: str, title: str = "t", waiver: dict | None = None) -> dict:
    """One ``controls[]`` entry exactly as ``reports/2.0`` emits it."""

    return {
        "id": cid,
        "title": title,
        "category": "governance",
        "lifecycle": "stable",
        "profile": "github-level-1",
        "state": state,
        "assurance": "deterministic",
        "confidence": "high",
        "weight": 3,
        "message": "m",
        "remediation": "r",
        "evidence": {"source_type": "static_clone"},
        "owner": None,
        "expires_at": None,
        "waiver": waiver,
        "extra": {},
        "finding_id": f"{cid}@github-level-1",
    }


def _report(controls: list[dict], *, profile: str = "github-level-1", kit: str = "10.0.5") -> dict:
    payload = {
        "schema_version": ("https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0"),
        "contract_version": CONTRACT,
        "generated_at": "2026-08-05T00:00:00Z",
        "kit_version": kit,
        "target_path": "repo",
        "profile": {"id": profile, "title": "p"},
        "summary_by_status": {},
        "controls_total": len(controls),
        "controls": controls,
    }
    # The digest has to be the one these controls actually imply: since v10.0.25 the
    # loader recomputes it, and a placeholder reads as a report somebody edited.
    payload["results_digest"] = digest_for_report_payload(payload)[0] or ""
    return payload


# --- the defect itself ----------------------------------------------------------------


def test_pass_to_fail_is_a_regression() -> None:
    """The exact shape the kit writes must produce a regression, not an empty diff."""

    before = _report([_control("GOV-SEC-001", "PASS")])
    after = _report([_control("GOV-SEC-001", "FAIL")])

    d = compute_drift(before, after)

    assert d.has_regressions, "a PASS->FAIL on reports/2.0 must trip the gate"
    assert [r.control_id for r in d.regressions] == ["GOV-SEC-001"]
    assert d.regressions[0].before_status == "PASS"
    assert d.regressions[0].after_status == "FAIL"


def test_the_real_world_scenario_that_slipped_through() -> None:
    """Deleting SECURITY.md, LICENSE and CODEOWNERS must not pass the drift gate."""

    intact = _report(
        [
            _control("GOV-SEC-001", "PASS", "SECURITY.md present"),
            _control("GOV-LIC-004", "PASS", "LICENSE present"),
            _control("GOV-COWN-003", "PASS", "CODEOWNERS present"),
            _control("CI-WF-005", "PASS", "workflow present"),
        ]
    )
    after_bad_pr = _report(
        [
            _control("GOV-SEC-001", "FAIL", "SECURITY.md present"),
            _control("GOV-LIC-004", "FAIL", "LICENSE present"),
            _control("GOV-COWN-003", "FAIL", "CODEOWNERS present"),
            _control("CI-WF-005", "PASS", "workflow present"),
        ]
    )

    d = compute_drift(intact, after_bad_pr)

    assert d.has_regressions
    assert len(d.regressions) == 3


def test_fail_to_pass_is_an_improvement() -> None:
    d = compute_drift(_report([_control("X", "FAIL")]), _report([_control("X", "PASS")]))
    assert len(d.improvements) == 1
    assert not d.has_regressions


@pytest.mark.parametrize("positive", ["PASS", "ATTESTED", "SELF_ATTESTED"])
def test_every_positive_state_regresses_to_fail(positive: str) -> None:
    """ATTESTED and SELF_ATTESTED are earned states; losing them is a regression."""

    d = compute_drift(_report([_control("X", positive)]), _report([_control("X", "FAIL")]))
    assert d.has_regressions, f"{positive} -> FAIL must be a regression"


@pytest.mark.parametrize("neutral", ["UNKNOWN", "NOT_APPLICABLE"])
def test_neutral_states_are_not_regressions(neutral: str) -> None:
    """UNKNOWN means "could not determine", not "failed" — it must not trip the gate.

    Pinned deliberately: widening this would turn every flaky evidence read into a
    build break, which is the failure mode that makes teams disable the gate.
    """

    d = compute_drift(_report([_control("X", "PASS")]), _report([_control("X", neutral)]))
    assert not d.has_regressions


def test_new_and_removed_controls_are_listed() -> None:
    d = compute_drift(
        _report([_control("A", "PASS")]),
        _report([_control("A", "PASS"), _control("B", "PASS")]),
    )
    assert d.new_controls == ["B"]

    d2 = compute_drift(
        _report([_control("A", "PASS"), _control("B", "PASS")]),
        _report([_control("A", "PASS")]),
    )
    assert d2.removed_controls == ["B"]


def test_dropped_waiver_is_reported_as_expired() -> None:
    waived = _control("W", "PASS", waiver={"control_id": "W", "owner": "o", "status": "active"})
    d = compute_drift(_report([waived]), _report([_control("W", "PASS")]))
    assert "W" in d.expired_waivers


def test_profile_id_still_read_from_2_0_nested_shape() -> None:
    d = compute_drift(
        _report([_control("A", "PASS")], profile="github-level-1"),
        _report([_control("A", "PASS")], profile="github-level-3"),
    )
    assert d.profile_mismatch is True
    assert d.before_profile_id == "github-level-1"
    assert d.after_profile_id == "github-level-3"


# --- the load boundary must not accept a removed contract ------------------------------


def test_load_rejects_a_removed_contract_instead_of_diffing_nothing(tmp_path: Path) -> None:
    """A pre-2.0 report must fail loudly. Silently diffing nothing is how this hid."""

    legacy = tmp_path / "legacy.json"
    legacy.write_text(
        json.dumps(
            {
                "contract_version": "reports/1.0",
                "kit_version": "8.0.0",
                "results": [{"control_id": "A", "status": "pass", "title": "t"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidInputError) as exc:
        load_report_json(legacy)

    assert "2.0" in str(exc.value)


def test_load_rejects_a_report_with_no_contract_marker(tmp_path: Path) -> None:
    p = tmp_path / "bare.json"
    p.write_text(json.dumps({"kit_version": "9", "controls": []}), encoding="utf-8")

    with pytest.raises(InvalidInputError):
        load_report_json(p)


def test_load_accepts_a_real_2_0_report(tmp_path: Path) -> None:
    p = tmp_path / "ok.json"
    p.write_text(json.dumps(_report([_control("A", "PASS")])), encoding="utf-8")

    loaded = load_report_json(p)

    assert loaded["contract_version"] == CONTRACT
    assert loaded["_path"] == str(p.resolve())
