"""A webhook scan that stopped at its file cap may not report that the repository has none.

The eight `SEC-WEBHOOK-*` controls read source files through one walk that stops at
`_SCAN_FILE_LIMIT` (400). The walk did not tell anyone it had stopped, so `has_route=False`
meant two different things -- "read everything, found no webhook" and "stopped early, none
so far" -- and every one of those controls turned the second into the first:

    status     : not-applicable
    confidence : high
    reason     : No webhook route or handler detected in repository; control is not applicable.

for a repository that does contain `@app.post('/webhook')`. Reproduced end to end through
the CLI on a synthetic repo of 451 files: exit 0, `not-applicable=3`, zero operational
warnings. `not-applicable` is a positive claim about the target, and this one was false.

Not a regression from the ordering work in v10.0.19: `a2e9f63` (v10.0.18) behaves
identically, checked in a worktree. Sorting only made the miss deterministic rather than
dependent on filesystem order.

`manual-review-required` is the honest answer for a truncated scan: the kit cannot
establish applicability, so it must not assert it either way.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application import evaluators_webhook as wh
from oss_policy_kit.cli.main import app

runner = CliRunner()

#: One more scannable file than the walk will look at, so the walk must stop.
_OVER_CAP = wh._SCAN_FILE_LIMIT + 50

#: Sorts after the filler, so a sorted walk reaches the filler first and stops before it.
_SIGNAL_DIR = "zz_api"


@pytest.fixture
def repo_with_a_late_webhook(tmp_path: Path) -> Path:
    """A real webhook route, placed behind more files than the scan will read."""

    repo = tmp_path / "repo"
    filler = repo / "app_core"
    filler.mkdir(parents=True)
    for i in range(_OVER_CAP):
        (filler / f"m{i:05d}.py").write_text("x = 1\n", encoding="utf-8")

    late = repo / _SIGNAL_DIR
    late.mkdir()
    (late / "handler.py").write_text(
        "@app.post('/webhook')\ndef handle():\n    verify_signature(request)\n",
        encoding="utf-8",
    )
    return repo


def test_the_walk_reports_that_it_stopped(repo_with_a_late_webhook: Path) -> None:
    """The mechanism, asserted at its source: a truncated walk must be observable."""

    walk = wh._collect_candidate_paths(repo_with_a_late_webhook)

    assert walk.truncated, (
        f"the walk read {len(walk.paths)} files out of more than {_OVER_CAP} and reported "
        "no truncation. Every caller then cannot tell 'read everything' from 'stopped early'."
    )
    assert len(walk.paths) == wh._SCAN_FILE_LIMIT


def test_a_complete_walk_does_not_claim_truncation(tmp_path: Path) -> None:
    """The other half. A flag that is always true would make the honest answer unreachable."""

    repo = tmp_path / "small"
    repo.mkdir()
    (repo / "app.py").write_text("@app.post('/webhook')\ndef h():\n    pass\n", encoding="utf-8")

    walk = wh._collect_candidate_paths(repo)

    assert not walk.truncated
    assert [p.name for p in walk.paths] == ["app.py"]


@pytest.mark.parametrize(
    "evaluator",
    [
        wh.eval_sec_webhook_001,
        wh.eval_sec_webhook_002,
        wh.eval_sec_webhook_hmac_001,
        wh.eval_sec_webhook_timing_002,
        wh.eval_sec_webhook_replay_003,
        wh.eval_sec_webhook_body_004,
        wh.eval_sec_webhook_idemp_005,
        wh.eval_sec_webhook_rotate_006,
    ],
    ids=lambda e: e.__name__,
)
def test_no_webhook_control_claims_absence_after_a_truncated_scan(
    evaluator: object, repo_with_a_late_webhook: Path
) -> None:
    """All eight controls of the module share the one walk, so all eight share the defect."""

    class _Ctx:
        repo_root = repo_with_a_late_webhook

    outcome = evaluator(_Ctx())  # type: ignore[operator]

    assert outcome.status.value != "not-applicable", (
        f"{evaluator.__name__} answered not-applicable for a repository that does contain a "  # type: ignore[attr-defined]
        f"webhook route. The scan stopped at {wh._SCAN_FILE_LIMIT} files; 'not applicable' is a "
        f"claim about the target, and this one is false. Reason given: {outcome.reason!r}"
    )
    assert outcome.status.value == "manual-review-required"
    assert "truncat" in outcome.reason.lower() or "limit" in outcome.reason.lower(), (
        f"the reason does not say the scan was cut short: {outcome.reason!r}"
    )


def test_the_report_written_by_the_cli_says_the_scan_was_truncated(
    repo_with_a_late_webhook: Path, tmp_path: Path
) -> None:
    """End to end, because a helper passing is not the contract the operator reads."""

    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(repo_with_a_late_webhook),
            "--profile",
            "webhook-security-1",
            "--output-dir",
            str(out),
        ],
    )
    assert result.exit_code in (0, 1), result.output[-400:]

    report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    webhook = [c for c in report["controls"] if c["id"].startswith("SEC-WEBHOOK")]
    assert webhook, "the profile produced no webhook controls, so this test proves nothing"

    for control in webhook:
        assert control["state"] != "NOT_APPLICABLE", (
            f"{control['id']} reached the operator's report as NOT_APPLICABLE for a repository "
            f"that has a webhook route: {control['message']!r}"
        )
