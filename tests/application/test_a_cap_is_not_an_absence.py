"""Past the 20-file cap, two container controls said "not applicable" about apt they never saw.

Measured against the built wheel, on 25 Dockerfiles where only the 25th runs
`RUN apt-get install -y curl`:

    CONT-IMAGE-001     UNKNOWN         ...the repository holds more Dockerfiles than were read
    CONT-IMAGE-002     UNKNOWN         ...same
    CONT-RUNTIME-003   UNKNOWN         ...same
    CONT-RUNTIME-005   NOT_APPLICABLE  "No apt-get install lines detected in any Dockerfile."
    CONT-RUNTIME-006   NOT_APPLICABLE  "No apt/apk install lines detected; nothing to pin."
    CONT-RUNTIME-001   FAIL            "No multi-stage Dockerfile found (single-stage: ...)"
    CONT-RUNTIME-002   FAIL            "No HEALTHCHECK declared in any Dockerfile (...)"

`_find_dockerfiles_capped` exists for exactly this, and its docstring said only
CONT-RUNTIME-003 needed it, because "the other controls here pass on finding one good file, so
a truncated list can only make them report a failure they would not otherwise report".

That is true of CONT-RUNTIME-001 and CONT-RUNTIME-002. It is not true of 005 and 006, which
answer on ABSENCE: no apt line found means `not-applicable`, which is a positive claim about
the repository and the one state no summary counts. What sorts this family is the direction of
the answer, not the control number, and two controls were on the wrong side of it.

The two FAILs keep their verdicts. `manual-review-required` trips no `--fail-on fail`, so
withdrawing there would clear a real gap out of a pipeline that was correctly red. They state
their scope instead.

The other half of the same blocker, a stage name read as an image, is in
`test_a_stage_name_is_not_an_image.py`.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application import evaluators_containers as ec
from oss_policy_kit.application.evaluators_common import DOCKERFILE_SCAN_LIMIT
from oss_policy_kit.domain.models import ControlStatus

#: Twenty of these fill the cap. None of them installs anything, declares a HEALTHCHECK, or
#: builds in stages, so each control reaches its absence answer honestly over what it read.
FILLER = "FROM alpine:3.19@sha256:" + "ab" * 32 + "\nUSER app\n"

#: The file past the cap. It is the only one that would change any of the four answers.
HIDDEN = (
    "FROM ubuntu:22.04@sha256:" + "cd" * 32 + " AS build\n"
    "RUN apt-get install -y curl\n"
    "\n"
    "FROM ubuntu:22.04@sha256:" + "cd" * 32 + " AS runtime\n"
    "HEALTHCHECK CMD /bin/true\n"
    "USER app\n"
)


def _repo(tmp_path: Path, *, count: int) -> Path:
    """A repository with *count* Dockerfiles, the last one sorting after every other."""

    for n in range(count - 1):
        d = tmp_path / f"svc{n:03d}"
        d.mkdir()
        (d / "Dockerfile").write_text(FILLER, encoding="utf-8")
    last = tmp_path / "zzz-last"
    last.mkdir()
    (last / "Dockerfile").write_text(HIDDEN, encoding="utf-8")
    return tmp_path


def _ctx(root: Path) -> SimpleNamespace:
    return SimpleNamespace(repo_root=root)


#: (evaluator, what it answers when the cap hides the deciding file).
#:
#: The two `not-applicable` answers are the defect. The two FAILs are deliberately unchanged:
#: withdrawing a failure would take it out of `--fail-on fail`.
PAST_THE_CAP = {
    "CONT-RUNTIME-001": (ec.eval_cont_runtime_001, ControlStatus.FAIL),
    "CONT-RUNTIME-002": (ec.eval_cont_runtime_002, ControlStatus.FAIL),
    "CONT-RUNTIME-005": (ec.eval_cont_runtime_005, ControlStatus.MANUAL_REVIEW_REQUIRED),
    "CONT-RUNTIME-006": (ec.eval_cont_runtime_006, ControlStatus.MANUAL_REVIEW_REQUIRED),
}


@pytest.mark.parametrize("control_id", sorted(PAST_THE_CAP))
def test_no_control_claims_absence_over_a_file_the_cap_hid(control_id: str, tmp_path: Path) -> None:
    evaluator, expected = PAST_THE_CAP[control_id]

    outcome = evaluator(_ctx(_repo(tmp_path, count=DOCKERFILE_SCAN_LIMIT + 5)))

    assert outcome.status == expected, outcome.reason


@pytest.mark.parametrize("control_id", sorted(PAST_THE_CAP))
def test_every_answer_past_the_cap_says_it_is_partial(control_id: str, tmp_path: Path) -> None:
    """A FAIL that keeps its verdict still has to stop claiming it looked everywhere."""

    evaluator, _ = PAST_THE_CAP[control_id]

    reason = evaluator(_ctx(_repo(tmp_path, count=DOCKERFILE_SCAN_LIMIT + 5))).reason

    assert str(DOCKERFILE_SCAN_LIMIT) in reason, reason
    assert "were read" in reason, reason


@pytest.mark.parametrize("control_id", sorted(PAST_THE_CAP))
def test_a_repository_inside_the_cap_is_untouched(control_id: str, tmp_path: Path) -> None:
    """The ordinary target, which is every target. Nothing here may change for it.

    The same twenty files, minus the twenty-first. `not-applicable` is the right answer about a
    repository that genuinely installs nothing, and this guard must not take it away.
    """

    evaluator, _ = PAST_THE_CAP[control_id]
    for n in range(DOCKERFILE_SCAN_LIMIT - 1):
        d = tmp_path / f"svc{n:03d}"
        d.mkdir()
        (d / "Dockerfile").write_text(FILLER, encoding="utf-8")

    outcome = evaluator(_ctx(tmp_path))

    assert outcome.status != ControlStatus.MANUAL_REVIEW_REQUIRED, outcome.reason
    assert str(DOCKERFILE_SCAN_LIMIT) not in outcome.reason, "an untruncated scan must not mention the cap"


def test_an_offender_inside_the_cap_still_fails_even_though_files_were_hidden(tmp_path: Path) -> None:
    """The ordering invariant, at the one place it could have been broken here.

    A withdrawal may replace `not-applicable` and never a FAIL. If an unpinned install line is
    visible in the first twenty files, the control has an answer and must give it: replacing
    that with `manual-review-required` would clear a real finding out of a red pipeline.
    """

    root = _repo(tmp_path, count=DOCKERFILE_SCAN_LIMIT + 5)
    (root / "svc000" / "Dockerfile").write_text("FROM ubuntu:22.04\nRUN apt-get install -y curl\n", encoding="utf-8")

    assert ec.eval_cont_runtime_005(_ctx(root)).status == ControlStatus.FAIL
    assert ec.eval_cont_runtime_006(_ctx(root)).status == ControlStatus.FAIL


def test_a_good_file_inside_the_cap_still_passes(tmp_path: Path) -> None:
    """And the same in the other direction, for the two that conclude from finding a signal."""

    root = _repo(tmp_path, count=DOCKERFILE_SCAN_LIMIT + 5)
    (root / "svc000" / "Dockerfile").write_text(
        "FROM alpine:3.19 AS build\nFROM alpine:3.19 AS run\nHEALTHCHECK CMD /bin/true\n",
        encoding="utf-8",
    )

    assert ec.eval_cont_runtime_001(_ctx(root)).status == ControlStatus.PASS
    assert ec.eval_cont_runtime_002(_ctx(root)).status == ControlStatus.PASS


def test_the_withdrawal_points_at_the_escape_hatch(tmp_path: Path) -> None:
    """ADR-045: this state is not a verdict, and an operator has to be able to gate on it."""

    outcome = ec.eval_cont_runtime_005(_ctx(_repo(tmp_path, count=DOCKERFILE_SCAN_LIMIT + 5)))

    assert "--fail-on degraded" in outcome.remediation


def test_the_fixture_would_change_every_answer_if_it_were_read(tmp_path: Path) -> None:
    """The control leg. Without it, "the cap hid it" could mean the file was harmless.

    Same file, in a repository small enough to be read whole: an apt install without cleanup,
    an unpinned package, a HEALTHCHECK and two stages. Each of the four controls answers
    differently than it does when the cap hides it.
    """

    (tmp_path / "Dockerfile").write_text(HIDDEN, encoding="utf-8")
    ctx = _ctx(tmp_path)

    assert ec.eval_cont_runtime_001(ctx).status == ControlStatus.PASS
    assert ec.eval_cont_runtime_002(ctx).status == ControlStatus.PASS
    assert ec.eval_cont_runtime_005(ctx).status == ControlStatus.FAIL
    assert ec.eval_cont_runtime_006(ctx).status == ControlStatus.FAIL
