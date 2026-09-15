"""A workflow whose encoding this reader cannot honour is not a workflow without the thing.

``decode_source`` deduces UTF-16 and UTF-32 from where the padding NULs fall, and that stride
breaks on any character outside Latin-1. The file then falls through to the replacement read and
arrives as mojibake: nothing parses out of it and the raw scan finds no ``uses:``, so both roads
to a finding are closed at once. Every control that concludes from finding NOTHING then stated an
absence about a file nobody read.

Measured against the tree at v10.0.22, one workflow, one CJK character in a comment:

    CI-DANGER-007   FAIL -> PASS   "No pull_request_target detected in workflows."
    CI-PIN-008      FAIL -> PASS   "No obvious mutable third-party action pins detected."
    GH-RUNNER-062   MRR  -> PASS   "No self-hosted runners detected in workflows."

The GH-RUNNER-062 case reached the same false PASS through a *second* reader -- a direct
``read_text(encoding="utf-8", errors="replace")`` that never saw ``decode_source`` at all -- and
so failed on a workflow carrying a BOM too, which the other two always handled. Both roads are
covered here, because fixing one and leaving the other is how this class kept coming back.

The negative controls matter as much as the positives. A cp1252 byte in a comment also produces
a replacement character, and the structure around it survives: the ``uses:`` line is still there
and the control is still right. Withdrawing over that would repeat the over-withdrawal this
project already shipped once, which turned sixteen Kubernetes controls UNKNOWN on its own
repository.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators import _shared as sh
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.source_text import decode_source, decode_source_detail
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

#: A `pull_request_target` workflow pinned to `@main`: the pwn-request vector, mutable pin and
#: all. Two controls must FAIL on it and a third must see its runner.
DANGEROUS = (
    "name: danger\n"
    "# {comment}\n"
    "on:\n"
    "  pull_request_target:\n"
    "jobs:\n"
    "  b:\n"
    "    runs-on: [self-hosted, linux]\n"
    "    steps:\n"
    "      - uses: actions/checkout@main\n"
)

#: Outside Latin-1, so the UTF-16 NUL stride breaks on it. This is the whole trigger.
WIDE_COMMENT = "\u6f22\u5b57"
#: Inside Latin-1: the stride holds, and in cp1252 it is one byte the replacement read eats.
NARROW_COMMENT = "caf\u00e9 com a\u00e7ucar"


def _repo(tmp_path: Path, body: str, encoding: str) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_bytes(body.encode(encoding))
    return tmp_path


def _ctx(root: Path) -> sh.EvalContext:
    return sh.EvalContext(
        repo_root=root,
        profile_id="github-level-1",
        workflows=analyze_workflows(root),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


# --- the primitive ------------------------------------------------------------------------- #


def test_decode_source_detail_returns_exactly_what_decode_source_returns() -> None:
    """The detail view may add fields; it may never change the text. That is the invariant."""

    for data in (
        b"",
        b"name: x\n",
        "name: caf\u00e9\n".encode("cp1252"),
        "name: x\n".encode("utf-16"),
        "name: x\n".encode("utf-16-le"),
        f"name: x # {WIDE_COMMENT}\n".encode("utf-16-le"),
    ):
        assert decode_source_detail(data).text == decode_source(data)


def test_a_wide_file_this_reader_cannot_honour_says_so() -> None:
    read = decode_source_detail(f"name: x\n# {WIDE_COMMENT}\n".encode("utf-16-le"))

    assert read.wide_unhonoured is True
    assert read.used_codec is None


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"name: x\nuses: a@main\n", id="plain-utf-8"),
        pytest.param("name: x # caf\u00e9\n".encode("cp1252"), id="cp1252-in-a-comment"),
        pytest.param("name: x\n".encode("utf-16"), id="utf-16-with-a-bom"),
        pytest.param("name: x\n".encode("utf-16-le"), id="utf-16-no-bom-stride-holds"),
        pytest.param(b"", id="empty"),
    ],
)
def test_a_file_that_read_fine_is_never_flagged(data: bytes) -> None:
    """The flag is narrow on purpose: only a file whose own bytes announced a wide encoding."""

    assert decode_source_detail(data).wide_unhonoured is False


# --- the controls -------------------------------------------------------------------------- #


@pytest.mark.parametrize("control_id", ["CI-DANGER-007", "CI-PIN-008"])
@pytest.mark.parametrize(
    "encoding",
    ["utf-8", "utf-16", "utf-16-le", "utf-16-be"],
)
def test_a_dangerous_workflow_never_reads_as_a_clean_one(control_id: str, encoding: str, tmp_path: Path) -> None:
    """Whatever the encoding, the answer is never a clean verdict about this repository."""

    root = _repo(tmp_path, DANGEROUS.format(comment=WIDE_COMMENT), encoding)

    outcome = EVALUATOR_REGISTRY[control_id](_ctx(root))

    assert outcome.status in {ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED}, (
        f"{control_id} answered {outcome.status} over a pull_request_target workflow "
        f"written {encoding}: {outcome.reason}"
    )


#: Push-triggered, so GH-RUNNER-062 leaves the parsed-analysis branch and reaches
#: ``_self_hosted_workflow_paths`` -- the SECOND reader, which had no ``decode_source`` at all and
#: so failed on a BOM file the parser had always handled. A `pull_request_target` fixture never
#: exercises it, which is how this half stayed hidden behind a passing test.
SELF_HOSTED_ON_PUSH = (
    "name: build\n"
    "# {comment}\n"
    "on:\n"
    "  push:\n"
    "jobs:\n"
    "  b:\n"
    "    runs-on: [self-hosted, linux]\n"
    "    steps:\n"
    "      - run: echo hi\n"
)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
def test_gh_runner_062_never_reports_a_clean_runner_fleet(encoding: str, tmp_path: Path) -> None:
    """The second reader reached the same false PASS, and on a BOM file the others handled."""

    root = _repo(tmp_path, SELF_HOSTED_ON_PUSH.format(comment=WIDE_COMMENT), encoding)

    outcome = EVALUATOR_REGISTRY["GH-RUNNER-062"](_ctx(root))

    assert outcome.status is not ControlStatus.PASS, (
        f"GH-RUNNER-062 answered PASS over a push-triggered workflow declaring a self-hosted "
        f"runner written {encoding}: {outcome.reason}"
    )


def test_gh_runner_062_reads_a_wide_workflow_that_carries_a_bom(tmp_path: Path) -> None:
    """Honoured, not withdrawn: the verdict names the runner it found, as UTF-8 always did."""

    root = _repo(tmp_path, SELF_HOSTED_ON_PUSH.format(comment=WIDE_COMMENT), "utf-16")

    outcome = EVALUATOR_REGISTRY["GH-RUNNER-062"](_ctx(root))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "Self-hosted runners detected" in outcome.reason


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_a_workflow_it_can_decode_is_judged_on_its_content(encoding: str, tmp_path: Path) -> None:
    """Not withdrawn, not excused: read, and failed. A BOM is all UTF-16 needs to be honoured."""

    root = _repo(tmp_path, DANGEROUS.format(comment=WIDE_COMMENT), encoding)
    ctx = _ctx(root)

    assert EVALUATOR_REGISTRY["CI-DANGER-007"](ctx).status is ControlStatus.FAIL
    assert EVALUATOR_REGISTRY["CI-PIN-008"](ctx).status is ControlStatus.FAIL
    assert "self-hosted" in EVALUATOR_REGISTRY["GH-RUNNER-062"](ctx).reason.lower()


@pytest.mark.parametrize("control_id", ["CI-DANGER-007", "CI-PIN-008"])
def test_one_accented_byte_does_not_withdraw_a_verdict(control_id: str, tmp_path: Path) -> None:
    """The over-withdrawal guard. A cp1252 comment loses one character, never the structure."""

    root = _repo(tmp_path, DANGEROUS.format(comment=NARROW_COMMENT), "cp1252")

    outcome = EVALUATOR_REGISTRY[control_id](_ctx(root))

    assert outcome.status is ControlStatus.FAIL, (
        f"{control_id} withdrew over one accented byte in a comment: {outcome.reason}"
    )


def test_the_withdrawal_names_the_file_it_could_not_read(tmp_path: Path) -> None:
    """An operator has to be able to act on this, so the message names the file and the fix."""

    root = _repo(tmp_path, SELF_HOSTED_ON_PUSH.format(comment=WIDE_COMMENT), "utf-16-le")

    outcome = EVALUATOR_REGISTRY["GH-RUNNER-062"](_ctx(root))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "ci.yml" in outcome.reason
    assert "byte-order mark" in outcome.remediation
