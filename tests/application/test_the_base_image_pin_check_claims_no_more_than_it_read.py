"""CONT-IMAGE-001 said "all base images are digest-pinned" about files it had not read.

Measured on the parent commit with `evaluate --profile github-level-3`, one Dockerfile per
target whose only base image is the unpinned `alpine:3.19`:

    FROM alpine:3.19            FAIL   correct
    from alpine:3.19            PASS   lowercase; Dockerfile keywords are case-insensitive
      FROM alpine:3.19          PASS   two spaces of indent, which Docker allows
    <tab>FROM alpine:3.19       PASS
    FrOm alpine:3.19            PASS
    (empty file)                PASS   nothing was read, so nothing was unpinned
    (binary file)               PASS
    (comments only, no FROM)    PASS
    (unreadable, ACL denied)    PASS
    26 Dockerfiles, 25 pinned   PASS   the cap reads 20; the 26th was the unpinned one

and the mirror, on a base image that IS pinned:

    FROM --platform=$BUILDPLATFORM alpine@sha256:...   FAIL   the flag was read as the image

Ten routes, one sentence. Unlike a control that crashes or refuses, this one answered, and the
answer was a positive claim about a security property nobody had checked.

The tests below are grouped by the three causes. The last group is the one that matters most:
`manual-review-required` trips no `--fail-on fail`, so a withdrawal that swallowed a real
finding would turn a red pipeline green, which `decode_source`'s docstring already records as
the larger mistake. It may replace a PASS and nothing else.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import supply_chain as sc
from oss_policy_kit.application.evaluators_common import (
    DOCKERFILE_SCAN_LIMIT,
    find_dockerfiles_capped,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

PINNED = "alpine@sha256:" + "a" * 64
UNPINNED = "alpine:3.19"


def _ctx(tmp_path: Path) -> sc.EvalContext:
    return sc.EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(workflow_paths=[]),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _dockerfile(tmp_path: Path, body: str, *, rel: str = "Dockerfile") -> Path:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _deny_read(monkeypatch: pytest.MonkeyPatch, target: Path) -> None:
    """Make exactly one file raise on read, leaving every other read alone.

    Patching `Path.read_bytes` rather than the filesystem keeps the test identical on every
    platform. The property under test is "an OSError on this read does not become a PASS", and
    which OS produces the error is not part of it. `read_bytes` and not `read_text`, because
    that is what the evaluator calls -- it decodes itself, so that UTF-16 Dockerfiles keep
    working.
    """

    real = Path.read_bytes

    def refuse(self: Path) -> bytes:
        if self == target:
            raise PermissionError(13, "Permission denied")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", refuse)


# --- Cause 1: spellings Docker accepts and the pattern did not -------------------------------

#: Every one of these is a Dockerfile `docker build` accepts, with one unpinned base image.
SPELLINGS = [
    ("uppercase at column 0", f"FROM {UNPINNED}\n"),
    ("lowercase", f"from {UNPINNED}\n"),
    ("mixed case", f"FrOm {UNPINNED}\n"),
    ("two spaces of indent", f"  FROM {UNPINNED}\n"),
    ("tab indent", f"\tFROM {UNPINNED}\n"),
    ("CRLF line endings", f"FROM {UNPINNED}\r\n"),
    ("after a comment", f"# base\nfrom {UNPINNED}\n"),
    ("second stage only", f"FROM {PINNED} AS build\nfrom {UNPINNED}\n"),
]


@pytest.mark.parametrize(("label", "body"), SPELLINGS, ids=[s[0] for s in SPELLINGS])
def test_an_unpinned_base_image_is_found_however_the_line_is_spelled(label: str, body: str, tmp_path: Path) -> None:
    """All eight are the same repository as far as Docker is concerned."""

    _dockerfile(tmp_path, body)

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.FAIL, f"{label} was read as having no unpinned image"


def test_a_pinned_multi_arch_build_is_not_failed_for_its_platform_flag(tmp_path: Path) -> None:
    """The mirror defect. `--platform` was captured as the image, and a flag has no digest."""

    _dockerfile(tmp_path, f"FROM --platform=$BUILDPLATFORM {PINNED}\n")

    assert sc.eval_cont_image_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_the_failure_names_the_image_rather_than_the_flag(tmp_path: Path) -> None:
    """A right verdict with a wrong reason sends the reader to fix the wrong thing."""

    _dockerfile(tmp_path, f"FROM --platform=linux/amd64 {UNPINNED}\n")

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.FAIL
    assert UNPINNED in outcome.reason
    assert "--platform" not in outcome.reason


def test_scratch_keeps_its_exemption_when_it_carries_a_stage_alias(tmp_path: Path) -> None:
    """`FROM scratch` cannot be digest-pinned; there is nothing to pin.

    This is why the capture stays at the first token rather than the whole line, which is what
    the sibling pattern in `evaluators_containers.py` captures. Copying that one wholesale would
    have compared `scratch AS base` against `scratch` and failed a repository for using the
    empty image.
    """

    _dockerfile(tmp_path, "FROM scratch AS base\nCOPY x /x\n")

    assert sc.eval_cont_image_001(_ctx(tmp_path)).status == ControlStatus.PASS


# --- Cause 2: files that back no claim either way --------------------------------------------

#: Each is a file discovery accepts and that yields no base image at all.
NOTHING_READABLE = [
    ("empty", b""),
    ("comments and ARG only", b"# just a note\nARG BASE\n"),
    ("binary", bytes(range(256)) * 8),
]


@pytest.mark.parametrize(("label", "raw"), NOTHING_READABLE, ids=[n[0] for n in NOTHING_READABLE])
def test_a_file_holding_no_base_image_withdraws_the_verdict(label: str, raw: bytes, tmp_path: Path) -> None:
    """ "I found no unpinned image" and "every image is pinned" are the same sentence only
    when something was actually read."""

    (tmp_path / "Dockerfile").write_bytes(raw)

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED, f"{label} produced a claim"


def test_a_dockerfile_that_cannot_be_read_withdraws_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`contextlib.suppress(OSError)` turned an unreadable file into an absent one."""

    target = _dockerfile(tmp_path, f"FROM {UNPINNED}\n")
    _deny_read(monkeypatch, target)

    assert sc.eval_cont_image_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_the_withdrawal_names_the_file_without_leaking_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`str(OSError)` carries the absolute filename, which is how an account name reaches a
    shareable report (M-002). This assertion is what blocks a change back to it."""

    target = _dockerfile(tmp_path, f"FROM {UNPINNED}\n")
    _deny_read(monkeypatch, target)

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    # Without this line the rest passes on the parent commit for the wrong reason: its PASS
    # message names no path either, so the three assertions below hold over a sentence that
    # should never have been emitted.
    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "Dockerfile" in outcome.reason
    assert str(tmp_path) not in outcome.reason
    assert os.sep not in outcome.reason


def test_the_discovery_cap_withdraws_rather_than_claiming_the_files_it_skipped(tmp_path: Path) -> None:
    """One more Dockerfile than the cap reads, every one of them pinned.

    The verdict is still wrong even when the unread files turn out to be fine, because the
    sentence is about all of them and only some were read.
    """

    for index in range(DOCKERFILE_SCAN_LIMIT + 1):
        _dockerfile(tmp_path, f"FROM {PINNED}\n", rel=f"svc{index:03d}/Dockerfile")

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert str(DOCKERFILE_SCAN_LIMIT) in outcome.reason


def test_find_dockerfiles_capped_reports_whether_the_cap_stopped_the_search(tmp_path: Path) -> None:
    """The discovery half, in isolation: exactly at the cap is not truncation."""

    for index in range(DOCKERFILE_SCAN_LIMIT):
        _dockerfile(tmp_path, "FROM x\n", rel=f"svc{index:03d}/Dockerfile")
    found, truncated = find_dockerfiles_capped(tmp_path)
    assert len(found) == DOCKERFILE_SCAN_LIMIT
    assert truncated is False

    _dockerfile(tmp_path, "FROM x\n", rel="one-more/Dockerfile")
    found, truncated = find_dockerfiles_capped(tmp_path)
    assert len(found) == DOCKERFILE_SCAN_LIMIT
    assert truncated is True


# --- Cause 3: the order of the two answers ----------------------------------------------------


def test_an_unpinned_image_still_fails_when_a_sibling_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The invariant that keeps this fix from being worse than the defect.

    `manual-review-required` satisfies `--fail-on fail`. If the withdrawal were ordered ahead of
    the finding, one unreadable file anywhere in the repository would clear a genuinely unpinned
    base image out of a pipeline that was correctly red. A withdrawal may replace a PASS and
    nothing else.
    """

    _dockerfile(tmp_path, f"FROM {UNPINNED}\n", rel="app/Dockerfile")
    unreadable = _dockerfile(tmp_path, f"FROM {PINNED}\n", rel="other/Dockerfile")
    _deny_read(monkeypatch, unreadable)

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.FAIL
    assert UNPINNED in outcome.reason


def test_a_repository_whose_images_are_all_pinned_still_passes(tmp_path: Path) -> None:
    """The other direction, and the reason this test exists rather than being obvious.

    An earlier guard of this class withdrew too widely and turned 16 of 16 Kubernetes controls
    UNKNOWN on this repository. Withdrawing everywhere is not caution, it is a different wrong
    answer, and PASS here is a true statement about these files.
    """

    _dockerfile(tmp_path, f"FROM {PINNED} AS build\nFROM {PINNED} AS runtime\n")
    _dockerfile(tmp_path, f"FROM --platform=$TARGETPLATFORM {PINNED}\n", rel="edge/Dockerfile")

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.PASS


def test_a_repository_with_no_dockerfile_is_still_not_applicable(tmp_path: Path) -> None:
    """The baseline the three withdrawal tests above would otherwise also satisfy."""

    assert sc.eval_cont_image_001(_ctx(tmp_path)).status == ControlStatus.NOT_APPLICABLE


# --- The sibling: CONT-IMAGE-002 read the same files through the same suppressed error --------
#
# Sweeping the siblings is what found it. Measured on a repository whose only Dockerfile says
# `USER root`, with the read denied:
#
#     CONT-IMAGE-001   FAIL -> manual-review-required
#     CONT-IMAGE-002   FAIL -> PASS   "... (4 file(s) checked)"
#     CONT-IMAGE-003   FAIL -> FAIL   reads CI config, not Dockerfile contents
#
# Its two patterns already carry IGNORECASE and an indent allowance, so only the unreadable
# file and the discovery cap apply here.


def test_a_root_user_is_not_cleared_by_the_file_being_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worst shape of the sibling defect: PASS over a file that says `USER root`."""

    target = _dockerfile(tmp_path, f"FROM {PINNED}\nUSER root\n")
    _deny_read(monkeypatch, target)

    assert sc.eval_cont_image_002(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_the_user_check_does_not_count_files_it_could_not_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Its PASS sentence ends "(N file(s) checked)", and N counted the unread ones too."""

    _dockerfile(tmp_path, f"FROM {PINNED}\nUSER app\n", rel="app/Dockerfile")
    unreadable = _dockerfile(tmp_path, f"FROM {PINNED}\nUSER app\n", rel="other/Dockerfile")
    _deny_read(monkeypatch, unreadable)

    outcome = sc.eval_cont_image_002(_ctx(tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "2 file(s) checked" not in outcome.reason


def test_the_user_check_withdraws_when_the_cap_hid_files(tmp_path: Path) -> None:
    """Same cap, same class: a claim about every Dockerfile over 20 of 21."""

    for index in range(DOCKERFILE_SCAN_LIMIT + 1):
        _dockerfile(tmp_path, f"FROM {PINNED}\nUSER app\n", rel=f"svc{index:03d}/Dockerfile")

    assert sc.eval_cont_image_002(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_a_root_user_still_fails_when_a_sibling_cannot_be_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ordering invariant again, for the second control that now has a withdrawal."""

    _dockerfile(tmp_path, f"FROM {PINNED}\nUSER root\n", rel="app/Dockerfile")
    unreadable = _dockerfile(tmp_path, f"FROM {PINNED}\nUSER app\n", rel="other/Dockerfile")
    _deny_read(monkeypatch, unreadable)

    assert sc.eval_cont_image_002(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_a_dockerfile_missing_a_user_still_fails_when_a_sibling_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other failure branch of the same control, under the same condition."""

    _dockerfile(tmp_path, f"FROM {PINNED}\nRUN echo hi\n", rel="app/Dockerfile")
    unreadable = _dockerfile(tmp_path, f"FROM {PINNED}\nUSER app\n", rel="other/Dockerfile")
    _deny_read(monkeypatch, unreadable)

    assert sc.eval_cont_image_002(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_a_repository_whose_dockerfiles_all_declare_a_user_still_passes(tmp_path: Path) -> None:
    """The over-withdrawal guard for the sibling."""

    _dockerfile(tmp_path, f"FROM {PINNED}\nUSER app\n", rel="app/Dockerfile")
    _dockerfile(tmp_path, f"FROM {PINNED}\nUSER 1001\n", rel="edge/Dockerfile")

    outcome = sc.eval_cont_image_002(_ctx(tmp_path))

    assert outcome.status == ControlStatus.PASS
    assert "2 file(s) checked" in outcome.reason


# --- Completing the sweep: the third control in the class ------------------------------------
#
# Seven more controls read Dockerfile contents, in `evaluators_containers.py` through a reader
# that returns "" on a failed read. Six of them fail when they find no signal, so "" leaves
# them restrictive. CONT-RUNTIME-003 passes when it finds no signal. Measured with a Dockerfile
# that fails all of them, then with its read denied:
#
#     CONT-RUNTIME-001/002/004   FAIL -> FAIL
#     CONT-RUNTIME-003           FAIL -> PASS   "No curl|bash / wget|sh pattern detected
#                                                across 1 Dockerfile(s)"
#     CONT-RUNTIME-005/006       not-applicable, both
#     CONT-SIGN-001              manual-review-required, both


def test_a_curl_into_shell_is_not_cleared_by_the_file_being_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PASS over a Dockerfile that was never opened, third and last of the class."""

    from oss_policy_kit.application import evaluators_containers as ec

    target = _dockerfile(tmp_path, f"FROM {PINNED}\nRUN curl http://x | sh\n")
    _deny_read(monkeypatch, target)

    assert ec.eval_cont_runtime_003(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_a_curl_into_shell_still_fails_when_a_sibling_cannot_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ordering invariant, for the third control."""

    from oss_policy_kit.application import evaluators_containers as ec

    _dockerfile(tmp_path, f"FROM {PINNED}\nRUN curl http://x | sh\n", rel="app/Dockerfile")
    unreadable = _dockerfile(tmp_path, f"FROM {PINNED}\nRUN echo hi\n", rel="other/Dockerfile")
    _deny_read(monkeypatch, unreadable)

    assert ec.eval_cont_runtime_003(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_a_clean_dockerfile_still_passes_the_curl_check(tmp_path: Path) -> None:
    """The over-withdrawal guard for the third control."""

    from oss_policy_kit.application import evaluators_containers as ec

    _dockerfile(tmp_path, f"FROM {PINNED}\nRUN apk add --no-cache git\n")

    assert ec.eval_cont_runtime_003(_ctx(tmp_path)).status == ControlStatus.PASS


def test_an_empty_dockerfile_is_not_confused_with_an_unreadable_one(tmp_path: Path) -> None:
    """The distinction the shared reader could not make.

    An empty Dockerfile has no curl-into-shell in it, and that is a true statement. Only the
    failed read is a gap, which is why the reader returns None rather than "" and the six
    controls that cannot be fooled by "" were left alone.
    """

    from oss_policy_kit.application import evaluators_containers as ec

    (tmp_path / "Dockerfile").write_bytes(b"")

    assert ec.eval_cont_runtime_003(_ctx(tmp_path)).status == ControlStatus.PASS


def test_the_gap_clause_says_and_more_past_three_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Four unreadable Dockerfiles: the clause samples three and says so."""

    targets = [_dockerfile(tmp_path, f"FROM {PINNED}\n", rel=f"svc{index}/Dockerfile") for index in range(4)]
    real = Path.read_bytes

    def refuse(self: Path) -> bytes:
        if self in targets:
            raise PermissionError(13, "Permission denied")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", refuse)

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "(and more)" in outcome.reason
