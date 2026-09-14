"""Three container defects, two of them sharing one root: there were two discovery functions.

All three measured against the built wheel in a clean room.

ONE. A repository whose only build file is named `Containerfile`, declaring `FROM alpine:3.19`,
`USER root` and `RUN curl http://x | sh`:

    container-baseline-1 -> 10 controls "No Dockerfile detected", confidence high
    --fail-on fail -> exit 0

`high` on a positive claim that is false, and a green gate over three real findings. The control
catalogue declares `**/Containerfile` and `**/Containerfile.*` as applicability triggers for
those very controls; discovery globbed only the Dockerfile spellings. `Containerfile` is what
Podman and Buildah write by default, so this is not an exotic repository.

TWO. In the same report `CONT-DISTROLESS-001` read the file, because it had a private discovery
function that knew about `Containerfile`. Two functions for one job is how they drifted, and the
private one was narrower in the other direction -- root `Dockerfile`/`Containerfile` plus nested
`**/Dockerfile` only. So it missed `Dockerfile.svc01`, `api.Dockerfile` and every nested
`Containerfile`, and claimed "No Dockerfile / Containerfile detected" at confidence high about a
repository full of them.

THREE. `CONT-DISTROLESS-001` computed `final_from = from_lines[-1]` and then decided with
`any(marker in line for line in from_lines)` -- any stage, not the final one. A throwaway
`FROM scratch` build stage passed a build whose runtime image is `alpine:3.19`. The value it
needed was already in a local variable the decision ignored.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import supply_chain as sc
from oss_policy_kit.application.evaluators_common import find_dockerfiles
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

PIN = "alpine@sha256:" + "a" * 64


def _ctx(tmp_path: Path) -> sc.EvalContext:
    return sc.EvalContext(
        repo_root=tmp_path,
        profile_id="container-baseline-1",
        workflows=WorkflowAnalysis(workflow_paths=[]),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(tmp_path: Path, rel: str, body: str) -> Path:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --- one: the spelling discovery never looked for -----------------------------------------------

#: Every one of these is a container build file the catalogue already claims to cover.
BUILD_FILE_NAMES = [
    "Containerfile",
    "containerfile",
    "Containerfile.dev",
    "Containerfile-prod",
    "api.Containerfile",
    "svc.containerfile",
    "Dockerfile",
    "Dockerfile.dev",
    "api.Dockerfile",
]


@pytest.mark.parametrize("name", BUILD_FILE_NAMES)
def test_every_build_file_spelling_is_discovered(name: str, tmp_path: Path) -> None:
    _write(tmp_path, name, f"FROM {PIN}\n")

    assert [p.name for p in find_dockerfiles(tmp_path)] == [name]


def test_a_nested_containerfile_is_discovered(tmp_path: Path) -> None:
    """The private function found root `Containerfile` only; nested ones were invisible."""

    _write(tmp_path, "services/edge/Containerfile", f"FROM {PIN}\n")

    assert [p.name for p in find_dockerfiles(tmp_path)] == ["Containerfile"]


def test_an_unpinned_containerfile_fails_the_pin_control(tmp_path: Path) -> None:
    """The blocker end to end: the control that said "No Dockerfile detected" now answers."""

    _write(tmp_path, "Containerfile", "FROM alpine:3.19\nUSER root\n")

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.FAIL
    assert "alpine:3.19" in outcome.reason


def test_a_root_user_in_a_containerfile_fails_the_user_control(tmp_path: Path) -> None:
    _write(tmp_path, "Containerfile", f"FROM {PIN}\nUSER root\n")

    assert sc.eval_cont_image_002(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_a_repository_with_no_build_file_at_all_is_still_not_applicable(tmp_path: Path) -> None:
    """The over-withdrawal check: widening discovery must not make absence into a finding."""

    outcome = sc.eval_cont_image_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.NOT_APPLICABLE
    assert "Containerfile" in outcome.reason, "the message must name what was actually looked for"


# --- three: the final stage is the image that ships ---------------------------------------------


def test_a_throwaway_scratch_stage_does_not_pass_an_alpine_runtime(tmp_path: Path) -> None:
    """The shipped image is `alpine:3.19`. An earlier `FROM scratch` is a build stage."""

    _write(tmp_path, "Dockerfile", "FROM scratch AS throwaway\nCOPY x /x\n\nFROM alpine:3.19 AS runtime\nUSER app\n")

    outcome = sc.eval_cont_distroless_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "alpine:3.19" in outcome.reason


def test_a_build_that_really_ends_distroless_still_passes(tmp_path: Path) -> None:
    """The other direction: a real multi-stage build ending minimal keeps its PASS."""

    _write(
        tmp_path,
        "Dockerfile",
        "FROM golang:1.22 AS build\nRUN go build\n\n"
        "FROM gcr.io/distroless/static AS runtime\nCOPY --from=build /app /app\n",
    )

    assert sc.eval_cont_distroless_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_every_build_file_must_end_minimal_not_just_one_of_them(tmp_path: Path) -> None:
    """`from_lines` was one flat list across every file, so one good file covered a bad one."""

    _write(tmp_path, "Dockerfile.good", "FROM gcr.io/distroless/static\n")
    _write(tmp_path, "Dockerfile.bad", "FROM ubuntu:22.04\n")

    outcome = sc.eval_cont_distroless_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "ubuntu" in outcome.reason


# --- two: the names the private discovery could not see -----------------------------------------


def test_the_distroless_control_sees_suffixed_and_prefixed_names(tmp_path: Path) -> None:
    """It answered "No Dockerfile / Containerfile detected" at high confidence for these."""

    _write(tmp_path, "Dockerfile.svc01", "FROM gcr.io/distroless/static\n")
    _write(tmp_path, "api.Dockerfile", "FROM cgr.dev/chainguard/static\n")

    outcome = sc.eval_cont_distroless_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.PASS
    assert "2 checked" in outcome.reason


def test_the_distroless_control_reads_a_containerfile(tmp_path: Path) -> None:
    _write(tmp_path, "Containerfile", "FROM ubuntu:22.04\n")

    outcome = sc.eval_cont_distroless_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "ubuntu" in outcome.reason


def test_the_distroless_control_withdraws_on_an_unreadable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same ordering rule as its siblings: a withdrawal may replace a PASS, never a finding."""

    _write(tmp_path, "Dockerfile", "FROM gcr.io/distroless/static\n")
    target = _write(tmp_path, "other/Dockerfile", "FROM gcr.io/distroless/static\n")
    real = Path.read_bytes

    def refuse(self: Path) -> bytes:
        if self == target:
            raise PermissionError(13, "Permission denied")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", refuse)

    assert sc.eval_cont_distroless_001(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_a_real_finding_still_outranks_an_unreadable_sibling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The invariant that keeps a withdrawal from clearing a red pipeline."""

    _write(tmp_path, "Dockerfile", "FROM ubuntu:22.04\n")
    target = _write(tmp_path, "other/Dockerfile", "FROM gcr.io/distroless/static\n")
    real = Path.read_bytes

    def refuse(self: Path) -> bytes:
        if self == target:
            raise PermissionError(13, "Permission denied")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", refuse)

    outcome = sc.eval_cont_distroless_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "ubuntu" in outcome.reason, "the finding must be named, not replaced by the gap"
