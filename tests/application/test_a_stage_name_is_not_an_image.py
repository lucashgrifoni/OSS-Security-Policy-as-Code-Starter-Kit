"""A fully digest-pinned Dockerfile failed CONT-IMAGE-001, because a stage name is not an image.

Measured against the built wheel:

    FROM python:3.12-slim@sha256:1234... AS base
    FROM base AS build
    FROM base AS runtime

    CONT-IMAGE-001       FAIL     without digest pin: Dockerfile: base; Dockerfile: base.
    CONT-DISTROLESS-001  UNKNOWN  Final base image does not appear distroless (Dockerfile: base).
    exit 1

`base` is the stage declared on line one, which IS digest-pinned. Docker resolves a stage name
against the stages declared earlier in the same file before it looks at any registry, so
`FROM base` pulls nothing at all.

The repository did exactly what the control asks for and the control failed it. That is not a
conservative error. A false FAIL on a control an adopter has already satisfied is how a control
gets waived, and a waived control is one nobody reads again.

The second half of the same blocker is the 20-file cap, in
`test_a_cap_is_not_an_absence.py`.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators._shared import docker_from_instructions
from oss_policy_kit.application.evaluators.supply_chain import (
    eval_cont_distroless_001,
    eval_cont_image_001,
)
from oss_policy_kit.domain.models import ControlStatus

PINNED = "python:3.12-slim@sha256:" + "ab" * 32
DISTROLESS = "gcr.io/distroless/static@sha256:" + "cd" * 32

LAYERED = f"""FROM {PINNED} AS base
RUN useradd -m app

FROM base AS build
RUN pip install --no-cache-dir build

FROM base AS runtime
COPY --from=build /app /app
USER app
"""


def _repo(tmp_path: Path, body: str, *, name: str = "Dockerfile") -> Path:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return tmp_path


def _ctx(root: Path) -> SimpleNamespace:
    return SimpleNamespace(repo_root=root)


# --- the helper, at its edges --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "content", "expected"),
    [
        ("one image", "FROM alpine:3.19\n", [("alpine:3.19", "alpine:3.19", False)]),
        (
            "a stage used later",
            "FROM alpine:3.19 AS base\nFROM base\n",
            [("alpine:3.19", "alpine:3.19", False), ("base", "alpine:3.19", True)],
        ),
        (
            "a chain of stages",
            "FROM alpine:3.19 AS base\nFROM base AS build\nFROM build AS final\n",
            [
                ("alpine:3.19", "alpine:3.19", False),
                ("base", "alpine:3.19", True),
                ("build", "alpine:3.19", True),
            ],
        ),
        (
            # Docker lowercases stage names, so `AS Base` and `FROM base` are the same stage.
            "case does not matter",
            "FROM alpine:3.19 AS Base\nFROM BASE\n",
            [("alpine:3.19", "alpine:3.19", False), ("BASE", "alpine:3.19", True)],
        ),
        (
            # Only backward. A name used before it is declared matches no stage, and Docker
            # would try to pull it -- so the control is right to judge it as an image.
            "a forward reference is a pull",
            "FROM later\nFROM alpine:3.19 AS later\n",
            [("later", "later", False), ("alpine:3.19", "alpine:3.19", False)],
        ),
        (
            "platform flags do not hide the ref",
            "FROM --platform=$BUILDPLATFORM alpine:3.19 AS base\nFROM base\n",
            [("alpine:3.19", "alpine:3.19", False), ("base", "alpine:3.19", True)],
        ),
        (
            "a commented FROM is not a FROM",
            "# FROM alpine:3.19 AS base\nFROM scratch\n",
            [("scratch", "scratch", False)],
        ),
    ],
)
def test_the_reader_resolves_stage_names(label: str, content: str, expected: list[tuple[str, str, bool]]) -> None:
    assert [(f.ref, f.resolved, f.names_a_stage) for f in docker_from_instructions(content)] == expected, label


# --- CONT-IMAGE-001 --------------------------------------------------------------------------------


def test_a_layered_pinned_build_passes(tmp_path: Path) -> None:
    """The reproduction. This said FAIL, twice, about a file with one registry reference."""

    outcome = eval_cont_image_001(_ctx(_repo(tmp_path, LAYERED)))

    assert outcome.status == ControlStatus.PASS, outcome.reason


def test_an_unpinned_image_still_fails_in_a_layered_build(tmp_path: Path) -> None:
    """The half this fix could have broken, which is the more expensive direction.

    Resolving stage names must not turn into ignoring images. The pin check still has to see
    every real registry reference, including one introduced by a later stage.
    """

    body = f"FROM {PINNED} AS base\nFROM alpine:3.19 AS tools\nFROM base AS runtime\n"

    outcome = eval_cont_image_001(_ctx(_repo(tmp_path, body)))

    assert outcome.status == ControlStatus.FAIL
    assert "alpine:3.19" in outcome.reason
    assert "base" not in outcome.reason.replace("base image", ""), "the stage name is not an unpinned image"


def test_a_forward_reference_is_still_judged_as_an_image(tmp_path: Path) -> None:
    """Docker would try to pull it, so the control must too. Skipping it would be a false PASS."""

    outcome = eval_cont_image_001(_ctx(_repo(tmp_path, "FROM later\nFROM alpine@sha256:" + "ef" * 32 + " AS later\n")))

    assert outcome.status == ControlStatus.FAIL
    assert "later" in outcome.reason


def test_a_single_unpinned_image_is_unaffected(tmp_path: Path) -> None:
    outcome = eval_cont_image_001(_ctx(_repo(tmp_path, "FROM ubuntu:22.04\n")))

    assert outcome.status == ControlStatus.FAIL
    assert "ubuntu:22.04" in outcome.reason


# --- CONT-DISTROLESS-001 ---------------------------------------------------------------------------


def test_the_final_stage_is_judged_by_the_image_it_resolves_to(tmp_path: Path) -> None:
    """`Final base image does not appear distroless (Dockerfile: base)` asked about a name."""

    body = f"FROM {DISTROLESS} AS base\nFROM base AS runtime\nUSER app\n"

    outcome = eval_cont_distroless_001(_ctx(_repo(tmp_path, body)))

    assert outcome.status == ControlStatus.PASS, outcome.reason


def test_a_layered_build_onto_a_fat_image_still_fails(tmp_path: Path) -> None:
    """The other direction: resolution must not launder a fat base through a stage name."""

    body = f"FROM {PINNED} AS base\nFROM base AS runtime\nUSER app\n"

    outcome = eval_cont_distroless_001(_ctx(_repo(tmp_path, body)))

    assert outcome.status != ControlStatus.PASS
    assert "python:3.12-slim" in outcome.reason, "the reader deserves the real image, not the stage name"


def test_a_build_stage_on_a_fat_image_does_not_fail_a_distroless_runtime(tmp_path: Path) -> None:
    """The ordinary multi-stage shape, and the one the control exists for."""

    body = f"FROM {PINNED} AS build\nRUN make\n\nFROM {DISTROLESS} AS runtime\nCOPY --from=build /app /app\n"

    assert eval_cont_distroless_001(_ctx(_repo(tmp_path, body))).status == ControlStatus.PASS
