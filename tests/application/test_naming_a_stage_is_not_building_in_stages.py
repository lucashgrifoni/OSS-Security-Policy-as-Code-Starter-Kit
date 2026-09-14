"""One stage called `AS build` is one stage. CONT-RUNTIME-001 called it a multi-stage build.

Measured against the built wheel in a clean room, on this Dockerfile:

    FROM ubuntu:22.04 AS build
    RUN apt-get update
    USER app

    CONT-RUNTIME-001 = PASS, "Multi-stage build detected in Dockerfile."

The condition was `len(froms) >= 2 or any(" AS <name>" in a FROM line)`. The second half is
the defect: naming a stage is not building in stages. The control exists to check that the
image which ships is not the image that compiled, and a one-stage build ships exactly the
build image however it is labelled. Labelling the only stage `AS build` is common, because
people copy the first line of a multi-stage example and stop there -- which is precisely the
repository this control should be failing.

A multi-stage build is two or more `FROM` instructions. Nothing else.

A commented-out `FROM` was checked too and needs no work: `_DOCKER_FROM_RE` anchors at the
start of the line and `#` is not whitespace, so `# FROM alpine AS runtime` never counted.
Verified rather than assumed, because this repository has shipped a control that read a
commented-out step as a live one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application import evaluators_containers as ec
from oss_policy_kit.application.evaluators import supply_chain as sc
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> sc.EvalContext:
    return sc.EvalContext(
        repo_root=tmp_path,
        profile_id="container-baseline-1",
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


#: Every one of these is ONE stage, however it is written.
SINGLE_STAGE = {
    "named AS build": "FROM ubuntu:22.04 AS build\nRUN apt-get update\nUSER app\n",
    "named AS runtime": "FROM ubuntu:22.04 AS runtime\nUSER app\n",
    "named, lowercase as": "FROM ubuntu:22.04 as build\nUSER app\n",
    "unnamed": "FROM ubuntu:22.04\nUSER app\n",
    "named, with a commented second FROM": (
        "FROM ubuntu:22.04 AS build\nUSER app\n# FROM alpine:3.19 AS runtime  (abandoned)\n"
    ),
    "named, with a platform flag": "FROM --platform=$BUILDPLATFORM ubuntu:22.04 AS build\nUSER app\n",
}


@pytest.mark.parametrize("label", sorted(SINGLE_STAGE), ids=sorted(SINGLE_STAGE))
def test_a_single_stage_build_does_not_pass_however_it_is_labelled(label: str, tmp_path: Path) -> None:
    _dockerfile(tmp_path, SINGLE_STAGE[label])

    outcome = ec.eval_cont_runtime_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.FAIL, f"{label} was read as a multi-stage build"


#: And every one of these really is more than one stage.
MULTI_STAGE = {
    "two stages, both named": (
        "FROM golang:1.22 AS build\nRUN go build\n\nFROM alpine:3.19 AS runtime\nCOPY --from=build /app /app\n"
    ),
    "two stages, neither named": "FROM golang:1.22\nRUN go build\n\nFROM alpine:3.19\nCOPY /app /app\n",
    "three stages": "FROM a AS one\n\nFROM b AS two\n\nFROM c AS three\n",
    "second stage indented": "FROM golang:1.22 AS build\n\n  FROM alpine:3.19 AS runtime\n",
    "second stage lowercase": "FROM golang:1.22 AS build\n\nfrom alpine:3.19 AS runtime\n",
}


@pytest.mark.parametrize("label", sorted(MULTI_STAGE), ids=sorted(MULTI_STAGE))
def test_a_real_multi_stage_build_still_passes(label: str, tmp_path: Path) -> None:
    """The half this fix could have broken, which is the more expensive direction."""

    _dockerfile(tmp_path, MULTI_STAGE[label])

    outcome = ec.eval_cont_runtime_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.PASS, f"{label} stopped being read as multi-stage"


def test_the_pass_message_says_how_many_stages_it_found(tmp_path: Path) -> None:
    """A count is checkable; "detected" was not, and it was wrong for two years of labels."""

    _dockerfile(tmp_path, MULTI_STAGE["three stages"])

    assert "3 stages" in ec.eval_cont_runtime_001(_ctx(tmp_path)).reason


def test_one_multi_stage_file_among_single_stage_ones_still_passes(tmp_path: Path) -> None:
    """The control is "at least one Dockerfile uses a multi-stage build", and stays so."""

    _dockerfile(tmp_path, SINGLE_STAGE["unnamed"], rel="a/Dockerfile")
    _dockerfile(tmp_path, MULTI_STAGE["two stages, both named"], rel="b/Dockerfile")

    assert ec.eval_cont_runtime_001(_ctx(tmp_path)).status == ControlStatus.PASS


def test_no_build_file_at_all_is_still_not_applicable(tmp_path: Path) -> None:
    outcome = ec.eval_cont_runtime_001(_ctx(tmp_path))

    assert outcome.status == ControlStatus.NOT_APPLICABLE
