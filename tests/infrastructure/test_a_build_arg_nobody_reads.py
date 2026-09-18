"""A build argument the Dockerfile declares and never reads, fed by two workflows.

`ARG KIT_VERSION=5.9.0` sat four major versions behind the tree it shipped in, and nothing in
the Dockerfile referenced it. Two workflows passed it: the CI smoke build sent `0.0.0+ci` and
the publish job sent the real release version, and neither value reached anything.

It cost more than a dead line. The Loop 05 release-readiness gate builds a version identity
matrix across every surface, read `5.9.0` there, and I spent the next stretch investigating an
image that turned out to be correct: the published image carries
`org.opencontainers.image.version` because `publish-container.yml` sets it as a LABEL, which has
nothing to do with this argument.

Two guards, derived rather than listed, because the failure was a list nobody updated:

- every `ARG` the Dockerfile declares is referenced somewhere in it;
- every `build-args` entry a workflow passes names an `ARG` the Dockerfile declares.

The second is the one that catches the drift in the direction it actually travelled: the
Dockerfile stopped using the value and the workflows kept sending it.
"""

from __future__ import annotations

import re

import yaml
from tests.conftest import ROOT

DOCKERFILE = ROOT / "Dockerfile"
WORKFLOWS = ROOT / ".github" / "workflows"

#: `ARG NAME`, `ARG NAME=default`, indented or not.
_ARG_DECLARATION = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)

#: `--build-arg NAME=...` as a document writes it, with either spelling of the separator.
_DOC_BUILD_ARG = re.compile(r"--build-arg[=\s]+([A-Za-z_][A-Za-z0-9_]*)")

#: A fenced code block, which is the part of a page a reader copies and runs.
_FENCED_BLOCK = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)


def _runnable_text(markdown: str) -> str:
    """Only the fenced blocks, because only those are instructions rather than prose.

    Searching the whole page cannot tell "run this" from "this was removed, here is why", so it
    forbids a page from documenting its own history. The first version of this guard did
    exactly that: it failed on the paragraph in `docs/container-image.md` that explains the
    argument is gone, because the explanation necessarily names it.
    """

    return "\n".join(_FENCED_BLOCK.findall(markdown))


def _declared_args() -> set[str]:
    return set(_ARG_DECLARATION.findall(DOCKERFILE.read_text(encoding="utf-8")))


def _workflow_build_args() -> dict[str, set[str]]:
    """`{workflow name: {build-arg names it passes}}`, read out of the shipped workflows."""

    found: dict[str, set[str]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        names: set[str] = set()
        for job in (data.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                raw = (step.get("with") or {}).get("build-args")
                if not isinstance(raw, str):
                    continue
                for line in raw.splitlines():
                    if "=" in line:
                        names.add(line.split("=", 1)[0].strip())
        if names:
            found[path.name] = names
    return found


def test_the_dockerfile_reads_every_argument_it_declares() -> None:
    body = DOCKERFILE.read_text(encoding="utf-8")
    unread = sorted(name for name in _declared_args() if not re.search(r"\$\{?" + re.escape(name) + r"\b", body))

    assert not unread, f"declared and never referenced in the Dockerfile: {unread}"


def test_no_workflow_passes_a_build_arg_the_dockerfile_does_not_declare() -> None:
    """The direction the drift travelled: the Dockerfile dropped it, the workflows kept sending it."""

    declared = _declared_args()
    stray = {
        workflow: sorted(names - declared) for workflow, names in _workflow_build_args().items() if names - declared
    }

    assert not stray, f"build-args that reach no ARG: {stray}"


def test_no_document_teaches_a_build_arg_the_dockerfile_does_not_declare() -> None:
    """The third direction, and the one the first two guards were blind to.

    Removing the argument fixed the Dockerfile and both workflows and added the two guards
    above, and left `docs/container-image.md` telling adopters to pass
    `--build-arg KIT_VERSION=...`, described as feeding the image labels. The guards could not
    see it: their inputs are the Dockerfile and the workflows, and a documentation page is
    neither. BuildKit discards an undeclared build argument silently, so the documented command
    kept exiting 0 and nothing surfaced the drift.

    A reader runs what a page tells them to run, which makes a document as much a consumer of
    the Dockerfile's interface as a workflow is.
    """

    declared = _declared_args()
    stray: dict[str, list[str]] = {}
    for path in sorted(ROOT.glob("docs/**/*.md")) + sorted(ROOT.glob("*.md")):
        runnable = _runnable_text(path.read_text(encoding="utf-8"))
        names = sorted(set(_DOC_BUILD_ARG.findall(runnable)) - declared)
        if names:
            stray[path.relative_to(ROOT).as_posix()] = names

    assert not stray, f"documented --build-arg that reaches no ARG: {stray}"


def test_the_guard_is_reading_something() -> None:
    """An anti-vacuum floor: the checks above pass trivially if the parsing returns nothing."""

    body = DOCKERFILE.read_text(encoding="utf-8")

    assert "FROM" in body, "the Dockerfile was not read"
    assert _workflow_build_args() or not re.search(r"build-args:", body), (
        "no workflow build-args were parsed, so the second guard checked an empty set"
    )
    assert list(ROOT.glob("docs/**/*.md")), "no documentation was read, so the third guard checked nothing"
