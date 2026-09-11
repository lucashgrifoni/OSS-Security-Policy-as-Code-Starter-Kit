"""A control must not say "no X here" about a file it never read.

Two ways the kit ended up doing exactly that, both found by end-user validation rather than by
the suite, and both producing a PASS on a security control:

1. The workflow size cap refused to read an oversized file, recorded an operational warning, and
   left the workflow signals empty. `CI-DANGER-007` then reported "No pull_request_target
   detected in workflows." Measured on the same repository with the same dangerous workflow,
   changing only the file's padding:

       131 bytes   CI-DANGER-007 = FAIL   "pull_request_target detected in: hidden.yml"   exit 1
       1.4 MiB     CI-DANGER-007 = PASS   "No pull_request_target detected in workflows." exit 0

   `pull_request_target` is the pwn-request vector, and auditing a repository you do not control
   is the case this product exists for. The cap was added in the release before this one, so this
   was a regression: the previous version read the file, slowly, and saw the finding.

2. A Dockerfile written in UTF-16 read as UTF-8 arrives as mojibake, every pattern misses, and
   `CONT-IMAGE-001` reported "All Dockerfile FROM instructions use digest-pinned base images" for
   a file whose first line is `FROM alpine:3.19`.

`parse_errors` could not carry the first case, because it already meant something narrower --
the text WAS read and the YAML did not parse, so a raw-text scan still saw the content. Hence
`unread_paths`, which is empty for every ordinary target, so adding the check to a control cannot
change a verdict it reaches today.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from oss_policy_kit.application.input_limits import MAX_CI_CONFIG_BYTES

REPO_ROOT = Path(__file__).resolve().parents[2]
HARDENED = REPO_ROOT / "examples" / "hardened-repo"

DANGEROUS_WORKFLOW = (
    "name: dangerous\n"
    "on:\n"
    "  pull_request_target:\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@main\n"
)


def _evaluate(target: Path, profile: str = "github-level-1") -> dict:
    out = target / "_out"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(target),
            "--profile",
            profile,
            "--output-dir",
            str(out),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        check=False,
    )
    return json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))


def _state(report: dict, control_id: str) -> str:
    return {c["id"]: c for c in report["controls"]}[control_id]["state"]


def _message(report: dict, control_id: str) -> str:
    return {c["id"]: c for c in report["controls"]}[control_id].get("message") or ""


@pytest.fixture
def target_with_dangerous_workflow(tmp_path: Path):
    """A hardened repository plus one workflow that should fail two controls."""

    def build(padding_bytes: int) -> Path:
        target = tmp_path / f"t{padding_bytes}"
        shutil.copytree(HARDENED, target)
        workflow = target / ".github" / "workflows" / "hidden.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        body = DANGEROUS_WORKFLOW
        if padding_bytes:
            # Comments: they change the size and nothing about what the workflow does.
            filler = "# " + "x" * 78 + "\n"
            body += filler * (1 + padding_bytes // len(filler))
        workflow.write_text(body, encoding="utf-8", newline="\n")
        return target

    return build


@pytest.mark.parametrize("control_id", ["CI-DANGER-007", "CI-PIN-008"])
def test_a_small_dangerous_workflow_fails_the_control(control_id: str, target_with_dangerous_workflow) -> None:
    """The baseline. Without this, the test below could pass on a target that was never risky."""

    report = _evaluate(target_with_dangerous_workflow(0))

    assert _state(report, control_id) == "FAIL"


@pytest.mark.parametrize("control_id", ["CI-DANGER-007", "CI-PIN-008"])
def test_the_same_workflow_past_the_cap_is_not_reported_as_absent(
    control_id: str, target_with_dangerous_workflow
) -> None:
    """Same content, same repository, only the padding differs. It must not become a PASS."""

    report = _evaluate(target_with_dangerous_workflow(MAX_CI_CONFIG_BYTES + 400_000))

    assert _state(report, control_id) != "PASS", (
        f"{control_id} claimed a clean result about a file the kit refused to read: {_message(report, control_id)!r}"
    )
    assert "could not be established" in _message(report, control_id)


def test_the_refused_file_is_named_so_the_operator_can_act(target_with_dangerous_workflow) -> None:
    """Degrading is half of it. A reader who cannot tell which file to fix is no better off."""

    report = _evaluate(target_with_dangerous_workflow(MAX_CI_CONFIG_BYTES + 400_000))

    assert "hidden.yml" in _message(report, "CI-DANGER-007")


def test_an_ordinary_repository_is_untouched_by_the_degradation(tmp_path: Path) -> None:
    """`unread_paths` is empty for every normal target, so no existing verdict moves.

    This is what makes the check safe to add to a control that already had none.
    """

    target = tmp_path / "clean"
    shutil.copytree(HARDENED, target)

    report = _evaluate(target)

    assert _state(report, "CI-DANGER-007") == "PASS"
    assert _message(report, "CI-DANGER-007") == "No pull_request_target detected in workflows."


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize(
    ("control_id", "expected_phrase"),
    [
        ("CONT-IMAGE-001", "without digest pin"),
        ("CONT-IMAGE-002", "USER root"),
    ],
)
def test_a_dockerfile_gets_the_same_verdict_whatever_encoding_wrote_it(
    encoding: str, control_id: str, expected_phrase: str, tmp_path: Path
) -> None:
    """The verdict is about the Dockerfile's content, not about the editor that saved it.

    The phrase matters as much as the state. Asserting only `FAIL` was not enough: with the
    decode reverted, `CONT-IMAGE-002` still failed this target -- but for the wrong reason, as
    "no non-root USER declared" rather than "USER root". Mojibake makes every pattern miss, and
    one of the misses happened to land on a different failing branch. The mutation run caught
    that; the state assertion alone did not.
    """

    target = tmp_path / f"{control_id}-{encoding}"
    target.mkdir(parents=True)
    (target / "Dockerfile").write_bytes("FROM alpine:3.19\nUSER root\n".encode(encoding))
    (target / "SECURITY.md").write_text("Report to security@example.com\n", encoding="utf-8")

    report = _evaluate(target, profile="github-level-3")

    assert _state(report, control_id) == "FAIL", (
        f"{control_id} came back {_state(report, control_id)} for a Dockerfile written in "
        f"{encoding}: {_message(report, control_id)!r}"
    )
    assert expected_phrase in _message(report, control_id), (
        f"{control_id} failed for the wrong reason on a {encoding} Dockerfile, which is what "
        f"reading mojibake looks like: {_message(report, control_id)!r}"
    )
