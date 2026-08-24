"""A CI file saved in UTF-16 is a CI file, and what it declares still counts.

`infrastructure/source_text.py` was written for exactly this failure and states it in its own
first paragraph: the scanners read everything as UTF-8 with `errors="replace"`, a file in another
encoding became mojibake, "the mojibake failed whatever 'is this a X' check came next, and the
file left through the *nothing to see here* door". `decode_source` is the repair. It was applied
to the CloudFormation, Bicep, Terraform and Kubernetes scanners -- and never reached the GitHub
workflow parser or the shared YAML reader every CI parser goes through.

Measured before this test existed, on a workflow whose single step is `actions/checkout@v4`:

    utf-8, deliberately unparseable  ->  CI-PIN-008 fail   (the raw-text fallback still saw it)
    utf-16, perfectly well-formed    ->  CI-PIN-008 PASS   (0 refs found, 1 parse error)

So the degraded PASS that CI-PIN-008 returns alongside parse errors is not itself the defect --
it is honest when the raw fallback can read the bytes, which case A shows it can. The defect is
that a UTF-16 file defeats both the parse and the fallback, and a mutable third-party pin earns a
clean pass for no reason other than how the file was saved.

YAML 1.2 requires a processor to accept UTF-8, UTF-16 and UTF-32. GitHub Actions runs such a
workflow. The kit was the only party treating it as unreadable.

`decode_source`'s own invariant makes this safe to apply widely: it honours a BOM and otherwise
falls back to precisely the lossy read that came before, so no input reads worse than it did.

A BOM is not required for any of this to be true. YAML 1.2 §5.2 specifies detection without one:
a YAML stream must begin with an ASCII character, so the null-byte pattern of the first four
bytes identifies the encoding unambiguously. `utf-16-le` and `utf-16-be` written without a BOM --
which is what several tools emit, and what anyone deliberately hiding a pin would choose -- were
still defeating the reader after the BOM'd forms were fixed. Both are covered here now.

The widening stays additive, which is the constraint that matters for this particular primitive:
detection is attempted, and anything that does not decode cleanly under the detected codec falls
back to the exact lossy read that came before. Two earlier attempts at making this reader
stricter shipped worse bugs than the one they fixed, both by refusing files the previous release
had read successfully. Nothing here refuses anything.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import _shared as s
from oss_policy_kit.application.evaluators.cicd import eval_ci_pin_008
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

_WORKFLOW = """name: ci
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""


def _ctx(repo_root: Path) -> s.EvalContext:
    return s.EvalContext(
        repo_root=repo_root,
        profile_id="github-level-1",
        workflows=analyze_workflows(repo_root),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _repo_with_workflow(root: Path, body: str, encoding: str) -> Path:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text(body, encoding=encoding)
    return root


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_a_workflow_in_a_wide_encoding_still_declares_what_it_declares(tmp_path: Path, encoding: str) -> None:
    """The reproduction: how the file was saved must not decide whether the control passes."""

    repo = _repo_with_workflow(tmp_path / encoding, _WORKFLOW, encoding)

    outcome = eval_ci_pin_008(_ctx(repo))

    assert outcome.status is ControlStatus.FAIL, (
        f"a workflow saved as {encoding} hid `actions/checkout@v4` and earned {outcome.status.value}"
    )


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-16-le", "utf-16-be"])
def test_such_a_workflow_parses_rather_than_being_recorded_as_broken(tmp_path: Path, encoding: str) -> None:
    """And it is not merely caught by the raw fallback -- it is a valid workflow and should parse.

    YAML 1.2 requires UTF-16 and UTF-32 support, so recording a parse error here would be the
    kit calling a file broken that GitHub Actions runs without complaint.
    """

    repo = _repo_with_workflow(tmp_path / encoding, _WORKFLOW, encoding)

    analysis = analyze_workflows(repo)

    assert not analysis.parse_errors, f"a valid {encoding} workflow was recorded as unparseable"
    assert analysis.workflow_paths


def test_the_raw_fallback_still_catches_a_genuinely_broken_workflow(tmp_path: Path) -> None:
    """Regression guard for the half that already worked.

    A tab in the indentation is a hard YAML error; the `uses:` line is untouched. This is the
    case that makes CI-PIN-008's degraded PASS defensible, and it must keep working.
    """

    repo = _repo_with_workflow(tmp_path / "broken", _WORKFLOW.replace("    steps:", "\tsteps:"), "utf-8")

    analysis = analyze_workflows(repo)

    assert analysis.parse_errors
    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.FAIL


def test_a_wide_encoding_and_a_broken_document_still_do_not_hide_the_pin(tmp_path: Path) -> None:
    """Both roads to the finding have to be open, because a hostile repository can close both.

    Once the shared reader decodes wide encodings, a UTF-16 workflow simply parses, and the
    raw-text fallback never runs -- so fixing the reader alone leaves the fallback still reading
    mojibake, and nothing in the suite would notice. This is the case that separates them: the
    file is UTF-16 *and* deliberately unparseable, so the fallback is the only thing left.
    """

    repo = _repo_with_workflow(tmp_path / "wide-and-broken", _WORKFLOW.replace("    steps:", "\tsteps:"), "utf-16")

    analysis = analyze_workflows(repo)

    assert analysis.parse_errors, "the harness is wrong: this document was supposed to be unparseable"
    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.FAIL


def test_a_single_odd_byte_does_not_cost_the_rest_of_the_file(tmp_path: Path) -> None:
    """`decode_source`'s invariant: never read less than the previous release read.

    A `.yml` saved as cp1252 with one accented byte in a comment is what any Windows editor
    produces. The old lossy read turned that byte into U+FFFD and still found everything under
    it; a strict read would refuse the file and lose the finding.
    """

    repo = tmp_path / "cp1252"
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(_WORKFLOW.replace("name: ci", "# revisão\nname: ci"), encoding="cp1252")

    assert eval_ci_pin_008(_ctx(repo)).status is ControlStatus.FAIL


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-16-le", "utf-16-be"])
def test_the_shared_yaml_reader_carries_the_same_repair(tmp_path: Path, encoding: str) -> None:
    """Every CI parser reads through `load_yaml_file`, so the repair belongs there too.

    A GitLab pipeline pinned to `python:latest` is a mutable tag GL-PIPE-002 fails on -- unless
    the file was saved in a wide encoding, in which case the kit found no image at all.
    """

    root = tmp_path / f"gitlab-{encoding}"
    root.mkdir()
    (root / ".gitlab-ci.yml").write_text("build:\n  image: python:latest\n  script: [make]\n", encoding=encoding)

    analysis = analyze_gitlab_ci(root)

    assert not analysis.parse_errors, f"a valid {encoding} pipeline was recorded as unparseable"
    assert analysis.image_refs_mutable_tag, "the mutable image tag was not seen"
