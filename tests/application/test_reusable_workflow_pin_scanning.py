"""Reusable-workflow SHA pinning, including the path taken when the YAML will not parse.

`CI-WFCALLSHA-055` normally reads the workflow structurally. When the file is not valid YAML it
falls back to a line regex, and that fallback is the half worth pinning: a workflow the parser
chokes on is exactly the one an attacker would leave unparseable, and the control must still
notice a `uses:` pointing at a mutable ref.

The two accumulator guards (`path not in call_paths`, `path not in bad_paths`) exist so one file
is reported once no matter how many offending references it holds, and both directions of each
are asserted -- a de-duplication that never de-duplicates looks identical to a file with a
single finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import cicd
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_SHA = "a" * 40


def _ctx(root: Path, *workflows: Path) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id="github-level-2",
        workflows=WorkflowAnalysis(workflow_paths=list(workflows)),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _workflow(root: Path, name: str, body: str) -> Path:
    path = root / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Regex fallback (unparseable YAML)
# --------------------------------------------------------------------------- #

_UNPARSEABLE = """\
jobs:
  call-a:
    uses: org/repo/.github/workflows/ci.yml@v1
  call-b:
    uses: org/repo/.github/workflows/release.yml@main
  checkout:
    uses: actions/checkout@v4
  dynamic:
    uses: ${{ inputs.workflow }}
broken: [
"""


def test_a_workflow_that_will_not_parse_is_still_scanned_for_mutable_pins(tmp_path: Path) -> None:
    """The parser giving up must not be the same thing as the control giving up."""

    wf = _workflow(tmp_path, "caller.yml", _UNPARSEABLE)
    outcome = cicd.eval_ci_wfcallsha_055(_ctx(tmp_path, wf))

    assert outcome.status is ControlStatus.FAIL
    assert "caller.yml" in outcome.reason
    assert any("regex-fallback" in src for src in outcome.evidence_sources)
    assert outcome.operational_warnings, "an adopter has to be told the structural check was skipped"


def test_the_fallback_reports_each_offending_reference_but_the_file_only_once(tmp_path: Path) -> None:
    wf = _workflow(tmp_path, "caller.yml", _UNPARSEABLE)
    acc = cicd._WfCallShaScan()
    cicd._scan_wfcallsha_regex(_UNPARSEABLE, wf, acc)

    assert acc.call_paths == [wf]
    assert acc.bad_paths == [wf]
    assert len(acc.bad_evidence_sources) == 2, acc.bad_evidence_sources


@pytest.mark.parametrize(
    ("label", "line"),
    [
        ("a plain action, not a reusable workflow", "    uses: actions/checkout@v4"),
        ("a ref built from an expression at runtime", "    uses: ${{ inputs.workflow }}"),
    ],
)
def test_the_fallback_ignores_references_that_are_not_reusable_workflow_calls(
    label: str, line: str, tmp_path: Path
) -> None:
    """Counting these would fail every repository that checks out its own code."""

    wf = _workflow(tmp_path, "caller.yml", f"jobs:\n{line}\nbroken: [\n")
    acc = cicd._WfCallShaScan()
    cicd._scan_wfcallsha_regex(wf.read_text(encoding="utf-8"), wf, acc)

    assert acc.call_paths == [], label
    assert acc.bad_paths == []


def test_the_fallback_accepts_a_full_sha(tmp_path: Path) -> None:
    body = f"jobs:\n  a:\n    uses: org/repo/.github/workflows/ci.yml@{_SHA}\nbroken: [\n"
    wf = _workflow(tmp_path, "caller.yml", body)
    outcome = cicd.eval_ci_wfcallsha_055(_ctx(tmp_path, wf))

    assert outcome.status is ControlStatus.PASS


# --------------------------------------------------------------------------- #
# Structured scan
# --------------------------------------------------------------------------- #


def test_two_mutable_calls_in_one_file_are_reported_as_one_file(tmp_path: Path) -> None:
    body = (
        "on: push\njobs:\n"
        "  a:\n    uses: org/repo/.github/workflows/ci.yml@v1\n"
        "  b:\n    uses: org/repo/.github/workflows/release.yml@main\n"
    )
    wf = _workflow(tmp_path, "caller.yml", body)
    outcome = cicd.eval_ci_wfcallsha_055(_ctx(tmp_path, wf))

    assert outcome.status is ControlStatus.FAIL
    assert outcome.reason.count("caller.yml") == 1
    assert len(outcome.evidence_sources) == 2, "both call sites still have to be locatable"
    assert not outcome.operational_warnings, "the file parsed; there is nothing to warn about"


def test_a_file_already_recorded_as_a_caller_is_not_recorded_twice(tmp_path: Path) -> None:
    """The accumulator is shared across files, so its guards are asserted at the helper.

    `eval_ci_wfcallsha_055` visits each workflow once, which means this idempotence can only be
    reached by handing the helper an accumulator that already knows the path -- exactly what a
    future caller looping over overlapping path lists would do.
    """

    wf = _workflow(tmp_path, "caller.yml", "on: push\njobs:\n  a:\n    uses: org/repo/.github/workflows/ci.yml@v1\n")
    acc = cicd._WfCallShaScan(call_paths=[wf], bad_paths=[wf])
    cicd._scan_wfcallsha_structured({"jobs": {"a": {"uses": "org/repo/.github/workflows/ci.yml@v1"}}}, wf, acc)

    assert acc.call_paths == [wf]
    assert acc.bad_paths == [wf]


def test_a_workflow_calling_nothing_reusable_is_not_applicable(tmp_path: Path) -> None:
    wf = _workflow(tmp_path, "ci.yml", "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
    assert cicd.eval_ci_wfcallsha_055(_ctx(tmp_path, wf)).status is ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# .gitignore that exists but cannot be read
# --------------------------------------------------------------------------- #


def test_an_unreadable_gitignore_is_not_credited_with_patterns_it_might_contain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file the kit cannot open has to be treated as empty, not as passing.

    Reading it is best-effort by design -- a permission error on `.gitignore` should not abort a
    whole evaluation -- but "best-effort" must resolve downwards.
    """

    (tmp_path / ".gitignore").write_text(".env\n*.pem\n", encoding="utf-8")
    original = Path.read_text

    def _refuse(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == ".gitignore":
            raise PermissionError("locked")
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    # read_bytes as well as read_text: the reader under test decodes bytes so it can honour
    # the encoding a file declares, and a patch that covers only one of them refuses nothing.
    monkeypatch.setattr(Path, "read_text", _refuse)
    monkeypatch.setattr(Path, "read_bytes", _refuse)
    outcome = cicd.eval_sec_gitignore_051(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "no common secret-protection patterns" in outcome.reason
