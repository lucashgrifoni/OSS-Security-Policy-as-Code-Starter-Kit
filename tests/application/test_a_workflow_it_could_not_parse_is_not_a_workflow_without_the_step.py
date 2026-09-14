"""SEC-DEPREV-011 said a repository had no dependency review, about the workflow that runs it.

Measured against the built wheel. Two workflows, one of them indented with tabs:

    .github/workflows/ci.yml     parses, no dependency review
    .github/workflows/deps.yml   does not parse, and runs
                                 actions/dependency-review-action@0efb1d1

    operational_warnings  ["Workflow parse issue deps.yml: found character '\\t' ..."]
    SEC-DEPREV-011        FAIL   "No dependency-review-action detected in workflows."

The run recorded the parse error and reported it as an operational warning. The control
ignored it and stated a universal negative over a file whose contents it never saw.

SCOPE, measured rather than assumed. Breaking one workflow's indentation in a repository that
has the full set of signals changes eight verdicts, and seven of them already answer
`manual-review-required`:

    CI-LEAST-009    pass           -> manual-review-required
    CI-PERM-006     pass           -> manual-review-required
    GH-PROV-023     not-applicable -> manual-review-required
    GH-REL-021      not-applicable -> manual-review-required
    GH-WF-018       pass           -> manual-review-required
    GH-WF-019       pass           -> manual-review-required
    GH-WF-020       pass           -> manual-review-required
    SEC-DEPREV-011  pass           -> FAIL

This was the last one, and it is the only one whose absence answer is a FAIL rather than a
PASS. That is why it was missed, and it is why the fix is a different shape.

WHAT IS DELIBERATELY NOT DONE HERE. The seven siblings withdraw a PASS, which is what
`unread_workflow_degradation` is for. Withdrawing this one would take a failure out of
`--fail-on fail`, and for the adopter who genuinely has no dependency review AND one
unreadable workflow that turns a red pipeline green. `decode_source` already wrote the rule
down while fixing a related bug: turning a red pipeline green is not a smaller mistake than a
wrong verdict, it is a larger one.

So the verdict stays FAIL, which is the safe answer and carries the right remediation either
way, and the sentence stops claiming more than the run checked.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.application.evaluators.cicd import eval_sec_deprev_011
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

PLAIN = """name: CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"""

#: Every signal the workflow family reads, so the readable leg proves the fixture is rich
#: before the unreadable leg claims a verdict went missing.
RICH = """name: Security
on: [pull_request]
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@0efb1d1d84fc9633afcdaa81c4b1c0fd8676396a
      - uses: github/codeql-action/analyze@df409f7d9260372bd5f19e5b04e83cb3c43714ae
      - uses: actions/attest-build-provenance@897ed5eae8a729bf8cbfad3f2a5b30a0d6a7bcbc
"""

#: The same file with one job key indented by a tab, which YAML forbids. This is what an
#: editor with the wrong setting produces, and GitHub Actions would refuse it too.
UNPARSEABLE = RICH.replace("\n  review:", "\n\treview:")


def _repo(tmp_path: Path, second: str, *, name: str = "sec.yml") -> Path:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "ci.yml").write_text(PLAIN, encoding="utf-8")
    (workflows / name).write_text(second, encoding="utf-8")
    return tmp_path


def _ctx(root: Path) -> EvalContext:
    """A real EvalContext, not a stand-in.

    The sweep at the bottom runs EVERY registered evaluator, and several read fields a
    hand-rolled namespace does not have. Building the real thing is also the only way the
    sweep proves anything: a control that raises is a control this file did not measure.
    """

    return EvalContext(
        repo_root=root,
        profile_id="github-level-1",
        workflows=analyze_workflows(root),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def test_the_fixture_really_does_run_dependency_review(tmp_path: Path) -> None:
    """The control leg. Without it, "the signal went missing" could mean it was never there."""

    outcome = eval_sec_deprev_011(_ctx(_repo(tmp_path, RICH)))

    assert outcome.status == ControlStatus.PASS


def test_the_absence_claim_names_the_workflow_it_could_not_read(tmp_path: Path) -> None:
    """The defect. The sentence was false, and nothing in the verdict said why."""

    outcome = eval_sec_deprev_011(_ctx(_repo(tmp_path, UNPARSEABLE)))

    assert "sec.yml" in outcome.reason, outcome.reason
    assert "does not cover" in outcome.reason


def test_the_verdict_stays_a_failure(tmp_path: Path) -> None:
    """The half that is easy to get wrong, and the reason this control is not withdrawn.

    An adopter who genuinely has no dependency review and one unreadable workflow must still
    get a FAIL. `manual-review-required` does not trip `--fail-on fail`, so withdrawing here
    would turn their red pipeline green -- a larger mistake than a wrong verdict, which is the
    rule `decode_source` recorded while fixing a related bug.
    """

    outcome = eval_sec_deprev_011(_ctx(_repo(tmp_path, UNPARSEABLE)))

    assert outcome.status == ControlStatus.FAIL


def test_the_confidence_drops_and_the_remediation_says_what_to_fix_first(tmp_path: Path) -> None:
    unreadable = eval_sec_deprev_011(_ctx(_repo(tmp_path, UNPARSEABLE)))

    assert unreadable.confidence == "low"
    assert "unreadable workflow" in unreadable.remediation


def test_an_ordinary_repository_gets_no_extra_clause(tmp_path: Path) -> None:
    """Every workflow read is every ordinary target, and the message there must not change."""

    outcome = eval_sec_deprev_011(_ctx(_repo(tmp_path, PLAIN, name="other.yml")))

    assert outcome.status == ControlStatus.FAIL
    assert outcome.reason == "No dependency-review-action detected in workflows."
    assert outcome.confidence == "medium"


def test_a_workflow_refused_by_the_size_cap_counts_too(tmp_path: Path) -> None:
    """`parse_errors` and `unread_paths` are separate lists and mean different things.

    One says the bytes were read and the YAML did not parse. The other says nothing was read
    at all. A control stating an absence is equally wrong about either, so the note covers
    both -- the first version of this read only `parse_errors` and left the size cap open.
    """

    from oss_policy_kit.application.evaluators._shared import unchecked_workflows_note

    only_unread = SimpleNamespace(parse_errors=[], unread_paths=[Path("huge.yml")])
    only_parse = SimpleNamespace(parse_errors=[(Path("bad.yml"), "boom")], unread_paths=[])
    clean = SimpleNamespace(parse_errors=[], unread_paths=[])

    assert "huge.yml" in unchecked_workflows_note(only_unread)
    assert "bad.yml" in unchecked_workflows_note(only_parse)
    assert unchecked_workflows_note(clean) == ""


def test_the_note_does_not_pass_off_a_truncated_list_as_a_complete_one() -> None:
    """Eight unread workflows must not be reported as the five the message has room for."""

    from oss_policy_kit.application.evaluators._shared import unchecked_workflows_note

    many = SimpleNamespace(parse_errors=[(Path(f"w{n}.yml"), "boom") for n in range(8)], unread_paths=[])

    assert "and 3 more" in unchecked_workflows_note(many)


def test_the_same_file_twice_is_counted_once() -> None:
    """A workflow can land in both lists, and naming it twice would overstate the damage."""

    from oss_policy_kit.application.evaluators._shared import unchecked_workflows_note

    both = SimpleNamespace(parse_errors=[(Path("a/bad.yml"), "boom")], unread_paths=[Path("b/bad.yml")])

    assert unchecked_workflows_note(both).count("bad.yml") == 1


# --- the family, measured ---------------------------------------------------------------------


#: What each control answers about a repository whose second workflow will not parse. Seven
#: withdraw, and the eighth is the one this file is about. Written down so a future change that
#: quietly moves one of them has to say so here.
EXPECTED_WHEN_UNREADABLE = {
    "CI-LEAST-009": ControlStatus.MANUAL_REVIEW_REQUIRED,
    "CI-PERM-006": ControlStatus.MANUAL_REVIEW_REQUIRED,
    "GH-PROV-023": ControlStatus.MANUAL_REVIEW_REQUIRED,
    "GH-REL-021": ControlStatus.MANUAL_REVIEW_REQUIRED,
    "GH-WF-018": ControlStatus.MANUAL_REVIEW_REQUIRED,
    "GH-WF-019": ControlStatus.MANUAL_REVIEW_REQUIRED,
    "GH-WF-020": ControlStatus.MANUAL_REVIEW_REQUIRED,
    "SEC-DEPREV-011": ControlStatus.FAIL,
}


@pytest.mark.parametrize("control_id", sorted(EXPECTED_WHEN_UNREADABLE))
def test_the_workflow_family_answers_as_measured(control_id: str, tmp_path: Path) -> None:
    ctx = _ctx(_repo(tmp_path, UNPARSEABLE))

    assert EVALUATOR_REGISTRY[control_id](ctx).status == EXPECTED_WHEN_UNREADABLE[control_id]


def test_no_control_silently_keeps_a_clean_verdict_over_the_unread_workflow(tmp_path: Path) -> None:
    """The sweep behind the table: nothing may go from a positive answer to another positive one.

    A control that answered PASS on the readable repository and still answers PASS after the
    same file stops parsing has either found its signal elsewhere, which is fine, or is
    asserting over content it did not read, which is the defect class. Enumerated so the next
    one cannot hide in a family nobody re-measured.
    """

    readable = {cid: fn(_ctx(_repo(tmp_path / "a", RICH))).status for cid, fn in EVALUATOR_REGISTRY.items()}
    unreadable = {cid: fn(_ctx(_repo(tmp_path / "b", UNPARSEABLE))).status for cid, fn in EVALUATOR_REGISTRY.items()}

    changed = {cid for cid in readable if readable[cid] != unreadable[cid]}

    assert changed == set(EXPECTED_WHEN_UNREADABLE), (
        "the set of controls that notice an unreadable workflow changed: "
        f"added {sorted(changed - set(EXPECTED_WHEN_UNREADABLE))}, "
        f"lost {sorted(set(EXPECTED_WHEN_UNREADABLE) - changed)}"
    )
    assert Counter(unreadable[c] for c in changed)[ControlStatus.PASS] == 0
